// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/quic/quic_stream_sequencer_buffer.h"

#include <algorithm>
#include <limits>
#include <map>
#include <string>
#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/rand_util.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gmock_mutant.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::min;
using std::string;

namespace net {

namespace test {

char GetCharFromIOVecs(size_t offset, iovec iov[], size_t count) {
  size_t start_offset = 0;
  for (size_t i = 0; i < count; i++) {
    if (iov[i].iov_len == 0) {
      continue;
    }
    size_t end_offset = start_offset + iov[i].iov_len - 1;
    if (offset >= start_offset && offset <= end_offset) {
      const char* buf = reinterpret_cast<const char*>(iov[i].iov_base);
      return buf[offset - start_offset];
    }
    start_offset += iov[i].iov_len;
  }
  LOG(ERROR) << "Could not locate char at offset " << offset << " in " << count
             << " iovecs";
  for (size_t i = 0; i < count; ++i) {
    LOG(ERROR) << "  iov[" << i << "].iov_len = " << iov[i].iov_len;
  }
  return '\0';
}

static const size_t kBlockSizeBytes =
    QuicStreamSequencerBuffer::kBlockSizeBytes;
typedef QuicStreamSequencerBuffer::BufferBlock BufferBlock;
typedef QuicStreamSequencerBuffer::Gap Gap;
typedef QuicStreamSequencerBuffer::FrameInfo FrameInfo;

class QuicStreamSequencerBufferPeer {
 public:
  explicit QuicStreamSequencerBufferPeer(QuicStreamSequencerBuffer* buffer)
      : buffer_(buffer) {}

  // Read from this buffer_->into the given destination buffer_-> up to the
  // size of the destination. Returns the number of bytes read. Reading from
  // an empty buffer_->returns 0.
  size_t Read(char* dest_buffer, size_t size) {
    iovec dest;
    dest.iov_base = dest_buffer, dest.iov_len = size;
    return buffer_->Readv(&dest, 1);
  }

  // If buffer is empty, the blocks_ array must be empty, which means all
  // blocks are deallocated.
  bool CheckEmptyInvariants() {
    return !buffer_->Empty() || IsBlockArrayEmpty();
  }

  bool IsBlockArrayEmpty() {
    size_t count = buffer_->blocks_count_;
    for (size_t i = 0; i < count; i++) {
      if (buffer_->blocks_[i] != nullptr) {
        return false;
      }
    }
    return true;
  }

  bool CheckInitialState() {
    EXPECT_TRUE(buffer_->Empty() && buffer_->total_bytes_read_ == 0 &&
                buffer_->num_bytes_buffered_ == 0);
    return CheckBufferInvariants();
  }

  bool CheckBufferInvariants() {
    QuicStreamOffset data_span =
        buffer_->gaps_.back().begin_offset - buffer_->total_bytes_read_;
    bool capacity_sane = data_span <= buffer_->max_buffer_capacity_bytes_ &&
                         data_span >= buffer_->num_bytes_buffered_;
    if (!capacity_sane) {
      LOG(ERROR) << "data span is larger than capacity.";
      LOG(ERROR) << "total read: " << buffer_->total_bytes_read_
                 << " last byte: " << buffer_->gaps_.back().begin_offset;
    }
    bool total_read_sane =
        buffer_->gaps_.front().begin_offset >= buffer_->total_bytes_read_;
    if (!total_read_sane) {
      LOG(ERROR) << "read across 1st gap.";
    }
    bool read_offset_sane = buffer_->ReadOffset() < kBlockSizeBytes;
    if (!capacity_sane) {
      LOG(ERROR) << "read offset go beyond 1st block";
    }
    bool block_match_capacity =
        (buffer_->max_buffer_capacity_bytes_ <=
         buffer_->blocks_count_ * kBlockSizeBytes) &&
        (buffer_->max_buffer_capacity_bytes_ >
         (buffer_->blocks_count_ - 1) * kBlockSizeBytes);
    if (!capacity_sane) {
      LOG(ERROR) << "block number not match capcaity.";
    }
    bool block_retired_when_empty = CheckEmptyInvariants();
    if (!block_retired_when_empty) {
      LOG(ERROR) << "block is not retired after use.";
    }
    return capacity_sane && total_read_sane && read_offset_sane &&
           block_match_capacity && block_retired_when_empty;
  }

  size_t GetInBlockOffset(QuicStreamOffset offset) {
    return buffer_->GetInBlockOffset(offset);
  }

  BufferBlock* GetBlock(size_t index) { return buffer_->blocks_[index]; }

  int GapSize() { return buffer_->gaps_.size(); }

  std::list<Gap> GetGaps() { return buffer_->gaps_; }

  size_t max_buffer_capacity() { return buffer_->max_buffer_capacity_bytes_; }

  size_t ReadableBytes() { return buffer_->ReadableBytes(); }

  std::map<QuicStreamOffset, FrameInfo>* frame_arrival_time_map() {
    return &(buffer_->frame_arrival_time_map_);
  }

  void set_total_bytes_read(QuicStreamOffset total_bytes_read) {
    buffer_->total_bytes_read_ = total_bytes_read;
  }

  void set_gaps(const std::list<Gap>& gaps) { buffer_->gaps_ = gaps; }

 private:
  QuicStreamSequencerBuffer* buffer_;
};

namespace {

class QuicStreamSequencerBufferTest : public testing::Test {
 public:
  void SetUp() override { Initialize(); }

  void ResetMaxCapacityBytes(size_t max_capacity_bytes) {
    max_capacity_bytes_ = max_capacity_bytes;
    Initialize();
  }

 protected:
  void Initialize() {
    buffer_.reset(new QuicStreamSequencerBuffer(max_capacity_bytes_));
    helper_.reset(new QuicStreamSequencerBufferPeer(buffer_.get()));
  }

  // Use 2.5 here to make sure the buffer has more than one block and its end
  // doesn't align with the end of a block in order to test all the offset
  // calculation.
  size_t max_capacity_bytes_ = 2.5 * kBlockSizeBytes;

  MockClock clock_;
  std::unique_ptr<QuicStreamSequencerBuffer> buffer_;
  std::unique_ptr<QuicStreamSequencerBufferPeer> helper_;
  string error_details_;
};

TEST_F(QuicStreamSequencerBufferTest, InitializationWithDifferentSizes) {
  const size_t kCapacity = 2 * QuicStreamSequencerBuffer::kBlockSizeBytes;
  ResetMaxCapacityBytes(kCapacity);
  EXPECT_EQ(max_capacity_bytes_, helper_->max_buffer_capacity());
  EXPECT_TRUE(helper_->CheckInitialState());

  const size_t kCapacity1 = 8 * QuicStreamSequencerBuffer::kBlockSizeBytes;
  ResetMaxCapacityBytes(kCapacity1);
  EXPECT_EQ(kCapacity1, helper_->max_buffer_capacity());
  EXPECT_TRUE(helper_->CheckInitialState());
}

TEST_F(QuicStreamSequencerBufferTest, ClearOnEmpty) {
  buffer_->Clear();
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamData0length) {
  size_t written;
  QuicErrorCode error = buffer_->OnStreamData(800, "", clock_.ApproximateNow(),
                                              &written, &error_details_);
  EXPECT_EQ(error, QUIC_EMPTY_STREAM_FRAME_NO_FIN);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithinBlock) {
  string source(1024, 'a');
  size_t written;
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t = clock_.ApproximateNow();
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(800, source, t, &written, &error_details_));
  BufferBlock* block_ptr = helper_->GetBlock(0);
  for (size_t i = 0; i < source.size(); ++i) {
    ASSERT_EQ('a', block_ptr->buffer[helper_->GetInBlockOffset(800) + i]);
  }
  EXPECT_EQ(2, helper_->GapSize());
  std::list<Gap> gaps = helper_->GetGaps();
  EXPECT_EQ(800u, gaps.front().end_offset);
  EXPECT_EQ(1824u, gaps.back().begin_offset);
  auto* frame_map = helper_->frame_arrival_time_map();
  EXPECT_EQ(1u, frame_map->size());
  EXPECT_EQ(800u, frame_map->begin()->first);
  EXPECT_EQ(t, (*frame_map)[800].timestamp);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithOverlap) {
  string source(1024, 'a');
  // Write something into [800, 1824)
  size_t written;
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t1 = clock_.ApproximateNow();
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(800, source, t1, &written, &error_details_));
  // Try to write to [0, 1024) and [1024, 2048).
  // But no byte will be written since overlap.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t2 = clock_.ApproximateNow();
  EXPECT_EQ(QUIC_OVERLAPPING_STREAM_DATA,
            buffer_->OnStreamData(0, source, t2, &written, &error_details_));
  EXPECT_EQ(QUIC_OVERLAPPING_STREAM_DATA,
            buffer_->OnStreamData(1024, source, t2, &written, &error_details_));
  auto* frame_map = helper_->frame_arrival_time_map();
  EXPECT_EQ(1u, frame_map->size());
  EXPECT_EQ(t1, (*frame_map)[800].timestamp);
}

TEST_F(QuicStreamSequencerBufferTest,
       OnStreamDataOverlapAndDuplicateCornerCases) {
  string source(1024, 'a');
  // Write something into [800, 1824)
  size_t written;
  buffer_->OnStreamData(800, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  source = string(800, 'b');
  // Try to write to [1, 801), but should fail due to overlapping
  EXPECT_EQ(QUIC_OVERLAPPING_STREAM_DATA,
            buffer_->OnStreamData(1, source, clock_.ApproximateNow(), &written,
                                  &error_details_));
  // write to [0, 800)
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                                  &error_details_));
  // Try to write one byte to [1823, 1824), but should count as duplicate
  string one_byte = "c";
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(1823, one_byte, clock_.ApproximateNow(),
                                  &written, &error_details_));
  EXPECT_EQ(0u, written);
  // write one byte to [1824, 1825)
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(1824, one_byte, clock_.ApproximateNow(),
                                  &written, &error_details_));
  auto* frame_map = helper_->frame_arrival_time_map();
  EXPECT_EQ(3u, frame_map->size());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataWithoutOverlap) {
  string source(1024, 'a');
  // Write something into [800, 1824).
  size_t written;
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(800, source, clock_.ApproximateNow(),
                                  &written, &error_details_));
  source = string(100, 'b');
  // Write something into [kBlockSizeBytes * 2 - 20, kBlockSizeBytes * 2 + 80).
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(kBlockSizeBytes * 2 - 20, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_EQ(3, helper_->GapSize());
  EXPECT_EQ(1024u + 100u, buffer_->BytesBuffered());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataInLongStreamWithOverlap) {
  // Assume a stream has already buffered almost 4GB.
  uint64_t total_bytes_read = pow(2, 32) - 1;
  helper_->set_total_bytes_read(total_bytes_read);
  helper_->set_gaps(std::list<Gap>(
      1, Gap(total_bytes_read, std::numeric_limits<QuicStreamOffset>::max())));

  // Three new out of order frames arrive.
  const size_t kBytesToWrite = 100;
  string source(kBytesToWrite, 'a');
  size_t written;
  // Frame [2^32 + 500, 2^32 + 600).
  QuicStreamOffset offset = pow(2, 32) + 500;
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(offset, source, clock_.ApproximateNow(),
                                  &written, &error_details_));
  EXPECT_EQ(2, helper_->GapSize());

  // Frame [2^32 + 700, 2^32 + 800).
  offset = pow(2, 32) + 700;
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(offset, source, clock_.ApproximateNow(),
                                  &written, &error_details_));
  EXPECT_EQ(3, helper_->GapSize());

  // Another frame [2^32 + 300, 2^32 + 400).
  offset = pow(2, 32) + 300;
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(offset, source, clock_.ApproximateNow(),
                                  &written, &error_details_));
  EXPECT_EQ(4, helper_->GapSize());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataTillEnd) {
  // Write 50 bytes to the end.
  const size_t kBytesToWrite = 50;
  string source(kBytesToWrite, 'a');
  size_t written;
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(max_capacity_bytes_ - kBytesToWrite, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_EQ(50u, buffer_->BytesBuffered());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataTillEndCorner) {
  // Write 1 byte to the end.
  const size_t kBytesToWrite = 1;
  string source(kBytesToWrite, 'a');
  size_t written;
  EXPECT_EQ(QUIC_NO_ERROR,
            buffer_->OnStreamData(max_capacity_bytes_ - kBytesToWrite, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_EQ(1u, buffer_->BytesBuffered());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, OnStreamDataBeyondCapacity) {
  string source(60, 'a');
  size_t written;
  EXPECT_EQ(QUIC_INTERNAL_ERROR,
            buffer_->OnStreamData(max_capacity_bytes_ - 50, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  source = "b";
  EXPECT_EQ(QUIC_INTERNAL_ERROR,
            buffer_->OnStreamData(max_capacity_bytes_, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_TRUE(helper_->CheckBufferInvariants());

  EXPECT_EQ(QUIC_INTERNAL_ERROR,
            buffer_->OnStreamData(max_capacity_bytes_ * 1000, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  EXPECT_EQ(0u, buffer_->BytesBuffered());
}

TEST_F(QuicStreamSequencerBufferTest, Readv100Bytes) {
  string source(1024, 'a');
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t1 = clock_.ApproximateNow();
  // Write something into [kBlockSizeBytes, kBlockSizeBytes + 1024).
  size_t written;
  buffer_->OnStreamData(kBlockSizeBytes, source, t1, &written, &error_details_);
  EXPECT_FALSE(buffer_->HasBytesToRead());
  source = string(100, 'b');
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t2 = clock_.ApproximateNow();
  // Write something into [0, 100).
  buffer_->OnStreamData(0, source, t2, &written, &error_details_);
  EXPECT_TRUE(buffer_->HasBytesToRead());
  EXPECT_EQ(2u, helper_->frame_arrival_time_map()->size());
  // Read into a iovec array with total capacity of 120 bytes.
  char dest[120];
  iovec iovecs[3]{iovec{dest, 40}, iovec{dest + 40, 40}, iovec{dest + 80, 40}};
  size_t read = buffer_->Readv(iovecs, 3);
  EXPECT_EQ(100u, read);
  EXPECT_EQ(100u, buffer_->BytesConsumed());
  EXPECT_EQ(source, string(dest, read));
  EXPECT_EQ(1u, helper_->frame_arrival_time_map()->size());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ReadvAcrossBlocks) {
  string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full and extand 50 bytes to next block.
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  EXPECT_EQ(source.size(), helper_->ReadableBytes());
  // Iteratively read 512 bytes from buffer_-> Overwrite dest[] each time.
  char dest[512];
  while (helper_->ReadableBytes()) {
    std::fill(dest, dest + 512, 0);
    iovec iovecs[2]{iovec{dest, 256}, iovec{dest + 256, 256}};
    buffer_->Readv(iovecs, 2);
  }
  // The last read only reads the rest 50 bytes in 2nd block.
  EXPECT_EQ(string(50, 'a'), string(dest, 50));
  EXPECT_EQ(0, dest[50]) << "Dest[50] shouln't be filled.";
  EXPECT_EQ(source.size(), buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ClearAfterRead) {
  string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full with 'a'.
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  // Read first 512 bytes from buffer to make space at the beginning.
  char dest[512]{0};
  const iovec iov{dest, 512};
  buffer_->Readv(&iov, 1);
  // Clear() should make buffer empty while preserving BytesConsumed()
  buffer_->Clear();
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest,
       OnStreamDataAcrossLastBlockAndFillCapacity) {
  string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full with 'a'.
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  // Read first 512 bytes from buffer to make space at the beginning.
  char dest[512]{0};
  const iovec iov{dest, 512};
  buffer_->Readv(&iov, 1);
  EXPECT_EQ(source.size(), written);

  // Write more than half block size of bytes in the last block with 'b', which
  // will wrap to the beginning and reaches the full capacity.
  source = string(0.5 * kBlockSizeBytes + 512, 'b');
  EXPECT_EQ(QUIC_NO_ERROR, buffer_->OnStreamData(2 * kBlockSizeBytes, source,
                                                 clock_.ApproximateNow(),
                                                 &written, &error_details_));
  EXPECT_EQ(source.size(), written);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest,
       OnStreamDataAcrossLastBlockAndExceedCapacity) {
  string source(kBlockSizeBytes + 50, 'a');
  // Write 1st block to full.
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  // Read first 512 bytes from buffer to make space at the beginning.
  char dest[512]{0};
  const iovec iov{dest, 512};
  buffer_->Readv(&iov, 1);

  // Try to write from [max_capacity_bytes_ - 0.5 * kBlockSizeBytes,
  // max_capacity_bytes_ +  512 + 1). But last bytes exceeds current capacity.
  source = string(0.5 * kBlockSizeBytes + 512 + 1, 'b');
  EXPECT_EQ(QUIC_INTERNAL_ERROR,
            buffer_->OnStreamData(2 * kBlockSizeBytes, source,
                                  clock_.ApproximateNow(), &written,
                                  &error_details_));
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, ReadvAcrossLastBlock) {
  // Write to full capacity and read out 512 bytes at beginning and continue
  // appending 256 bytes.
  string source(max_capacity_bytes_, 'a');
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t = clock_.ApproximateNow();
  size_t written;
  buffer_->OnStreamData(0, source, t, &written, &error_details_);
  char dest[512]{0};
  const iovec iov{dest, 512};
  buffer_->Readv(&iov, 1);
  source = string(256, 'b');
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t2 = clock_.ApproximateNow();
  buffer_->OnStreamData(max_capacity_bytes_, source, t2, &written,
                        &error_details_);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  EXPECT_EQ(2u, helper_->frame_arrival_time_map()->size());

  // Read all data out.
  std::unique_ptr<char[]> dest1{new char[max_capacity_bytes_]};
  dest1[0] = 0;
  const iovec iov1{dest1.get(), max_capacity_bytes_};
  EXPECT_EQ(max_capacity_bytes_ - 512 + 256, buffer_->Readv(&iov1, 1));
  EXPECT_EQ(max_capacity_bytes_ + 256, buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  EXPECT_EQ(0u, helper_->frame_arrival_time_map()->size());
}

TEST_F(QuicStreamSequencerBufferTest, ReadvEmpty) {
  char dest[512]{0};
  iovec iov{dest, 512};
  size_t read = buffer_->Readv(&iov, 1);
  EXPECT_EQ(0u, read);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsEmpty) {
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(0, iov_count);
  EXPECT_EQ(nullptr, iovs[iov_count].iov_base);
  EXPECT_EQ(0u, iovs[iov_count].iov_len);
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsBlockedByGap) {
  // Write into [1, 1024).
  string source(1023, 'a');
  size_t written;
  buffer_->OnStreamData(1, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  // Try to get readable regions, but none is there.
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(0, iov_count);
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsTillEndOfBlock) {
  // Write first block to full with [0, 256) 'a' and the rest 'b' then read out
  // [0, 256)
  string source(kBlockSizeBytes, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1024)
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(1, iov_count);
  EXPECT_EQ(
      string(kBlockSizeBytes - 256, 'a'),
      string(reinterpret_cast<const char*>(iovs[0].iov_base), iovs[0].iov_len));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionsWithinOneBlock) {
  // Write into [0, 1024) and then read out [0, 256)
  string source(1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1024)
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(1, iov_count);
  EXPECT_EQ(
      string(1024 - 256, 'a'),
      string(reinterpret_cast<const char*>(iovs[0].iov_base), iovs[0].iov_len));
}

TEST_F(QuicStreamSequencerBufferTest,
       GetReadableRegionsAcrossBlockWithLongIOV) {
  // Write into [0, 2 * kBlockSizeBytes + 1024) and then read out [0, 1024)
  string source(2 * kBlockSizeBytes + 1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);

  iovec iovs[4];
  int iov_count = buffer_->GetReadableRegions(iovs, 4);
  EXPECT_EQ(3, iov_count);
  EXPECT_EQ(kBlockSizeBytes - 1024, iovs[0].iov_len);
  EXPECT_EQ(kBlockSizeBytes, iovs[1].iov_len);
  EXPECT_EQ(1024u, iovs[2].iov_len);
}

TEST_F(QuicStreamSequencerBufferTest,
       GetReadableRegionsWithMultipleIOVsAcrossEnd) {
  // Write into [0, 2 * kBlockSizeBytes + 1024) and then read out [0, 1024)
  // and then append 1024 + 512 bytes.
  string source(2.5 * kBlockSizeBytes - 1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);
  // Write across the end.
  source = string(1024 + 512, 'b');
  buffer_->OnStreamData(2.5 * kBlockSizeBytes - 1024, source,
                        clock_.ApproximateNow(), &written, &error_details_);
  // Use short iovec's.
  iovec iovs[2];
  int iov_count = buffer_->GetReadableRegions(iovs, 2);
  EXPECT_EQ(2, iov_count);
  EXPECT_EQ(kBlockSizeBytes - 1024, iovs[0].iov_len);
  EXPECT_EQ(kBlockSizeBytes, iovs[1].iov_len);
  // Use long iovec's and wrap the end of buffer.
  iovec iovs1[5];
  EXPECT_EQ(4, buffer_->GetReadableRegions(iovs1, 5));
  EXPECT_EQ(0.5 * kBlockSizeBytes, iovs1[2].iov_len);
  EXPECT_EQ(512u, iovs1[3].iov_len);
  EXPECT_EQ(string(512, 'b'),
            string(reinterpret_cast<const char*>(iovs1[3].iov_base),
                   iovs1[3].iov_len));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionEmpty) {
  iovec iov;
  QuicTime t = QuicTime::Zero();
  EXPECT_FALSE(buffer_->GetReadableRegion(&iov, &t));
  EXPECT_EQ(nullptr, iov.iov_base);
  EXPECT_EQ(0u, iov.iov_len);
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionBeforeGap) {
  // Write into [1, 1024).
  string source(1023, 'a');
  size_t written;
  buffer_->OnStreamData(1, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  // GetReadableRegion should return false because range  [0,1) hasn't been
  // filled yet.
  iovec iov;
  QuicTime t = QuicTime::Zero();
  EXPECT_FALSE(buffer_->GetReadableRegion(&iov, &t));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionTillEndOfBlock) {
  // Write into [0, kBlockSizeBytes + 1) and then read out [0, 256)
  string source(kBlockSizeBytes + 1, 'a');
  size_t written;
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t = clock_.ApproximateNow();
  buffer_->OnStreamData(0, source, t, &written, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1024)
  iovec iov;
  QuicTime t2 = QuicTime::Zero();
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov, &t2));
  EXPECT_EQ(t, t2);
  EXPECT_EQ(string(kBlockSizeBytes - 256, 'a'),
            string(reinterpret_cast<const char*>(iov.iov_base), iov.iov_len));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionTillGap) {
  // Write into [0, kBlockSizeBytes - 1) and then read out [0, 256)
  string source(kBlockSizeBytes - 1, 'a');
  size_t written;
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t = clock_.ApproximateNow();
  buffer_->OnStreamData(0, source, t, &written, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Get readable region from [256, 1023)
  iovec iov;
  QuicTime t2 = QuicTime::Zero();
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov, &t2));
  EXPECT_EQ(t, t2);
  EXPECT_EQ(string(kBlockSizeBytes - 1 - 256, 'a'),
            string(reinterpret_cast<const char*>(iov.iov_base), iov.iov_len));
}

TEST_F(QuicStreamSequencerBufferTest, GetReadableRegionByArrivalTime) {
  // Write into [0, kBlockSizeBytes - 100) and then read out [0, 256)
  string source(kBlockSizeBytes - 100, 'a');
  size_t written;
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t = clock_.ApproximateNow();
  buffer_->OnStreamData(0, source, t, &written, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);
  // Write into [kBlockSizeBytes - 100, kBlockSizeBytes - 50)] in same time
  string source2(50, 'b');
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  buffer_->OnStreamData(kBlockSizeBytes - 100, source2, t, &written,
                        &error_details_);

  // Write into [kBlockSizeBytes - 50, kBlockSizeBytes)] in another time
  string source3(50, 'c');
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  QuicTime t3 = clock_.ApproximateNow();
  buffer_->OnStreamData(kBlockSizeBytes - 50, source3, t3, &written,
                        &error_details_);

  // Get readable region from [256, 1024 - 50)
  iovec iov;
  QuicTime t4 = QuicTime::Zero();
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov, &t4));
  EXPECT_EQ(t, t4);
  EXPECT_EQ(string(kBlockSizeBytes - 100 - 256, 'a') + source2,
            string(reinterpret_cast<const char*>(iov.iov_base), iov.iov_len));
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedInOneBlock) {
  // Write into [0, 1024) and then read out [0, 256)
  string source(1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[256];
  helper_->Read(dest, 256);

  EXPECT_TRUE(buffer_->MarkConsumed(512));
  EXPECT_EQ(256u + 512u, buffer_->BytesConsumed());
  EXPECT_EQ(256u, helper_->ReadableBytes());
  EXPECT_EQ(1u, helper_->frame_arrival_time_map()->size());
  buffer_->MarkConsumed(256);
  EXPECT_EQ(0u, helper_->frame_arrival_time_map()->size());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedNotEnoughBytes) {
  // Write into [0, 1024) and then read out [0, 256)
  string source(1024, 'a');
  size_t written;
  QuicTime t = clock_.ApproximateNow();
  buffer_->OnStreamData(0, source, t, &written, &error_details_);
  char dest[256];
  helper_->Read(dest, 256);

  // Consume 1st 512 bytes
  EXPECT_TRUE(buffer_->MarkConsumed(512));
  EXPECT_EQ(256u + 512u, buffer_->BytesConsumed());
  EXPECT_EQ(256u, helper_->ReadableBytes());
  // Try to consume one bytes more than available. Should return false.
  EXPECT_FALSE(buffer_->MarkConsumed(257));
  EXPECT_EQ(256u + 512u, buffer_->BytesConsumed());
  QuicTime t2 = QuicTime::Zero();
  iovec iov;
  EXPECT_TRUE(buffer_->GetReadableRegion(&iov, &t2));
  EXPECT_EQ(t, t2);
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedAcrossBlock) {
  // Write into [0, 2 * kBlockSizeBytes + 1024) and then read out [0, 1024)
  string source(2 * kBlockSizeBytes + 1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);

  buffer_->MarkConsumed(2 * kBlockSizeBytes);
  EXPECT_EQ(source.size(), buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, MarkConsumedAcrossEnd) {
  // Write into [0, 2.5 * kBlockSizeBytes - 1024) and then read out [0, 1024)
  // and then append 1024 + 512 bytes.
  string source(2.5 * kBlockSizeBytes - 1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);
  source = string(1024 + 512, 'b');
  buffer_->OnStreamData(2.5 * kBlockSizeBytes - 1024, source,
                        clock_.ApproximateNow(), &written, &error_details_);
  EXPECT_EQ(1024u, buffer_->BytesConsumed());

  // Consume to the end of 2nd block.
  buffer_->MarkConsumed(2 * kBlockSizeBytes - 1024);
  EXPECT_EQ(2 * kBlockSizeBytes, buffer_->BytesConsumed());
  // Consume across the physical end of buffer
  buffer_->MarkConsumed(0.5 * kBlockSizeBytes + 500);
  EXPECT_EQ(max_capacity_bytes_ + 500, buffer_->BytesConsumed());
  EXPECT_EQ(12u, helper_->ReadableBytes());
  // Consume to the logical end of buffer
  buffer_->MarkConsumed(12);
  EXPECT_EQ(max_capacity_bytes_ + 512, buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

TEST_F(QuicStreamSequencerBufferTest, FlushBufferedFrames) {
  // Write into [0, 2.5 * kBlockSizeBytes - 1024) and then read out [0, 1024).
  string source(max_capacity_bytes_ - 1024, 'a');
  size_t written;
  buffer_->OnStreamData(0, source, clock_.ApproximateNow(), &written,
                        &error_details_);
  char dest[1024];
  helper_->Read(dest, 1024);
  EXPECT_EQ(1024u, buffer_->BytesConsumed());
  // Write [1024, 512) to the physical beginning.
  source = string(512, 'b');
  buffer_->OnStreamData(max_capacity_bytes_, source, clock_.ApproximateNow(),
                        &written, &error_details_);
  EXPECT_EQ(512u, written);
  EXPECT_EQ(max_capacity_bytes_ - 1024 + 512, buffer_->FlushBufferedFrames());
  EXPECT_EQ(max_capacity_bytes_ + 512, buffer_->BytesConsumed());
  EXPECT_TRUE(buffer_->Empty());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
  // Clear buffer at this point should still preserve BytesConsumed().
  buffer_->Clear();
  EXPECT_EQ(max_capacity_bytes_ + 512, buffer_->BytesConsumed());
  EXPECT_TRUE(helper_->CheckBufferInvariants());
}

class QuicStreamSequencerBufferRandomIOTest
    : public QuicStreamSequencerBufferTest {
 public:
  typedef std::pair<QuicStreamOffset, size_t> OffsetSizePair;

  void SetUp() override {
    // Test against a larger capacity then above tests. Also make sure the last
    // block is partially available to use.
    max_capacity_bytes_ = 6.25 * kBlockSizeBytes;
    // Stream to be buffered should be larger than the capacity to test wrap
    // around.
    bytes_to_buffer_ = 2 * max_capacity_bytes_;
    Initialize();

    uint32_t seed = base::RandInt(0, std::numeric_limits<int32_t>::max());
    LOG(INFO) << "RandomWriteAndProcessInPlace test seed is " << seed;
    rng_.set_seed(seed);
  }

  // Create an out-of-order source stream with given size to populate
  // shuffled_buf_.
  void CreateSourceAndShuffle(size_t max_chunk_size_bytes) {
    max_chunk_size_bytes_ = max_chunk_size_bytes;
    std::unique_ptr<OffsetSizePair[]> chopped_stream(
        new OffsetSizePair[bytes_to_buffer_]);

    // Split stream into small chunks with random length. chopped_stream will be
    // populated with segmented stream chunks.
    size_t start_chopping_offset = 0;
    size_t iterations = 0;
    while (start_chopping_offset < bytes_to_buffer_) {
      size_t max_chunk = min<size_t>(max_chunk_size_bytes_,
                                     bytes_to_buffer_ - start_chopping_offset);
      size_t chunk_size = rng_.RandUint64() % max_chunk + 1;
      chopped_stream[iterations] =
          OffsetSizePair(start_chopping_offset, chunk_size);
      start_chopping_offset += chunk_size;
      ++iterations;
    }
    DCHECK(start_chopping_offset == bytes_to_buffer_);
    size_t chunk_num = iterations;

    // Randomly change the sequence of in-ordered OffsetSizePairs to make a
    // out-of-order array of OffsetSizePairs.
    for (int i = chunk_num - 1; i >= 0; --i) {
      size_t random_idx = rng_.RandUint64() % (i + 1);
      DVLOG(1) << "chunk offset " << chopped_stream[random_idx].first
               << " size " << chopped_stream[random_idx].second;
      shuffled_buf_.push_front(chopped_stream[random_idx]);
      chopped_stream[random_idx] = chopped_stream[i];
    }
  }

  // Write the currently first chunk of data in the out-of-order stream into
  // QuicStreamSequencerBuffer. If current chuck cannot be written into buffer
  // because it goes beyond current capacity, move it to the end of
  // shuffled_buf_ and write it later.
  void WriteNextChunkToBuffer() {
    OffsetSizePair& chunk = shuffled_buf_.front();
    QuicStreamOffset offset = chunk.first;
    const size_t num_to_write = chunk.second;
    std::unique_ptr<char[]> write_buf{new char[max_chunk_size_bytes_]};
    for (size_t i = 0; i < num_to_write; ++i) {
      write_buf[i] = (offset + i) % 256;
    }
    base::StringPiece string_piece_w(write_buf.get(), num_to_write);
    size_t written;
    auto result =
        buffer_->OnStreamData(offset, string_piece_w, clock_.ApproximateNow(),
                              &written, &error_details_);
    if (result == QUIC_NO_ERROR) {
      shuffled_buf_.pop_front();
      total_bytes_written_ += num_to_write;
    } else {
      // This chunk offset exceeds window size.
      shuffled_buf_.push_back(chunk);
      shuffled_buf_.pop_front();
    }
    DVLOG(1) << " write at offset: " << offset
             << " len to write: " << num_to_write << " write result: " << result
             << " left over: " << shuffled_buf_.size();
  }

 protected:
  std::list<OffsetSizePair> shuffled_buf_;
  size_t max_chunk_size_bytes_;
  QuicStreamOffset bytes_to_buffer_;
  size_t total_bytes_written_ = 0;
  size_t total_bytes_read_ = 0;
  SimpleRandom rng_;
};

TEST_F(QuicStreamSequencerBufferRandomIOTest, RandomWriteAndReadv) {
  // Set kMaxReadSize larger than kBlockSizeBytes to test both small and large
  // read.
  const size_t kMaxReadSize = kBlockSizeBytes * 2;
  // kNumReads is larger than 1 to test how multiple read destinations work.
  const size_t kNumReads = 2;
  // Since write and read operation have equal possibility to be called. Bytes
  // to be written into and read out of should roughly the same.
  const size_t kMaxWriteSize = kNumReads * kMaxReadSize;
  size_t iterations = 0;

  CreateSourceAndShuffle(kMaxWriteSize);

  while ((!shuffled_buf_.empty() || total_bytes_read_ < bytes_to_buffer_) &&
         iterations <= 2 * bytes_to_buffer_) {
    uint8_t next_action =
        shuffled_buf_.empty() ? uint8_t{1} : rng_.RandUint64() % 2;
    DVLOG(1) << "iteration: " << iterations;
    switch (next_action) {
      case 0: {  // write
        WriteNextChunkToBuffer();
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
      case 1: {  // readv
        std::unique_ptr<char[][kMaxReadSize]> read_buf{
            new char[kNumReads][kMaxReadSize]};
        iovec dest_iov[kNumReads];
        size_t num_to_read = 0;
        for (size_t i = 0; i < kNumReads; ++i) {
          dest_iov[i].iov_base =
              reinterpret_cast<void*>(const_cast<char*>(read_buf[i]));
          dest_iov[i].iov_len = rng_.RandUint64() % kMaxReadSize;
          num_to_read += dest_iov[i].iov_len;
        }
        size_t actually_read = buffer_->Readv(dest_iov, kNumReads);
        ASSERT_LE(actually_read, num_to_read);
        DVLOG(1) << " read from offset: " << total_bytes_read_
                 << " size: " << num_to_read
                 << " actual read: " << actually_read;
        for (size_t i = 0; i < actually_read; ++i) {
          char ch = (i + total_bytes_read_) % 256;
          ASSERT_EQ(ch, GetCharFromIOVecs(i, dest_iov, kNumReads))
              << " at iteration " << iterations;
        }
        total_bytes_read_ += actually_read;
        ASSERT_EQ(total_bytes_read_, buffer_->BytesConsumed());
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
    }
    ++iterations;
    ASSERT_LE(total_bytes_read_, total_bytes_written_);
  }
  EXPECT_LT(iterations, bytes_to_buffer_) << "runaway test";
  EXPECT_LE(bytes_to_buffer_, total_bytes_read_) << "iterations: "
                                                 << iterations;
  EXPECT_LE(bytes_to_buffer_, total_bytes_written_);
}

TEST_F(QuicStreamSequencerBufferRandomIOTest, RandomWriteAndConsumeInPlace) {
  // The value 4 is chosen such that the max write size is no larger than the
  // maximum buffer capacity.
  const size_t kMaxNumReads = 4;
  // Adjust write amount be roughly equal to that GetReadableRegions() can get.
  const size_t kMaxWriteSize = kMaxNumReads * kBlockSizeBytes;
  ASSERT_LE(kMaxWriteSize, max_capacity_bytes_);
  size_t iterations = 0;

  CreateSourceAndShuffle(kMaxWriteSize);

  while ((!shuffled_buf_.empty() || total_bytes_read_ < bytes_to_buffer_) &&
         iterations <= 2 * bytes_to_buffer_) {
    uint8_t next_action =
        shuffled_buf_.empty() ? uint8_t{1} : rng_.RandUint64() % 2;
    DVLOG(1) << "iteration: " << iterations;
    switch (next_action) {
      case 0: {  // write
        WriteNextChunkToBuffer();
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
      case 1: {  // GetReadableRegions and then MarkConsumed
        size_t num_read = rng_.RandUint64() % kMaxNumReads + 1;
        iovec dest_iov[kMaxNumReads];
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        size_t actually_num_read =
            buffer_->GetReadableRegions(dest_iov, num_read);
        ASSERT_LE(actually_num_read, num_read);
        size_t avail_bytes = 0;
        for (size_t i = 0; i < actually_num_read; ++i) {
          avail_bytes += dest_iov[i].iov_len;
        }
        // process random number of bytes (check the value of each byte).
        size_t bytes_to_process = rng_.RandUint64() % (avail_bytes + 1);
        size_t bytes_processed = 0;
        for (size_t i = 0; i < actually_num_read; ++i) {
          size_t bytes_in_block = min<size_t>(
              bytes_to_process - bytes_processed, dest_iov[i].iov_len);
          if (bytes_in_block == 0) {
            break;
          }
          for (size_t j = 0; j < bytes_in_block; ++j) {
            ASSERT_LE(bytes_processed, bytes_to_process);
            char char_expected =
                (buffer_->BytesConsumed() + bytes_processed) % 256;
            ASSERT_EQ(char_expected,
                      reinterpret_cast<const char*>(dest_iov[i].iov_base)[j])
                << " at iteration " << iterations;
            ++bytes_processed;
          }
        }

        buffer_->MarkConsumed(bytes_processed);

        DVLOG(1) << "iteration " << iterations << ": try to get " << num_read
                 << " readable regions, actually get " << actually_num_read
                 << " from offset: " << total_bytes_read_
                 << "\nprocesse bytes: " << bytes_processed;
        total_bytes_read_ += bytes_processed;
        ASSERT_EQ(total_bytes_read_, buffer_->BytesConsumed());
        ASSERT_TRUE(helper_->CheckBufferInvariants());
        break;
      }
    }
    ++iterations;
    ASSERT_LE(total_bytes_read_, total_bytes_written_);
  }
  EXPECT_LT(iterations, bytes_to_buffer_) << "runaway test";
  EXPECT_LE(bytes_to_buffer_, total_bytes_read_) << "iterations: "
                                                 << iterations;
  EXPECT_LE(bytes_to_buffer_, total_bytes_written_);
}

}  // anonymous namespace

}  // namespace test

}  // namespace net
