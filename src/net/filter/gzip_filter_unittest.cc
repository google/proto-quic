// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/gzip_filter.h"

#include <fstream>
#include <memory>
#include <ostream>

#include "base/bit_cast.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "net/base/io_buffer.h"
#include "net/filter/mock_filter_context.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "third_party/zlib/zlib.h"

namespace {

const int kDefaultBufferSize = 4096;
const int kSmallBufferSize = 128;

// The GZIP header (see RFC 1952):
//   +---+---+---+---+---+---+---+---+---+---+
//   |ID1|ID2|CM |FLG|     MTIME     |XFL|OS |
//   +---+---+---+---+---+---+---+---+---+---+
//     ID1     \037
//     ID2     \213
//     CM      \010 (compression method == DEFLATE)
//     FLG     \000 (special flags that we do not support)
//     MTIME   Unix format modification time (0 means not available)
//     XFL     2-4? DEFLATE flags
//     OS      ???? Operating system indicator (255 means unknown)
//
// Header value we generate:
const char kGZipHeader[] = { '\037', '\213', '\010', '\000', '\000',
                             '\000', '\000', '\000', '\002', '\377' };

enum EncodeMode {
  ENCODE_GZIP,      // Wrap the deflate with a GZip header.
  ENCODE_DEFLATE    // Raw deflate.
};

}  // namespace

namespace net {

// These tests use the path service, which uses autoreleased objects on the
// Mac, so this needs to be a PlatformTest.
class GZipUnitTest : public PlatformTest {
 protected:
  void SetUp() override {
    PlatformTest::SetUp();

    deflate_encode_buffer_ = NULL;
    gzip_encode_buffer_ = NULL;

    // Get the path of source data file.
    base::FilePath file_path;
    PathService::Get(base::DIR_SOURCE_ROOT, &file_path);
    file_path = file_path.AppendASCII("net");
    file_path = file_path.AppendASCII("data");
    file_path = file_path.AppendASCII("filter_unittests");
    file_path = file_path.AppendASCII("google.txt");

    // Read data from the file into buffer.
    ASSERT_TRUE(base::ReadFileToString(file_path, &source_buffer_));

    // Encode the data with deflate
    deflate_encode_buffer_ = new char[kDefaultBufferSize];
    ASSERT_TRUE(deflate_encode_buffer_ != NULL);

    deflate_encode_len_ = kDefaultBufferSize;
    int code = CompressAll(ENCODE_DEFLATE , source_buffer(), source_len(),
                           deflate_encode_buffer_, &deflate_encode_len_);
    ASSERT_TRUE(code == Z_STREAM_END);
    ASSERT_GT(deflate_encode_len_, 0);
    ASSERT_TRUE(deflate_encode_len_ <= kDefaultBufferSize);

    // Encode the data with gzip
    gzip_encode_buffer_ = new char[kDefaultBufferSize];
    ASSERT_TRUE(gzip_encode_buffer_ != NULL);

    gzip_encode_len_ = kDefaultBufferSize;
    code = CompressAll(ENCODE_GZIP, source_buffer(), source_len(),
                           gzip_encode_buffer_, &gzip_encode_len_);
    ASSERT_TRUE(code == Z_STREAM_END);
    ASSERT_GT(gzip_encode_len_, 0);
    ASSERT_TRUE(gzip_encode_len_ <= kDefaultBufferSize);
  }

  void TearDown() override {
    delete[] deflate_encode_buffer_;
    deflate_encode_buffer_ = NULL;

    delete[] gzip_encode_buffer_;
    gzip_encode_buffer_ = NULL;

    PlatformTest::TearDown();
  }

  // Compress the data in source with deflate encoding and write output to the
  // buffer provided by dest. The function returns Z_OK if success, and returns
  // other zlib error code if fail.
  // The parameter mode specifies the encoding mechanism.
  // The dest buffer should be large enough to hold all the output data.
  int CompressAll(EncodeMode mode, const char* source, int source_size,
                  char* dest, int* dest_len) {
    z_stream zlib_stream;
    memset(&zlib_stream, 0, sizeof(zlib_stream));
    int code;

    // Initialize zlib
    if (mode == ENCODE_GZIP) {
      code = deflateInit2(&zlib_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                          -MAX_WBITS,
                          8,  // DEF_MEM_LEVEL
                          Z_DEFAULT_STRATEGY);
    } else {
      code = deflateInit(&zlib_stream, Z_DEFAULT_COMPRESSION);
    }

    if (code != Z_OK)
      return code;

    // Fill in zlib control block
    zlib_stream.next_in = bit_cast<Bytef*>(source);
    zlib_stream.avail_in = source_size;
    zlib_stream.next_out = bit_cast<Bytef*>(dest);
    zlib_stream.avail_out = *dest_len;

    // Write header if needed
    if (mode == ENCODE_GZIP) {
      if (zlib_stream.avail_out < sizeof(kGZipHeader))
        return Z_BUF_ERROR;
      memcpy(zlib_stream.next_out, kGZipHeader, sizeof(kGZipHeader));
      zlib_stream.next_out += sizeof(kGZipHeader);
      zlib_stream.avail_out -= sizeof(kGZipHeader);
    }

    // Do deflate
    code = deflate(&zlib_stream, Z_FINISH);
    *dest_len = *dest_len - zlib_stream.avail_out;

    deflateEnd(&zlib_stream);
    return code;
  }

  // Use filter to decode compressed data, and compare the decoding result with
  // the orginal Data.
  // Parameters: Source and source_len are original data and its size.
  // Encoded_source and encoded_source_len are compressed data and its size.
  // Output_buffer_size specifies the size of buffer to read out data from
  // filter.
  void DecodeAndCompareWithFilter(Filter* filter,
                                  const char* source,
                                  int source_len,
                                  const char* encoded_source,
                                  int encoded_source_len,
                                  int output_buffer_size) {
    // Make sure we have enough space to hold the decoding output.
    ASSERT_TRUE(source_len <= kDefaultBufferSize);
    ASSERT_TRUE(output_buffer_size <= kDefaultBufferSize);

    char decode_buffer[kDefaultBufferSize];
    char* decode_next = decode_buffer;
    int decode_avail_size = kDefaultBufferSize;

    const char* encode_next = encoded_source;
    int encode_avail_size = encoded_source_len;

    int code = Filter::FILTER_OK;
    while (code != Filter::FILTER_DONE) {
      int encode_data_len;
      encode_data_len = std::min(encode_avail_size,
                                 filter->stream_buffer_size());
      memcpy(filter->stream_buffer()->data(), encode_next, encode_data_len);
      filter->FlushStreamBuffer(encode_data_len);
      encode_next += encode_data_len;
      encode_avail_size -= encode_data_len;

      while (1) {
        int decode_data_len = std::min(decode_avail_size, output_buffer_size);

        code = filter->ReadData(decode_next, &decode_data_len);
        decode_next += decode_data_len;
        decode_avail_size -= decode_data_len;

        ASSERT_TRUE(code != Filter::FILTER_ERROR);

        if (code == Filter::FILTER_NEED_MORE_DATA ||
            code == Filter::FILTER_DONE) {
          break;
        }
      }
    }

    // Compare the decoding result with source data
    int decode_total_data_len = kDefaultBufferSize - decode_avail_size;
    EXPECT_TRUE(decode_total_data_len == source_len);
    EXPECT_EQ(memcmp(source, decode_buffer, source_len), 0);
  }

  // Unsafe function to use filter to decode compressed data.
  // Parameters: Source and source_len are compressed data and its size.
  // Dest is the buffer for decoding results. Upon entry, *dest_len is the size
  // of the dest buffer. Upon exit, *dest_len is the number of chars written
  // into the buffer.
  int DecodeAllWithFilter(Filter* filter, const char* source, int source_len,
                          char* dest, int* dest_len) {
    memcpy(filter->stream_buffer()->data(), source, source_len);
    filter->FlushStreamBuffer(source_len);
    return filter->ReadData(dest, dest_len);
  }

  void InitFilter(Filter::FilterType type) {
    std::vector<Filter::FilterType> filter_types;
    filter_types.push_back(type);
    filter_ = Filter::Factory(filter_types, filter_context_);
    ASSERT_TRUE(filter_.get());
    ASSERT_GE(filter_->stream_buffer_size(), kDefaultBufferSize);
  }

  void InitFilterWithBufferSize(Filter::FilterType type, int buffer_size) {
    std::vector<Filter::FilterType> filter_types;
    filter_types.push_back(type);
    filter_ =
        Filter::FactoryForTests(filter_types, filter_context_, buffer_size);
    ASSERT_TRUE(filter_.get());
  }

  const char* source_buffer() const { return source_buffer_.data(); }
  int source_len() const { return static_cast<int>(source_buffer_.size()); }

  std::unique_ptr<Filter> filter_;

  std::string source_buffer_;

  char* deflate_encode_buffer_;
  int deflate_encode_len_;

  char* gzip_encode_buffer_;
  int gzip_encode_len_;

 private:
  MockFilterContext filter_context_;
};

// Basic scenario: decoding deflate data with big enough buffer.
TEST_F(GZipUnitTest, DecodeDeflate) {
  // Decode the compressed data with filter
  InitFilter(Filter::FILTER_TYPE_DEFLATE);
  memcpy(filter_->stream_buffer()->data(), deflate_encode_buffer_,
         deflate_encode_len_);
  filter_->FlushStreamBuffer(deflate_encode_len_);

  char deflate_decode_buffer[kDefaultBufferSize];
  int deflate_decode_size = kDefaultBufferSize;
  filter_->ReadData(deflate_decode_buffer, &deflate_decode_size);

  // Compare the decoding result with source data
  EXPECT_TRUE(deflate_decode_size == source_len());
  EXPECT_EQ(memcmp(source_buffer(), deflate_decode_buffer, source_len()), 0);
}

// Basic scenario: decoding gzip data with big enough buffer.
TEST_F(GZipUnitTest, DecodeGZip) {
  // Decode the compressed data with filter
  InitFilter(Filter::FILTER_TYPE_GZIP);
  memcpy(filter_->stream_buffer()->data(), gzip_encode_buffer_,
         gzip_encode_len_);
  filter_->FlushStreamBuffer(gzip_encode_len_);

  char gzip_decode_buffer[kDefaultBufferSize];
  int gzip_decode_size = kDefaultBufferSize;
  filter_->ReadData(gzip_decode_buffer, &gzip_decode_size);

  // Compare the decoding result with source data
  EXPECT_TRUE(gzip_decode_size == source_len());
  EXPECT_EQ(memcmp(source_buffer(), gzip_decode_buffer, source_len()), 0);
}

// Tests we can call filter repeatedly to get all the data decoded.
// To do that, we create a filter with a small buffer that can not hold all
// the input data.
TEST_F(GZipUnitTest, DecodeWithSmallBuffer) {
  InitFilterWithBufferSize(Filter::FILTER_TYPE_DEFLATE, kSmallBufferSize);
  EXPECT_EQ(kSmallBufferSize, filter_->stream_buffer_size());
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             deflate_encode_buffer_, deflate_encode_len_,
                             kDefaultBufferSize);
}

// Tests we can still decode with just 1 byte buffer in the filter.
// The purpose of this tests are two: (1) Verify filter can parse partial GZip
// header correctly. (2) Sometimes the filter will consume input without
// generating output. Verify filter can handle it correctly.
TEST_F(GZipUnitTest, DecodeWithOneByteBuffer) {
  InitFilterWithBufferSize(Filter::FILTER_TYPE_GZIP, 1);
  EXPECT_EQ(1, filter_->stream_buffer_size());
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             gzip_encode_buffer_, gzip_encode_len_,
                             kDefaultBufferSize);
}

// Tests we can decode when caller has small buffer to read out from filter.
TEST_F(GZipUnitTest, DecodeWithSmallOutputBuffer) {
  InitFilter(Filter::FILTER_TYPE_DEFLATE);
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             deflate_encode_buffer_, deflate_encode_len_,
                             kSmallBufferSize);
}

// Tests we can still decode with just 1 byte buffer in the filter and just 1
// byte buffer in the caller.
TEST_F(GZipUnitTest, DecodeWithOneByteInputAndOutputBuffer) {
  InitFilterWithBufferSize(Filter::FILTER_TYPE_GZIP, 1);
  EXPECT_EQ(1, filter_->stream_buffer_size());
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             gzip_encode_buffer_, gzip_encode_len_, 1);
}

// Decoding deflate stream with corrupted data.
TEST_F(GZipUnitTest, DecodeCorruptedData) {
  char corrupt_data[kDefaultBufferSize];
  int corrupt_data_len = deflate_encode_len_;
  memcpy(corrupt_data, deflate_encode_buffer_, deflate_encode_len_);

  int pos = corrupt_data_len / 2;
  corrupt_data[pos] = !corrupt_data[pos];

  // Decode the corrupted data with filter
  InitFilter(Filter::FILTER_TYPE_DEFLATE);
  char corrupt_decode_buffer[kDefaultBufferSize];
  int corrupt_decode_size = kDefaultBufferSize;

  int code = DecodeAllWithFilter(filter_.get(), corrupt_data, corrupt_data_len,
                                 corrupt_decode_buffer, &corrupt_decode_size);

  // Expect failures
  EXPECT_TRUE(code == Filter::FILTER_ERROR);
}

// Decoding deflate stream with missing data.
TEST_F(GZipUnitTest, DecodeMissingData) {
  char corrupt_data[kDefaultBufferSize];
  int corrupt_data_len = deflate_encode_len_;
  memcpy(corrupt_data, deflate_encode_buffer_, deflate_encode_len_);

  int pos = corrupt_data_len / 2;
  int len = corrupt_data_len - pos - 1;
  memmove(&corrupt_data[pos], &corrupt_data[pos+1], len);
  --corrupt_data_len;

  // Decode the corrupted data with filter
  InitFilter(Filter::FILTER_TYPE_DEFLATE);
  char corrupt_decode_buffer[kDefaultBufferSize];
  int corrupt_decode_size = kDefaultBufferSize;

  int code = DecodeAllWithFilter(filter_.get(), corrupt_data, corrupt_data_len,
                                 corrupt_decode_buffer, &corrupt_decode_size);

  // Expect failures
  EXPECT_EQ(Filter::FILTER_ERROR, code);
}

// Decoding gzip stream with corrupted header.
TEST_F(GZipUnitTest, DecodeCorruptedHeader) {
  char corrupt_data[kDefaultBufferSize];
  int corrupt_data_len = gzip_encode_len_;
  memcpy(corrupt_data, gzip_encode_buffer_, gzip_encode_len_);

  corrupt_data[2] = !corrupt_data[2];

  // Decode the corrupted data with filter
  InitFilter(Filter::FILTER_TYPE_GZIP);
  char corrupt_decode_buffer[kDefaultBufferSize];
  int corrupt_decode_size = kDefaultBufferSize;

  int code = DecodeAllWithFilter(filter_.get(), corrupt_data, corrupt_data_len,
                                 corrupt_decode_buffer, &corrupt_decode_size);

  // Expect failures
  EXPECT_TRUE(code == Filter::FILTER_ERROR);
}

}  // namespace net
