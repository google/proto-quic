// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/brotli_filter.h"

#include <memory>

#include "base/files/file_util.h"
#include "base/path_service.h"
#include "net/base/io_buffer.h"
#include "net/filter/mock_filter_context.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace {
const int kDefaultBufferSize = 4096;
const int kSmallBufferSize = 128;
}  // namespace

namespace net {

// These tests use the path service, which uses autoreleased objects on the
// Mac, so this needs to be a PlatformTest.
class BrotliUnitTest : public PlatformTest {
 protected:
  void SetUp() override {
    PlatformTest::SetUp();

    // Get the path of data directory.
    base::FilePath data_dir;
    PathService::Get(base::DIR_SOURCE_ROOT, &data_dir);
    data_dir = data_dir.AppendASCII("net");
    data_dir = data_dir.AppendASCII("data");
    data_dir = data_dir.AppendASCII("filter_unittests");

    // Read data from the original file into buffer.
    base::FilePath file_path;
    file_path = data_dir.AppendASCII("google.txt");
    ASSERT_TRUE(base::ReadFileToString(file_path, &source_buffer_));

    // Read data from the encoded file into buffer.
    base::FilePath encoded_file_path;
    encoded_file_path = data_dir.AppendASCII("google.br");
    ASSERT_TRUE(base::ReadFileToString(encoded_file_path, &encoded_buffer_));
    ASSERT_GE(kDefaultBufferSize, static_cast<int>(encoded_buffer_.size()));
  }

  // Use filter to decode compressed data, and compare the decoded result with
  // the orginal data.
  // Parameters: |source| and |source_len| are original data and its size.
  // |encoded_source| and |encoded_source_len| are compressed data and its size.
  // |output_buffer_size| specifies the size of buffer to read out data from
  // filter.
  void DecodeAndCompareWithFilter(Filter* filter,
                                  const char* source,
                                  int source_len,
                                  const char* encoded_source,
                                  int encoded_source_len,
                                  int output_buffer_size) {
    // Make sure we have enough space to hold the decoding output.
    ASSERT_GE(kDefaultBufferSize, source_len);
    ASSERT_GE(kDefaultBufferSize, output_buffer_size);

    char decode_buffer[kDefaultBufferSize];
    char* decode_next = decode_buffer;
    int decode_avail_size = kDefaultBufferSize;

    const char* encode_next = encoded_source;
    int encode_avail_size = encoded_source_len;

    int code = Filter::FILTER_OK;
    while (code != Filter::FILTER_DONE) {
      int encode_data_len =
          std::min(encode_avail_size, filter->stream_buffer_size());
      memcpy(filter->stream_buffer()->data(), encode_next, encode_data_len);
      filter->FlushStreamBuffer(encode_data_len);
      encode_next += encode_data_len;
      encode_avail_size -= encode_data_len;

      while (true) {
        int decode_data_len = std::min(decode_avail_size, output_buffer_size);

        code = filter->ReadData(decode_next, &decode_data_len);
        decode_next += decode_data_len;
        decode_avail_size -= decode_data_len;

        ASSERT_NE(Filter::FILTER_ERROR, code);

        if (code == Filter::FILTER_NEED_MORE_DATA ||
            code == Filter::FILTER_DONE) {
          break;
        }
      }
    }

    // Compare the decoding result with source data
    int decode_total_data_len = kDefaultBufferSize - decode_avail_size;
    EXPECT_EQ(source_len, decode_total_data_len);
    EXPECT_EQ(memcmp(source, decode_buffer, source_len), 0);
  }

  // Unsafe function to use filter to decode compressed data.
  // Parameters: |source| and |source_len| are compressed data and its size.
  // |dest| is the buffer for decoding results. Upon entry, |*dest_len| is the
  // size of the output buffer. Upon exit, |*dest_len| is the number of chars
  // written into the buffer.
  int DecodeAllWithFilter(Filter* filter,
                          const char* source,
                          int source_len,
                          char* dest,
                          int* dest_len) {
    memcpy(filter->stream_buffer()->data(), source, source_len);
    filter->FlushStreamBuffer(source_len);
    return filter->ReadData(dest, dest_len);
  }

  void InitFilter() {
    std::vector<Filter::FilterType> filter_types;
    filter_types.push_back(Filter::FILTER_TYPE_BROTLI);
    filter_ = Filter::Factory(filter_types, filter_context_);
    ASSERT_TRUE(filter_.get());
    ASSERT_LE(kDefaultBufferSize, filter_->stream_buffer_size());
  }

  void InitFilterWithBufferSize(int buffer_size) {
    std::vector<Filter::FilterType> filter_types;
    filter_types.push_back(Filter::FILTER_TYPE_BROTLI);
    filter_ =
        Filter::FactoryForTests(filter_types, filter_context_, buffer_size);
    ASSERT_TRUE(filter_.get());
  }

  const char* source_buffer() const { return source_buffer_.data(); }
  int source_len() const { return static_cast<int>(source_buffer_.size()); }

  const char* encoded_buffer() const { return encoded_buffer_.data(); }
  int encoded_len() const { return static_cast<int>(encoded_buffer_.size()); }

  std::unique_ptr<Filter> filter_;

 private:
  MockFilterContext filter_context_;
  std::string source_buffer_;
  std::string encoded_buffer_;
};

// Basic scenario: decoding brotli data with big enough buffer.
TEST_F(BrotliUnitTest, DecodeBrotli) {
  InitFilter();
  memcpy(filter_->stream_buffer()->data(), encoded_buffer(), encoded_len());
  filter_->FlushStreamBuffer(encoded_len());

  ASSERT_GE(kDefaultBufferSize, source_len());
  char decode_buffer[kDefaultBufferSize];
  int decode_size = kDefaultBufferSize;
  filter_->ReadData(decode_buffer, &decode_size);

  // Compare the decoding result with source data
  EXPECT_EQ(source_len(), decode_size);
  EXPECT_EQ(memcmp(source_buffer(), decode_buffer, source_len()), 0);
}

// Tests we can call filter repeatedly to get all the data decoded.
// To do that, we create a filter with a small buffer that can not hold all
// the input data.
TEST_F(BrotliUnitTest, DecodeWithSmallBuffer) {
  InitFilterWithBufferSize(kSmallBufferSize);
  EXPECT_EQ(kSmallBufferSize, filter_->stream_buffer_size());
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             encoded_buffer(), encoded_len(),
                             kDefaultBufferSize);
}

// Tests we can still decode with just 1 byte buffer in the filter.
// The purpose of this test: sometimes the filter will consume input without
// generating output. Verify filter can handle it correctly.
TEST_F(BrotliUnitTest, DecodeWithOneByteBuffer) {
  InitFilterWithBufferSize(1);
  EXPECT_EQ(1, filter_->stream_buffer_size());
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             encoded_buffer(), encoded_len(),
                             kDefaultBufferSize);
}

// Tests we can decode when caller has small buffer to read out from filter.
TEST_F(BrotliUnitTest, DecodeWithSmallOutputBuffer) {
  InitFilter();
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             encoded_buffer(), encoded_len(), kSmallBufferSize);
}

// Tests we can decode when caller has small buffer and input is also broken
// into small parts. This may uncover some corner cases that doesn't happen with
// one-byte buffers.
TEST_F(BrotliUnitTest, DecodeWithSmallInputAndOutputBuffer) {
  InitFilterWithBufferSize(kSmallBufferSize);
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             encoded_buffer(), encoded_len(), kSmallBufferSize);
}

// Tests we can still decode with just 1 byte buffer in the filter and just 1
// byte buffer in the caller.
TEST_F(BrotliUnitTest, DecodeWithOneByteInputAndOutputBuffer) {
  InitFilterWithBufferSize(1);
  EXPECT_EQ(1, filter_->stream_buffer_size());
  DecodeAndCompareWithFilter(filter_.get(), source_buffer(), source_len(),
                             encoded_buffer(), encoded_len(), 1);
}

// Decoding deflate stream with corrupted data.
TEST_F(BrotliUnitTest, DecodeCorruptedData) {
  char corrupt_data[kDefaultBufferSize];
  int corrupt_data_len = encoded_len();
  memcpy(corrupt_data, encoded_buffer(), encoded_len());

  int pos = corrupt_data_len / 2;
  corrupt_data[pos] = !corrupt_data[pos];

  // Decode the corrupted data with filter
  InitFilter();
  char corrupt_decode_buffer[kDefaultBufferSize];
  int corrupt_decode_size = kDefaultBufferSize;

  int code = DecodeAllWithFilter(filter_.get(), corrupt_data, corrupt_data_len,
                                 corrupt_decode_buffer, &corrupt_decode_size);

  // Expect failures
  EXPECT_EQ(Filter::FILTER_ERROR, code);
}

// Decoding deflate stream with missing data.
TEST_F(BrotliUnitTest, DecodeMissingData) {
  char corrupt_data[kDefaultBufferSize];
  int corrupt_data_len = encoded_len();
  memcpy(corrupt_data, encoded_buffer(), encoded_len());

  int pos = corrupt_data_len / 2;
  int len = corrupt_data_len - pos - 1;
  memmove(&corrupt_data[pos], &corrupt_data[pos + 1], len);
  --corrupt_data_len;

  // Decode the corrupted data with filter
  InitFilter();
  char corrupt_decode_buffer[kDefaultBufferSize];
  int corrupt_decode_size = kDefaultBufferSize;

  int code = DecodeAllWithFilter(filter_.get(), corrupt_data, corrupt_data_len,
                                 corrupt_decode_buffer, &corrupt_decode_size);

  // Expect failures
  EXPECT_EQ(Filter::FILTER_ERROR, code);
}

// Decoding brotli stream with empty output data.
TEST_F(BrotliUnitTest, DecodeEmptyData) {
  char data[1] = {6};  // WBITS = 16, ISLAST = 1, ISLASTEMPTY = 1
  int data_len = 1;

  InitFilter();
  char decode_buffer[kDefaultBufferSize];
  int decode_size = kDefaultBufferSize;
  int code = DecodeAllWithFilter(filter_.get(), data, data_len, decode_buffer,
                                 &decode_size);

  // Expect success / empty output.
  EXPECT_EQ(Filter::FILTER_DONE, code);
  EXPECT_EQ(0, decode_size);
}

}  // namespace net
