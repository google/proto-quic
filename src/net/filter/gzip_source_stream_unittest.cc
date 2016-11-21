// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/bit_cast.h"
#include "base/callback.h"
#include "base/memory/ptr_util.h"
#include "net/base/completion_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/filter_source_stream_test_util.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/zlib/zlib.h"

namespace net {

namespace {

const int kBigBufferSize = 4096;
const int kSmallBufferSize = 1;

// How many bytes to leave unused at the end of |source_data_|. This margin is
// present so that tests that need to append data after the zlib EOF do not run
// out of room in the output buffer.
const size_t kEOFMargin = 64;

struct GzipTestParam {
  GzipTestParam(int buf_size, MockSourceStream::Mode read_mode)
      : buffer_size(buf_size), mode(read_mode) {}

  const int buffer_size;
  const MockSourceStream::Mode mode;
};

}  // namespace

class GzipSourceStreamTest : public ::testing::TestWithParam<GzipTestParam> {
 protected:
  GzipSourceStreamTest() : output_buffer_size_(GetParam().buffer_size) {}

  // Helpful function to initialize the test fixture.|type| specifies which type
  // of GzipSourceStream to create. It must be one of TYPE_GZIP,
  // TYPE_GZIP_FALLBACK and TYPE_DEFLATE.
  void Init(SourceStream::SourceType type) {
    EXPECT_TRUE(SourceStream::TYPE_GZIP == type ||
                SourceStream::TYPE_GZIP_FALLBACK == type ||
                SourceStream::TYPE_DEFLATE == type);
    source_data_len_ = kBigBufferSize - kEOFMargin;

    for (size_t i = 0; i < source_data_len_; i++)
      source_data_[i] = i % 256;

    encoded_data_len_ = kBigBufferSize;
    CompressGzip(source_data_, source_data_len_, encoded_data_,
                 &encoded_data_len_, type != SourceStream::TYPE_DEFLATE);

    output_buffer_ = new IOBuffer(output_buffer_size_);
    std::unique_ptr<MockSourceStream> source(new MockSourceStream());
    source_ = source.get();
    stream_ = GzipSourceStream::Create(std::move(source), type);
  }

  // If MockSourceStream::Mode is ASYNC, completes 1 read from |mock_stream| and
  // wait for |callback| to complete. If Mode is not ASYNC, does nothing and
  // returns |previous_result|.
  int CompleteReadIfAsync(int previous_result,
                          TestCompletionCallback* callback,
                          MockSourceStream* mock_stream) {
    if (GetParam().mode == MockSourceStream::ASYNC) {
      EXPECT_EQ(ERR_IO_PENDING, previous_result);
      mock_stream->CompleteNextRead();
      return callback->WaitForResult();
    }
    return previous_result;
  }

  char* source_data() { return source_data_; }
  size_t source_data_len() { return source_data_len_; }

  char* encoded_data() { return encoded_data_; }
  size_t encoded_data_len() { return encoded_data_len_; }

  IOBuffer* output_buffer() { return output_buffer_.get(); }
  char* output_data() { return output_buffer_->data(); }
  size_t output_buffer_size() { return output_buffer_size_; }

  MockSourceStream* source() { return source_; }
  GzipSourceStream* stream() { return stream_.get(); }

  // Reads from |stream_| until an error occurs or the EOF is reached.
  // When an error occurs, returns the net error code. When an EOF is reached,
  // returns the number of bytes read and appends data read to |output|.
  int ReadStream(std::string* output) {
    int bytes_read = 0;
    while (true) {
      TestCompletionCallback callback;
      int rv = stream_->Read(output_buffer(), output_buffer_size(),
                             callback.callback());
      if (rv == ERR_IO_PENDING)
        rv = CompleteReadIfAsync(rv, &callback, source());
      if (rv == OK)
        break;
      if (rv < OK)
        return rv;
      EXPECT_GT(rv, OK);
      bytes_read += rv;
      output->append(output_data(), rv);
    }
    return bytes_read;
  }

 private:
  char source_data_[kBigBufferSize];
  size_t source_data_len_;

  char encoded_data_[kBigBufferSize];
  size_t encoded_data_len_;

  scoped_refptr<IOBuffer> output_buffer_;
  const int output_buffer_size_;

  MockSourceStream* source_;
  std::unique_ptr<GzipSourceStream> stream_;
};

INSTANTIATE_TEST_CASE_P(
    GzipSourceStreamTests,
    GzipSourceStreamTest,
    ::testing::Values(GzipTestParam(kBigBufferSize, MockSourceStream::SYNC),
                      GzipTestParam(kSmallBufferSize, MockSourceStream::SYNC),
                      GzipTestParam(kBigBufferSize, MockSourceStream::ASYNC),
                      GzipTestParam(kSmallBufferSize,
                                    MockSourceStream::ASYNC)));

TEST_P(GzipSourceStreamTest, EmptyStream) {
  Init(SourceStream::TYPE_DEFLATE);
  source()->AddReadResult("", 0, OK, GetParam().mode);
  TestCompletionCallback callback;
  std::string actual_output;
  int result = ReadStream(&actual_output);
  EXPECT_EQ(OK, result);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateOneBlock) {
  Init(SourceStream::TYPE_DEFLATE);
  source()->AddReadResult(encoded_data(), encoded_data_len(), OK,
                          GetParam().mode);
  source()->AddReadResult(encoded_data(), 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, GzipOneBloc) {
  Init(SourceStream::TYPE_GZIP);
  source()->AddReadResult(encoded_data(), encoded_data_len(), OK,
                          GetParam().mode);
  source()->AddReadResult(encoded_data(), 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateTwoReads) {
  Init(SourceStream::TYPE_DEFLATE);
  source()->AddReadResult(encoded_data(), 10, OK, GetParam().mode);
  source()->AddReadResult(encoded_data() + 10, encoded_data_len() - 10, OK,
                          GetParam().mode);
  source()->AddReadResult(encoded_data() + encoded_data_len(), 0, OK,
                          GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, PassThroughAfterEOF) {
  Init(SourceStream::TYPE_DEFLATE);
  char test_data[] = "Hello, World!";
  std::string encoded_data_with_trailing_data(encoded_data(),
                                              encoded_data_len());
  encoded_data_with_trailing_data.append(test_data, sizeof(test_data));
  source()->AddReadResult(encoded_data_with_trailing_data.c_str(),
                          encoded_data_len() + sizeof(test_data), OK,
                          GetParam().mode);
  source()->AddReadResult(encoded_data(), 0, OK, GetParam().mode);
  // Compressed and uncompressed data get returned as separate Read() results,
  // so this test has to call Read twice.
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  std::string expected_output(source_data(), source_data_len());
  expected_output.append(test_data, sizeof(test_data));
  EXPECT_EQ(static_cast<int>(expected_output.size()), rv);
  EXPECT_EQ(expected_output, actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, MissingZlibHeader) {
  Init(SourceStream::TYPE_DEFLATE);
  const size_t kZlibHeaderLen = 2;
  source()->AddReadResult(encoded_data() + kZlibHeaderLen,
                          encoded_data_len() - kZlibHeaderLen, OK,
                          GetParam().mode);
  source()->AddReadResult(encoded_data(), 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, CorruptGzipHeader) {
  Init(SourceStream::TYPE_GZIP);
  encoded_data()[0] = 0;
  source()->AddReadResult(encoded_data(), encoded_data_len(), OK,
                          GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  EXPECT_EQ("GZIP", stream()->Description());
}

TEST_P(GzipSourceStreamTest, GzipFallback) {
  Init(SourceStream::TYPE_GZIP_FALLBACK);
  source()->AddReadResult(source_data(), source_data_len(), OK,
                          GetParam().mode);
  source()->AddReadResult(source_data(), 0, OK, GetParam().mode);

  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("GZIP_FALLBACK", stream()->Description());
}

// This test checks that the gzip stream source works correctly on 'golden' data
// as produced by gzip(1).
TEST_P(GzipSourceStreamTest, GzipCorrectness) {
  Init(SourceStream::TYPE_GZIP);
  char plain_data[] = "Hello, World!";
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // The footer is the last 8 bytes.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  source()->AddReadResult(reinterpret_cast<char*>(gzip_data), sizeof(gzip_data),
                          OK, GetParam().mode);
  source()->AddReadResult(
      reinterpret_cast<char*>(gzip_data) + sizeof(gzip_data), 0, OK,
      GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(plain_data)), rv);
  EXPECT_EQ(plain_data, actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

// Only test synchronous read because it's not straightforward to know how many
// MockSourceStream reads to complete in order for GzipSourceStream to return.
TEST_P(GzipSourceStreamTest, GzipCorrectnessWithSmallInputBuffer) {
  Init(SourceStream::TYPE_GZIP);
  char plain_data[] = "Hello, World!";
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // The footer is the last 8 bytes.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  size_t gzip_data_len = sizeof(gzip_data);
  // Add a sequence of small reads.
  for (size_t i = 0; i < gzip_data_len; i++) {
    source()->AddReadResult(reinterpret_cast<char*>(gzip_data) + i, 1, OK,
                            MockSourceStream::SYNC);
  }
  source()->AddReadResult(reinterpret_cast<char*>(gzip_data) + gzip_data_len, 0,
                          OK, MockSourceStream::SYNC);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(plain_data)), rv);
  EXPECT_EQ(plain_data, actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

// Same as GzipCorrectness except that last 8 bytes are removed to test that the
// implementation can handle missing footer.
TEST_P(GzipSourceStreamTest, GzipCorrectnessWithoutFooter) {
  Init(SourceStream::TYPE_GZIP);
  char plain_data[] = "Hello, World!";
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // with the 8 footer bytes removed.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00,
      0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08,
      0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00};
  source()->AddReadResult(reinterpret_cast<char*>(gzip_data), sizeof(gzip_data),
                          OK, GetParam().mode);
  source()->AddReadResult(reinterpret_cast<char*>(gzip_data), 0, OK,
                          GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(plain_data)), rv);
  EXPECT_EQ(plain_data, actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

}  // namespace net
