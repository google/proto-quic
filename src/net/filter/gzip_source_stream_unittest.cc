// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/bind.h"
#include "base/bit_cast.h"
#include "base/callback.h"
#include "net/base/completion_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/zlib/zlib.h"

namespace net {

namespace {

const int kBufferSize = 4096;
const int kSmallBufferSize = 1;

// How many bytes to leave unused at the end of |source_data_|. This margin is
// present so that tests that need to append data after the zlib EOF do not run
// out of room in the output buffer.
const size_t kEOFMargin = 64;

}  // namespace

class GzipSourceStreamTest
    : public ::testing::TestWithParam<MockSourceStream::Mode> {
 protected:
  GzipSourceStreamTest() : output_buffer_size_(kBufferSize) {}
  // If |allow_gzip_fallback| is true, will use
  // GZIP_SOURCE_STREAM_GZIP_WITH_FALLBACK when constructing |gzip_stream_|.
  void Init(bool allow_gzip_fallback) {
    source_data_len_ = kBufferSize - kEOFMargin;

    for (size_t i = 0; i < source_data_len_; i++)
      source_data_[i] = i % 256;

    deflated_data_len_ = kBufferSize;
    Compress(source_data_, source_data_len_, deflated_data_,
             &deflated_data_len_, false);

    gzipped_data_len_ = kBufferSize;
    Compress(source_data_, source_data_len_, gzipped_data_, &gzipped_data_len_,
             true);

    output_buffer_ = new IOBuffer(output_buffer_size_);
    std::unique_ptr<MockSourceStream> deflate_source(new MockSourceStream);
    deflate_source_ = deflate_source.get();
    deflate_stream_ = GzipSourceStream::Create(std::move(deflate_source),
                                               SourceStream::TYPE_DEFLATE);
    std::unique_ptr<MockSourceStream> gzip_source(new MockSourceStream);
    gzip_source_ = gzip_source.get();
    if (allow_gzip_fallback) {
      gzip_stream_ = GzipSourceStream::Create(std::move(gzip_source),
                                              SourceStream::TYPE_GZIP_FALLBACK);
    } else {
      gzip_stream_ = GzipSourceStream::Create(std::move(gzip_source),
                                              SourceStream::TYPE_GZIP);
    }
  }

  // Compress |source| with length |source_len|. Write output into |dest|, and
  // output length into |dest_len|. If |gzip_framing| is true, header will be
  // added.
  void Compress(char* source,
                size_t source_len,
                char* dest,
                size_t* dest_len,
                bool gzip_framing) {
    size_t dest_left = *dest_len;
    z_stream zlib_stream;
    memset(&zlib_stream, 0, sizeof(zlib_stream));
    int code;
    if (gzip_framing) {
      const int kMemLevel = 8;  // the default, see deflateInit2(3)
      code = deflateInit2(&zlib_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                          -MAX_WBITS, kMemLevel, Z_DEFAULT_STRATEGY);
    } else {
      code = deflateInit(&zlib_stream, Z_DEFAULT_COMPRESSION);
    }
    DCHECK_EQ(Z_OK, code);

    // If compressing with gzip framing, prepend a gzip header. See RFC 1952 2.2
    // and 2.3 for more information.
    if (gzip_framing) {
      const unsigned char gzip_header[] = {
          0x1f,
          0x8b,  // magic number
          0x08,  // CM 0x08 == "deflate"
          0x00,  // FLG 0x00 == nothing
          0x00, 0x00, 0x00,
          0x00,  // MTIME 0x00000000 == no mtime
          0x00,  // XFL 0x00 == nothing
          0xff,  // OS 0xff == unknown
      };
      DCHECK_GE(dest_left, sizeof(gzip_header));
      memcpy(dest, gzip_header, sizeof(gzip_header));
      dest += sizeof(gzip_header);
      dest_left -= sizeof(gzip_header);
    }

    zlib_stream.next_in = bit_cast<Bytef*>(source);
    zlib_stream.avail_in = source_len;
    zlib_stream.next_out = bit_cast<Bytef*>(dest);
    zlib_stream.avail_out = dest_left;

    code = deflate(&zlib_stream, Z_FINISH);
    DCHECK_EQ(Z_STREAM_END, code);
    dest_left = zlib_stream.avail_out;

    deflateEnd(&zlib_stream);
    *dest_len -= dest_left;
  }

  // If MockSourceStream::Mode is ASYNC, completes 1 read from |mock_stream| and
  // wait for |callback| to complete. If Mode is not ASYNC, does nothing and
  // returns |previous_result|.
  int CompleteReadIfAsync(int previous_result,
                          TestCompletionCallback* callback,
                          MockSourceStream* mock_stream) {
    if (GetParam() == MockSourceStream::ASYNC) {
      EXPECT_EQ(ERR_IO_PENDING, previous_result);
      mock_stream->CompleteNextRead();
      return callback->WaitForResult();
    }
    return previous_result;
  }

  void set_output_buffer_size(int output_buffer_size) {
    output_buffer_size_ = output_buffer_size;
  }

  char* source_data() { return source_data_; }
  size_t source_data_len() { return source_data_len_; }

  char* deflated_data() { return deflated_data_; }
  size_t deflated_data_len() { return deflated_data_len_; }

  char* gzipped_data() { return gzipped_data_; }
  size_t gzipped_data_len() { return gzipped_data_len_; }

  IOBuffer* output_buffer() { return output_buffer_.get(); }
  char* output_data() { return output_buffer_->data(); }
  size_t output_buffer_size() { return output_buffer_size_; }

  MockSourceStream* deflate_source() { return deflate_source_; }
  GzipSourceStream* deflate_stream() { return deflate_stream_.get(); }
  MockSourceStream* gzip_source() { return gzip_source_; }
  GzipSourceStream* gzip_stream() { return gzip_stream_.get(); }

  void AddTrailingDeflatedData(const char* data, size_t data_len) {
    DCHECK_LE(data_len, kBufferSize - deflated_data_len_);
    memcpy(deflated_data_ + deflated_data_len_, data, data_len);
    deflated_data_len_ += data_len;
  }

  int ReadStream(GzipSourceStream* stream, const CompletionCallback& callback) {
    return stream->Read(output_buffer(), output_buffer_size(), callback);
  }

  int ReadDeflateStream(const CompletionCallback& callback) {
    return ReadStream(deflate_stream_.get(), callback);
  }

  int ReadGzipStream(const CompletionCallback& callback) {
    return ReadStream(gzip_stream_.get(), callback);
  }

 private:
  char source_data_[kBufferSize];
  size_t source_data_len_;

  char deflated_data_[kBufferSize];
  size_t deflated_data_len_;

  char gzipped_data_[kBufferSize];
  size_t gzipped_data_len_;

  scoped_refptr<IOBuffer> output_buffer_;
  int output_buffer_size_;

  MockSourceStream* deflate_source_;
  std::unique_ptr<GzipSourceStream> deflate_stream_;
  MockSourceStream* gzip_source_;
  std::unique_ptr<GzipSourceStream> gzip_stream_;
};

INSTANTIATE_TEST_CASE_P(GzipSourceStreamTests,
                        GzipSourceStreamTest,
                        ::testing::Values(MockSourceStream::SYNC,
                                          MockSourceStream::ASYNC));

TEST_P(GzipSourceStreamTest, EmptyStream) {
  Init(/*allow_gzip_fallback=*/false);
  deflate_source()->AddReadResult("", 0, OK, GetParam());
  TestCompletionCallback callback;
  int result = ReadDeflateStream(callback.callback());
  result = CompleteReadIfAsync(result, &callback, deflate_source());
  EXPECT_EQ(OK, result);
  EXPECT_EQ("DEFLATE", deflate_stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateOneBlock) {
  Init(/*allow_gzip_fallback=*/false);
  deflate_source()->AddReadResult(deflated_data(), deflated_data_len(), OK,
                                  GetParam());
  TestCompletionCallback callback;
  int rv = ReadDeflateStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, deflate_source());
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(0, memcmp(output_data(), source_data(), source_data_len()));
  EXPECT_EQ("DEFLATE", deflate_stream()->Description());
}

TEST_P(GzipSourceStreamTest, GzipOneBloc) {
  Init(/*allow_gzip_fallback=*/false);
  gzip_source()->AddReadResult(gzipped_data(), gzipped_data_len(), OK,
                               GetParam());
  TestCompletionCallback callback;
  int rv = ReadGzipStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, gzip_source());
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(0, memcmp(output_data(), source_data(), source_data_len()));
  EXPECT_EQ("GZIP", gzip_stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateTwoBlocks) {
  Init(/*allow_gzip_fallback=*/false);
  deflate_source()->AddReadResult(deflated_data(), 10, OK, GetParam());
  deflate_source()->AddReadResult(deflated_data() + 10,
                                  deflated_data_len() - 10, OK, GetParam());
  deflate_source()->AddReadResult(deflated_data() + deflated_data_len(), 0, OK,
                                  GetParam());
  std::string actual_output;
  while (true) {
    TestCompletionCallback callback;
    int rv = ReadDeflateStream(callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, deflate_source());
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_data(), rv);
  }
  EXPECT_EQ(source_data_len(), actual_output.size());
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", deflate_stream()->Description());
}

TEST_P(GzipSourceStreamTest, PassThroughAfterEOF) {
  Init(/*allow_gzip_fallback=*/false);
  char test_data[] = "Hello, World!";
  AddTrailingDeflatedData(test_data, sizeof(test_data));
  deflate_source()->AddReadResult(deflated_data(), deflated_data_len(), OK,
                                  GetParam());
  // Compressed and uncompressed data get returned as separate Read() results,
  // so this test has to call Read twice.
  TestCompletionCallback callback;
  int rv = ReadDeflateStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, deflate_source());
  EXPECT_EQ(static_cast<int>(source_data_len() + sizeof(test_data)), rv);
  EXPECT_EQ(0, memcmp(output_data(), source_data(), source_data_len()));
  EXPECT_EQ(0, memcmp(output_data() + source_data_len(), test_data,
                      sizeof(test_data)));
  EXPECT_EQ("DEFLATE", deflate_stream()->Description());
}

TEST_P(GzipSourceStreamTest, MissingZlibHeader) {
  Init(/*allow_gzip_fallback=*/false);
  const size_t kZlibHeaderLen = 2;
  deflate_source()->AddReadResult(deflated_data() + kZlibHeaderLen,
                                  deflated_data_len() - kZlibHeaderLen, OK,
                                  GetParam());
  TestCompletionCallback callback;
  int rv = ReadDeflateStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, deflate_source());
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(0, memcmp(output_data(), source_data(), source_data_len()));
  EXPECT_EQ("DEFLATE", deflate_stream()->Description());
}

TEST_P(GzipSourceStreamTest, CorruptGzipHeader) {
  Init(/*allow_gzip_fallback=*/false);
  gzipped_data()[0] = 0;
  gzip_source()->AddReadResult(gzipped_data(), gzipped_data_len(), OK,
                               GetParam());
  TestCompletionCallback callback;
  int rv = ReadGzipStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, gzip_source());
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  EXPECT_EQ("GZIP", gzip_stream()->Description());
}

TEST_P(GzipSourceStreamTest, GzipFallback) {
  Init(/*allow_gzip_fallback=*/true);
  gzip_source()->AddReadResult(source_data(), source_data_len(), OK,
                               GetParam());
  TestCompletionCallback callback;
  int rv = ReadGzipStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, gzip_source());
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(0, memcmp(output_data(), source_data(), source_data_len()));
  EXPECT_EQ("GZIP_FALLBACK", gzip_stream()->Description());
}

// This test checks that the gzip stream source works correctly on 'golden' data
// as produced by gzip(1).
TEST_P(GzipSourceStreamTest, GzipCorrectness) {
  Init(/*allow_gzip_fallback=*/false);
  char plain_data[] = "Hello, World!";
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // The footer is the last 8 bytes.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  gzip_source()->AddReadResult(reinterpret_cast<char*>(gzip_data),
                               sizeof(gzip_data), OK, GetParam());
  TestCompletionCallback callback;
  int rv = ReadGzipStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, gzip_source());
  EXPECT_EQ(static_cast<int>(strlen(plain_data)), rv);
  EXPECT_EQ(0, memcmp(output_data(), plain_data, strlen(plain_data)));
  EXPECT_EQ("GZIP", gzip_stream()->Description());
}

TEST_P(GzipSourceStreamTest, GzipCorrectnessWithSmallOutputBuffer) {
  set_output_buffer_size(kSmallBufferSize);
  Init(/*allow_gzip_fallback=*/false);
  char plain_data[] = "Hello, World!";
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // The footer is the last 8 bytes.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  gzip_source()->AddReadResult(reinterpret_cast<char*>(gzip_data),
                               sizeof(gzip_data), OK, GetParam());
  gzip_source()->AddReadResult(
      reinterpret_cast<char*>(gzip_data) + sizeof(gzip_data), 0, OK,
      GetParam());
  std::string actual_output;
  while (true) {
    TestCompletionCallback callback;
    int rv = ReadGzipStream(callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, gzip_source());
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_data(), rv);
  }
  EXPECT_EQ(plain_data, actual_output);
  EXPECT_EQ("GZIP", gzip_stream()->Description());
}

// Only test synchronous read because it's not straightforward to know how many
// MockSourceStream reads to complete in order for GzipSourceStream to return.
TEST_P(GzipSourceStreamTest, GzipCorrectnessWithSmallInputBuffer) {
  Init(/*allow_gzip_fallback=*/false);
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
    gzip_source()->AddReadResult(reinterpret_cast<char*>(gzip_data) + i, 1, OK,
                                 MockSourceStream::SYNC);
  }
  gzip_source()->AddReadResult(
      reinterpret_cast<char*>(gzip_data) + gzip_data_len, 0, OK,
      MockSourceStream::SYNC);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = ReadGzipStream(callback.callback());
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_data(), rv);
  }
  EXPECT_EQ(strlen(plain_data), actual_output.size());
  EXPECT_EQ(plain_data, actual_output);
  EXPECT_EQ("GZIP", gzip_stream()->Description());
}

// Same as GzipCorrectness except that last 8 bytes are removed to test that the
// implementation can handle missing footer.
TEST_P(GzipSourceStreamTest, GzipCorrectnessWithoutFooter) {
  Init(/*allow_gzip_fallback=*/false);
  char plain_data[] = "Hello, World!";
  unsigned char gzip_data[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // with the 8 footer bytes removed.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00,
      0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08,
      0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00};
  gzip_source()->AddReadResult(reinterpret_cast<char*>(gzip_data),
                               sizeof(gzip_data), OK, GetParam());
  TestCompletionCallback callback;
  int rv = ReadGzipStream(callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, gzip_source());
  EXPECT_EQ(static_cast<int>(strlen(plain_data)), rv);
  EXPECT_EQ(0, memcmp(output_data(), plain_data, strlen(plain_data)));
  EXPECT_EQ("GZIP", gzip_stream()->Description());
}

}  // namespace
