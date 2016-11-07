// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/bind.h"
#include "base/bit_cast.h"
#include "base/callback.h"
#include "base/memory/ptr_util.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/mock_source_stream.h"
#include "net/filter/sdch_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/zlib/zlib.h"

namespace net {

namespace {

const size_t kBufferSize = 4096;
const size_t kSmallBufferSize = 1;

// Provide sample data and compression results with a sample VCDIFF dictionary.
// Note an SDCH dictionary has extra meta-data before the VCDIFF dictionary.
static const char kTestVcdiffDictionary[] =
    "DictionaryFor"
    "SdchCompression1SdchCompression2SdchCompression3SdchCompression\n";

// Pre-compression test data. Note that we pad with a lot of highly gzip
// compressible content to help to exercise the chaining pipeline. That is why
// there are a PILE of zeros at the start and end.
static const char kTestData[] =
    "0000000000000000000000000000000000000000000000"
    "0000000000000000000000000000TestData "
    "SdchCompression1SdchCompression2SdchCompression3SdchCompression"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000\n";
static const char kSdchCompressedTestData[] =
    "\326\303\304\0\0\001M\0\201S\202\004\0\201E\006\001"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "TestData 00000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000\n\001S\023\077\001r\r";

// Helper function to perform gzip compression of data.
static std::string gzip_compress(const std::string& input,
                                 size_t input_size,
                                 size_t* output_size) {
  z_stream zlib_stream;
  memset(&zlib_stream, 0, sizeof(zlib_stream));
  int code;

  // Initialize zlib
  code =
      deflateInit2(&zlib_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
                   8,  // DEF_MEM_LEVEL
                   Z_DEFAULT_STRATEGY);

  CHECK_EQ(Z_OK, code);

  // Fill in zlib control block
  zlib_stream.next_in = bit_cast<Bytef*>(input.data());
  zlib_stream.avail_in = input_size;

  // Assume we can compress into similar buffer (add 100 bytes to be sure).
  size_t gzip_compressed_length = zlib_stream.avail_in + 100;
  std::unique_ptr<char[]> gzip_compressed(new char[gzip_compressed_length]);
  zlib_stream.next_out = bit_cast<Bytef*>(gzip_compressed.get());
  zlib_stream.avail_out = gzip_compressed_length;

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
  const char kGZipHeader[] = {'\037', '\213', '\010', '\000', '\000',
                              '\000', '\000', '\000', '\002', '\377'};
  CHECK_GT(zlib_stream.avail_out, sizeof(kGZipHeader));
  memcpy(zlib_stream.next_out, kGZipHeader, sizeof(kGZipHeader));
  zlib_stream.next_out += sizeof(kGZipHeader);
  zlib_stream.avail_out -= sizeof(kGZipHeader);

  // Do deflate
  code = deflate(&zlib_stream, Z_FINISH);
  gzip_compressed_length -= zlib_stream.avail_out;
  std::string compressed(gzip_compressed.get(), gzip_compressed_length);
  deflateEnd(&zlib_stream);
  *output_size = gzip_compressed_length;
  return compressed;
}

class MockDelegate : public SdchSourceStream::Delegate {
 public:
  MockDelegate(const std::string& test_dictionary_id,
               const std::string& test_dictionary_text,
               SdchSourceStream::Delegate::ErrorRecovery error_recover,
               const std::string& replace_output)
      : dictionary_id_error_handled_(false),
        get_dictionary_error_handled_(false),
        decoding_error_handled_(false),
        test_dictionary_id_(test_dictionary_id),
        test_dictionary_text_(test_dictionary_text),
        error_recover_(error_recover),
        replace_output_(replace_output) {}

  // SdchSourceStream::Delegate implementation.
  SdchSourceStream::Delegate::ErrorRecovery OnDictionaryIdError(
      std::string* replace_output) override {
    dictionary_id_error_handled_ = true;
    if (error_recover_ == REPLACE_OUTPUT)
      *replace_output = replace_output_;
    return error_recover_;
  }

  SdchSourceStream::Delegate::ErrorRecovery OnGetDictionaryError(
      std::string* replace_output) override {
    get_dictionary_error_handled_ = true;
    if (error_recover_ == REPLACE_OUTPUT)
      *replace_output = replace_output_;
    return error_recover_;
  }

  SdchSourceStream::Delegate::ErrorRecovery OnDecodingError(
      std::string* replace_output) override {
    decoding_error_handled_ = true;
    if (error_recover_ == REPLACE_OUTPUT)
      *replace_output = replace_output_;
    return error_recover_;
  }

  bool OnGetDictionary(const std::string& server_id,
                       const std::string** text) override {
    last_get_dictionary_id_ = server_id;
    if (server_id == test_dictionary_id_) {
      *text = &test_dictionary_text_;
      return true;
    }
    return false;
  }

  void OnStreamDestroyed(SdchSourceStream::InputState input_state,
                         bool buffered_output_present,
                         bool decoding_not_finished) override {}

  bool dictionary_id_error_handled() { return dictionary_id_error_handled_; }
  bool get_dictionary_error_handled() { return get_dictionary_error_handled_; }
  bool decoding_error_handled() { return decoding_error_handled_; }
  std::string last_get_dictionary_id() { return last_get_dictionary_id_; }

 private:
  std::string last_get_dictionary_id_;
  bool dictionary_id_error_handled_;
  bool get_dictionary_error_handled_;
  bool decoding_error_handled_;
  std::string test_dictionary_id_;
  std::string test_dictionary_text_;
  SdchSourceStream::Delegate::ErrorRecovery error_recover_;
  std::string replace_output_;

  DISALLOW_COPY_AND_ASSIGN(MockDelegate);
};
}  // namespace

class SdchSourceStreamTest
    : public ::testing::TestWithParam<MockSourceStream::Mode> {
 public:
  SdchSourceStreamTest() : out_buffer_size_(kBufferSize) {}

  void Init() {
    out_buffer_ = new IOBufferWithSize(out_buffer_size_);
    std::unique_ptr<MockSourceStream> source(new MockSourceStream);
    source_ = source.get();
    std::unique_ptr<MockDelegate> delegate(GetNewDelegate());
    delegate_ = delegate.get();
    sdch_source_.reset(new SdchSourceStream(
        std::move(source), std::move(delegate), SourceStream::TYPE_SDCH));
  }

  // If MockSourceStream::Mode is ASYNC, completes 1 read from
  // |mock_stream| and wait for |callback| to complete. If Mode is not ASYNC,
  // does nothing and returns |previous_result|.
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

  int CompleteReadIfAsync(int previous_result,
                          TestCompletionCallback* callback,
                          MockSourceStream* mock_stream,
                          int num_reads) {
    if (GetParam() == MockSourceStream::ASYNC) {
      EXPECT_EQ(ERR_IO_PENDING, previous_result);
      while (num_reads > 0) {
        mock_stream->CompleteNextRead();
        num_reads--;
      }
      return callback->WaitForResult();
    }
    return previous_result;
  }

  IOBuffer* out_buffer() { return out_buffer_.get(); }
  char* out_data() { return out_buffer_->data(); }
  size_t out_buffer_size() { return out_buffer_size_; }

  MockSourceStream* mock_source() { return source_; }
  SdchSourceStream* sdch_source() { return sdch_source_.get(); }

  int ReadStream(const TestCompletionCallback& callback) {
    return sdch_source()->Read(out_buffer(), out_buffer_size(),
                               callback.callback());
  }

  void set_out_buffer_size(int out_buffer_size) {
    out_buffer_size_ = out_buffer_size;
  }

  void SetTestDictionary(const std::string& dictionary_id,
                         const std::string& dictionary_text) {
    test_dictionary_id_ = dictionary_id;
    test_dictionary_text_ = dictionary_text;
  }

  void SetErrorRecovery(SdchSourceStream::Delegate::ErrorRecovery error_recover,
                        const std::string& replace_output) {
    error_recover_ = error_recover;
    replace_output_ = replace_output;
  }

  void AppendDictionaryIdTo(std::string* resp, std::string* server_id) {
    std::string client_id;
    SdchManager::GenerateHash(kTestVcdiffDictionary, &client_id, server_id);
    SetTestDictionary(*server_id, kTestVcdiffDictionary);
    std::string response(server_id->data(), server_id->size());
    response.append("\0");
    resp->append(response.data(), server_id->size() + 1);
  }

  MockDelegate* delegate() { return delegate_; }

  // Gets a new MockDelegate and take ownership of it.
  std::unique_ptr<MockDelegate> GetNewDelegate() {
    return base::WrapUnique(new MockDelegate(test_dictionary_id_,
                                             test_dictionary_text_,
                                             error_recover_, replace_output_));
  }

 private:
  // Owned by |sdch_source_|.
  MockSourceStream* source_;
  MockDelegate* delegate_;

  std::unique_ptr<SdchSourceStream> sdch_source_;
  scoped_refptr<IOBufferWithSize> out_buffer_;
  int out_buffer_size_;
  std::string test_dictionary_id_;
  std::string test_dictionary_text_;
  SdchSourceStream::Delegate::ErrorRecovery error_recover_;
  std::string replace_output_;

  DISALLOW_COPY_AND_ASSIGN(SdchSourceStreamTest);
};

TEST(SdchSourceStreamTest, GetTypeAsString) {
  SourceStream::SourceType types[] = {SourceStream::TYPE_SDCH_POSSIBLE,
                                      SourceStream::TYPE_SDCH};
  for (auto type : types) {
    std::unique_ptr<MockSourceStream> mock_source(new MockSourceStream());
    std::unique_ptr<MockDelegate> dummy_delegate(
        new MockDelegate("", "", SdchSourceStream::Delegate::NONE, ""));

    SdchSourceStream stream(std::move(mock_source), std::move(dummy_delegate),
                            type);
    EXPECT_EQ(
        type == SourceStream::TYPE_SDCH_POSSIBLE ? "SDCH_POSSIBLE" : "SDCH",
        stream.Description());
  }
}

INSTANTIATE_TEST_CASE_P(SdchSourceStreamTests,
                        SdchSourceStreamTest,
                        ::testing::Values(MockSourceStream::SYNC,
                                          MockSourceStream::ASYNC));

TEST_P(SdchSourceStreamTest, EmptyStream) {
  Init();
  mock_source()->AddReadResult("", 0, OK, GetParam());
  TestCompletionCallback callback;
  int result = ReadStream(callback);
  result = CompleteReadIfAsync(result, &callback, mock_source());
  EXPECT_EQ(OK, result);
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

// Ensure that GetDictionary() is not called at all if the SDCH dictionary ID is
// malformed.
TEST_P(SdchSourceStreamTest, BogusDictionaryId) {
  char id[] = {0x1f, '0', '0', '0', '0', '0', '0', '0', 0x0};
  SetTestDictionary(id, "...");
  SetErrorRecovery(SdchSourceStream::Delegate::PASS_THROUGH, std::string());
  Init();
  mock_source()->AddReadResult(id, sizeof(id), OK, GetParam());
  TestCompletionCallback callback;
  int result = ReadStream(callback);
  result = CompleteReadIfAsync(result, &callback, mock_source());

  EXPECT_TRUE(delegate()->dictionary_id_error_handled());
  EXPECT_EQ("", delegate()->last_get_dictionary_id());
  EXPECT_EQ(9, result);
  EXPECT_EQ(0, memcmp(id, out_data(), result));
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

// Regression test for crbug.com/661570.
// Tests that if output is replaced, SdchSourceStream::FilterData correctly
// drains input buffer and breaks out of the while loop.
TEST_P(SdchSourceStreamTest, BogusSdchContentInvalidDictionaryId) {
  // Test a regular string and an empty string.
  std::string recovery_strings[] = {"this is a recovery", ""};
  int out_buffer_sizes[] = {kBufferSize, kSmallBufferSize};
  for (auto recovery : recovery_strings) {
    for (auto out_buffer_size : out_buffer_sizes) {
      set_out_buffer_size(out_buffer_size);
      SetErrorRecovery(SdchSourceStream::Delegate::REPLACE_OUTPUT, recovery);
      Init();
      std::string response(
          "some random string that is not a valid sdch response.");
      std::unique_ptr<MockDelegate> delegate = GetNewDelegate();
      MockDelegate* raw_delegate_pointer = delegate.get();
      MockSourceStream* mock_source = new MockSourceStream;
      std::unique_ptr<SdchSourceStream> sdch_source(
          new SdchSourceStream(base::WrapUnique(mock_source),
                               std::move(delegate), SourceStream::TYPE_SDCH));
      mock_source->AddReadResult(response.c_str(), response.size(), OK,
                                 GetParam());
      // Add a synchronous EOF.
      mock_source->AddReadResult(response.c_str(), 0, OK,
                                 MockSourceStream::SYNC);
      std::string actual_output;
      while (true) {
        TestCompletionCallback callback;
        int rv = sdch_source->Read(out_buffer(), out_buffer_size,
                                   callback.callback());
        if (rv == ERR_IO_PENDING)
          rv = CompleteReadIfAsync(rv, &callback, mock_source);
        if (rv == OK)
          break;
        if (out_buffer_size == kSmallBufferSize)
          EXPECT_GE(kSmallBufferSize, static_cast<size_t>(rv));
        ASSERT_GT(rv, OK);
        actual_output.append(out_data(), rv);
      }

      EXPECT_TRUE(raw_delegate_pointer->dictionary_id_error_handled());
      EXPECT_EQ(recovery, actual_output);
      EXPECT_EQ("SDCH", sdch_source->Description());
    }
  }
}

// Same as BogusDictionaryContentInvalidDictionaryId, but with a valid
// dictionary id.
TEST_P(SdchSourceStreamTest, BogusSdchContent) {
  // Test a regular string and an empty string.
  std::string recovery_strings[] = {"this is a recovery", ""};
  int out_buffer_sizes[] = {kBufferSize, kSmallBufferSize};
  for (auto recovery : recovery_strings) {
    for (auto out_buffer_size : out_buffer_sizes) {
      set_out_buffer_size(out_buffer_size);
      SetErrorRecovery(SdchSourceStream::Delegate::REPLACE_OUTPUT, recovery);
      Init();
      std::string response;
      std::string server_id;
      AppendDictionaryIdTo(&response, &server_id);
      response.append("some random string that is not a valid sdch response.");
      std::unique_ptr<MockDelegate> delegate = GetNewDelegate();
      MockDelegate* raw_delegate_pointer = delegate.get();
      MockSourceStream* mock_source = new MockSourceStream;
      std::unique_ptr<SdchSourceStream> sdch_source(
          new SdchSourceStream(base::WrapUnique(mock_source),
                               std::move(delegate), SourceStream::TYPE_SDCH));
      mock_source->AddReadResult(response.c_str(), response.size(), OK,
                                 GetParam());
      // Add a synchronous EOF.
      mock_source->AddReadResult(response.c_str(), 0, OK,
                                 MockSourceStream::SYNC);
      std::string actual_output;
      while (true) {
        TestCompletionCallback callback;
        int rv = sdch_source->Read(out_buffer(), out_buffer_size,
                                   callback.callback());
        if (rv == ERR_IO_PENDING)
          rv = CompleteReadIfAsync(rv, &callback, mock_source);
        if (rv == OK)
          break;
        if (out_buffer_size == kSmallBufferSize)
          EXPECT_GE(kSmallBufferSize, static_cast<size_t>(rv));
        ASSERT_GT(rv, OK);
        actual_output.append(out_data(), rv);
      }

      // Should have a decoding error and not a dictionary id error.
      EXPECT_TRUE(raw_delegate_pointer->decoding_error_handled());
      EXPECT_EQ(recovery, actual_output);
      EXPECT_EQ(server_id, raw_delegate_pointer->last_get_dictionary_id());
      EXPECT_EQ("SDCH", sdch_source->Description());
    }
  }
}

// When encounter a dictionary error, delegate returns ErrorRecovery NONE.
TEST_P(SdchSourceStreamTest, BogusDictionaryIdNoRecover) {
  char id[] = {0x1f, '0', '0', '0', '0', '0', '0', '0', 0x0};
  SetTestDictionary(id, "...");
  SetErrorRecovery(SdchSourceStream::Delegate::NONE, std::string());
  Init();
  mock_source()->AddReadResult(id, sizeof(id), OK, GetParam());
  TestCompletionCallback callback;
  int result = ReadStream(callback);
  result = CompleteReadIfAsync(result, &callback, mock_source());

  EXPECT_TRUE(delegate()->dictionary_id_error_handled());
  EXPECT_EQ("", delegate()->last_get_dictionary_id());
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, result);
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

// Ensure that the stream's dictionary error handler is called if GetDictionary
// returns no dictionary.
TEST_P(SdchSourceStreamTest, NoDictionaryError) {
  char id[] = "00000000";
  SetErrorRecovery(SdchSourceStream::Delegate::PASS_THROUGH, std::string());
  Init();
  mock_source()->AddReadResult(id, sizeof(id), OK, GetParam());
  TestCompletionCallback callback;
  int result = ReadStream(callback);
  result = CompleteReadIfAsync(result, &callback, mock_source());
  EXPECT_EQ(9, result);
  EXPECT_TRUE(delegate()->get_dictionary_error_handled());
  EXPECT_EQ(id, delegate()->last_get_dictionary_id());
  EXPECT_EQ(0, memcmp(id, out_data(), result));
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

TEST_P(SdchSourceStreamTest, DictionaryLoaded) {
  std::string response;
  std::string server_id;
  AppendDictionaryIdTo(&response, &server_id);
  Init();
  mock_source()->AddReadResult(response.data(), response.size(), OK,
                               GetParam());
  mock_source()->AddReadResult(response.data(), 0, OK, MockSourceStream::SYNC);
  TestCompletionCallback callback;
  int rv = ReadStream(callback);
  rv = CompleteReadIfAsync(rv, &callback, mock_source());
  // Decoded response should be empty.
  EXPECT_EQ(0, rv);
  EXPECT_FALSE(delegate()->get_dictionary_error_handled());
  EXPECT_EQ(server_id, delegate()->last_get_dictionary_id());
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

TEST_P(SdchSourceStreamTest, DecompressOneBlock) {
  std::string response;
  std::string server_id;
  AppendDictionaryIdTo(&response, &server_id);
  Init();
  response.append(kSdchCompressedTestData, sizeof(kSdchCompressedTestData) - 1);
  mock_source()->AddReadResult(response.data(), response.size(), OK,
                               GetParam());
  TestCompletionCallback callback;
  int rv = ReadStream(callback);
  rv = CompleteReadIfAsync(rv, &callback, mock_source());

  EXPECT_FALSE(delegate()->decoding_error_handled());
  EXPECT_EQ(server_id, delegate()->last_get_dictionary_id());
  EXPECT_EQ(static_cast<int>(sizeof(kTestData) - 1), rv);
  EXPECT_EQ(0, memcmp(kTestData, out_data(), rv));
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

TEST_P(SdchSourceStreamTest, DecompressWithSmallOutputBuffer) {
  set_out_buffer_size(kSmallBufferSize);
  std::string response;
  std::string server_id;
  AppendDictionaryIdTo(&response, &server_id);
  Init();
  response.append(kSdchCompressedTestData, sizeof(kSdchCompressedTestData) - 1);
  mock_source()->AddReadResult(response.data(), response.size(), OK,
                               GetParam());
  // Add a 0 byte read to signal EOF.
  mock_source()->AddReadResult(kSdchCompressedTestData, 0, OK,
                               MockSourceStream::SYNC);

  std::string actual_output;
  while (true) {
    TestCompletionCallback callback;
    int rv = ReadStream(callback);
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_source());
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    EXPECT_GE(kSmallBufferSize, static_cast<size_t>(rv));
    actual_output.append(out_data(), rv);
  }
  EXPECT_FALSE(delegate()->decoding_error_handled());
  EXPECT_EQ(server_id, delegate()->last_get_dictionary_id());
  EXPECT_EQ(sizeof(kTestData) - 1, actual_output.size());
  EXPECT_EQ(kTestData, actual_output);
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

TEST_P(SdchSourceStreamTest, DecompressWithSmallInputBuffer) {
  std::string response;
  std::string server_id;
  AppendDictionaryIdTo(&response, &server_id);
  Init();
  response.append(kSdchCompressedTestData, sizeof(kSdchCompressedTestData) - 1);
  // Add a sequence of small reads.
  for (size_t i = 0; i < response.size(); i++) {
    mock_source()->AddReadResult(response.data() + i, 1, OK,
                                 MockSourceStream::SYNC);
  }
  // Add a 0 byte read to signal EOF.
  mock_source()->AddReadResult(kSdchCompressedTestData, 0, OK,
                               MockSourceStream::SYNC);
  std::string actual_output;
  while (true) {
    TestCompletionCallback callback;
    int rv = ReadStream(callback);
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_source());
    if (rv == OK)
      break;
    actual_output.append(out_data(), rv);
  }
  EXPECT_FALSE(delegate()->decoding_error_handled());
  EXPECT_EQ(server_id, delegate()->last_get_dictionary_id());
  EXPECT_EQ(sizeof(kTestData) - 1, actual_output.size());
  EXPECT_EQ(kTestData, actual_output);
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

TEST_P(SdchSourceStreamTest, DecompressTwoBlocks) {
  std::string response;
  std::string server_id;
  AppendDictionaryIdTo(&response, &server_id);
  Init();
  response.append(kSdchCompressedTestData, sizeof(kSdchCompressedTestData) - 1);
  mock_source()->AddReadResult(response.data(), 32, OK, GetParam());
  mock_source()->AddReadResult(response.data() + 32, response.size() - 32, OK,
                               GetParam());
  mock_source()->AddReadResult(kSdchCompressedTestData, 0, OK,
                               MockSourceStream::SYNC);
  std::string actual_output;
  while (true) {
    TestCompletionCallback callback;
    int rv = ReadStream(callback);
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_source(), 2);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(out_data(), rv);
  }
  EXPECT_FALSE(delegate()->decoding_error_handled());
  EXPECT_EQ(server_id, delegate()->last_get_dictionary_id());
  EXPECT_EQ(sizeof(kTestData) - 1, actual_output.size());
  EXPECT_EQ(kTestData, actual_output);
  EXPECT_EQ("SDCH", sdch_source()->Description());
}

// Test that filters can be cascaded (chained) so that the output of one filter
// is processed by the next one. This is most critical for SDCH, which is
// routinely followed by gzip (during encoding). The filter we'll test for will
// do the gzip decoding first, and then decode the SDCH content.
TEST_P(SdchSourceStreamTest, FilterChaining) {
  int out_buffer_sizes[] = {kBufferSize, kSmallBufferSize};
  for (auto out_buffer_size : out_buffer_sizes) {
    set_out_buffer_size(out_buffer_size);
    std::string sdch_response;
    std::string server_id;
    AppendDictionaryIdTo(&sdch_response, &server_id);
    Init();
    sdch_response.append(kSdchCompressedTestData,
                         sizeof(kSdchCompressedTestData) - 1);
    size_t expected_length =
        server_id.length() + sizeof(kSdchCompressedTestData);
    size_t gzip_length;
    std::string gzip_compressed_sdch =
        gzip_compress(sdch_response, expected_length, &gzip_length);
    MockSourceStream* source = new MockSourceStream;
    source->AddReadResult(gzip_compressed_sdch.data(), gzip_length, OK,
                          GetParam());
    // Add a 0 byte read to signal EOF.
    source->AddReadResult(gzip_compressed_sdch.data(), 0, OK,
                          MockSourceStream::SYNC);
    std::unique_ptr<GzipSourceStream> gzip_source = GzipSourceStream::Create(
        base::WrapUnique(source), SourceStream::TYPE_GZIP);
    std::unique_ptr<MockDelegate> delegate = GetNewDelegate();
    MockDelegate* raw_delegate_pointer = delegate.get();
    std::unique_ptr<SdchSourceStream> sdch_source(new SdchSourceStream(
        std::move(gzip_source), std::move(delegate), SourceStream::TYPE_SDCH));
    std::string actual_output;
    while (true) {
      TestCompletionCallback callback;
      int rv =
          sdch_source->Read(out_buffer(), out_buffer_size, callback.callback());
      if (rv == ERR_IO_PENDING)
        rv = CompleteReadIfAsync(rv, &callback, source);
      if (rv == OK)
        break;
      ASSERT_GT(rv, OK);
      if (out_buffer_size == kSmallBufferSize)
        EXPECT_GE(kSmallBufferSize, static_cast<size_t>(rv));
      actual_output.append(out_data(), rv);
    }
    EXPECT_FALSE(raw_delegate_pointer->decoding_error_handled());
    EXPECT_EQ(server_id, raw_delegate_pointer->last_get_dictionary_id());
    EXPECT_EQ(sizeof(kTestData) - 1, actual_output.size());
    EXPECT_EQ(kTestData, actual_output);
    EXPECT_EQ("GZIP,SDCH", sdch_source->Description());
  }
}

// Test that if TYPE_SDCH_POSSIBLE and TYPE_GZIP_FALLBACK are added to a
// gzipped content, the content can be decoded without problem.
TEST_P(SdchSourceStreamTest, PossibleSdchActuallyGzip) {
  int out_buffer_sizes[] = {kBufferSize, kSmallBufferSize};
  for (auto out_buffer_size : out_buffer_sizes) {
    char plain_data[] = "Hello, World!";
    unsigned char gzip_data[] = {
        // From:
        //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
        // with the 8 footer bytes removed.
        0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00,
        0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08,
        0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00};
    SetErrorRecovery(SdchSourceStream::Delegate::PASS_THROUGH, std::string());
    Init();
    std::unique_ptr<MockDelegate> delegate = GetNewDelegate();
    MockDelegate* raw_delegate_pointer = delegate.get();
    MockSourceStream* source = new MockSourceStream();
    source->AddReadResult(reinterpret_cast<char*>(gzip_data), sizeof(gzip_data),
                          OK, GetParam());
    source->AddReadResult(
        reinterpret_cast<char*>(gzip_data) + sizeof(gzip_data), 0, OK,
        MockSourceStream::SYNC);
    std::unique_ptr<GzipSourceStream> gzip_source = GzipSourceStream::Create(
        base::WrapUnique(source), SourceStream::TYPE_GZIP);
    std::unique_ptr<GzipSourceStream> gzip_fallback_source =
        GzipSourceStream::Create(std::move(gzip_source),
                                 SourceStream::TYPE_GZIP_FALLBACK);
    std::unique_ptr<SdchSourceStream> sdch_possible(new SdchSourceStream(
        std::move(gzip_fallback_source), std::move(delegate),
        SourceStream::TYPE_SDCH_POSSIBLE));
    std::string actual_output;
    while (true) {
      TestCompletionCallback callback;
      int rv = sdch_possible->Read(out_buffer(), out_buffer_size,
                                   callback.callback());
      if (rv == ERR_IO_PENDING)
        rv = CompleteReadIfAsync(rv, &callback, source);
      if (rv == OK)
        break;
      ASSERT_GT(rv, OK);
      if (out_buffer_size == kSmallBufferSize)
        EXPECT_GE(kSmallBufferSize, static_cast<size_t>(rv));

      actual_output.append(out_data(), rv);
    }
    EXPECT_TRUE(raw_delegate_pointer->dictionary_id_error_handled());
    EXPECT_EQ(plain_data, actual_output);
    EXPECT_EQ("GZIP,GZIP_FALLBACK,SDCH_POSSIBLE", sdch_possible->Description());
  }
}

}  // namespace net
