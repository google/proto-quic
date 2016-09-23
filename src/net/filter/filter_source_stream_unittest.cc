// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <string>

#include "base/bind.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/numerics/safe_conversions.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

const size_t kDefaultBufferSize = 4096;
const size_t kSmallBufferSize = 1;

class TestFilterSourceStreamBase : public FilterSourceStream {
 public:
  TestFilterSourceStreamBase(std::unique_ptr<SourceStream> upstream)
      : FilterSourceStream(SourceStream::TYPE_NONE, std::move(upstream)) {}
  ~TestFilterSourceStreamBase() override { DCHECK(buffer_.empty()); }
  std::string GetTypeAsString() const override { return type_string_; }

  void set_type_string(const std::string& type_string) {
    type_string_ = type_string;
  }

 protected:
  // Writes contents of |buffer_| to |output_buffer| and returns the number of
  // bytes written or an error code. Additionally removes consumed data from
  // |buffer_|.
  int WriteBufferToOutput(IOBuffer* output_buffer, int output_buffer_size) {
    size_t bytes_to_filter =
        std::min(buffer_.length(), static_cast<size_t>(output_buffer_size));
    memcpy(output_buffer->data(), buffer_.data(), bytes_to_filter);
    buffer_.erase(0, bytes_to_filter);
    return base::checked_cast<int>(bytes_to_filter);
  }

  // Buffer used by subclasses to hold data that is yet to be passed to the
  // caller.
  std::string buffer_;

 private:
  std::string type_string_;

  DISALLOW_COPY_AND_ASSIGN(TestFilterSourceStreamBase);
};

// A FilterSourceStream that needs all input data before it can return non-zero
// bytes read.
class NeedsAllInputFilterSourceStream : public TestFilterSourceStreamBase {
 public:
  NeedsAllInputFilterSourceStream(std::unique_ptr<SourceStream> upstream,
                                  size_t expected_input_bytes)
      : TestFilterSourceStreamBase(std::move(upstream)),
        expected_input_bytes_(expected_input_bytes) {}
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool upstream_eof_reached) override {
    buffer_.append(input_buffer->data(), input_buffer_size);
    EXPECT_GE(expected_input_bytes_, input_buffer_size);
    expected_input_bytes_ -= input_buffer_size;
    *consumed_bytes = input_buffer_size;
    if (!upstream_eof_reached) {
      // Keep returning 0 bytes read until all input has been consumed.
      return 0;
    }
    EXPECT_EQ(0, expected_input_bytes_);
    return WriteBufferToOutput(output_buffer, output_buffer_size);
  }

 private:
  // Expected remaining bytes to be received from |upstream|.
  int expected_input_bytes_;

  DISALLOW_COPY_AND_ASSIGN(NeedsAllInputFilterSourceStream);
};

// A FilterSourceStream that repeat every input byte by |multiplier| amount of
// times.
class MultiplySourceStream : public TestFilterSourceStreamBase {
 public:
  MultiplySourceStream(std::unique_ptr<SourceStream> upstream, int multiplier)
      : TestFilterSourceStreamBase(std::move(upstream)),
        multiplier_(multiplier) {}
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool /*upstream_eof_reached*/) override {
    for (int i = 0; i < input_buffer_size; i++) {
      for (int j = 0; j < multiplier_; j++)
        buffer_.append(input_buffer->data() + i, 1);
    }
    *consumed_bytes = input_buffer_size;
    return WriteBufferToOutput(output_buffer, output_buffer_size);
  }

 private:
  int multiplier_;

  DISALLOW_COPY_AND_ASSIGN(MultiplySourceStream);
};

// A FilterSourceStream passes through data unchanged to consumer.
class PassThroughFilterSourceStream : public TestFilterSourceStreamBase {
 public:
  explicit PassThroughFilterSourceStream(std::unique_ptr<SourceStream> upstream)
      : TestFilterSourceStreamBase(std::move(upstream)) {}
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool /*upstream_eof_reached*/) override {
    buffer_.append(input_buffer->data(), input_buffer_size);
    *consumed_bytes = input_buffer_size;
    return WriteBufferToOutput(output_buffer, output_buffer_size);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(PassThroughFilterSourceStream);
};

// A FilterSourceStream passes throttle input data such that it returns them to
// caller only one bytes at a time.
class ThrottleSourceStream : public TestFilterSourceStreamBase {
 public:
  explicit ThrottleSourceStream(std::unique_ptr<SourceStream> upstream)
      : TestFilterSourceStreamBase(std::move(upstream)) {}
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool /*upstream_eof_reached*/) override {
    buffer_.append(input_buffer->data(), input_buffer_size);
    *consumed_bytes = input_buffer_size;
    int bytes_to_read = std::min(1, static_cast<int>(buffer_.size()));
    memcpy(output_buffer->data(), buffer_.data(), bytes_to_read);
    buffer_.erase(0, bytes_to_read);
    return bytes_to_read;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ThrottleSourceStream);
};

// A FilterSourceStream that consumes all input data but return no output.
class NoOutputSourceStream : public TestFilterSourceStreamBase {
 public:
  NoOutputSourceStream(std::unique_ptr<SourceStream> upstream,
                       size_t expected_input_size)
      : TestFilterSourceStreamBase(std::move(upstream)),
        expected_input_size_(expected_input_size),
        consumed_all_input_(false) {}
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool /*upstream_eof_reached*/) override {
    expected_input_size_ -= input_buffer_size;
    *consumed_bytes = input_buffer_size;
    EXPECT_LE(0, expected_input_size_);
    consumed_all_input_ = (expected_input_size_ == 0);
    return OK;
  }

  bool consumed_all_input() const { return consumed_all_input_; }

 private:
  // Expected remaining bytes to be received from |upstream|.
  int expected_input_size_;
  bool consumed_all_input_;

  DISALLOW_COPY_AND_ASSIGN(NoOutputSourceStream);
};

// A FilterSourceStream return an error code in FilterData().
class ErrorFilterSourceStream : public FilterSourceStream {
 public:
  explicit ErrorFilterSourceStream(std::unique_ptr<SourceStream> upstream)
      : FilterSourceStream(SourceStream::TYPE_NONE, std::move(upstream)) {}

  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool /*upstream_eof_reached*/) override {
    return ERR_CONTENT_DECODING_FAILED;
  }
  std::string GetTypeAsString() const override { return ""; }

 private:
  DISALLOW_COPY_AND_ASSIGN(ErrorFilterSourceStream);
};

}  // namespace

class FilterSourceStreamTest
    : public ::testing::TestWithParam<MockSourceStream::Mode> {
 protected:
  // If MockSourceStream::Mode is ASYNC, completes |num_reads| from
  // |mock_stream| and wait for |callback| to complete. If Mode is not ASYNC,
  // does nothing and returns |previous_result|.
  int CompleteReadIfAsync(int previous_result,
                          TestCompletionCallback* callback,
                          MockSourceStream* mock_stream,
                          size_t num_reads) {
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
};

INSTANTIATE_TEST_CASE_P(FilterSourceStreamTests,
                        FilterSourceStreamTest,
                        ::testing::Values(MockSourceStream::SYNC,
                                          MockSourceStream::ASYNC));

// Tests that a FilterSourceStream subclass (NeedsAllInputFilterSourceStream)
// can return 0 bytes for FilterData()s when it has not consumed EOF from the
// upstream. In this case, FilterSourceStream should continue reading from
// upstream to complete filtering.
TEST_P(FilterSourceStreamTest, FilterDataReturnNoBytesExceptLast) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input("hello, world!");
  size_t read_size = 2;
  size_t num_reads = 0;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
    num_reads++;
  }
  source->AddReadResult(input.data(), 0, OK, GetParam());  // EOF
  num_reads++;

  MockSourceStream* mock_stream = source.get();
  NeedsAllInputFilterSourceStream stream(std::move(source), input.length());
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, num_reads);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns 0 byte read because the upstream gives an
// EOF.
TEST_P(FilterSourceStreamTest, FilterDataReturnNoByte) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input;
  source->AddReadResult(input.data(), 0, OK, GetParam());
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  TestCompletionCallback callback;
  int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                       callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, mock_stream, 1);
  EXPECT_EQ(OK, rv);
}

// Tests that FilterData() returns 0 byte filtered even though the upstream
// produces data.
TEST_P(FilterSourceStreamTest, FilterDataOutputNoData) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  size_t read_size = 2;
  size_t num_reads = 0;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
    num_reads++;
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  num_reads++;
  MockSourceStream* mock_stream = source.get();
  NoOutputSourceStream stream(std::move(source), input.length());
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  TestCompletionCallback callback;
  int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                       callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, mock_stream, num_reads);
  EXPECT_EQ(OK, rv);
  EXPECT_TRUE(stream.consumed_all_input());
}

// Tests that FilterData() returns non-zero bytes because the upstream
// returns data.
TEST_P(FilterSourceStreamTest, FilterDataReturnData) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  size_t read_size = 2;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GE(static_cast<int>(read_size), rv);
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns more data than what it consumed.
TEST_P(FilterSourceStreamTest, FilterDataReturnMoreData) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  size_t read_size = 2;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  MockSourceStream* mock_stream = source.get();
  int multiplier = 2;
  MultiplySourceStream stream(std::move(source), multiplier);
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GE(static_cast<int>(read_size) * multiplier, rv);
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ("hheelllloo,,  wwoorrlldd!!", actual_output);
}

// Tests that FilterData() returns non-zero bytes and output buffer size is
// smaller than the number of bytes read from the upstream.
TEST_P(FilterSourceStreamTest, FilterDataOutputSpace) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  size_t read_size = 2;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  // Use an extremely small buffer size, so FilterData will need more output
  // space.
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kSmallBufferSize);
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    ASSERT_GE(kSmallBufferSize, static_cast<size_t>(rv));
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns an error code, which is then surfaced as
// the result of calling Read().
TEST_P(FilterSourceStreamTest, FilterDataReturnError) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input;
  source->AddReadResult(input.data(), 0, OK, GetParam());
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  MockSourceStream* mock_stream = source.get();
  ErrorFilterSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                       callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  // Reading from |stream| again should return the same error.
  rv = stream.Read(output_buffer.get(), output_buffer->size(),
                   callback.callback());
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
}

TEST_P(FilterSourceStreamTest, FilterChaining) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  source->AddReadResult(input.data(), input.length(), OK, GetParam());
  source->AddReadResult(input.data(), 0, OK, GetParam());  // EOF

  MockSourceStream* mock_stream = source.get();
  std::unique_ptr<PassThroughFilterSourceStream> pass_through_source(
      new PassThroughFilterSourceStream(std::move(source)));
  pass_through_source->set_type_string("FIRST_PASS_THROUGH");
  std::unique_ptr<NeedsAllInputFilterSourceStream> needs_all_input_source(
      new NeedsAllInputFilterSourceStream(std::move(pass_through_source),
                                          input.length()));
  needs_all_input_source->set_type_string("NEEDS_ALL");
  std::unique_ptr<PassThroughFilterSourceStream> second_pass_through_source(
      new PassThroughFilterSourceStream(std::move(needs_all_input_source)));
  second_pass_through_source->set_type_string("SECOND_PASS_THROUGH");
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);

  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = second_pass_through_source->Read(
        output_buffer.get(), output_buffer->size(), callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/2);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
  // Type string (from left to right) should be the order of data flow.
  EXPECT_EQ("FIRST_PASS_THROUGH,NEEDS_ALL,SECOND_PASS_THROUGH",
            second_pass_through_source->Description());
}

// Tests that FilterData() returns multiple times for a single MockStream
// read, because there is not enough output space.
TEST_P(FilterSourceStreamTest, OutputSpaceForOneRead) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  source->AddReadResult(input.data(), input.length(), OK, GetParam());
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  // Use an extremely small buffer size (1 byte), so FilterData will need more
  // output space.
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kSmallBufferSize);
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    ASSERT_GE(kSmallBufferSize, static_cast<size_t>(rv));
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns multiple times for a single MockStream
// read, because the filter returns one byte at a time.
TEST_P(FilterSourceStreamTest, ThrottleSourceStream) {
  std::unique_ptr<MockSourceStream> source(new MockSourceStream);
  std::string input = "hello, world!";
  source->AddReadResult(input.data(), input.length(), OK, GetParam());
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  scoped_refptr<IOBufferWithSize> output_buffer =
      new IOBufferWithSize(kDefaultBufferSize);
  MockSourceStream* mock_stream = source.get();
  ThrottleSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    // ThrottleSourceStream returns 1 byte at a time.
    ASSERT_GE(1u, static_cast<size_t>(rv));
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

}  // namespace net
