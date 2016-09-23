// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tests for WebSocketBasicStream. Note that we do not attempt to verify that
// frame parsing itself functions correctly, as that is covered by the
// WebSocketFrameParser tests.

#include "net/websockets/websocket_basic_stream.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>  // for memcpy() and memset().
#include <string>
#include <utility>
#include <vector>

#include "base/big_endian.h"
#include "base/macros.h"
#include "net/base/test_completion_callback.h"
#include "net/log/test_net_log.h"
#include "net/socket/socket_test_util.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

#define WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(name, value) \
  const char k##name[] = value;                                  \
  const size_t k##name##Size = arraysize(k##name) - 1;

WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(SampleFrame, "\x81\x06Sample");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(
    PartialLargeFrame,
    "\x81\x7F\x00\x00\x00\x00\x7F\xFF\xFF\xFF"
    "chromiunum ad pasco per loca insanis pullum manducat frumenti");
const size_t kLargeFrameHeaderSize = 10;
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(MultipleFrames,
                                            "\x81\x01X\x81\x01Y\x81\x01Z");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyFirstFrame, "\x01\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyMiddleFrame, "\x00\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyFinalTextFrame, "\x81\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(EmptyFinalContinuationFrame,
                                            "\x80\x00");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(ValidPong, "\x8A\x00");
// This frame encodes a payload length of 7 in two bytes, which is always
// invalid.
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(InvalidFrame,
                                            "\x81\x7E\x00\x07Invalid");
// Control frames must have the FIN bit set. This one does not.
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(PingFrameWithoutFin, "\x09\x00");
// Control frames must have a payload of 125 bytes or less. This one has
// a payload of 126 bytes.
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(
    126BytePong,
    "\x8a\x7e\x00\x7eZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(CloseFrame,
                                            "\x88\x09\x03\xe8occludo");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(WriteFrame,
                                            "\x81\x85\x00\x00\x00\x00Write");
WEBSOCKET_BASIC_STREAM_TEST_DEFINE_CONSTANT(MaskedEmptyPong,
                                            "\x8A\x80\x00\x00\x00\x00");
const WebSocketMaskingKey kNulMaskingKey = {{'\0', '\0', '\0', '\0'}};
const WebSocketMaskingKey kNonNulMaskingKey = {
    {'\x0d', '\x1b', '\x06', '\x17'}};

// A masking key generator function which generates the identity mask,
// ie. "\0\0\0\0".
WebSocketMaskingKey GenerateNulMaskingKey() { return kNulMaskingKey; }

// A masking key generation function which generates a fixed masking key with no
// nul characters.
WebSocketMaskingKey GenerateNonNulMaskingKey() { return kNonNulMaskingKey; }

// Base class for WebSocketBasicStream test fixtures.
class WebSocketBasicStreamTest : public ::testing::Test {
 protected:
  std::unique_ptr<WebSocketBasicStream> stream_;
  TestNetLog net_log_;
};

// A subclass of StaticSocketDataProvider modified to require that all data
// expected to be read or written actually is.
class StrictStaticSocketDataProvider : public StaticSocketDataProvider {
 public:
  StrictStaticSocketDataProvider(MockRead* reads,
                                 size_t reads_count,
                                 MockWrite* writes,
                                 size_t writes_count,
                                 bool strict_mode)
      : StaticSocketDataProvider(reads, reads_count, writes, writes_count),
        strict_mode_(strict_mode) {}

  ~StrictStaticSocketDataProvider() override {
    if (strict_mode_) {
      EXPECT_EQ(read_count(), read_index());
      EXPECT_EQ(write_count(), write_index());
    }
  }

 private:
  const bool strict_mode_;
};

// A fixture for tests which only perform normal socket operations.
class WebSocketBasicStreamSocketTest : public WebSocketBasicStreamTest {
 protected:
  WebSocketBasicStreamSocketTest()
      : pool_(1, 1, &factory_),
        generator_(&GenerateNulMaskingKey),
        expect_all_io_to_complete_(true) {}

  ~WebSocketBasicStreamSocketTest() override {
    // stream_ has a reference to socket_data_ (via MockTCPClientSocket) and so
    // should be destroyed first.
    stream_.reset();
  }

  std::unique_ptr<ClientSocketHandle> MakeTransportSocket(MockRead reads[],
                                                          size_t reads_count,
                                                          MockWrite writes[],
                                                          size_t writes_count) {
    socket_data_.reset(new StrictStaticSocketDataProvider(
        reads, reads_count, writes, writes_count, expect_all_io_to_complete_));
    socket_data_->set_connect_data(MockConnect(SYNCHRONOUS, OK));
    factory_.AddSocketDataProvider(socket_data_.get());

    std::unique_ptr<ClientSocketHandle> transport_socket(
        new ClientSocketHandle);
    scoped_refptr<MockTransportSocketParams> params;
    transport_socket->Init("a", params, MEDIUM,
                           ClientSocketPool::RespectLimits::ENABLED,
                           CompletionCallback(), &pool_, net_log_.bound());
    return transport_socket;
  }

  void SetHttpReadBuffer(const char* data, size_t size) {
    http_read_buffer_ = new GrowableIOBuffer;
    http_read_buffer_->SetCapacity(size);
    memcpy(http_read_buffer_->data(), data, size);
    http_read_buffer_->set_offset(size);
  }

  void CreateStream(MockRead reads[],
                    size_t reads_count,
                    MockWrite writes[],
                    size_t writes_count) {
    stream_ = WebSocketBasicStream::CreateWebSocketBasicStreamForTesting(
        MakeTransportSocket(reads, reads_count, writes, writes_count),
        http_read_buffer_,
        sub_protocol_,
        extensions_,
        generator_);
  }

  template <size_t N>
  void CreateReadOnly(MockRead (&reads)[N]) {
    CreateStream(reads, N, NULL, 0);
  }

  void CreateNullStream() { CreateStream(NULL, 0, NULL, 0); }

  std::unique_ptr<SocketDataProvider> socket_data_;
  MockClientSocketFactory factory_;
  MockTransportClientSocketPool pool_;
  BoundTestNetLog(net_log_);
  std::vector<std::unique_ptr<WebSocketFrame>> frames_;
  TestCompletionCallback cb_;
  scoped_refptr<GrowableIOBuffer> http_read_buffer_;
  std::string sub_protocol_;
  std::string extensions_;
  WebSocketBasicStream::WebSocketMaskingKeyGeneratorFunction generator_;
  bool expect_all_io_to_complete_;
};

// A test fixture for the common case of tests that only perform a single read.
class WebSocketBasicStreamSocketSingleReadTest
    : public WebSocketBasicStreamSocketTest {
 protected:
  void CreateRead(const MockRead& read) {
    reads_[0] = read;
    CreateStream(reads_, 1U, NULL, 0);
  }

  MockRead reads_[1];
};

// A test fixture for tests that perform chunked reads.
class WebSocketBasicStreamSocketChunkedReadTest
    : public WebSocketBasicStreamSocketTest {
 protected:
  // Specify the behaviour if there aren't enough chunks to use all the data. If
  // LAST_FRAME_BIG is specified, then the rest of the data will be
  // put in the last chunk. If LAST_FRAME_NOT_BIG is specified, then the last
  // frame will be no bigger than the rest of the frames (but it can be smaller,
  // if not enough data remains).
  enum LastFrameBehaviour {
    LAST_FRAME_BIG,
    LAST_FRAME_NOT_BIG
  };

  // Prepares a read from |data| of |data_size|, split into |number_of_chunks|,
  // each of |chunk_size| (except that the last chunk may be larger or
  // smaller). All reads must be either SYNCHRONOUS or ASYNC (not a mixture),
  // and errors cannot be simulated. Once data is exhausted, further reads will
  // return 0 (ie. connection closed).
  void CreateChunkedRead(IoMode mode,
                         const char data[],
                         size_t data_size,
                         int chunk_size,
                         int number_of_chunks,
                         LastFrameBehaviour last_frame_behaviour) {
    reads_.reset(new MockRead[number_of_chunks]);
    const char* start = data;
    for (int i = 0; i < number_of_chunks; ++i) {
      int len = chunk_size;
      const bool is_last_chunk = (i == number_of_chunks - 1);
      if ((last_frame_behaviour == LAST_FRAME_BIG && is_last_chunk) ||
          static_cast<int>(data + data_size - start) < len) {
        len = static_cast<int>(data + data_size - start);
      }
      reads_[i] = MockRead(mode, start, len);
      start += len;
    }
    CreateStream(reads_.get(), number_of_chunks, NULL, 0);
  }

  std::unique_ptr<MockRead[]> reads_;
};

// Test fixture for write tests.
class WebSocketBasicStreamSocketWriteTest
    : public WebSocketBasicStreamSocketTest {
 protected:
  // All write tests use the same frame, so it is easiest to create it during
  // test creation.
  void SetUp() override { PrepareWriteFrame(); }

  // Creates a WebSocketFrame with a wire format matching kWriteFrame and adds
  // it to |frames_|.
  void PrepareWriteFrame() {
    std::unique_ptr<WebSocketFrame> frame(
        new WebSocketFrame(WebSocketFrameHeader::kOpCodeText));
    const size_t payload_size =
        kWriteFrameSize - (WebSocketFrameHeader::kBaseHeaderSize +
                           WebSocketFrameHeader::kMaskingKeyLength);
    frame->data = new IOBuffer(payload_size);
    memcpy(frame->data->data(),
           kWriteFrame + kWriteFrameSize - payload_size,
           payload_size);
    WebSocketFrameHeader& header = frame->header;
    header.final = true;
    header.masked = true;
    header.payload_length = payload_size;
    frames_.push_back(std::move(frame));
  }

  // Creates a stream that expects the listed writes.
  template <size_t N>
  void CreateWriteOnly(MockWrite (&writes)[N]) {
    CreateStream(NULL, 0, writes, N);
  }
};

TEST_F(WebSocketBasicStreamSocketTest, ConstructionWorks) {
  CreateNullStream();
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncReadWorks) {
  CreateRead(MockRead(SYNCHRONOUS, kSampleFrame, kSampleFrameSize));
  int result = stream_->ReadFrames(&frames_, cb_.callback());
  EXPECT_THAT(result, IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
  EXPECT_TRUE(frames_[0]->header.final);
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncReadWorks) {
  CreateRead(MockRead(ASYNC, kSampleFrame, kSampleFrameSize));
  int result = stream_->ReadFrames(&frames_, cb_.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
  // Don't repeat all the tests from SyncReadWorks; just enough to be sure the
  // frame was really read.
}

// ReadFrames will not return a frame whose header has not been wholly received.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, HeaderFragmentedSync) {
  CreateChunkedRead(
      SYNCHRONOUS, kSampleFrame, kSampleFrameSize, 1, 2, LAST_FRAME_BIG);
  int result = stream_->ReadFrames(&frames_, cb_.callback());
  EXPECT_THAT(result, IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
}

// The same behaviour applies to asynchronous reads.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, HeaderFragmentedAsync) {
  CreateChunkedRead(
      ASYNC, kSampleFrame, kSampleFrameSize, 1, 2, LAST_FRAME_BIG);
  int result = stream_->ReadFrames(&frames_, cb_.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
}

// If it receives an incomplete header in a synchronous call, then has to wait
// for the rest of the frame, ReadFrames will return ERR_IO_PENDING.
TEST_F(WebSocketBasicStreamSocketTest, HeaderFragmentedSyncAsync) {
  MockRead reads[] = {MockRead(SYNCHRONOUS, kSampleFrame, 1),
                      MockRead(ASYNC, kSampleFrame + 1, kSampleFrameSize - 1)};
  CreateReadOnly(reads);
  int result = stream_->ReadFrames(&frames_, cb_.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
}

// An extended header should also return ERR_IO_PENDING if it is not completely
// received.
TEST_F(WebSocketBasicStreamSocketTest, FragmentedLargeHeader) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kPartialLargeFrame, kLargeFrameHeaderSize - 1),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  CreateReadOnly(reads);
  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
}

// A frame that does not arrive in a single read should be broken into separate
// frames.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, LargeFrameFirstChunk) {
  CreateRead(MockRead(SYNCHRONOUS, kPartialLargeFrame, kPartialLargeFrameSize));
  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_FALSE(frames_[0]->header.final);
  EXPECT_EQ(kPartialLargeFrameSize - kLargeFrameHeaderSize,
            static_cast<size_t>(frames_[0]->header.payload_length));
}

// If only the header of a data frame arrives, we should receive a frame with a
// zero-size payload.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, HeaderOnlyChunk) {
  CreateRead(MockRead(SYNCHRONOUS, kPartialLargeFrame, kLargeFrameHeaderSize));

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(NULL, frames_[0]->data.get());
  EXPECT_EQ(0U, frames_[0]->header.payload_length);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_[0]->header.opcode);
}

// If the header and the body of a data frame arrive seperately, we should see
// them as separate frames.
TEST_F(WebSocketBasicStreamSocketTest, HeaderBodySeparated) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kPartialLargeFrame, kLargeFrameHeaderSize),
      MockRead(ASYNC,
               kPartialLargeFrame + kLargeFrameHeaderSize,
               kPartialLargeFrameSize - kLargeFrameHeaderSize)};
  CreateReadOnly(reads);
  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(NULL, frames_[0]->data.get());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_[0]->header.opcode);
  frames_.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(kPartialLargeFrameSize - kLargeFrameHeaderSize,
            frames_[0]->header.payload_length);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
            frames_[0]->header.opcode);
}

// Every frame has a header with a correct payload_length field.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, LargeFrameTwoChunks) {
  const size_t kChunkSize = 16;
  CreateChunkedRead(ASYNC,
                    kPartialLargeFrame,
                    kPartialLargeFrameSize,
                    kChunkSize,
                    2,
                    LAST_FRAME_NOT_BIG);
  TestCompletionCallback cb[2];

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(kChunkSize - kLargeFrameHeaderSize,
            frames_[0]->header.payload_length);

  frames_.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[1].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[1].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(kChunkSize, frames_[0]->header.payload_length);
}

// Only the final frame of a fragmented message has |final| bit set.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, OnlyFinalChunkIsFinal) {
  static const size_t kFirstChunkSize = 4;
  CreateChunkedRead(ASYNC,
                    kSampleFrame,
                    kSampleFrameSize,
                    kFirstChunkSize,
                    2,
                    LAST_FRAME_BIG);
  TestCompletionCallback cb[2];

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  ASSERT_FALSE(frames_[0]->header.final);

  frames_.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[1].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[1].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  ASSERT_TRUE(frames_[0]->header.final);
}

// All frames after the first have their opcode changed to Continuation.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, ContinuationOpCodeUsed) {
  const size_t kFirstChunkSize = 3;
  const int kChunkCount = 3;
  // The input data is one frame with opcode Text, which arrives in three
  // separate chunks.
  CreateChunkedRead(ASYNC,
                    kSampleFrame,
                    kSampleFrameSize,
                    kFirstChunkSize,
                    kChunkCount,
                    LAST_FRAME_BIG);
  TestCompletionCallback cb[kChunkCount];

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_[0]->header.opcode);

  // This test uses a loop to verify that the opcode for every frames generated
  // after the first is converted to Continuation.
  for (int i = 1; i < kChunkCount; ++i) {
    frames_.clear();
    ASSERT_THAT(stream_->ReadFrames(&frames_, cb[i].callback()),
                IsError(ERR_IO_PENDING));
    EXPECT_THAT(cb[i].WaitForResult(), IsOk());
    ASSERT_EQ(1U, frames_.size());
    EXPECT_EQ(WebSocketFrameHeader::kOpCodeContinuation,
              frames_[0]->header.opcode);
  }
}

// Multiple frames that arrive together should be parsed correctly.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, ThreeFramesTogether) {
  CreateRead(MockRead(SYNCHRONOUS, kMultipleFrames, kMultipleFramesSize));

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(3U, frames_.size());
  EXPECT_TRUE(frames_[0]->header.final);
  EXPECT_TRUE(frames_[1]->header.final);
  EXPECT_TRUE(frames_[2]->header.final);
}

// ERR_CONNECTION_CLOSED must be returned on close.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncClose) {
  CreateRead(MockRead(SYNCHRONOUS, "", 0));

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->ReadFrames(&frames_, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncClose) {
  CreateRead(MockRead(ASYNC, "", 0));

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// The result should be the same if the socket returns
// ERR_CONNECTION_CLOSED. This is not expected to happen on an established
// connection; a Read of size 0 is the expected behaviour. The key point of this
// test is to confirm that ReadFrames() behaviour is identical in both cases.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncCloseWithErr) {
  CreateRead(MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED));

  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->ReadFrames(&frames_, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncCloseWithErr) {
  CreateRead(MockRead(ASYNC, ERR_CONNECTION_CLOSED));

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncErrorsPassedThrough) {
  // ERR_INSUFFICIENT_RESOURCES here represents an arbitrary error that
  // WebSocketBasicStream gives no special handling to.
  CreateRead(MockRead(SYNCHRONOUS, ERR_INSUFFICIENT_RESOURCES));

  EXPECT_EQ(ERR_INSUFFICIENT_RESOURCES,
            stream_->ReadFrames(&frames_, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncErrorsPassedThrough) {
  CreateRead(MockRead(ASYNC, ERR_INSUFFICIENT_RESOURCES));

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_INSUFFICIENT_RESOURCES));
}

// If we get a frame followed by a close, we should receive them separately.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, CloseAfterFrame) {
  // The chunk size equals the data size, so the second chunk is 0 size, closing
  // the connection.
  CreateChunkedRead(SYNCHRONOUS,
                    kSampleFrame,
                    kSampleFrameSize,
                    kSampleFrameSize,
                    2,
                    LAST_FRAME_NOT_BIG);

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames_.size());
  frames_.clear();
  EXPECT_EQ(ERR_CONNECTION_CLOSED,
            stream_->ReadFrames(&frames_, cb_.callback()));
}

// Synchronous close after an async frame header is handled by a different code
// path.
TEST_F(WebSocketBasicStreamSocketTest, AsyncCloseAfterIncompleteHeader) {
  MockRead reads[] = {MockRead(ASYNC, kSampleFrame, 1U),
                      MockRead(SYNCHRONOUS, "", 0)};
  CreateReadOnly(reads);

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// When Stream::Read returns ERR_CONNECTION_CLOSED we get the same result via a
// slightly different code path.
TEST_F(WebSocketBasicStreamSocketTest, AsyncErrCloseAfterIncompleteHeader) {
  MockRead reads[] = {MockRead(ASYNC, kSampleFrame, 1U),
                      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED)};
  CreateReadOnly(reads);

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// An empty first frame is not ignored.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, EmptyFirstFrame) {
  CreateRead(MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize));

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(NULL, frames_[0]->data.get());
  EXPECT_EQ(0U, frames_[0]->header.payload_length);
}

// An empty frame in the middle of a message is ignored.
TEST_F(WebSocketBasicStreamSocketTest, EmptyMiddleFrame) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize),
      MockRead(SYNCHRONOUS, kEmptyMiddleFrame, kEmptyMiddleFrameSize),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  CreateReadOnly(reads);

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames_.size());
  frames_.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
}

// An empty frame in the middle of a message that arrives separately is still
// ignored.
TEST_F(WebSocketBasicStreamSocketTest, EmptyMiddleFrameAsync) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize),
      MockRead(ASYNC, kEmptyMiddleFrame, kEmptyMiddleFrameSize),
      // We include a pong message to verify the middle frame was actually
      // processed.
      MockRead(ASYNC, kValidPong, kValidPongSize)};
  CreateReadOnly(reads);

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  EXPECT_EQ(1U, frames_.size());
  frames_.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodePong, frames_[0]->header.opcode);
}

// An empty final frame is not ignored.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, EmptyFinalFrame) {
  CreateRead(
      MockRead(SYNCHRONOUS, kEmptyFinalTextFrame, kEmptyFinalTextFrameSize));

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(NULL, frames_[0]->data.get());
  EXPECT_EQ(0U, frames_[0]->header.payload_length);
}

// An empty middle frame is ignored with a final frame present.
TEST_F(WebSocketBasicStreamSocketTest, ThreeFrameEmptyMessage) {
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kEmptyFirstFrame, kEmptyFirstFrameSize),
      MockRead(SYNCHRONOUS, kEmptyMiddleFrame, kEmptyMiddleFrameSize),
      MockRead(SYNCHRONOUS,
               kEmptyFinalContinuationFrame,
               kEmptyFinalContinuationFrameSize)};
  CreateReadOnly(reads);

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_[0]->header.opcode);
  frames_.clear();
  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_TRUE(frames_[0]->header.final);
}

// If there was a frame read at the same time as the response headers (and the
// handshake succeeded), then we should parse it.
TEST_F(WebSocketBasicStreamSocketTest, HttpReadBufferIsUsed) {
  SetHttpReadBuffer(kSampleFrame, kSampleFrameSize);
  CreateNullStream();

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  ASSERT_TRUE(frames_[0]->data.get());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
}

// Check that a frame whose header partially arrived at the end of the response
// headers works correctly.
TEST_F(WebSocketBasicStreamSocketSingleReadTest,
       PartialFrameHeaderInHttpResponse) {
  SetHttpReadBuffer(kSampleFrame, 1);
  CreateRead(MockRead(ASYNC, kSampleFrame + 1, kSampleFrameSize - 1));

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  ASSERT_TRUE(frames_[0]->data.get());
  EXPECT_EQ(UINT64_C(6), frames_[0]->header.payload_length);
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeText, frames_[0]->header.opcode);
}

// Check that a control frame which partially arrives at the end of the response
// headers works correctly.
TEST_F(WebSocketBasicStreamSocketSingleReadTest,
       PartialControlFrameInHttpResponse) {
  const size_t kPartialFrameBytes = 3;
  SetHttpReadBuffer(kCloseFrame, kPartialFrameBytes);
  CreateRead(MockRead(ASYNC,
                      kCloseFrame + kPartialFrameBytes,
                      kCloseFrameSize - kPartialFrameBytes));

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames_[0]->header.opcode);
  EXPECT_EQ(kCloseFrameSize - 2, frames_[0]->header.payload_length);
  EXPECT_EQ(
      0,
      memcmp(frames_[0]->data->data(), kCloseFrame + 2, kCloseFrameSize - 2));
}

// Check that a control frame which partially arrives at the end of the response
// headers works correctly. Synchronous version (unlikely in practice).
TEST_F(WebSocketBasicStreamSocketSingleReadTest,
       PartialControlFrameInHttpResponseSync) {
  const size_t kPartialFrameBytes = 3;
  SetHttpReadBuffer(kCloseFrame, kPartialFrameBytes);
  CreateRead(MockRead(SYNCHRONOUS,
                      kCloseFrame + kPartialFrameBytes,
                      kCloseFrameSize - kPartialFrameBytes));

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames_[0]->header.opcode);
}

// Check that an invalid frame results in an error.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, SyncInvalidFrame) {
  CreateRead(MockRead(SYNCHRONOUS, kInvalidFrame, kInvalidFrameSize));

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames_, cb_.callback()));
}

TEST_F(WebSocketBasicStreamSocketSingleReadTest, AsyncInvalidFrame) {
  CreateRead(MockRead(ASYNC, kInvalidFrame, kInvalidFrameSize));

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_WS_PROTOCOL_ERROR));
}

// A control frame without a FIN flag is invalid and should not be passed
// through to higher layers. RFC6455 5.5 "All control frames ... MUST NOT be
// fragmented."
TEST_F(WebSocketBasicStreamSocketSingleReadTest, ControlFrameWithoutFin) {
  CreateRead(
      MockRead(SYNCHRONOUS, kPingFrameWithoutFin, kPingFrameWithoutFinSize));

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames_, cb_.callback()));
  EXPECT_TRUE(frames_.empty());
}

// A control frame over 125 characters is invalid. RFC6455 5.5 "All control
// frames MUST have a payload length of 125 bytes or less". Since we use a
// 125-byte buffer to assemble fragmented control frames, we need to detect this
// error before attempting to assemble the fragments.
TEST_F(WebSocketBasicStreamSocketSingleReadTest, OverlongControlFrame) {
  CreateRead(MockRead(SYNCHRONOUS, k126BytePong, k126BytePongSize));

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames_, cb_.callback()));
  EXPECT_TRUE(frames_.empty());
}

// A control frame over 125 characters should still be rejected if it is split
// into multiple chunks.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, SplitOverlongControlFrame) {
  const size_t kFirstChunkSize = 16;
  expect_all_io_to_complete_ = false;
  CreateChunkedRead(SYNCHRONOUS,
                    k126BytePong,
                    k126BytePongSize,
                    kFirstChunkSize,
                    2,
                    LAST_FRAME_BIG);

  EXPECT_EQ(ERR_WS_PROTOCOL_ERROR,
            stream_->ReadFrames(&frames_, cb_.callback()));
  EXPECT_TRUE(frames_.empty());
}

TEST_F(WebSocketBasicStreamSocketChunkedReadTest,
       AsyncSplitOverlongControlFrame) {
  const size_t kFirstChunkSize = 16;
  expect_all_io_to_complete_ = false;
  CreateChunkedRead(ASYNC,
                    k126BytePong,
                    k126BytePongSize,
                    kFirstChunkSize,
                    2,
                    LAST_FRAME_BIG);

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsError(ERR_WS_PROTOCOL_ERROR));
  // The caller should not call ReadFrames() again after receiving an error
  // other than ERR_IO_PENDING.
  EXPECT_TRUE(frames_.empty());
}

// In the synchronous case, ReadFrames assembles the whole control frame before
// returning.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, SyncControlFrameAssembly) {
  const size_t kChunkSize = 3;
  CreateChunkedRead(
      SYNCHRONOUS, kCloseFrame, kCloseFrameSize, kChunkSize, 3, LAST_FRAME_BIG);

  EXPECT_THAT(stream_->ReadFrames(&frames_, cb_.callback()), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames_[0]->header.opcode);
}

// In the asynchronous case, the callback is not called until the control frame
// has been completely assembled.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, AsyncControlFrameAssembly) {
  const size_t kChunkSize = 3;
  CreateChunkedRead(
      ASYNC, kCloseFrame, kCloseFrameSize, kChunkSize, 3, LAST_FRAME_BIG);

  ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_EQ(WebSocketFrameHeader::kOpCodeClose, frames_[0]->header.opcode);
}

// A frame with a 1MB payload that has to be read in chunks.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, OneMegFrame) {
  // This should be equal to the definition of kReadBufferSize in
  // websocket_basic_stream.cc.
  const int kReadBufferSize = 32 * 1024;
  const uint64_t kPayloadSize = 1 << 20;
  const size_t kWireSize = kPayloadSize + kLargeFrameHeaderSize;
  const size_t kExpectedFrameCount =
      (kWireSize + kReadBufferSize - 1) / kReadBufferSize;
  std::unique_ptr<char[]> big_frame(new char[kWireSize]);
  memcpy(big_frame.get(), "\x81\x7F", 2);
  base::WriteBigEndian(big_frame.get() + 2, kPayloadSize);
  memset(big_frame.get() + kLargeFrameHeaderSize, 'A', kPayloadSize);

  CreateChunkedRead(ASYNC,
                    big_frame.get(),
                    kWireSize,
                    kReadBufferSize,
                    kExpectedFrameCount,
                    LAST_FRAME_BIG);

  for (size_t frame = 0; frame < kExpectedFrameCount; ++frame) {
    frames_.clear();
    ASSERT_THAT(stream_->ReadFrames(&frames_, cb_.callback()),
                IsError(ERR_IO_PENDING));
    EXPECT_THAT(cb_.WaitForResult(), IsOk());
    ASSERT_EQ(1U, frames_.size());
    size_t expected_payload_size = kReadBufferSize;
    if (frame == 0) {
      expected_payload_size = kReadBufferSize - kLargeFrameHeaderSize;
    } else if (frame == kExpectedFrameCount - 1) {
      expected_payload_size = kLargeFrameHeaderSize;
    }
    EXPECT_EQ(expected_payload_size, frames_[0]->header.payload_length);
  }
}

// A frame with reserved flag(s) set that arrives in chunks should only have the
// reserved flag(s) set on the first chunk when split.
TEST_F(WebSocketBasicStreamSocketChunkedReadTest, ReservedFlagCleared) {
  static const char kReservedFlagFrame[] = "\x41\x05Hello";
  const size_t kReservedFlagFrameSize = arraysize(kReservedFlagFrame) - 1;
  const size_t kChunkSize = 5;

  CreateChunkedRead(ASYNC,
                    kReservedFlagFrame,
                    kReservedFlagFrameSize,
                    kChunkSize,
                    2,
                    LAST_FRAME_BIG);

  TestCompletionCallback cb[2];
  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[0].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[0].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_TRUE(frames_[0]->header.reserved1);

  frames_.clear();
  ASSERT_THAT(stream_->ReadFrames(&frames_, cb[1].callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb[1].WaitForResult(), IsOk());
  ASSERT_EQ(1U, frames_.size());
  EXPECT_FALSE(frames_[0]->header.reserved1);
}

// Check that writing a frame all at once works.
TEST_F(WebSocketBasicStreamSocketWriteTest, WriteAtOnce) {
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, kWriteFrame, kWriteFrameSize)};
  CreateWriteOnly(writes);

  EXPECT_THAT(stream_->WriteFrames(&frames_, cb_.callback()), IsOk());
}

// Check that completely async writing works.
TEST_F(WebSocketBasicStreamSocketWriteTest, AsyncWriteAtOnce) {
  MockWrite writes[] = {MockWrite(ASYNC, kWriteFrame, kWriteFrameSize)};
  CreateWriteOnly(writes);

  ASSERT_THAT(stream_->WriteFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
}

// Check that writing a frame to an extremely full kernel buffer (so that it
// ends up being sent in bits) works. The WriteFrames() callback should not be
// called until all parts have been written.
TEST_F(WebSocketBasicStreamSocketWriteTest, WriteInBits) {
  MockWrite writes[] = {MockWrite(SYNCHRONOUS, kWriteFrame, 4),
                        MockWrite(ASYNC, kWriteFrame + 4, 4),
                        MockWrite(ASYNC, kWriteFrame + 8, kWriteFrameSize - 8)};
  CreateWriteOnly(writes);

  ASSERT_THAT(stream_->WriteFrames(&frames_, cb_.callback()),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(cb_.WaitForResult(), IsOk());
}

// Check that writing a Pong frame with a NULL body works.
TEST_F(WebSocketBasicStreamSocketWriteTest, WriteNullPong) {
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kMaskedEmptyPong, kMaskedEmptyPongSize)};
  CreateWriteOnly(writes);

  std::unique_ptr<WebSocketFrame> frame(
      new WebSocketFrame(WebSocketFrameHeader::kOpCodePong));
  WebSocketFrameHeader& header = frame->header;
  header.final = true;
  header.masked = true;
  header.payload_length = 0;
  std::vector<std::unique_ptr<WebSocketFrame>> frames;
  frames.push_back(std::move(frame));
  EXPECT_THAT(stream_->WriteFrames(&frames, cb_.callback()), IsOk());
}

// Check that writing with a non-NULL mask works correctly.
TEST_F(WebSocketBasicStreamSocketTest, WriteNonNulMask) {
  std::string masked_frame = std::string("\x81\x88");
  masked_frame += std::string(kNonNulMaskingKey.key, 4);
  masked_frame += "jiggered";
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, masked_frame.data(), masked_frame.size())};
  generator_ = &GenerateNonNulMaskingKey;
  CreateStream(NULL, 0, writes, arraysize(writes));

  std::unique_ptr<WebSocketFrame> frame(
      new WebSocketFrame(WebSocketFrameHeader::kOpCodeText));
  const std::string unmasked_payload = "graphics";
  const size_t payload_size = unmasked_payload.size();
  frame->data = new IOBuffer(payload_size);
  memcpy(frame->data->data(), unmasked_payload.data(), payload_size);
  WebSocketFrameHeader& header = frame->header;
  header.final = true;
  header.masked = true;
  header.payload_length = payload_size;
  frames_.push_back(std::move(frame));

  EXPECT_THAT(stream_->WriteFrames(&frames_, cb_.callback()), IsOk());
}

TEST_F(WebSocketBasicStreamSocketTest, GetExtensionsWorks) {
  extensions_ = "inflate-uuencode";
  CreateNullStream();

  EXPECT_EQ("inflate-uuencode", stream_->GetExtensions());
}

TEST_F(WebSocketBasicStreamSocketTest, GetSubProtocolWorks) {
  sub_protocol_ = "cyberchat";
  CreateNullStream();

  EXPECT_EQ("cyberchat", stream_->GetSubProtocol());
}

}  // namespace
}  // namespace net
