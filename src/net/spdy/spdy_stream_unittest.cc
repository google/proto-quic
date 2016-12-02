// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_stream.h"

#include <stdint.h>

#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/strings/string_piece.h"
#include "net/base/completion_callback.h"
#include "net/base/request_priority.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_stream_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

// TODO(ukai): factor out common part with spdy_http_stream_unittest.cc
//
namespace net {

namespace test {

namespace {

const char kPushUrl[] = "https://www.example.org/push";
const char kPostBody[] = "\0hello!\xff";
const size_t kPostBodyLength = arraysize(kPostBody);
const base::StringPiece kPostBodyStringPiece(kPostBody, kPostBodyLength);

static base::TimeTicks g_time_now;

base::TimeTicks InstantaneousReads() {
  return g_time_now;
}

}  // namespace

class SpdyStreamTest : public ::testing::Test {
 protected:
  // A function that takes a SpdyStream and the number of bytes which
  // will unstall the next frame completely.
  typedef base::Callback<void(const base::WeakPtr<SpdyStream>&, int32_t)>
      UnstallFunction;

  SpdyStreamTest()
      : url_(kDefaultUrl),
        session_(SpdySessionDependencies::SpdyCreateSession(&session_deps_)),
        offset_(0),
        ssl_(SYNCHRONOUS, OK) {}

  ~SpdyStreamTest() override {}

  base::WeakPtr<SpdySession> CreateDefaultSpdySession() {
    SpdySessionKey key(HostPortPair::FromURL(url_), ProxyServer::Direct(),
                       PRIVACY_MODE_DISABLED);
    return CreateSecureSpdySession(session_.get(), key, NetLogWithSource());
  }

  void TearDown() override { base::RunLoop().RunUntilIdle(); }

  void RunResumeAfterUnstallRequestResponseTest(
      const UnstallFunction& unstall_function);

  void RunResumeAfterUnstallBidirectionalTest(
      const UnstallFunction& unstall_function);

  // Add{Read,Write}() populates lists that are eventually passed to a
  // SocketData class. |frame| must live for the whole test.

  void AddRead(const SpdySerializedFrame& frame) {
    reads_.push_back(CreateMockRead(frame, offset_++));
  }

  void AddWrite(const SpdySerializedFrame& frame) {
    writes_.push_back(CreateMockWrite(frame, offset_++));
  }

  void AddReadEOF() {
    reads_.push_back(MockRead(ASYNC, 0, offset_++));
  }

  void AddWritePause() {
    writes_.push_back(MockWrite(ASYNC, ERR_IO_PENDING, offset_++));
  }

  void AddReadPause() {
    reads_.push_back(MockRead(ASYNC, ERR_IO_PENDING, offset_++));
  }

  MockRead* GetReads() { return reads_.data(); }

  size_t GetNumReads() const {
    return reads_.size();
  }

  MockWrite* GetWrites() { return writes_.data(); }

  int GetNumWrites() const {
    return writes_.size();
  }

  void ActivatePushStream(SpdySession* session, SpdyStream* stream) {
    std::unique_ptr<SpdyStream> activated =
        session->ActivateCreatedStream(stream);
    activated->set_stream_id(2);
    session->InsertActivatedStream(std::move(activated));
  }

  void AddSSLSocketData() {
    // Load a cert that is valid for
    // www.example.org, mail.example.org, and mail.example.com.
    ssl_.cert = ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  const GURL url_;
  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;

 private:
  // Used by Add{Read,Write}() above.
  std::vector<MockWrite> writes_;
  std::vector<MockRead> reads_;
  int offset_;
  SSLSocketDataProvider ssl_;
};

TEST_F(SpdyStreamTest, SendDataAfterOpen) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddWrite(msg);

  SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(echo);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Delegate that receives trailers.
class StreamDelegateWithTrailers : public test::StreamDelegateWithBody {
 public:
  StreamDelegateWithTrailers(const base::WeakPtr<SpdyStream>& stream,
                             base::StringPiece data)
      : StreamDelegateWithBody(stream, data) {}

  ~StreamDelegateWithTrailers() override {}

  void OnTrailers(const SpdyHeaderBlock& trailers) override {
    trailers_ = trailers.Clone();
  }

  const SpdyHeaderBlock& trailers() const { return trailers_; }

 private:
  SpdyHeaderBlock trailers_;
};

// Regression test for https://crbug.com/481033.
TEST_F(SpdyStreamTest, Trailers) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, true));
  AddWrite(msg);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(echo);

  SpdyHeaderBlock late_headers;
  late_headers["foo"] = "bar";
  SpdySerializedFrame trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(late_headers), false));
  AddRead(trailers);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateWithTrailers delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  const SpdyHeaderBlock& received_trailers = delegate.trailers();
  SpdyHeaderBlock::const_iterator it = received_trailers.find("foo");
  EXPECT_EQ("bar", it->second);
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, PushedStream) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPush(nullptr, 0, 2, 1, kPushUrl));
  AddRead(push);

  AddReadPause();

  base::StringPiece pushed_msg("foo");
  SpdySerializedFrame pushed_body(spdy_util_.ConstructSpdyDataFrame(
      2, pushed_msg.data(), pushed_msg.size(), true));
  AddRead(pushed_body);

  base::StringPiece msg("bar");
  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, msg.data(), msg.size(), true));
  AddRead(body);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  g_time_now = base::TimeTicks::Now();
  session_deps_.time_func = InstantaneousReads;
  session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  data.RunUntilPaused();

  base::WeakPtr<SpdyStream> push_stream;
  EXPECT_THAT(
      session->GetPushStream(GURL(kPushUrl), &push_stream, NetLogWithSource()),
      IsOk());
  ASSERT_TRUE(push_stream);
  EXPECT_EQ(kPushUrl, push_stream->GetUrlFromHeaders().spec());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(push_stream->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(g_time_now, load_timing_info.push_start);
  EXPECT_TRUE(load_timing_info.push_end.is_null());

  StreamDelegateDoNothing push_delegate(push_stream);
  push_stream->SetDelegate(&push_delegate);

  data.Resume();

  EXPECT_TRUE(push_stream->GetLoadTimingInfo(&load_timing_info));
  EXPECT_EQ(g_time_now, load_timing_info.push_start);
  EXPECT_FALSE(load_timing_info.push_end.is_null());

  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(msg, delegate.TakeReceivedData());

  EXPECT_THAT(push_delegate.WaitForClose(), IsOk());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(pushed_msg, push_delegate.TakeReceivedData());
}

TEST_F(SpdyStreamTest, StreamError) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddWrite(msg);

  SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(echo);

  AddReadEOF();

  BoundTestNetLog log;

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, log.bound());
  ASSERT_TRUE(stream);

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  const SpdyStreamId stream_id = delegate.stream_id();

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Check that the NetLog was filled reasonably.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  EXPECT_LT(0u, entries.size());

  // Check that we logged SPDY_STREAM_ERROR correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_STREAM_ERROR, NetLogEventPhase::NONE);

  int stream_id2;
  ASSERT_TRUE(entries[pos].GetIntegerValue("stream_id", &stream_id2));
  EXPECT_EQ(static_cast<int>(stream_id), stream_id2);
}

// Make sure that large blocks of data are properly split up into frame-sized
// chunks for a request/response (i.e., an HTTP-like) stream.
TEST_F(SpdyStreamTest, SendLargeDataAfterOpenRequestResponse) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  SpdySerializedFrame chunk(spdy_util_.ConstructSpdyDataFrame(
      1, chunk_data.data(), chunk_data.length(), false));
  AddWrite(chunk);
  AddWrite(chunk);

  SpdySerializedFrame last_chunk(spdy_util_.ConstructSpdyDataFrame(
      1, chunk_data.data(), chunk_data.length(), true));
  AddWrite(last_chunk);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  std::string body_data(3 * kMaxSpdyFrameChunkSize, 'x');
  StreamDelegateWithBody delegate(stream, body_data);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Make sure that large blocks of data are properly split up into frame-sized
// chunks for a bidirectional (i.e., non-HTTP-like) stream.
TEST_F(SpdyStreamTest, SendLargeDataAfterOpenBidirectional) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  AddRead(resp);

  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  SpdySerializedFrame chunk(spdy_util_.ConstructSpdyDataFrame(
      1, chunk_data.data(), chunk_data.length(), false));
  AddWrite(chunk);
  AddWrite(chunk);
  AddWrite(chunk);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  std::string body_data(3 * kMaxSpdyFrameChunkSize, 'x');
  StreamDelegateSendImmediate delegate(stream, body_data);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Receiving a header with uppercase ASCII should result in a protocol error.
TEST_F(SpdyStreamTest, UpperCaseHeaders) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(
      kExtraHeaders, arraysize(kExtraHeaders) / 2, 1));
  AddRead(reply);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_PROTOCOL_ERROR));

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Receiving a header with uppercase ASCII should result in a protocol error
// even for a push stream.
TEST_F(SpdyStreamTest, UpperCaseHeadersOnPush) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  SpdySerializedFrame push(spdy_util_.ConstructSpdyPush(
      kExtraHeaders, arraysize(kExtraHeaders) / 2, 2, 1, kPushUrl));
  AddRead(push);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadPause();

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  data.RunUntilPaused();

  base::WeakPtr<SpdyStream> push_stream;
  EXPECT_THAT(
      session->GetPushStream(GURL(kPushUrl), &push_stream, NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(push_stream);

  data.Resume();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, HeadersMustHaveStatus) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  // Response headers without ":status" header field: protocol error.
  SpdyHeaderBlock header_block_without_status;
  header_block_without_status[spdy_util_.GetMethodKey()] = "GET";
  header_block_without_status[spdy_util_.GetHostKey()] = "www.example.org";
  header_block_without_status[spdy_util_.GetSchemeKey()] = "https";
  header_block_without_status[spdy_util_.GetPathKey()] = "/";
  SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyReply(1, std::move(header_block_without_status)));
  AddRead(reply);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_PROTOCOL_ERROR));

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, HeadersMustHaveStatusOnPushedStream) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  SpdySerializedFrame push_promise(spdy_util_.ConstructInitialSpdyPushFrame(
      spdy_util_.ConstructGetHeaderBlock(kPushUrl), 2, 1));
  AddRead(push_promise);

  // Response headers without ":status" header field: protocol error.
  SpdyHeaderBlock header_block_without_status;
  header_block_without_status[spdy_util_.GetMethodKey()] = "GET";
  header_block_without_status[spdy_util_.GetHostKey()] = "www.example.org";
  header_block_without_status[spdy_util_.GetSchemeKey()] = "https";
  header_block_without_status[spdy_util_.GetPathKey()] = "/";
  SpdySerializedFrame pushed_reply(
      spdy_util_.ConstructSpdyReply(2, std::move(header_block_without_status)));
  AddRead(pushed_reply);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, true));
  AddRead(body);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, HeadersMustPreceedData) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  // Response body not preceeded by headers: protocol error.
  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, true));
  AddRead(body);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_PROTOCOL_ERROR));
}

TEST_F(SpdyStreamTest, HeadersMustPreceedDataOnPushedStream) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  SpdySerializedFrame push_promise(spdy_util_.ConstructInitialSpdyPushFrame(
      spdy_util_.ConstructGetHeaderBlock(kPushUrl), 2, 1));
  AddRead(push_promise);

  SpdySerializedFrame pushed_body(
      spdy_util_.ConstructSpdyDataFrame(2, kPostBody, kPostBodyLength, true));
  AddRead(pushed_body);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, true));
  AddRead(body);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(spdy_util_.GetStatusKey()));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, TrailersMustNotFollowTrailers) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(body);

  SpdyHeaderBlock trailers_block;
  trailers_block["foo"] = "bar";
  SpdySerializedFrame first_trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(trailers_block), false));
  AddRead(first_trailers);

  // Trailers following trailers: procotol error.
  SpdySerializedFrame second_trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(trailers_block), true));
  AddRead(second_trailers);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_PROTOCOL_ERROR));

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdyStreamTest, DataMustNotFollowTrailers) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(body);

  SpdyHeaderBlock trailers_block;
  trailers_block["foo"] = "bar";
  SpdySerializedFrame trailers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(trailers_block), false));
  AddRead(trailers);

  // DATA frame following trailers: protocol error.
  AddRead(body);

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, stream->SendRequestHeaders(std::move(headers),
                                                       NO_MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_PROTOCOL_ERROR));

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Call IncreaseSendWindowSize on a stream with a large enough delta to overflow
// an int32_t. The SpdyStream should handle that case gracefully.
TEST_F(SpdyStreamTest, IncreaseSendWindowSizeOverflow) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  AddReadPause();

  // Triggered by the overflowing call to IncreaseSendWindowSize
  // below.
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_FLOW_CONTROL_ERROR));
  AddWrite(rst);

  AddReadEOF();

  BoundTestNetLog log;

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, log.bound());
  ASSERT_TRUE(stream);
  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  data.RunUntilPaused();

  int32_t old_send_window_size = stream->send_window_size();
  ASSERT_GT(old_send_window_size, 0);
  int32_t delta_window_size =
      std::numeric_limits<int32_t>::max() - old_send_window_size + 1;
  stream->IncreaseSendWindowSize(delta_window_size);
  EXPECT_FALSE(stream);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_PROTOCOL_ERROR));
}

// Functions used with
// RunResumeAfterUnstall{RequestResponse,Bidirectional}Test().

void StallStream(const base::WeakPtr<SpdyStream>& stream) {
  // Reduce the send window size to 0 to stall.
  while (stream->send_window_size() > 0) {
    stream->DecreaseSendWindowSize(
        std::min(kMaxSpdyFrameChunkSize, stream->send_window_size()));
  }
}

void IncreaseStreamSendWindowSize(const base::WeakPtr<SpdyStream>& stream,
                                  int32_t delta_window_size) {
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  stream->IncreaseSendWindowSize(delta_window_size);
  EXPECT_FALSE(stream->send_stalled_by_flow_control());
}

void AdjustStreamSendWindowSize(const base::WeakPtr<SpdyStream>& stream,
                                int32_t delta_window_size) {
  // Make sure that negative adjustments are handled properly.
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  stream->AdjustSendWindowSize(-delta_window_size);
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  stream->AdjustSendWindowSize(+delta_window_size);
  EXPECT_TRUE(stream->send_stalled_by_flow_control());
  stream->AdjustSendWindowSize(+delta_window_size);
  EXPECT_FALSE(stream->send_stalled_by_flow_control());
}

// Given an unstall function, runs a test to make sure that a
// request/response (i.e., an HTTP-like) stream resumes after a stall
// and unstall.
void SpdyStreamTest::RunResumeAfterUnstallRequestResponseTest(
    const UnstallFunction& unstall_function) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, true));
  AddWrite(body);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateWithBody delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());
  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  StallStream(stream);

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream->send_stalled_by_flow_control());

  unstall_function.Run(stream, kPostBodyLength);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeIncreaseRequestResponse) {
  RunResumeAfterUnstallRequestResponseTest(
      base::Bind(&IncreaseStreamSendWindowSize));
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeAdjustRequestResponse) {
  RunResumeAfterUnstallRequestResponseTest(
      base::Bind(&AdjustStreamSendWindowSize));
}

// Given an unstall function, runs a test to make sure that a bidirectional
// (i.e., non-HTTP-like) stream resumes after a stall and unstall.
void SpdyStreamTest::RunResumeAfterUnstallBidirectionalTest(
    const UnstallFunction& unstall_function) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kPostBodyLength, LOWEST, nullptr, 0));
  AddWrite(req);

  AddReadPause();

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(resp);

  SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddWrite(msg);

  SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(echo);

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateSendImmediate delegate(stream, kPostBodyStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kPostBodyLength));
  EXPECT_THAT(stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND),
              IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  data.RunUntilPaused();

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  StallStream(stream);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream->send_stalled_by_flow_control());

  unstall_function.Run(stream, kPostBodyLength);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(kPostBody, kPostBodyLength),
            delegate.TakeReceivedData());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeIncreaseBidirectional) {
  RunResumeAfterUnstallBidirectionalTest(
      base::Bind(&IncreaseStreamSendWindowSize));
}

TEST_F(SpdyStreamTest, ResumeAfterSendWindowSizeAdjustBidirectional) {
  RunResumeAfterUnstallBidirectionalTest(
      base::Bind(&AdjustStreamSendWindowSize));
}

// Test calculation of amount of bytes received from network.
TEST_F(SpdyStreamTest, ReceivedBytes) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  AddWrite(req);

  AddReadPause();

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  AddRead(reply);

  AddReadPause();

  SpdySerializedFrame msg(
      spdy_util_.ConstructSpdyDataFrame(1, kPostBody, kPostBodyLength, false));
  AddRead(msg);

  AddReadPause();

  AddReadEOF();

  SequencedSocketData data(GetReads(), GetNumReads(), GetWrites(),
                           GetNumWrites());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session(CreateDefaultSpdySession());

  base::WeakPtr<SpdyStream> stream = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session, url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);

  EXPECT_TRUE(stream->GetUrlFromHeaders().is_empty());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_THAT(
      stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND),
      IsError(ERR_IO_PENDING));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  int64_t reply_frame_len = reply.size();
  int64_t data_header_len = SpdyConstants::kDataFrameMinimumSize;
  int64_t data_frame_len = data_header_len + kPostBodyLength;
  int64_t response_len = reply_frame_len + data_frame_len;

  EXPECT_EQ(0, stream->raw_received_bytes());

  // REQUEST
  data.RunUntilPaused();
  EXPECT_EQ(0, stream->raw_received_bytes());

  // REPLY
  data.Resume();
  data.RunUntilPaused();
  EXPECT_EQ(reply_frame_len, stream->raw_received_bytes());

  // DATA
  data.Resume();
  data.RunUntilPaused();
  EXPECT_EQ(response_len, stream->raw_received_bytes());

  // FIN
  data.Resume();
  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
}

}  // namespace test

}  // namespace net
