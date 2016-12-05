// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_session.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/base64.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/run_loop.h"
#include "base/test/histogram_tester.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/proxy_delegate.h"
#include "net/base/request_priority.h"
#include "net/base/test_data_stream.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/ct_policy_status.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/proxy_server.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_session_test_util.h"
#include "net/spdy/spdy_stream.h"
#include "net/spdy/spdy_stream_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;
using net::test::TestServerPushDelegate;

namespace net {

namespace {

const char kHttpURLFromAnotherOrigin[] = "http://www.example2.org/a.dat";
const char kHttpsURLFromAnotherOrigin[] = "https://www.example2.org/b.dat";

const char kBodyData[] = "Body data";
const size_t kBodyDataSize = arraysize(kBodyData);
const base::StringPiece kBodyDataStringPiece(kBodyData, kBodyDataSize);

static base::TimeDelta g_time_delta;
static base::TimeTicks g_time_now;

base::TimeTicks TheNearFuture() {
  return base::TimeTicks::Now() + g_time_delta;
}

base::TimeTicks SlowReads() {
  g_time_delta +=
      base::TimeDelta::FromMilliseconds(2 * kYieldAfterDurationMilliseconds);
  return base::TimeTicks::Now() + g_time_delta;
}

base::TimeTicks InstantaneousReads() {
  return g_time_now;
}

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD1(IsCTRequiredForHost,
               CTRequirementLevel(const std::string& host));
};

}  // namespace

class SpdySessionTest : public PlatformTest {
 public:
  // Functions used with RunResumeAfterUnstallTest().

  void StallSessionOnly(SpdyStream* stream) { StallSessionSend(); }

  void StallStreamOnly(SpdyStream* stream) { StallStreamSend(stream); }

  void StallSessionStream(SpdyStream* stream) {
    StallSessionSend();
    StallStreamSend(stream);
  }

  void StallStreamSession(SpdyStream* stream) {
    StallStreamSend(stream);
    StallSessionSend();
  }

  void UnstallSessionOnly(SpdyStream* stream, int32_t delta_window_size) {
    UnstallSessionSend(delta_window_size);
  }

  void UnstallStreamOnly(SpdyStream* stream, int32_t delta_window_size) {
    UnstallStreamSend(stream, delta_window_size);
  }

  void UnstallSessionStream(SpdyStream* stream, int32_t delta_window_size) {
    UnstallSessionSend(delta_window_size);
    UnstallStreamSend(stream, delta_window_size);
  }

  void UnstallStreamSession(SpdyStream* stream, int32_t delta_window_size) {
    UnstallStreamSend(stream, delta_window_size);
    UnstallSessionSend(delta_window_size);
  }

 protected:
  SpdySessionTest()
      : old_max_group_sockets_(ClientSocketPoolManager::max_sockets_per_group(
            HttpNetworkSession::NORMAL_SOCKET_POOL)),
        old_max_pool_sockets_(ClientSocketPoolManager::max_sockets_per_pool(
            HttpNetworkSession::NORMAL_SOCKET_POOL)),
        spdy_session_pool_(nullptr),
        test_url_(kDefaultUrl),
        test_server_(test_url_),
        key_(HostPortPair::FromURL(test_url_),
             ProxyServer::Direct(),
             PRIVACY_MODE_DISABLED),
        ssl_(SYNCHRONOUS, OK) {}

  ~SpdySessionTest() override {
    // Important to restore the per-pool limit first, since the pool limit must
    // always be greater than group limit, and the tests reduce both limits.
    ClientSocketPoolManager::set_max_sockets_per_pool(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_pool_sockets_);
    ClientSocketPoolManager::set_max_sockets_per_group(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_group_sockets_);
  }

  void SetUp() override {
    g_time_delta = base::TimeDelta();
    g_time_now = base::TimeTicks::Now();
    session_deps_.net_log = log_.bound().net_log();
  }

  void CreateNetworkSession() {
    DCHECK(!http_session_);
    DCHECK(!spdy_session_pool_);
    http_session_ =
        SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    spdy_session_pool_ = http_session_->spdy_session_pool();
  }

  void CreateInsecureSpdySession() {
    DCHECK(!session_);
    session_ = ::net::CreateInsecureSpdySession(http_session_.get(), key_,
                                                log_.bound());
  }

  void AddSSLSocketData() {
    ssl_.cert = ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  void CreateSecureSpdySession() {
    DCHECK(!session_);
    session_ =
        ::net::CreateSecureSpdySession(http_session_.get(), key_, log_.bound());
  }

  void StallSessionSend() {
    // Reduce the send window size to 0 to stall.
    while (session_->session_send_window_size_ > 0) {
      session_->DecreaseSendWindowSize(std::min(
          kMaxSpdyFrameChunkSize, session_->session_send_window_size_));
    }
  }

  void UnstallSessionSend(int32_t delta_window_size) {
    session_->IncreaseSendWindowSize(delta_window_size);
  }

  void StallStreamSend(SpdyStream* stream) {
    // Reduce the send window size to 0 to stall.
    while (stream->send_window_size() > 0) {
      stream->DecreaseSendWindowSize(
          std::min(kMaxSpdyFrameChunkSize, stream->send_window_size()));
    }
  }

  void UnstallStreamSend(SpdyStream* stream, int32_t delta_window_size) {
    stream->IncreaseSendWindowSize(delta_window_size);
  }

  void RunResumeAfterUnstallTest(
      const base::Callback<void(SpdyStream*)>& stall_function,
      const base::Callback<void(SpdyStream*, int32_t)>& unstall_function);

  // Original socket limits.  Some tests set these.  Safest to always restore
  // them once each test has been run.
  int old_max_group_sockets_;
  int old_max_pool_sockets_;

  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> http_session_;
  base::WeakPtr<SpdySession> session_;
  TestServerPushDelegate test_push_delegate_;
  SpdySessionPool* spdy_session_pool_;
  const GURL test_url_;
  const url::SchemeHostPort test_server_;
  SpdySessionKey key_;
  SSLSocketDataProvider ssl_;
  BoundTestNetLog log_;
};

// Try to create a SPDY session that will fail during
// initialization. Nothing should blow up.
TEST_F(SpdySessionTest, InitialReadError) {
  CreateNetworkSession();

  session_ = TryCreateFakeSpdySessionExpectingFailure(spdy_session_pool_, key_,
                                                      ERR_CONNECTION_CLOSED);
  EXPECT_TRUE(session_);
  // Flush the read.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

namespace {

// A helper class that vends a callback that, when fired, destroys a
// given SpdyStreamRequest.
class StreamRequestDestroyingCallback : public TestCompletionCallbackBase {
 public:
  StreamRequestDestroyingCallback() {}

  ~StreamRequestDestroyingCallback() override {}

  void SetRequestToDestroy(std::unique_ptr<SpdyStreamRequest> request) {
    request_ = std::move(request);
  }

  CompletionCallback MakeCallback() {
    return base::Bind(&StreamRequestDestroyingCallback::OnComplete,
                      base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    request_.reset();
    SetResult(result);
  }

  std::unique_ptr<SpdyStreamRequest> request_;
};

}  // namespace

// Request kInitialMaxConcurrentStreams streams.  Request two more
// streams, but have the callback for one destroy the second stream
// request. Close the session. Nothing should blow up. This is a
// regression test for http://crbug.com/250841 .
TEST_F(SpdySessionTest, PendingStreamCancellingAnother) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {MockRead(ASYNC, 0, 0), };

  SequencedSocketData data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Create the maximum number of concurrent streams.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  SpdyStreamRequest request1;
  std::unique_ptr<SpdyStreamRequest> request2(new SpdyStreamRequest);

  StreamRequestDestroyingCallback callback1;
  ASSERT_EQ(ERR_IO_PENDING,
            request1.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource(),
                                  callback1.MakeCallback()));

  // |callback2| is never called.
  TestCompletionCallback callback2;
  ASSERT_EQ(
      ERR_IO_PENDING,
      request2->StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                             MEDIUM, NetLogWithSource(), callback2.callback()));

  callback1.SetRequestToDestroy(std::move(request2));

  session_->CloseSessionOnError(ERR_ABORTED, "Aborting session");

  EXPECT_THAT(callback1.WaitForResult(), IsError(ERR_ABORTED));
}

// A session receiving a GOAWAY frame with no active streams should close.
TEST_F(SpdySessionTest, GoAwayWithNoActiveStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      CreateMockRead(goaway, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);
}

// A session receiving a GOAWAY frame immediately with no active
// streams should then close.
TEST_F(SpdySessionTest, GoAwayImmediatelyWithNoActiveStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      CreateMockRead(goaway, 0, SYNCHRONOUS), MockRead(ASYNC, 0, 1)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();

  session_ = TryCreateSpdySessionExpectingFailure(
      http_session_.get(), key_, ERR_CONNECTION_CLOSED, NetLogWithSource());
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_);
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(data.AllReadDataConsumed());
}

// A session receiving a GOAWAY frame with active streams should close
// when the last active stream is closed.
TEST_F(SpdySessionTest, GoAwayWithActiveStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  SpdyHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));

  EXPECT_TRUE(session_->IsGoingAway());

  // Should close the session.
  spdy_stream1->Close();
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Regression test for https://crbug.com/547130.
TEST_F(SpdySessionTest, GoAwayWithActiveAndCreatedStream) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(0));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway, 2),
  };

  // No |req2|, because the second stream will never get activated.
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);
  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream1->stream_id());

  // Active stream 1.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_TRUE(session_->IsStreamActive(1));

  // Create stream corresponding to the next request.
  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());

  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Read and process the GOAWAY frame before the second stream could be
  // activated.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Have a session receive two GOAWAY frames, with the last one causing
// the last active stream to be closed. The session should then be
// closed after the second GOAWAY frame.
TEST_F(SpdySessionTest, GoAwayTwice) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway1(spdy_util_.ConstructSpdyGoAway(1));
  SpdySerializedFrame goaway2(spdy_util_.ConstructSpdyGoAway(0));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway1, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), CreateMockRead(goaway2, 5),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7)  // EOF
  };
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  SpdyHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the first GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));
  EXPECT_TRUE(session_->IsGoingAway());

  // Read and process the second GOAWAY frame, which should close the
  // session.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Have a session with active streams receive a GOAWAY frame and then
// close it. It should handle the close properly (i.e., not try to
// make itself unavailable in its pool twice).
TEST_F(SpdySessionTest, GoAwayWithActiveStreamsThenClose) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  SpdyHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));
  EXPECT_TRUE(session_->IsGoingAway());

  session_->CloseSessionOnError(ERR_ABORTED, "Aborting session");
  EXPECT_FALSE(spdy_stream1);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Process a joint read buffer which causes the session to begin draining, and
// then processes a GOAWAY. The session should gracefully drain. Regression test
// for crbug.com/379469
TEST_F(SpdySessionTest, GoAwayWhileDraining) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  size_t joint_size = goaway.size() * 2 + body.size();

  // Compose interleaved |goaway| and |body| frames into a single read.
  std::unique_ptr<char[]> buffer(new char[joint_size]);
  {
    size_t out = 0;
    memcpy(&buffer[out], goaway.data(), goaway.size());
    out += goaway.size();
    memcpy(&buffer[out], body.data(), body.size());
    out += body.size();
    memcpy(&buffer[out], goaway.data(), goaway.size());
    out += goaway.size();
    ASSERT_EQ(out, joint_size);
  }
  SpdySerializedFrame joint_frames(buffer.get(), joint_size, false);

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(joint_frames, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Stream and session closed gracefully.
  EXPECT_TRUE(delegate.StreamIsClosed());
  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ(kUploadData, delegate.TakeReceivedData());
  EXPECT_FALSE(session_);
}

// Try to create a stream after receiving a GOAWAY frame. It should
// fail.
TEST_F(SpdySessionTest, CreateStreamAfterGoAway) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), MockRead(ASYNC, 0, 4)  // EOF
  };
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_TRUE(session_->IsStreamActive(1));

  SpdyStreamRequest stream_request;
  int rv = stream_request.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                       test_url_, MEDIUM, NetLogWithSource(),
                                       CompletionCallback());
  EXPECT_THAT(rv, IsError(ERR_FAILED));

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Receiving a HEADERS frame after a GOAWAY frame should result in
// the stream being refused.
TEST_F(SpdySessionTest, HeadersAfterGoAway) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPush(nullptr, 0, 2, 1, kDefaultUrl));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push, 4),
      MockRead(ASYNC, 0, 6)  // EOF
  };
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 5)};
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_TRUE(session_->IsStreamActive(1));

  // Read and process the HEADERS frame, the subsequent RST_STREAM,
  // and EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// A session observing a network change with active streams should close
// when the last active stream is closed.
TEST_F(SpdySessionTest, NetworkChangeWithActiveStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), MockRead(ASYNC, 0, 2)  // EOF
  };
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));

  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  spdy_session_pool_->OnIPAddressChanged();

  // The SpdySessionPool behavior differs based on how the OSs reacts to
  // network changes; see comment in SpdySessionPool::OnIPAddressChanged().
#if defined(OS_ANDROID) || defined(OS_WIN) || defined(OS_IOS)
  // For OSs where the TCP connections will close upon relevant network
  // changes, SpdySessionPool doesn't need to force them to close, so in these
  // cases verify the session has become unavailable but remains open and the
  // pre-existing stream is still active.
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_TRUE(session_->IsGoingAway());

  EXPECT_TRUE(session_->IsStreamActive(1));

  // Should close the session.
  spdy_stream->Close();
#endif
  EXPECT_FALSE(spdy_stream);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, ClientPing) {
  session_deps_.enable_ping = true;
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame read_ping(spdy_util_.ConstructSpdyPing(1, true));
  MockRead reads[] = {
      CreateMockRead(read_ping, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };
  SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(1, false));
  MockWrite writes[] = {
      CreateMockWrite(write_ping, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, nullptr);
  spdy_stream1->SetDelegate(&delegate);

  base::TimeTicks before_ping_time = base::TimeTicks::Now();

  session_->set_connection_at_risk_of_loss_time(
      base::TimeDelta::FromSeconds(-1));
  session_->set_hung_interval(base::TimeDelta::FromMilliseconds(50));

  session_->SendPrefacePingIfNoneInFlight();

  base::RunLoop().RunUntilIdle();

  session_->CheckPingStatus(before_ping_time);

  EXPECT_EQ(0, session_->pings_in_flight());
  EXPECT_GE(session_->next_ping_id(), 1U);
  EXPECT_FALSE(session_->check_ping_status_pending());
  EXPECT_GE(session_->last_activity_time(), before_ping_time);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, ServerPing) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame read_ping(spdy_util_.ConstructSpdyPing(2, false));
  MockRead reads[] = {
      CreateMockRead(read_ping), MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(2, true));
  MockWrite writes[] = {
      CreateMockWrite(write_ping),
  };
  StaticSocketDataProvider data(
      reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, nullptr);
  spdy_stream1->SetDelegate(&delegate);

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_);
  EXPECT_FALSE(spdy_stream1);
}

// Cause a ping to be sent out while producing a write. The write loop
// should handle this properly, i.e. another DoWriteLoop task should
// not be posted. This is a regression test for
// http://crbug.com/261043 .
TEST_F(SpdySessionTest, PingAndWriteLoop) {
  session_deps_.enable_ping = true;
  session_deps_.time_func = TheNearFuture;

  SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(1, false));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(write_ping, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Shift time so that a ping will be sent out.
  g_time_delta = base::TimeDelta::FromSeconds(11);

  base::RunLoop().RunUntilIdle();
  session_->CloseSessionOnError(ERR_ABORTED, "Aborting");

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, StreamIdSpaceExhausted) {
  const SpdyStreamId kLastStreamId = 0x7fffffff;
  session_deps_.host_resolver->set_synchronous_mode(true);

  // Test setup: |stream_hi_water_mark_| and |max_concurrent_streams_| are
  // fixed to allow for two stream ID assignments, and three concurrent
  // streams. Four streams are started, and two are activated. Verify the
  // session goes away, and that the created (but not activated) and
  // stalled streams are aborted. Also verify the activated streams complete,
  // at which point the session closes.

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, kLastStreamId - 2, MEDIUM, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, kLastStreamId, MEDIUM, true));

  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, kLastStreamId - 2));
  SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, kLastStreamId));

  SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(kLastStreamId - 2, true));
  SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(kLastStreamId, true));

  MockRead reads[] = {
      CreateMockRead(resp1, 2),           CreateMockRead(resp2, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), CreateMockRead(body1, 5),
      CreateMockRead(body2, 6),           MockRead(ASYNC, 0, 7)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Fix stream_hi_water_mark_ to allow for two stream activations.
  session_->stream_hi_water_mark_ = kLastStreamId - 2;
  // Fix max_concurrent_streams to allow for three stream creations.
  session_->max_concurrent_streams_ = 3;

  // Create three streams synchronously, and begin a fourth (which is stalled).
  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(stream1);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(stream2);
  stream2->SetDelegate(&delegate2);

  base::WeakPtr<SpdyStream> stream3 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate3(stream3);
  stream3->SetDelegate(&delegate3);

  SpdyStreamRequest request4;
  TestCompletionCallback callback4;
  EXPECT_EQ(
      ERR_IO_PENDING,
      request4.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_,
                            MEDIUM, NetLogWithSource(), callback4.callback()));

  // Streams 1-3 were created. 4th is stalled. No streams are active yet.
  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(3u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(MEDIUM));

  // Activate stream 1. One ID remains available.
  stream1->SendRequestHeaders(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl),
                              NO_MORE_DATA_TO_SEND);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(kLastStreamId - 2u, stream1->stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(2u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(MEDIUM));

  // Activate stream 2. ID space is exhausted.
  stream2->SendRequestHeaders(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl),
                              NO_MORE_DATA_TO_SEND);
  base::RunLoop().RunUntilIdle();

  // Active streams remain active.
  EXPECT_EQ(kLastStreamId, stream2->stream_id());
  EXPECT_EQ(2u, session_->num_active_streams());

  // Session is going away. Created and stalled streams were aborted.
  EXPECT_EQ(SpdySession::STATE_GOING_AWAY, session_->availability_state_);
  EXPECT_THAT(delegate3.WaitForClose(), IsError(ERR_ABORTED));
  EXPECT_THAT(callback4.WaitForResult(), IsError(ERR_ABORTED));
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(MEDIUM));

  // Read responses on remaining active streams.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate1.WaitForClose(), IsOk());
  EXPECT_EQ(kUploadData, delegate1.TakeReceivedData());
  EXPECT_THAT(delegate2.WaitForClose(), IsOk());
  EXPECT_EQ(kUploadData, delegate2.TakeReceivedData());

  // Session was destroyed.
  EXPECT_FALSE(session_);
}

// Regression test for https://crbug.com/481009.
TEST_F(SpdySessionTest, MaxConcurrentStreamsZero) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  // Receive SETTINGS frame that sets max_concurrent_streams to zero.
  SettingsMap settings_zero;
  settings_zero[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, 0);
  SpdySerializedFrame settings_frame_zero(
      spdy_util_.ConstructSpdySettings(settings_zero));

  // Acknowledge it.
  SpdySerializedFrame settings_ack0(spdy_util_.ConstructSpdySettingsAck());

  // Receive SETTINGS frame that sets max_concurrent_streams to one.
  SettingsMap settings_one;
  settings_one[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, 1);
  SpdySerializedFrame settings_frame_one(
      spdy_util_.ConstructSpdySettings(settings_one));

  // Acknowledge it.
  SpdySerializedFrame settings_ack1(spdy_util_.ConstructSpdySettingsAck());

  // Request and response.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {CreateMockRead(settings_frame_zero, 0),
                      MockRead(ASYNC, ERR_IO_PENDING, 2),
                      CreateMockRead(settings_frame_one, 3),
                      CreateMockRead(resp, 6),
                      CreateMockRead(body, 7),
                      MockRead(ASYNC, 0, 8)};

  MockWrite writes[] = {CreateMockWrite(settings_ack0, 1),
                        CreateMockWrite(settings_ack1, 4),
                        CreateMockWrite(req, 5)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  // Create session.
  CreateNetworkSession();
  CreateSecureSpdySession();

  // Receive SETTINGS frame that sets max_concurrent_streams to zero.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, session_->max_concurrent_streams_);

  // Start request.
  SpdyStreamRequest request;
  TestCompletionCallback callback;
  int rv =
      request.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_,
                           MEDIUM, NetLogWithSource(), callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Stream is stalled.
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(MEDIUM));
  EXPECT_EQ(0u, session_->num_created_streams());

  // Receive SETTINGS frame that sets max_concurrent_streams to one.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, session_->max_concurrent_streams_);

  // Stream is created.
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(MEDIUM));
  EXPECT_EQ(1u, session_->num_created_streams());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Send request.
  base::WeakPtr<SpdyStream> stream = request.ReleaseStream();
  test::StreamDelegateDoNothing delegate(stream);
  stream->SetDelegate(&delegate);
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ("hello!", delegate.TakeReceivedData());

  // Session is destroyed.
  EXPECT_FALSE(session_);
}

// Verifies that an unstalled pending stream creation racing with a new stream
// creation doesn't violate the maximum stream concurrency. Regression test for
// crbug.com/373858.
TEST_F(SpdySessionTest, UnstallRacesWithStreamCreation) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Fix max_concurrent_streams to allow for one open stream.
  session_->max_concurrent_streams_ = 1;

  // Create two streams: one synchronously, and one which stalls.
  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());

  SpdyStreamRequest request2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      request2.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_,
                            MEDIUM, NetLogWithSource(), callback2.callback()));

  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(MEDIUM));

  // Cancel the first stream. A callback to unstall the second stream was
  // posted. Don't run it yet.
  stream1->Cancel();

  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(MEDIUM));

  // Create a third stream prior to the second stream's callback.
  base::WeakPtr<SpdyStream> stream3 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());

  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(MEDIUM));

  // Now run the message loop. The unstalled stream will re-stall itself.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(MEDIUM));

  // Cancel the third stream and run the message loop. Verify that the second
  // stream creation now completes.
  stream3->Cancel();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(MEDIUM));
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
}

TEST_F(SpdySessionTest, CancelPushAfterSessionGoesAway) {
  base::HistogramTester histogram_tester;
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = TheNearFuture;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 5)};

  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdySerializedFrame push_a_body(spdy_util_.ConstructSpdyDataFrame(2, false));
  // In ascii "0" < "a". We use it to verify that we properly handle std::map
  // iterators inside. See http://crbug.com/443490
  SpdySerializedFrame push_b(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, "https://www.example.org/0.dat"));
  MockRead reads[] = {
      CreateMockRead(push_a, 1),          CreateMockRead(push_a_body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  session_->set_push_delegate(&test_push_delegate_);

  // Process the principal request, and the first push stream request & body.
  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Verify that there is one unclaimed push stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/a.dat")));

  // Unclaimed push body consumed bytes from the session window.
  EXPECT_EQ(kDefaultInitialWindowSize - kUploadDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Shift time to expire the push stream. Read the second HEADERS,
  // and verify a RST_STREAM was written.
  g_time_delta = base::TimeDelta::FromSeconds(301);
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Verify that the second pushed stream evicted the first pushed stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/0.dat")));

  // Verify that the session window reclaimed the evicted stream body.
  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize, session_->session_unacked_recv_window_bytes_);
  EXPECT_TRUE(session_);

  // Read and process EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Cancel the first push after session goes away. Verify the test doesn't
  // crash.
  EXPECT_FALSE(session_);
  EXPECT_TRUE(
      test_push_delegate_.CancelPush(GURL("https://www.example.org/a.dat")));

  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedBytes", 6, 1);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedAndUnclaimedBytes",
                                     6, 1);
}

TEST_F(SpdySessionTest, CancelPushAfterExpired) {
  base::HistogramTester histogram_tester;
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = TheNearFuture;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 5)};

  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdySerializedFrame push_a_body(spdy_util_.ConstructSpdyDataFrame(2, false));
  // In ascii "0" < "a". We use it to verify that we properly handle std::map
  // iterators inside. See http://crbug.com/443490
  SpdySerializedFrame push_b(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, "https://www.example.org/0.dat"));
  MockRead reads[] = {
      CreateMockRead(push_a, 1),          CreateMockRead(push_a_body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  session_->set_push_delegate(&test_push_delegate_);

  // Process the principal request, and the first push stream request & body.
  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Verify that there is one unclaimed push stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/a.dat")));

  // Unclaimed push body consumed bytes from the session window.
  EXPECT_EQ(kDefaultInitialWindowSize - kUploadDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Shift time to expire the push stream. Read the second HEADERS,
  // and verify a RST_STREAM was written.
  g_time_delta = base::TimeDelta::FromSeconds(301);
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Verify that the second pushed stream evicted the first pushed stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/0.dat")));

  // Cancel the first push after its expiration.
  EXPECT_TRUE(
      test_push_delegate_.CancelPush(GURL("https://www.example.org/a.dat")));
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_TRUE(session_);

  // Verify that the session window reclaimed the evicted stream body.
  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize, session_->session_unacked_recv_window_bytes_);
  EXPECT_TRUE(session_);

  // Read and process EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedBytes", 6, 1);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedAndUnclaimedBytes",
                                     6, 1);
}

TEST_F(SpdySessionTest, CancelPushBeforeClaimed) {
  base::HistogramTester histogram_tester;
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = TheNearFuture;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 5)};

  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdySerializedFrame push_a_body(spdy_util_.ConstructSpdyDataFrame(2, false));
  // In ascii "0" < "a". We use it to verify that we properly handle std::map
  // iterators inside. See http://crbug.com/443490
  SpdySerializedFrame push_b(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, "https://www.example.org/0.dat"));
  MockRead reads[] = {
      CreateMockRead(push_a, 1),          CreateMockRead(push_a_body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  session_->set_push_delegate(&test_push_delegate_);

  // Process the principal request, and the first push stream request & body.
  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Verify that there is one unclaimed push stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/a.dat")));

  // Unclaimed push body consumed bytes from the session window.
  EXPECT_EQ(kDefaultInitialWindowSize - kUploadDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Shift time to expire the push stream. Read the second HEADERS,
  // and verify a RST_STREAM was written.
  g_time_delta = base::TimeDelta::FromSeconds(301);
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Verify that the second pushed stream evicted the first pushed stream.
  GURL pushed_url("https://www.example.org/0.dat");
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(pushed_url));

  // Verify that the session window reclaimed the evicted stream body.
  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize, session_->session_unacked_recv_window_bytes_);

  EXPECT_TRUE(session_);
  // Cancel the push before it's claimed.
  EXPECT_TRUE(test_push_delegate_.CancelPush(pushed_url));
  EXPECT_EQ(0u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(0u, session_->count_unclaimed_pushed_streams_for_url(pushed_url));

  // Read and process EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedBytes", 6, 1);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedAndUnclaimedBytes",
                                     6, 1);
}

TEST_F(SpdySessionTest, DeleteExpiredPushStreams) {
  base::HistogramTester histogram_tester;
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = TheNearFuture;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 5)};

  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdySerializedFrame push_a_body(spdy_util_.ConstructSpdyDataFrame(2, false));
  // In ascii "0" < "a". We use it to verify that we properly handle std::map
  // iterators inside. See http://crbug.com/443490
  SpdySerializedFrame push_b(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, "https://www.example.org/0.dat"));
  MockRead reads[] = {
      CreateMockRead(push_a, 1),          CreateMockRead(push_a_body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Process the principal request, and the first push stream request & body.
  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Verify that there is one unclaimed push stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/a.dat")));

  // Unclaimed push body consumed bytes from the session window.
  EXPECT_EQ(kDefaultInitialWindowSize - kUploadDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Shift time to expire the push stream. Read the second HEADERS,
  // and verify a RST_STREAM was written.
  g_time_delta = base::TimeDelta::FromSeconds(301);
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Verify that the second pushed stream evicted the first pushed stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/0.dat")));

  // Verify that the session window reclaimed the evicted stream body.
  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize, session_->session_unacked_recv_window_bytes_);

  // Read and process EOF.
  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedBytes", 6, 1);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedAndUnclaimedBytes",
                                     6, 1);
}

TEST_F(SpdySessionTest, MetricsCollectionOnPushStreams) {
  base::HistogramTester histogram_tester;
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = TheNearFuture;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 5)};

  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdySerializedFrame push_a_body(spdy_util_.ConstructSpdyDataFrame(2, false));
  // In ascii "0" < "a". We use it to verify that we properly handle std::map
  // iterators inside. See http://crbug.com/443490
  SpdySerializedFrame push_b(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, "https://www.example.org/0.dat"));
  SpdySerializedFrame push_c(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 6, 1, "https://www.example.org/1.dat"));
  SpdySerializedFrame push_c_body(spdy_util_.ConstructSpdyDataFrame(6, false));

  MockRead reads[] = {
      CreateMockRead(push_a, 1),
      CreateMockRead(push_a_body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6),
      CreateMockRead(push_c, 7),
      CreateMockRead(push_c_body, 8),
      MockRead(ASYNC, ERR_IO_PENDING, 9),
      MockRead(ASYNC, 0, 10)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Process the principal request, and the first push stream request & body.
  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Verify that there is one unclaimed push stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/a.dat")));

  // Unclaimed push body consumed bytes from the session window.
  EXPECT_EQ(kDefaultInitialWindowSize - kUploadDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Shift time to expire the push stream. Read the second HEADERS,
  // and verify a RST_STREAM was written.
  g_time_delta = base::TimeDelta::FromSeconds(300);
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Verify that the second pushed stream evicted the first pushed stream.
  EXPECT_EQ(1u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/0.dat")));

  // Verify that the session window reclaimed the evicted stream body.
  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize, session_->session_unacked_recv_window_bytes_);

  // Read the third PUSH, this will not be expired when the test tear down.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2u, session_->num_unclaimed_pushed_streams());
  EXPECT_EQ(1u, session_->count_unclaimed_pushed_streams_for_url(
                    GURL("https://www.example.org/1.dat")));

  // Read and process EOF.
  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedBytes", 12, 1);
  histogram_tester.ExpectBucketCount("Net.SpdySession.PushedAndUnclaimedBytes",
                                     6, 1);
}

TEST_F(SpdySessionTest, FailedPing) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  SpdySerializedFrame write_ping(spdy_util_.ConstructSpdyPing(1, false));
  SpdySerializedFrame goaway(
      spdy_util_.ConstructSpdyGoAway(0, GOAWAY_PROTOCOL_ERROR, "Failed ping."));
  MockWrite writes[] = {CreateMockWrite(write_ping), CreateMockWrite(goaway)};

  StaticSocketDataProvider data(
      reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  test::StreamDelegateSendImmediate delegate(spdy_stream1, nullptr);
  spdy_stream1->SetDelegate(&delegate);

  session_->set_connection_at_risk_of_loss_time(
      base::TimeDelta::FromSeconds(0));
  session_->set_hung_interval(base::TimeDelta::FromSeconds(0));

  // Send a PING frame.
  session_->WritePingFrame(1, false);
  EXPECT_LT(0, session_->pings_in_flight());
  EXPECT_GE(session_->next_ping_id(), 1U);
  EXPECT_TRUE(session_->check_ping_status_pending());

  // Assert session is not closed.
  EXPECT_TRUE(session_->IsAvailable());
  EXPECT_LT(0u,
            session_->num_active_streams() + session_->num_created_streams());
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // We set last time we have received any data in 1 sec less than now.
  // CheckPingStatus will trigger timeout because hung interval is zero.
  base::TimeTicks now = base::TimeTicks::Now();
  session_->last_activity_time_ = now - base::TimeDelta::FromSeconds(1);
  session_->CheckPingStatus(now);
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_);
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(spdy_stream1);
}

// Request kInitialMaxConcurrentStreams + 1 streams.  Receive a
// settings frame increasing the max concurrent streams by 1.  Make
// sure nothing blows up. This is a regression test for
// http://crbug.com/57331 .
TEST_F(SpdySessionTest, OnSettings) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  const SpdySettingsIds kSpdySettingsIds = SETTINGS_MAX_CONCURRENT_STREAMS;

  SettingsMap new_settings;
  const uint32_t max_concurrent_streams = kInitialMaxConcurrentStreams + 1;
  new_settings[kSpdySettingsIds] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, max_concurrent_streams);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));
  MockRead reads[] = {
      CreateMockRead(settings_frame, 0), MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 0, 3),
  };

  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {CreateMockWrite(settings_ack, 1)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Create the maximum number of concurrent streams.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  StreamReleaserCallback stream_releaser;
  SpdyStreamRequest request;
  ASSERT_EQ(ERR_IO_PENDING,
            request.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                 MEDIUM, NetLogWithSource(),
                                 stream_releaser.MakeCallback(&request)));

  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(stream_releaser.WaitForResult(), IsOk());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Create one more stream than maximum number of concurrent streams,
// so that one of them is pending.  Cancel one stream, which should trigger the
// creation of the pending stream.  Then cancel that one immediately as well,
// and make sure this does not lead to a crash.
// This is a regression test for https://crbug.com/63532.
TEST_F(SpdySessionTest, CancelPendingCreateStream) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Leave room for only one more stream to be created.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams - 1; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  // Create 2 more streams.  First will succeed.  Second will be pending.
  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);

  // Use unique_ptr to let us invalidate the memory when we want to, to trigger
  // a valgrind error if the callback is invoked when it's not supposed to be.
  std::unique_ptr<TestCompletionCallback> callback(new TestCompletionCallback);

  SpdyStreamRequest request;
  ASSERT_THAT(
      request.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                           MEDIUM, NetLogWithSource(), callback->callback()),
      IsError(ERR_IO_PENDING));

  // Release the first one, this will allow the second to be created.
  spdy_stream1->Cancel();
  EXPECT_FALSE(spdy_stream1);

  request.CancelRequest();
  callback.reset();

  // Should not crash when running the pending callback.
  base::RunLoop().RunUntilIdle();
}

TEST_F(SpdySessionTest, SendInitialDataOnNewSession) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  SettingsMap settings;
  settings[SETTINGS_HEADER_TABLE_SIZE] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, kMaxHeaderTableSize);
  settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, kMaxConcurrentPushedStreams);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  MockWrite writes[] = {MockWrite(ASYNC, kHttp2ConnectionHeaderPrefix,
                                  kHttp2ConnectionHeaderPrefixSize),
                        CreateMockWrite(settings_frame)};

  StaticSocketDataProvider data(reads, arraysize(reads), writes,
                                arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();

  SpdySessionPoolPeer pool_peer(spdy_session_pool_);
  pool_peer.SetEnableSendingInitialData(true);

  CreateSecureSpdySession();

  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdySessionTest, Initialize) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
    MockRead(ASYNC, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_LT(0u, entries.size());

  // Check that we logged HTTP2_SESSION_INITIALIZED correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_INITIALIZED,
      NetLogEventPhase::NONE);
  EXPECT_LT(0, pos);

  TestNetLogEntry entry = entries[pos];
  NetLogSource socket_source;
  EXPECT_TRUE(
      NetLogSource::FromEventParameters(entry.params.get(), &socket_source));
  EXPECT_TRUE(socket_source.IsValid());
  EXPECT_NE(log_.bound().source().id, socket_source.id);
}

TEST_F(SpdySessionTest, NetLogOnSessionGoaway) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(
      spdy_util_.ConstructSpdyGoAway(42, GOAWAY_ENHANCE_YOUR_CALM, "foo"));
  MockRead reads[] = {
      CreateMockRead(goaway), MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);

  // Check that the NetLog was filled reasonably.
  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_LT(0u, entries.size());

  int pos = ExpectLogContainsSomewhere(entries, 0,
                                       NetLogEventType::HTTP2_SESSION_GOAWAY,
                                       NetLogEventPhase::NONE);
  TestNetLogEntry entry = entries[pos];
  int last_accepted_stream_id;
  ASSERT_TRUE(entry.GetIntegerValue("last_accepted_stream_id",
                                    &last_accepted_stream_id));
  EXPECT_EQ(42, last_accepted_stream_id);
  int active_streams;
  ASSERT_TRUE(entry.GetIntegerValue("active_streams", &active_streams));
  EXPECT_EQ(0, active_streams);
  int unclaimed_streams;
  ASSERT_TRUE(entry.GetIntegerValue("unclaimed_streams", &unclaimed_streams));
  EXPECT_EQ(0, unclaimed_streams);
  int status;
  ASSERT_TRUE(entry.GetIntegerValue("status", &status));
  EXPECT_EQ(GOAWAY_ENHANCE_YOUR_CALM, status);
  std::string debug_data;
  ASSERT_TRUE(entry.GetStringValue("debug_data", &debug_data));
  EXPECT_EQ("foo", debug_data);

  // Check that we logged SPDY_SESSION_CLOSE correctly.
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_CLOSE, NetLogEventPhase::NONE);
  entry = entries[pos];
  int error_code = 0;
  ASSERT_TRUE(entry.GetNetErrorCode(&error_code));
  EXPECT_THAT(error_code, IsOk());
}

TEST_F(SpdySessionTest, NetLogOnSessionEOF) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Flush the read completion task.
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);

  // Check that the NetLog was filled reasonably.
  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_LT(0u, entries.size());

  // Check that we logged SPDY_SESSION_CLOSE correctly.
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_CLOSE, NetLogEventPhase::NONE);

  if (pos < static_cast<int>(entries.size())) {
    TestNetLogEntry entry = entries[pos];
    int error_code = 0;
    ASSERT_TRUE(entry.GetNetErrorCode(&error_code));
    EXPECT_THAT(error_code, IsError(ERR_CONNECTION_CLOSED));
  } else {
    ADD_FAILURE();
  }
}

TEST_F(SpdySessionTest, HeadersCompressionHistograms) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Write request headers & capture resulting histogram update.
  base::HistogramTester histogram_tester;

  base::RunLoop().RunUntilIdle();
  // Regression test of compression performance under the request fixture.
  histogram_tester.ExpectBucketCount("Net.SpdyHeadersCompressionPercentage", 76,
                                     1);

  // Read and process EOF.
  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Queue up a low-priority HEADERS followed by a high-priority
// one. The high priority one should still send first and receive
// first.
TEST_F(SpdySessionTest, OutOfOrderHeaders) {
  // Construct the request.
  SpdySerializedFrame req_highest(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST, true));
  SpdySerializedFrame req_lowest(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req_highest, 0), CreateMockWrite(req_lowest, 1),
  };

  SpdySerializedFrame resp_highest(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body_highest(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame resp_lowest(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  SpdySerializedFrame body_lowest(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(resp_highest, 2), CreateMockRead(body_highest, 3),
      CreateMockRead(resp_lowest, 4), CreateMockRead(body_lowest, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream_lowest =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream_lowest);
  EXPECT_EQ(0u, spdy_stream_lowest->stream_id());
  test::StreamDelegateDoNothing delegate_lowest(spdy_stream_lowest);
  spdy_stream_lowest->SetDelegate(&delegate_lowest);

  base::WeakPtr<SpdyStream> spdy_stream_highest =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream_highest);
  EXPECT_EQ(0u, spdy_stream_highest->stream_id());
  test::StreamDelegateDoNothing delegate_highest(spdy_stream_highest);
  spdy_stream_highest->SetDelegate(&delegate_highest);

  // Queue the lower priority one first.

  SpdyHeaderBlock headers_lowest(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream_lowest->SendRequestHeaders(std::move(headers_lowest),
                                         NO_MORE_DATA_TO_SEND);

  SpdyHeaderBlock headers_highest(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream_highest->SendRequestHeaders(std::move(headers_highest),
                                          NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream_lowest);
  EXPECT_FALSE(spdy_stream_highest);
  EXPECT_EQ(3u, delegate_lowest.stream_id());
  EXPECT_EQ(1u, delegate_highest.stream_id());
}

TEST_F(SpdySessionTest, CancelStream) {
  // Request 1, at HIGHEST priority, will be cancelled before it writes data.
  // Request 2, at LOWEST priority, will be a full request and will be id 1.
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req2, 0),
  };

  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp2, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(body2, 3), MockRead(ASYNC, 0, 4)  // EOF
  };

  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  SpdyHeaderBlock headers2(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream1->stream_id());

  spdy_stream1->Cancel();
  EXPECT_FALSE(spdy_stream1);

  EXPECT_EQ(0u, delegate1.stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0u, delegate1.stream_id());
  EXPECT_EQ(1u, delegate2.stream_id());

  spdy_stream2->Cancel();
  EXPECT_FALSE(spdy_stream2);
}

// Create two streams that are set to re-close themselves on close,
// and then close the session. Nothing should blow up. Also a
// regression test for http://crbug.com/139518 .
TEST_F(SpdySessionTest, CloseSessionWithTwoCreatedSelfClosingStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);


  // No actual data will be sent.
  MockWrite writes[] = {
    MockWrite(ASYNC, 0, 1)  // EOF
  };

  MockRead reads[] = {
    MockRead(ASYNC, 0, 0)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  test::ClosingDelegate delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  test::ClosingDelegate delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  SpdyHeaderBlock headers2(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Create two streams that are set to close each other on close, and
// then close the session. Nothing should blow up.
TEST_F(SpdySessionTest, CloseSessionWithTwoCreatedMutuallyClosingStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(nullptr, 0, nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Make |spdy_stream1| close |spdy_stream2|.
  test::ClosingDelegate delegate1(spdy_stream2);
  spdy_stream1->SetDelegate(&delegate1);

  // Make |spdy_stream2| close |spdy_stream1|.
  test::ClosingDelegate delegate2(spdy_stream1);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  SpdyHeaderBlock headers2(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Create two streams that are set to re-close themselves on close,
// activate them, and then close the session. Nothing should blow up.
TEST_F(SpdySessionTest, CloseSessionWithTwoActivatedSelfClosingStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  test::ClosingDelegate delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  test::ClosingDelegate delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  SpdyHeaderBlock headers2(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Create two streams that are set to close each other on close,
// activate them, and then close the session. Nothing should blow up.
TEST_F(SpdySessionTest, CloseSessionWithTwoActivatedMutuallyClosingStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Make |spdy_stream1| close |spdy_stream2|.
  test::ClosingDelegate delegate1(spdy_stream2);
  spdy_stream1->SetDelegate(&delegate1);

  // Make |spdy_stream2| close |spdy_stream1|.
  test::ClosingDelegate delegate2(spdy_stream1);
  spdy_stream2->SetDelegate(&delegate2);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  SpdyHeaderBlock headers2(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Ensure that the streams have not yet been activated and assigned an id.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  EXPECT_EQ(0u, spdy_stream2->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  // Ensure we don't crash while closing the session.
  session_->CloseSessionOnError(ERR_ABORTED, std::string());

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(delegate1.StreamIsClosed());
  EXPECT_TRUE(delegate2.StreamIsClosed());

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Delegate that closes a given session when the stream is closed.
class SessionClosingDelegate : public test::StreamDelegateDoNothing {
 public:
  SessionClosingDelegate(const base::WeakPtr<SpdyStream>& stream,
                         const base::WeakPtr<SpdySession>& session_to_close)
      : StreamDelegateDoNothing(stream),
        session_to_close_(session_to_close) {}

  ~SessionClosingDelegate() override {}

  void OnClose(int status) override {
    session_to_close_->CloseSessionOnError(ERR_SPDY_PROTOCOL_ERROR, "Error");
  }

 private:
  base::WeakPtr<SpdySession> session_to_close_;
};

// Close an activated stream that closes its session. Nothing should
// blow up. This is a regression test for https://crbug.com/263691.
TEST_F(SpdySessionTest, CloseActivatedStreamThatClosesSession) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_CANCEL));
  SpdySerializedFrame goaway(
      spdy_util_.ConstructSpdyGoAway(0, GOAWAY_PROTOCOL_ERROR, "Error"));
  // The GOAWAY has higher-priority than the RST_STREAM, and is written first
  // despite being queued second.
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(goaway, 1),
      CreateMockWrite(rst, 3),
  };

  MockRead reads[] = {
      MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());

  SessionClosingDelegate delegate(spdy_stream, session_);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  // Ensure we don't crash while closing the stream (which closes the
  // session).
  spdy_stream->Cancel();

  EXPECT_FALSE(spdy_stream);
  EXPECT_TRUE(delegate.StreamIsClosed());

  // Write the RST_STREAM & GOAWAY.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdySessionTest, VerifyDomainAuthentication) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(nullptr, 0, nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  EXPECT_TRUE(session_->VerifyDomainAuthentication("www.example.org"));
  EXPECT_TRUE(session_->VerifyDomainAuthentication("mail.example.org"));
  EXPECT_TRUE(session_->VerifyDomainAuthentication("mail.example.com"));
  EXPECT_FALSE(session_->VerifyDomainAuthentication("mail.google.com"));
}

TEST_F(SpdySessionTest, ConnectionPooledWithTlsChannelId) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(nullptr, 0, nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  ssl_.channel_id_sent = true;
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  EXPECT_TRUE(session_->VerifyDomainAuthentication("www.example.org"));
  EXPECT_TRUE(session_->VerifyDomainAuthentication("mail.example.org"));
  EXPECT_FALSE(session_->VerifyDomainAuthentication("mail.example.com"));
  EXPECT_FALSE(session_->VerifyDomainAuthentication("mail.google.com"));
}

TEST_F(SpdySessionTest, CloseTwoStalledCreateStream) {
  // TODO(rtenneti): Define a helper class/methods and move the common code in
  // this file.
  SettingsMap new_settings;
  const SpdySettingsIds kSpdySettingsIds1 = SETTINGS_MAX_CONCURRENT_STREAMS;
  const uint32_t max_concurrent_streams = 1;
  new_settings[kSpdySettingsIds1] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, max_concurrent_streams);

  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  spdy_util_.UpdateWithStreamDestruction(3);
  SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(settings_ack, 1), CreateMockWrite(req1, 2),
      CreateMockWrite(req2, 5), CreateMockWrite(req3, 8),
  };

  // Set up the socket so we read a SETTINGS frame that sets max concurrent
  // streams to 1.
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));

  SpdySerializedFrame resp3(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, true));

  MockRead reads[] = {
      CreateMockRead(settings_frame, 0),
      CreateMockRead(resp1, 3),
      CreateMockRead(body1, 4),
      CreateMockRead(resp2, 6),
      CreateMockRead(body2, 7),
      CreateMockRead(resp3, 9),
      CreateMockRead(body3, 10),
      MockRead(ASYNC, ERR_IO_PENDING, 11),
      MockRead(ASYNC, 0, 12)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Read the settings frame.
  base::RunLoop().RunUntilIdle();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  TestCompletionCallback callback2;
  SpdyStreamRequest request2;
  ASSERT_EQ(
      ERR_IO_PENDING,
      request2.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_,
                            LOWEST, NetLogWithSource(), callback2.callback()));

  TestCompletionCallback callback3;
  SpdyStreamRequest request3;
  ASSERT_EQ(
      ERR_IO_PENDING,
      request3.StartRequest(SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_,
                            LOWEST, NetLogWithSource(), callback3.callback()));

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(2u, session_->pending_create_stream_queue_size(LOWEST));

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated and then closed.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);
  EXPECT_EQ(1u, delegate1.stream_id());

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(LOWEST));

  // Pump loop for SpdySession::ProcessPendingStreamRequests() to
  // create the 2nd stream.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(LOWEST));

  base::WeakPtr<SpdyStream> stream2 = request2.ReleaseStream();
  test::StreamDelegateDoNothing delegate2(stream2);
  stream2->SetDelegate(&delegate2);
  SpdyHeaderBlock headers2(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  // Run until 2nd stream is activated and then closed.
  EXPECT_EQ(0u, delegate2.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream2);
  EXPECT_EQ(3u, delegate2.stream_id());

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(LOWEST));

  // Pump loop for SpdySession::ProcessPendingStreamRequests() to
  // create the 3rd stream.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(LOWEST));

  base::WeakPtr<SpdyStream> stream3 = request3.ReleaseStream();
  test::StreamDelegateDoNothing delegate3(stream3);
  stream3->SetDelegate(&delegate3);
  SpdyHeaderBlock headers3(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  stream3->SendRequestHeaders(std::move(headers3), NO_MORE_DATA_TO_SEND);

  // Run until 2nd stream is activated and then closed.
  EXPECT_EQ(0u, delegate3.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream3);
  EXPECT_EQ(5u, delegate3.stream_id());

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(LOWEST));

  data.Resume();
  base::RunLoop().RunUntilIdle();
}

TEST_F(SpdySessionTest, CancelTwoStalledCreateStream) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Leave room for only one more stream to be created.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams - 1; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  TestCompletionCallback callback2;
  SpdyStreamRequest request2;
  ASSERT_EQ(
      ERR_IO_PENDING,
      request2.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                            LOWEST, NetLogWithSource(), callback2.callback()));

  TestCompletionCallback callback3;
  SpdyStreamRequest request3;
  ASSERT_EQ(
      ERR_IO_PENDING,
      request3.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                            LOWEST, NetLogWithSource(), callback3.callback()));

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams, session_->num_created_streams());
  EXPECT_EQ(2u, session_->pending_create_stream_queue_size(LOWEST));

  // Cancel the first stream; this will allow the second stream to be created.
  EXPECT_TRUE(spdy_stream1);
  spdy_stream1->Cancel();
  EXPECT_FALSE(spdy_stream1);

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams, session_->num_created_streams());
  EXPECT_EQ(1u, session_->pending_create_stream_queue_size(LOWEST));

  // Cancel the second stream; this will allow the third stream to be created.
  base::WeakPtr<SpdyStream> spdy_stream2 = request2.ReleaseStream();
  spdy_stream2->Cancel();
  EXPECT_FALSE(spdy_stream2);

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(LOWEST));

  // Cancel the third stream.
  base::WeakPtr<SpdyStream> spdy_stream3 = request3.ReleaseStream();
  spdy_stream3->Cancel();
  EXPECT_FALSE(spdy_stream3);
  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(kInitialMaxConcurrentStreams - 1, session_->num_created_streams());
  EXPECT_EQ(0u, session_->pending_create_stream_queue_size(LOWEST));
}

// Test that SpdySession::DoReadLoop reads data from the socket
// without yielding.  This test makes 32k - 1 bytes of data available
// on the socket for reading. It then verifies that it has read all
// the available data without yielding.
TEST_F(SpdySessionTest, ReadDataWithoutYielding) {
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = InstantaneousReads;

  BufferedSpdyFramer framer;

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  // Build buffer of size kYieldAfterBytesRead / 4
  // (-spdy_data_frame_size).
  ASSERT_EQ(32 * 1024, kYieldAfterBytesRead);
  const int kPayloadSize =
      kYieldAfterBytesRead / 4 - framer.GetFrameHeaderSize();
  TestDataStream test_stream;
  scoped_refptr<IOBuffer> payload(new IOBuffer(kPayloadSize));
  char* payload_data = payload->data();
  test_stream.GetBytes(payload_data, kPayloadSize);

  SpdySerializedFrame partial_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, payload_data, kPayloadSize, /*fin=*/false));
  SpdySerializedFrame finish_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, payload_data, kPayloadSize - 1, /*fin=*/true));

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Write 1 byte less than kMaxReadBytes to check that DoRead reads up to 32k
  // bytes.
  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(partial_data_frame, 3),
      CreateMockRead(partial_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 6, SYNCHRONOUS),
      MockRead(ASYNC, 0, 7)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to verify SpdySession::DoReadLoop doesn't
  // post a task.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify SpdySession::DoReadLoop has not
  // posted a task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);

  // Verify task observer's executed_count is zero, which indicates DoRead read
  // all the available data.
  EXPECT_EQ(0u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Test that SpdySession::DoReadLoop yields if more than
// |kYieldAfterDurationMilliseconds| has passed.  This test uses a mock time
// function that makes the response frame look very slow to read.
TEST_F(SpdySessionTest, TestYieldingSlowReads) {
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = SlowReads;

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  MockRead reads[] = {
      CreateMockRead(resp1, 1), MockRead(ASYNC, 0, 2)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to verify that SpdySession::DoReadLoop posts a
  // task.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  EXPECT_EQ(0u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify that SpdySession::DoReadLoop has posted a
  // task.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_FALSE(spdy_stream1);

  // Verify task that the observer's executed_count is 1, which indicates DoRead
  // has posted only one task and thus yielded though there is data available
  // for it to read.
  EXPECT_EQ(1u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Regression test for https://crbug.com/531570.
// Test the case where DoRead() takes long but returns synchronously.
TEST_F(SpdySessionTest, TestYieldingSlowSynchronousReads) {
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = SlowReads;

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  SpdySerializedFrame partial_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "foo ", 4, /*fin=*/false));
  SpdySerializedFrame finish_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "bar", 3, /*fin=*/true));

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(partial_data_frame, 3, ASYNC),
      CreateMockRead(partial_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 6, SYNCHRONOUS),
      MockRead(ASYNC, 0, 7)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());

  // Read all the data and verify SpdySession::DoReadLoop has posted a task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ("foo foo foo bar", delegate1.TakeReceivedData());
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Test that SpdySession::DoReadLoop yields while reading the
// data. This test makes 32k + 1 bytes of data available on the socket
// for reading. It then verifies that DoRead has yielded even though
// there is data available for it to read (i.e, socket()->Read didn't
// return ERR_IO_PENDING during socket reads).
TEST_F(SpdySessionTest, TestYieldingDuringReadData) {
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = InstantaneousReads;

  BufferedSpdyFramer framer;

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  // Build buffer of size kYieldAfterBytesRead / 4
  // (-spdy_data_frame_size).
  ASSERT_EQ(32 * 1024, kYieldAfterBytesRead);
  const int kPayloadSize =
      kYieldAfterBytesRead / 4 - framer.GetFrameHeaderSize();
  TestDataStream test_stream;
  scoped_refptr<IOBuffer> payload(new IOBuffer(kPayloadSize));
  char* payload_data = payload->data();
  test_stream.GetBytes(payload_data, kPayloadSize);

  SpdySerializedFrame partial_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, payload_data, kPayloadSize, /*fin=*/false));
  SpdySerializedFrame finish_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "h", 1, /*fin=*/true));

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  // Write 1 byte more than kMaxReadBytes to check that DoRead yields.
  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(partial_data_frame, 3),
      CreateMockRead(partial_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(partial_data_frame, 6, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 7, SYNCHRONOUS),
      MockRead(ASYNC, 0, 8)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to verify SpdySession::DoReadLoop posts a task.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify SpdySession::DoReadLoop has posted a task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);

  // Verify task observer's executed_count is 1, which indicates DoRead has
  // posted only one task and thus yielded though there is data available for it
  // to read.
  EXPECT_EQ(1u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Test that SpdySession::DoReadLoop() tests interactions of yielding
// + async, by doing the following MockReads.
//
// MockRead of SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 2K
// ASYNC 8K, SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 8K, SYNCHRONOUS 2K.
//
// The above reads 26K synchronously. Since that is less that 32K, we
// will attempt to read again. However, that DoRead() will return
// ERR_IO_PENDING (because of async read), so DoReadLoop() will
// yield. When we come back, DoRead() will read the results from the
// async read, and rest of the data synchronously.
TEST_F(SpdySessionTest, TestYieldingDuringAsyncReadData) {
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.time_func = InstantaneousReads;

  BufferedSpdyFramer framer;

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  // Build buffer of size kYieldAfterBytesRead / 4
  // (-spdy_data_frame_size).
  ASSERT_EQ(32 * 1024, kYieldAfterBytesRead);
  TestDataStream test_stream;
  const int kEightKPayloadSize =
      kYieldAfterBytesRead / 4 - framer.GetFrameHeaderSize();
  scoped_refptr<IOBuffer> eightk_payload(new IOBuffer(kEightKPayloadSize));
  char* eightk_payload_data = eightk_payload->data();
  test_stream.GetBytes(eightk_payload_data, kEightKPayloadSize);

  // Build buffer of 2k size.
  TestDataStream test_stream2;
  const int kTwoKPayloadSize = kEightKPayloadSize - 6 * 1024;
  scoped_refptr<IOBuffer> twok_payload(new IOBuffer(kTwoKPayloadSize));
  char* twok_payload_data = twok_payload->data();
  test_stream2.GetBytes(twok_payload_data, kTwoKPayloadSize);

  SpdySerializedFrame eightk_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, eightk_payload_data, kEightKPayloadSize, /*fin=*/false));
  SpdySerializedFrame twok_data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, twok_payload_data, kTwoKPayloadSize, /*fin=*/false));
  SpdySerializedFrame finish_data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "h", 1, /*fin=*/true));

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  MockRead reads[] = {
      CreateMockRead(resp1, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(eightk_data_frame, 3),
      CreateMockRead(eightk_data_frame, 4, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 5, SYNCHRONOUS),
      CreateMockRead(twok_data_frame, 6, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 7, ASYNC),
      CreateMockRead(eightk_data_frame, 8, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 9, SYNCHRONOUS),
      CreateMockRead(eightk_data_frame, 10, SYNCHRONOUS),
      CreateMockRead(twok_data_frame, 11, SYNCHRONOUS),
      CreateMockRead(finish_data_frame, 12, SYNCHRONOUS),
      MockRead(ASYNC, 0, 13)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Set up the TaskObserver to monitor SpdySession::DoReadLoop
  // posting of tasks.
  SpdySessionTestTaskObserver observer("spdy_session.cc", "DoReadLoop");

  // Run until 1st read.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(0u, observer.executed_count());

  // Read all the data and verify SpdySession::DoReadLoop has posted a
  // task.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);

  // Verify task observer's executed_count is 1, which indicates DoRead has
  // posted only one task and thus yielded though there is data available for
  // it to read.
  EXPECT_EQ(1u, observer.executed_count());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Send a GoAway frame when SpdySession is in DoReadLoop. Make sure
// nothing blows up.
TEST_F(SpdySessionTest, GoAwayWhileInDoReadLoop) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway());

  MockRead reads[] = {
      CreateMockRead(resp1, 1), MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(body1, 3), CreateMockRead(goaway, 4),
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  // Run until 1st read.
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, spdy_stream1->stream_id());

  // Run until GoAway.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream1);
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_FALSE(session_);
}

// Within this framework, a SpdySession should be initialized with
// flow control disabled for protocol version 2, with flow control
// enabled only for streams for protocol version 3, and with flow
// control enabled for streams and sessions for higher versions.
TEST_F(SpdySessionTest, ProtocolNegotiation) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  CreateNetworkSession();
  session_ = CreateFakeSpdySession(spdy_session_pool_, key_);

  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_send_window_size_);
  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);
}

// Tests the case of a non-SPDY request closing an idle SPDY session when no
// pointers to the idle session are currently held.
TEST_F(SpdySessionTest, CloseOneIdleConnection) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();

  TransportClientSocketPool* pool =
      http_session_->GetTransportSocketPool(
          HttpNetworkSession::NORMAL_SOCKET_POOL);

  // Create an idle SPDY session.
  CreateSecureSpdySession();
  EXPECT_FALSE(pool->IsStalled());

  // Trying to create a new connection should cause the pool to be stalled, and
  // post a task asynchronously to try and close the session.
  TestCompletionCallback callback2;
  HostPortPair host_port2("2.com", 80);
  scoped_refptr<TransportSocketParams> params2(new TransportSocketParams(
      host_port2, false, OnHostResolutionCallback(),
      TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DEFAULT));
  std::unique_ptr<ClientSocketHandle> connection2(new ClientSocketHandle);
  EXPECT_EQ(ERR_IO_PENDING,
            connection2->Init(host_port2.ToString(), params2, DEFAULT_PRIORITY,
                              ClientSocketPool::RespectLimits::ENABLED,
                              callback2.callback(), pool, NetLogWithSource()));
  EXPECT_TRUE(pool->IsStalled());

  // The socket pool should close the connection asynchronously and establish a
  // new connection.
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(pool->IsStalled());
  EXPECT_FALSE(session_);
}

// Tests the case of a non-SPDY request closing an idle SPDY session when no
// pointers to the idle session are currently held, in the case the SPDY session
// has an alias.
TEST_F(SpdySessionTest, CloseOneIdleConnectionWithAlias) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.host_resolver->rules()->AddIPLiteralRule(
      "www.example.org", "192.168.0.2", std::string());
  session_deps_.host_resolver->rules()->AddIPLiteralRule(
      "mail.example.org", "192.168.0.2", std::string());
  // Not strictly needed.
  session_deps_.host_resolver->rules()->AddIPLiteralRule(
      "3.com", "192.168.0.3", std::string());

  CreateNetworkSession();

  TransportClientSocketPool* pool =
      http_session_->GetTransportSocketPool(
          HttpNetworkSession::NORMAL_SOCKET_POOL);

  // Create an idle SPDY session.
  SpdySessionKey key1(HostPortPair("www.example.org", 80),
                      ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> session1 = ::net::CreateSecureSpdySession(
      http_session_.get(), key1, NetLogWithSource());
  EXPECT_FALSE(pool->IsStalled());

  // Set up an alias for the idle SPDY session, increasing its ref count to 2.
  SpdySessionKey key2(HostPortPair("mail.example.org", 80),
                      ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  HostResolver::RequestInfo info(key2.host_port_pair());
  AddressList addresses;
  std::unique_ptr<HostResolver::Request> request;
  // Pre-populate the DNS cache, since a synchronous resolution is required in
  // order to create the alias.
  session_deps_.host_resolver->Resolve(info, DEFAULT_PRIORITY, &addresses,
                                       CompletionCallback(), &request,
                                       NetLogWithSource());
  // Get a session for |key2|, which should return the session created earlier.
  base::WeakPtr<SpdySession> session2 =
      spdy_session_pool_->FindAvailableSession(key2, GURL(),
                                               NetLogWithSource());
  ASSERT_EQ(session1.get(), session2.get());
  EXPECT_FALSE(pool->IsStalled());

  // Trying to create a new connection should cause the pool to be stalled, and
  // post a task asynchronously to try and close the session.
  TestCompletionCallback callback3;
  HostPortPair host_port3("3.com", 80);
  scoped_refptr<TransportSocketParams> params3(new TransportSocketParams(
      host_port3, false, OnHostResolutionCallback(),
      TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DEFAULT));
  std::unique_ptr<ClientSocketHandle> connection3(new ClientSocketHandle);
  EXPECT_EQ(ERR_IO_PENDING,
            connection3->Init(host_port3.ToString(), params3, DEFAULT_PRIORITY,
                              ClientSocketPool::RespectLimits::ENABLED,
                              callback3.callback(), pool, NetLogWithSource()));
  EXPECT_TRUE(pool->IsStalled());

  // The socket pool should close the connection asynchronously and establish a
  // new connection.
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(pool->IsStalled());
  EXPECT_FALSE(session1);
  EXPECT_FALSE(session2);
}

// Tests that when a SPDY session becomes idle, it closes itself if there is
// a lower layer pool stalled on the per-pool socket limit.
TEST_F(SpdySessionTest, CloseSessionOnIdleWhenPoolStalled) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame cancel1(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req1, 1), CreateMockWrite(cancel1, 1),
  };
  StaticSocketDataProvider data(reads, arraysize(reads),
                                writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  MockRead http_reads[] = {
    MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads), nullptr,
                                     0);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  AddSSLSocketData();

  CreateNetworkSession();

  TransportClientSocketPool* pool =
      http_session_->GetTransportSocketPool(
          HttpNetworkSession::NORMAL_SOCKET_POOL);

  // Create a SPDY session.
  CreateSecureSpdySession();
  EXPECT_FALSE(pool->IsStalled());

  // Create a stream using the session, and send a request.

  TestCompletionCallback callback1;
  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, test_url_, DEFAULT_PRIORITY,
      NetLogWithSource());
  ASSERT_TRUE(spdy_stream1.get());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers1(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, spdy_stream1->SendRequestHeaders(
                                std::move(headers1), NO_MORE_DATA_TO_SEND));

  base::RunLoop().RunUntilIdle();

  // Trying to create a new connection should cause the pool to be stalled, and
  // post a task asynchronously to try and close the session.
  TestCompletionCallback callback2;
  HostPortPair host_port2("2.com", 80);
  scoped_refptr<TransportSocketParams> params2(new TransportSocketParams(
      host_port2, false, OnHostResolutionCallback(),
      TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DEFAULT));
  std::unique_ptr<ClientSocketHandle> connection2(new ClientSocketHandle);
  EXPECT_EQ(ERR_IO_PENDING,
            connection2->Init(host_port2.ToString(), params2, DEFAULT_PRIORITY,
                              ClientSocketPool::RespectLimits::ENABLED,
                              callback2.callback(), pool, NetLogWithSource()));
  EXPECT_TRUE(pool->IsStalled());

  // Running the message loop should cause the socket pool to ask the SPDY
  // session to close an idle socket, but since the socket is in use, nothing
  // happens.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(pool->IsStalled());
  EXPECT_FALSE(callback2.have_result());

  // Cancelling the request should result in the session's socket being
  // closed, since the pool is stalled.
  ASSERT_TRUE(spdy_stream1.get());
  spdy_stream1->Cancel();
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(pool->IsStalled());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
}

// Verify that SpdySessionKey and therefore SpdySession is different when
// privacy mode is enabled or disabled.
TEST_F(SpdySessionTest, SpdySessionKeyPrivacyMode) {
  CreateNetworkSession();

  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key_privacy_enabled(host_port_pair, ProxyServer::Direct(),
                                     PRIVACY_MODE_ENABLED);
  SpdySessionKey key_privacy_disabled(host_port_pair, ProxyServer::Direct(),
                                     PRIVACY_MODE_DISABLED);

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  // Add SpdySession with PrivacyMode Enabled to the pool.
  base::WeakPtr<SpdySession> session_privacy_enabled =
      CreateFakeSpdySession(spdy_session_pool_, key_privacy_enabled);

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  // Add SpdySession with PrivacyMode Disabled to the pool.
  base::WeakPtr<SpdySession> session_privacy_disabled =
      CreateFakeSpdySession(spdy_session_pool_, key_privacy_disabled);

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  session_privacy_enabled->CloseSessionOnError(ERR_ABORTED, std::string());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));

  session_privacy_disabled->CloseSessionOnError(ERR_ABORTED, std::string());
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_enabled));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_privacy_disabled));
}

// Delegate that creates another stream when its stream is closed.
class StreamCreatingDelegate : public test::StreamDelegateDoNothing {
 public:
  StreamCreatingDelegate(const base::WeakPtr<SpdyStream>& stream,
                         const base::WeakPtr<SpdySession>& session)
      : StreamDelegateDoNothing(stream),
        session_(session) {}

  ~StreamCreatingDelegate() override {}

  void OnClose(int status) override {
    GURL url(kDefaultUrl);
    ignore_result(CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM,
                                            session_, url, MEDIUM,
                                            NetLogWithSource()));
  }

 private:
  const base::WeakPtr<SpdySession> session_;
};

// Create another stream in response to a stream being reset. Nothing
// should blow up. This is a regression test for
// http://crbug.com/263690 .
TEST_F(SpdySessionTest, CreateStreamOnStreamReset) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_REFUSED_STREAM));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), MockRead(ASYNC, 0, 4)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());

  StreamCreatingDelegate delegate(spdy_stream, session_);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream->stream_id());

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream->stream_id());

  // Cause the stream to be reset, which should cause another stream
  // to be created.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream);
  EXPECT_TRUE(delegate.StreamIsClosed());
  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, UpdateStreamsSendWindowSize) {
  // Set SETTINGS_INITIAL_WINDOW_SIZE to a small number so that WINDOW_UPDATE
  // gets sent.
  SettingsMap new_settings;
  int32_t window_size = 1;
  new_settings[SETTINGS_INITIAL_WINDOW_SIZE] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, window_size);

  // Set up the socket so we read a SETTINGS frame that sets
  // INITIAL_WINDOW_SIZE.
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));
  MockRead reads[] = {
      CreateMockRead(settings_frame, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };

  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {
      CreateMockWrite(settings_ack, 3),
  };

  session_deps_.host_resolver->set_synchronous_mode(true);

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  TestCompletionCallback callback1;
  EXPECT_NE(spdy_stream1->send_window_size(), window_size);

  // Process the SETTINGS frame.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(session_->stream_initial_send_window_size(), window_size);
  EXPECT_EQ(spdy_stream1->send_window_size(), window_size);

  // Release the first one, this will allow the second to be created.
  spdy_stream1->Cancel();
  EXPECT_FALSE(spdy_stream1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);
  EXPECT_EQ(spdy_stream2->send_window_size(), window_size);
  spdy_stream2->Cancel();
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// SpdySession::{Increase,Decrease}RecvWindowSize should properly
// adjust the session receive window size. In addition,
// SpdySession::IncreaseRecvWindowSize should trigger
// sending a WINDOW_UPDATE frame for a large enough delta.
TEST_F(SpdySessionTest, AdjustRecvWindowSize) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  const int32_t delta_window_size = 100;

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), MockRead(ASYNC, 0, 2)  // EOF
  };
  SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      kSessionFlowControlStreamId, initial_window_size + delta_window_size));
  MockWrite writes[] = {
      CreateMockWrite(window_update, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  session_->IncreaseRecvWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size + delta_window_size,
            session_->session_recv_window_size_);
  EXPECT_EQ(delta_window_size, session_->session_unacked_recv_window_bytes_);

  // Should trigger sending a WINDOW_UPDATE frame.
  session_->IncreaseRecvWindowSize(initial_window_size);
  EXPECT_EQ(initial_window_size + delta_window_size + initial_window_size,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  base::RunLoop().RunUntilIdle();

  // DecreaseRecvWindowSize() expects |in_io_loop_| to be true.
  session_->in_io_loop_ = true;
  session_->DecreaseRecvWindowSize(initial_window_size + delta_window_size +
                                   initial_window_size);
  session_->in_io_loop_ = false;
  EXPECT_EQ(0, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// SpdySession::{Increase,Decrease}SendWindowSize should properly
// adjust the session send window size when the "enable_spdy_31" flag
// is set.
TEST_F(SpdySessionTest, AdjustSendWindowSize) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
    MockRead(SYNCHRONOUS, 0, 0)  // EOF
  };
  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  CreateNetworkSession();
  session_ = CreateFakeSpdySession(spdy_session_pool_, key_);

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  const int32_t delta_window_size = 100;

  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);

  session_->IncreaseSendWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size + delta_window_size,
            session_->session_send_window_size_);

  session_->DecreaseSendWindowSize(delta_window_size);
  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);
}

// Incoming data for an inactive stream should not cause the session
// receive window size to decrease, but it should cause the unacked
// bytes to increase.
TEST_F(SpdySessionTest, SessionFlowControlInactiveStream) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyDataFrame(1, false));
  MockRead reads[] = {
      CreateMockRead(resp, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize, session_->session_unacked_recv_window_bytes_);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// The frame header is not included in flow control, but frame payload
// (including optional pad length and padding) is.
TEST_F(SpdySessionTest, SessionFlowControlPadding) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  const int padding_length = 42;
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyDataFrame(
      1, kUploadData, kUploadDataSize, false, padding_length));
  MockRead reads[] = {
      CreateMockRead(resp, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(kDefaultInitialWindowSize, session_->session_recv_window_size_);
  EXPECT_EQ(kUploadDataSize + padding_length,
            session_->session_unacked_recv_window_bytes_);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Peer sends more data than stream level receiving flow control window.
TEST_F(SpdySessionTest, StreamFlowControlTooMuchData) {
  const int32_t stream_max_recv_window_size = 1024;
  const int32_t data_frame_size = 2 * stream_max_recv_window_size;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_FLOW_CONTROL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const std::string payload(data_frame_size, 'a');
  SpdySerializedFrame data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, payload.data(), data_frame_size, false));
  MockRead reads[] = {
      CreateMockRead(resp, 1),       MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(data_frame, 3), MockRead(ASYNC, ERR_IO_PENDING, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();

  SpdySessionPoolPeer pool_peer(spdy_session_pool_);
  pool_peer.SetStreamInitialRecvWindowSize(stream_max_recv_window_size);
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  EXPECT_EQ(stream_max_recv_window_size, spdy_stream->recv_window_size());

  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, spdy_stream->SendRequestHeaders(
                                std::move(headers), NO_MORE_DATA_TO_SEND));

  // Request and response.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, spdy_stream->stream_id());

  // Too large data frame causes flow control error, should close stream.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Regression test for a bug that was caused by including unsent WINDOW_UPDATE
// deltas in the receiving window size when checking incoming frames for flow
// control errors at session level.
TEST_F(SpdySessionTest, SessionFlowControlTooMuchDataTwoDataFrames) {
  const int32_t session_max_recv_window_size = 500;
  const int32_t first_data_frame_size = 200;
  const int32_t second_data_frame_size = 400;

  // First data frame should not trigger a WINDOW_UPDATE.
  ASSERT_GT(session_max_recv_window_size / 2, first_data_frame_size);
  // Second data frame would be fine had there been a WINDOW_UPDATE.
  ASSERT_GT(session_max_recv_window_size, second_data_frame_size);
  // But in fact, the two data frames together overflow the receiving window at
  // session level.
  ASSERT_LT(session_max_recv_window_size,
            first_data_frame_size + second_data_frame_size);

  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_FLOW_CONTROL_ERROR,
      "delta_window_size is 400 in DecreaseRecvWindowSize, which is larger "
      "than the receive window size of 500"));
  MockWrite writes[] = {
      CreateMockWrite(goaway, 4),
  };

  const std::string first_data_frame(first_data_frame_size, 'a');
  SpdySerializedFrame first(spdy_util_.ConstructSpdyDataFrame(
      1, first_data_frame.data(), first_data_frame_size, false));
  const std::string second_data_frame(second_data_frame_size, 'b');
  SpdySerializedFrame second(spdy_util_.ConstructSpdyDataFrame(
      1, second_data_frame.data(), second_data_frame_size, false));
  MockRead reads[] = {
      CreateMockRead(first, 0), MockRead(ASYNC, ERR_IO_PENDING, 1),
      CreateMockRead(second, 2), MockRead(ASYNC, 0, 3),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  // Setting session level receiving window size to smaller than initial is not
  // possible via SpdySessionPoolPeer.
  session_->session_recv_window_size_ = session_max_recv_window_size;

  // First data frame is immediately consumed and does not trigger
  // WINDOW_UPDATE.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(first_data_frame_size,
            session_->session_unacked_recv_window_bytes_);
  EXPECT_EQ(session_max_recv_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(SpdySession::STATE_AVAILABLE, session_->availability_state_);

  // Second data frame overflows receiving window, causes session to close.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(SpdySession::STATE_DRAINING, session_->availability_state_);
}

// Regression test for a bug that was caused by including unsent WINDOW_UPDATE
// deltas in the receiving window size when checking incoming data frames for
// flow control errors at stream level.
TEST_F(SpdySessionTest, StreamFlowControlTooMuchDataTwoDataFrames) {
  const int32_t stream_max_recv_window_size = 500;
  const int32_t first_data_frame_size = 200;
  const int32_t second_data_frame_size = 400;

  // First data frame should not trigger a WINDOW_UPDATE.
  ASSERT_GT(stream_max_recv_window_size / 2, first_data_frame_size);
  // Second data frame would be fine had there been a WINDOW_UPDATE.
  ASSERT_GT(stream_max_recv_window_size, second_data_frame_size);
  // But in fact, they should overflow the receiving window at stream level.
  ASSERT_LT(stream_max_recv_window_size,
            first_data_frame_size + second_data_frame_size);

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_FLOW_CONTROL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 6),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  const std::string first_data_frame(first_data_frame_size, 'a');
  SpdySerializedFrame first(spdy_util_.ConstructSpdyDataFrame(
      1, first_data_frame.data(), first_data_frame_size, false));
  const std::string second_data_frame(second_data_frame_size, 'b');
  SpdySerializedFrame second(spdy_util_.ConstructSpdyDataFrame(
      1, second_data_frame.data(), second_data_frame_size, false));
  MockRead reads[] = {
      CreateMockRead(resp, 1),   MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(first, 3),  MockRead(ASYNC, ERR_IO_PENDING, 4),
      CreateMockRead(second, 5), MockRead(ASYNC, ERR_IO_PENDING, 7),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  SpdySessionPoolPeer pool_peer(spdy_session_pool_);
  pool_peer.SetStreamInitialRecvWindowSize(stream_max_recv_window_size);

  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  EXPECT_EQ(ERR_IO_PENDING, spdy_stream->SendRequestHeaders(
                                std::move(headers), NO_MORE_DATA_TO_SEND));

  // Request and response.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(spdy_stream->IsLocallyClosed());
  EXPECT_EQ(stream_max_recv_window_size, spdy_stream->recv_window_size());

  // First data frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(spdy_stream->IsLocallyClosed());
  EXPECT_EQ(stream_max_recv_window_size - first_data_frame_size,
            spdy_stream->recv_window_size());

  // Consume first data frame.  This does not trigger a WINDOW_UPDATE.
  std::string received_data = delegate.TakeReceivedData();
  EXPECT_EQ(static_cast<size_t>(first_data_frame_size), received_data.size());
  EXPECT_EQ(stream_max_recv_window_size, spdy_stream->recv_window_size());

  // Second data frame overflows receiving window, causes the stream to close.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(spdy_stream.get());

  // RST_STREAM
  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// A delegate that drops any received data.
class DropReceivedDataDelegate : public test::StreamDelegateSendImmediate {
 public:
  DropReceivedDataDelegate(const base::WeakPtr<SpdyStream>& stream,
                           base::StringPiece data)
      : StreamDelegateSendImmediate(stream, data) {}

  ~DropReceivedDataDelegate() override {}

  // Drop any received data.
  void OnDataReceived(std::unique_ptr<SpdyBuffer> buffer) override {}
};

// Send data back and forth but use a delegate that drops its received
// data. The receive window should still increase to its original
// value, i.e. we shouldn't "leak" receive window bytes.
TEST_F(SpdySessionTest, SessionFlowControlNoReceiveLeaks) {
  const int32_t kMsgDataSize = 100;
  const std::string msg_data(kMsgDataSize, 'a');

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMsgDataSize, MEDIUM, nullptr, 0));
  SpdySerializedFrame msg(spdy_util_.ConstructSpdyDataFrame(
      1, msg_data.data(), kMsgDataSize, false));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(msg, 2),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame echo(spdy_util_.ConstructSpdyDataFrame(
      1, msg_data.data(), kMsgDataSize, false));
  SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      kSessionFlowControlStreamId, kMsgDataSize));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(echo, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(0u, stream->stream_id());

  DropReceivedDataDelegate delegate(stream, msg_data);
  stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kMsgDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(kMsgDataSize, session_->session_unacked_recv_window_bytes_);

  stream->Close();
  EXPECT_FALSE(stream);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());

  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(kMsgDataSize, session_->session_unacked_recv_window_bytes_);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Send data back and forth but close the stream before its data frame
// can be written to the socket. The send window should then increase
// to its original value, i.e. we shouldn't "leak" send window bytes.
TEST_F(SpdySessionTest, SessionFlowControlNoSendLeaks) {
  const int32_t kMsgDataSize = 100;
  const std::string msg_data(kMsgDataSize, 'a');

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMsgDataSize, MEDIUM, nullptr, 0));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(0u, stream->stream_id());

  test::StreamDelegateSendImmediate delegate(stream, msg_data);
  stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kMsgDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);

  // Write request.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);

  // Read response, but do not run the message loop, so that the body is not
  // written to the socket.
  data.Resume();

  EXPECT_EQ(initial_window_size - kMsgDataSize,
            session_->session_send_window_size_);

  // Closing the stream should increase the session's send window.
  stream->Close();
  EXPECT_FALSE(stream);

  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Send data back and forth; the send and receive windows should
// change appropriately.
TEST_F(SpdySessionTest, SessionFlowControlEndToEnd) {
  const int32_t kMsgDataSize = 100;
  const std::string msg_data(kMsgDataSize, 'a');

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMsgDataSize, MEDIUM, nullptr, 0));
  SpdySerializedFrame msg(spdy_util_.ConstructSpdyDataFrame(
      1, msg_data.data(), kMsgDataSize, false));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(msg, 2),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame echo(spdy_util_.ConstructSpdyDataFrame(
      1, msg_data.data(), kMsgDataSize, false));
  SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      kSessionFlowControlStreamId, kMsgDataSize));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(echo, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),
      CreateMockRead(window_update, 6),
      MockRead(ASYNC, ERR_IO_PENDING, 7),
      MockRead(ASYNC, 0, 8)  // EOF
  };

  // Create SpdySession and SpdyStream and send the request.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.host_resolver->set_synchronous_mode(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_, test_url_,
                                MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream);
  EXPECT_EQ(0u, stream->stream_id());

  test::StreamDelegateSendImmediate delegate(stream, msg_data);
  stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kMsgDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));

  const int32_t initial_window_size = kDefaultInitialWindowSize;
  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);
  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Send request and message.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size - kMsgDataSize,
            session_->session_send_window_size_);
  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Read echo.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size - kMsgDataSize,
            session_->session_send_window_size_);
  EXPECT_EQ(initial_window_size - kMsgDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  // Read window update.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);
  EXPECT_EQ(initial_window_size - kMsgDataSize,
            session_->session_recv_window_size_);
  EXPECT_EQ(0, session_->session_unacked_recv_window_bytes_);

  EXPECT_EQ(msg_data, delegate.TakeReceivedData());

  // Draining the delegate's read queue should increase the session's
  // receive window.
  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);
  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(kMsgDataSize, session_->session_unacked_recv_window_bytes_);

  stream->Close();
  EXPECT_FALSE(stream);

  EXPECT_THAT(delegate.WaitForClose(), IsOk());

  EXPECT_EQ(initial_window_size, session_->session_send_window_size_);
  EXPECT_EQ(initial_window_size, session_->session_recv_window_size_);
  EXPECT_EQ(kMsgDataSize, session_->session_unacked_recv_window_bytes_);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Given a stall function and an unstall function, runs a test to make
// sure that a stream resumes after unstall.
void SpdySessionTest::RunResumeAfterUnstallTest(
    const base::Callback<void(SpdyStream*)>& stall_function,
    const base::Callback<void(SpdyStream*, int32_t)>& unstall_function) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyData, kBodyDataSize, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame echo(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyData, kBodyDataSize, false));
  MockRead reads[] = {
      CreateMockRead(resp, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream);

  test::StreamDelegateWithBody delegate(stream, kBodyDataStringPiece);
  stream->SetDelegate(&delegate);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  SpdyHeaderBlock headers(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING,
            stream->SendRequestHeaders(std::move(headers), MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream->GetUrlFromHeaders().spec());

  stall_function.Run(stream.get());

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream->send_stalled_by_flow_control());

  unstall_function.Run(stream.get(), kBodyDataSize);

  EXPECT_FALSE(stream->send_stalled_by_flow_control());

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate.send_headers_completed());
  EXPECT_EQ("200", delegate.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate.TakeReceivedData());
  EXPECT_FALSE(session_);
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Run the resume-after-unstall test with all possible stall and
// unstall sequences.

TEST_F(SpdySessionTest, ResumeAfterUnstallSession) {
  RunResumeAfterUnstallTest(
      base::Bind(&SpdySessionTest::StallSessionOnly,
                 base::Unretained(this)),
      base::Bind(&SpdySessionTest::UnstallSessionOnly,
                 base::Unretained(this)));
}

// Equivalent to
// SpdyStreamTest.ResumeAfterSendWindowSizeIncrease.
TEST_F(SpdySessionTest, ResumeAfterUnstallStream) {
  RunResumeAfterUnstallTest(
      base::Bind(&SpdySessionTest::StallStreamOnly,
                 base::Unretained(this)),
      base::Bind(&SpdySessionTest::UnstallStreamOnly,
                 base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallSessionStreamResumeAfterUnstallSessionStream) {
  RunResumeAfterUnstallTest(
      base::Bind(&SpdySessionTest::StallSessionStream,
                 base::Unretained(this)),
      base::Bind(&SpdySessionTest::UnstallSessionStream,
                 base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallStreamSessionResumeAfterUnstallSessionStream) {
  RunResumeAfterUnstallTest(
      base::Bind(&SpdySessionTest::StallStreamSession,
                 base::Unretained(this)),
      base::Bind(&SpdySessionTest::UnstallSessionStream,
                 base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallStreamSessionResumeAfterUnstallStreamSession) {
  RunResumeAfterUnstallTest(
      base::Bind(&SpdySessionTest::StallStreamSession,
                 base::Unretained(this)),
      base::Bind(&SpdySessionTest::UnstallStreamSession,
                 base::Unretained(this)));
}

TEST_F(SpdySessionTest, StallSessionStreamResumeAfterUnstallStreamSession) {
  RunResumeAfterUnstallTest(
      base::Bind(&SpdySessionTest::StallSessionStream,
                 base::Unretained(this)),
      base::Bind(&SpdySessionTest::UnstallStreamSession,
                 base::Unretained(this)));
}

// Cause a stall by reducing the flow control send window to 0. The
// streams should resume in priority order when that window is then
// increased.
TEST_F(SpdySessionTest, ResumeByPriorityAfterSendWindowSizeIncrease) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, MEDIUM, nullptr, 0));
  SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyData, kBodyDataSize, true));
  SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, kBodyData, kBodyDataSize, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
      CreateMockWrite(body2, 2), CreateMockWrite(body1, 3),
  };

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {
      CreateMockRead(resp1, 4), CreateMockRead(resp2, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(stream2);

  test::StreamDelegateWithBody delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  StallSessionSend();

  SpdyHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  SpdyHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  // This should unstall only stream2.
  UnstallSessionSend(kBodyDataSize);

  EXPECT_TRUE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  // This should then unstall stream1.
  UnstallSessionSend(kBodyDataSize);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ("200", delegate1.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ("200", delegate2.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_FALSE(session_);
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Delegate that closes a given stream after sending its body.
class StreamClosingDelegate : public test::StreamDelegateWithBody {
 public:
  StreamClosingDelegate(const base::WeakPtr<SpdyStream>& stream,
                        base::StringPiece data)
      : StreamDelegateWithBody(stream, data) {}

  ~StreamClosingDelegate() override {}

  void set_stream_to_close(const base::WeakPtr<SpdyStream>& stream_to_close) {
    stream_to_close_ = stream_to_close;
  }

  void OnDataSent() override {
    test::StreamDelegateWithBody::OnDataSent();
    if (stream_to_close_.get()) {
      stream_to_close_->Close();
      EXPECT_FALSE(stream_to_close_);
    }
  }

 private:
  base::WeakPtr<SpdyStream> stream_to_close_;
};

// Cause a stall by reducing the flow control send window to
// 0. Unstalling the session should properly handle deleted streams.
TEST_F(SpdySessionTest, SendWindowSizeIncreaseWithDeletedStreams) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame req3(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 5, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, kBodyData, kBodyDataSize, true));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
      CreateMockWrite(req3, 2), CreateMockWrite(body2, 3),
  };

  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead reads[] = {
      CreateMockRead(resp2, 4), MockRead(ASYNC, ERR_IO_PENDING, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream2);

  StreamClosingDelegate delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  base::WeakPtr<SpdyStream> stream3 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream3);

  test::StreamDelegateWithBody delegate3(stream3, kBodyDataStringPiece);
  stream3->SetDelegate(&delegate3);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());
  EXPECT_FALSE(stream3->send_stalled_by_flow_control());

  StallSessionSend();

  SpdyHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  SpdyHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  SpdyHeaderBlock headers3(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream3->SendRequestHeaders(std::move(headers3),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream3->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(5u, stream3->stream_id());
  EXPECT_TRUE(stream3->send_stalled_by_flow_control());

  SpdyStreamId stream_id1 = stream1->stream_id();
  SpdyStreamId stream_id2 = stream2->stream_id();
  SpdyStreamId stream_id3 = stream3->stream_id();

  // Close stream1 preemptively.
  session_->CloseActiveStream(stream_id1, ERR_CONNECTION_CLOSED);
  EXPECT_FALSE(stream1);

  EXPECT_FALSE(session_->IsStreamActive(stream_id1));
  EXPECT_TRUE(session_->IsStreamActive(stream_id2));
  EXPECT_TRUE(session_->IsStreamActive(stream_id3));

  // Unstall stream2, which should then close stream3.
  delegate2.set_stream_to_close(stream3);
  UnstallSessionSend(kBodyDataSize);

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream3);

  EXPECT_FALSE(stream2->send_stalled_by_flow_control());
  EXPECT_FALSE(session_->IsStreamActive(stream_id1));
  EXPECT_TRUE(session_->IsStreamActive(stream_id2));
  EXPECT_FALSE(session_->IsStreamActive(stream_id3));

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(stream2);
  EXPECT_FALSE(session_);

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate3.WaitForClose(), IsOk());

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ("200", delegate2.GetResponseHeaderValue(":status"));
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_TRUE(delegate3.send_headers_completed());
  EXPECT_EQ(std::string(), delegate3.TakeReceivedData());

  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Cause a stall by reducing the flow control send window to
// 0. Unstalling the session should properly handle the session itself
// being closed.
TEST_F(SpdySessionTest, SendWindowSizeIncreaseWithDeletedSession) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  SpdySerializedFrame req1(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame req2(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 3, kBodyDataSize, LOWEST, nullptr, 0));
  SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(1, kBodyData, kBodyDataSize, false));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream1);

  test::StreamDelegateWithBody delegate1(stream1, kBodyDataStringPiece);
  stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(stream2);

  test::StreamDelegateWithBody delegate2(stream2, kBodyDataStringPiece);
  stream2->SetDelegate(&delegate2);

  EXPECT_FALSE(stream1->send_stalled_by_flow_control());
  EXPECT_FALSE(stream2->send_stalled_by_flow_control());

  StallSessionSend();

  SpdyHeaderBlock headers1(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream1->SendRequestHeaders(std::move(headers1),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream1->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, stream1->stream_id());
  EXPECT_TRUE(stream1->send_stalled_by_flow_control());

  SpdyHeaderBlock headers2(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kBodyDataSize));
  EXPECT_EQ(ERR_IO_PENDING, stream2->SendRequestHeaders(std::move(headers2),
                                                        MORE_DATA_TO_SEND));
  EXPECT_EQ(kDefaultUrl, stream2->GetUrlFromHeaders().spec());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, stream2->stream_id());
  EXPECT_TRUE(stream2->send_stalled_by_flow_control());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Unstall stream1.
  UnstallSessionSend(kBodyDataSize);

  // Close the session (since we can't do it from within the delegate
  // method, since it's in the stream's loop).
  session_->CloseSessionOnError(ERR_CONNECTION_CLOSED, "Closing session");
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_THAT(delegate1.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));
  EXPECT_THAT(delegate2.WaitForClose(), IsError(ERR_CONNECTION_CLOSED));

  EXPECT_TRUE(delegate1.send_headers_completed());
  EXPECT_EQ(std::string(), delegate1.TakeReceivedData());

  EXPECT_TRUE(delegate2.send_headers_completed());
  EXPECT_EQ(std::string(), delegate2.TakeReceivedData());

  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdySessionTest, GoAwayOnSessionFlowControlError) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_FLOW_CONTROL_ERROR,
      "delta_window_size is 6 in DecreaseRecvWindowSize, which is larger than "
      "the receive window size of 1"));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(goaway, 4),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Write request.
  base::RunLoop().RunUntilIdle();

  // Put session on the edge of overflowing it's recv window.
  session_->session_recv_window_size_ = 1;

  // Read response headers & body. Body overflows the session window, and a
  // goaway is written.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(delegate.WaitForClose(), IsError(ERR_SPDY_FLOW_CONTROL_ERROR));
  EXPECT_FALSE(session_);
}

// Regression. Sorta. Push streams and client streams were sharing a single
// limit for a long time.
TEST_F(SpdySessionTest, PushedStreamShouldNotCountToClientConcurrencyLimit) {
  SettingsMap new_settings;
  new_settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, 2);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(new_settings));
  SpdySerializedFrame pushed(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  MockRead reads[] = {
      CreateMockRead(settings_frame, 0),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(pushed, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),
      MockRead(ASYNC, 0, 6),
  };

  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(settings_ack, 1), CreateMockWrite(req, 2),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  // Read the settings frame.
  base::RunLoop().RunUntilIdle();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Run until pushed stream is created.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Second stream should not be stalled, although we have 2 active streams, but
  // one of them is push stream and should not be taken into account when we
  // create streams on the client.
  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  EXPECT_TRUE(spdy_stream2);
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, RejectPushedStreamExceedingConcurrencyLimit) {
  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdySerializedFrame push_b(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, "https://www.example.org/b.dat"));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(push_a, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7),
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(4, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 5),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  session_->set_max_concurrent_pushed_streams(1);

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Run until pushed stream is created.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Reset incoming pushed stream.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Tests that HTTP SPDY push streams that advertise an origin different from the
// associated stream are accepted from a trusted SPDY proxy.
TEST_F(SpdySessionTest, TrustedSpdyProxy) {
  // Origin of kDefaultUrl should be different from the origin of
  // kHttpURLFromAnotherOrigin and kHttpsURLFromAnotherOrigin.
  ASSERT_NE(GURL(kDefaultUrl).host(), GURL(kHttpURLFromAnotherOrigin).host());
  ASSERT_NE(GURL(kDefaultUrl).host(), GURL(kHttpsURLFromAnotherOrigin).host());

  // cross_origin_push contains HTTP resource for an origin different from the
  // origin of kDefaultUrl, and should be accepted.
  SpdySerializedFrame cross_origin_push(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, kHttpURLFromAnotherOrigin));
  // cross_origin_https_push contains HTTPS resource, and should be refused.
  SpdySerializedFrame cross_origin_https_push(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 1, kHttpsURLFromAnotherOrigin));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      CreateMockRead(cross_origin_push, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(cross_origin_https_push, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6),
      MockRead(ASYNC, 0, 7),
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(4, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 5),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<TestProxyDelegate> proxy_delegate(new TestProxyDelegate());
  proxy_delegate->set_trusted_spdy_proxy(
      net::ProxyServer(net::ProxyServer::SCHEME_HTTPS,
                       HostPortPair(GURL(kDefaultUrl).host(), 443)));
  session_deps_.proxy_delegate.reset(proxy_delegate.release());

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated.
  EXPECT_EQ(0u, delegate.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate.stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Run until pushed stream is created.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Reset incoming pushed stream.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Tests that if the SPDY trusted proxy is not set, then push streams that
// advertise an origin different from the associated stream are refused.
TEST_F(SpdySessionTest, TrustedSpdyProxyNotSet) {
  // Origin of kDefaultUrl should be different from the origin of
  // kHttpURLFromAnotherOrigin.
  ASSERT_NE(GURL(kDefaultUrl).host(), GURL(kHttpURLFromAnotherOrigin).host());

  // cross_origin_push contains resource for an origin different from the
  // origin of kDefaultUrl, and should be refused.
  SpdySerializedFrame cross_origin_push(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, kHttpURLFromAnotherOrigin));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(cross_origin_push, 2),
      MockRead(ASYNC, 0, 4),
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 3),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated.
  EXPECT_EQ(0u, delegate.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate.stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, IgnoreReservedRemoteStreamsCount) {
  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://www.example.org/a.dat"));
  SpdyHeaderBlock push_headers;
  spdy_util_.AddUrlToHeaderBlock("https://www.example.org/b.dat",
                                 &push_headers);
  SpdySerializedFrame push_b(
      spdy_util_.ConstructInitialSpdyPushFrame(std::move(push_headers), 4, 1));
  SpdySerializedFrame headers_b(
      spdy_util_.ConstructSpdyPushHeaders(4, nullptr, 0));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(push_a, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(push_b, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5), CreateMockRead(headers_b, 6),
      MockRead(ASYNC, ERR_IO_PENDING, 8), MockRead(ASYNC, 0, 9),
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(4, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 7),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();
  session_->set_max_concurrent_pushed_streams(1);

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Run until pushed stream is created.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Accept promised stream. It should not count towards pushed stream limit.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(2u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Reset last pushed stream upon headers reception as it is going to be 2nd,
  // while we accept only one.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(1u, session_->num_active_pushed_streams());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

TEST_F(SpdySessionTest, CancelReservedStreamOnHeadersReceived) {
  const char kPushedUrl[] = "https://www.example.org/a.dat";
  SpdyHeaderBlock push_headers;
  spdy_util_.AddUrlToHeaderBlock(kPushedUrl, &push_headers);
  SpdySerializedFrame push_promise(
      spdy_util_.ConstructInitialSpdyPushFrame(std::move(push_headers), 2, 1));
  SpdySerializedFrame headers_frame(
      spdy_util_.ConstructSpdyPushHeaders(2, nullptr, 0));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(push_promise, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), CreateMockRead(headers_frame, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7),
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 5),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, LOWEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);
  EXPECT_EQ(0u, spdy_stream1->stream_id());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  EXPECT_EQ(0u, session_->num_active_streams());
  EXPECT_EQ(1u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  // Run until 1st stream is activated.
  EXPECT_EQ(0u, delegate1.stream_id());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, delegate1.stream_id());
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Run until pushed stream is created.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(1u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  base::WeakPtr<SpdyStream> pushed_stream;
  int rv = session_->GetPushStream(GURL(kPushedUrl), &pushed_stream,
                                   NetLogWithSource());
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(pushed_stream);
  test::StreamDelegateCloseOnHeaders delegate2(pushed_stream);
  pushed_stream->SetDelegate(&delegate2);

  // Receive headers for pushed stream. Delegate will cancel the stream, ensure
  // that all our counters are in consistent state.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, session_->num_active_streams());
  EXPECT_EQ(0u, session_->num_created_streams());
  EXPECT_EQ(0u, session_->num_pushed_streams());
  EXPECT_EQ(0u, session_->num_active_pushed_streams());

  // Read EOF.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

TEST_F(SpdySessionTest, RejectInvalidUnknownFrames) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  session_->stream_hi_water_mark_ = 5;
  // Low client (odd) ids are fine.
  EXPECT_TRUE(session_->OnUnknownFrame(3, 0));
  // Client id exceeding watermark.
  EXPECT_FALSE(session_->OnUnknownFrame(9, 0));

  session_->last_accepted_push_stream_id_ = 6;
  // Low server (even) ids are fine.
  EXPECT_TRUE(session_->OnUnknownFrame(2, 0));
  // Server id exceeding last accepted id.
  EXPECT_FALSE(session_->OnUnknownFrame(8, 0));
}

class AltSvcFrameTest : public SpdySessionTest {
 public:
  AltSvcFrameTest()
      : alternative_service_("quic",
                             "alternative.example.org",
                             443,
                             86400,
                             SpdyAltSvcWireFormat::VersionVector()) {}

  void AddSocketData(const SpdyAltSvcIR& altsvc_ir) {
    altsvc_frame_ = spdy_util_.SerializeFrame(altsvc_ir);
    reads_.push_back(CreateMockRead(altsvc_frame_, 0));
    reads_.push_back(MockRead(ASYNC, 0, 1));

    data_.reset(
        new SequencedSocketData(reads_.data(), reads_.size(), nullptr, 0));
    session_deps_.socket_factory->AddSocketDataProvider(data_.get());
  }

  void CreateSecureSpdySession() {
    session_ = ::net::CreateSecureSpdySession(http_session_.get(), key_,
                                              NetLogWithSource());
  }

  SpdyAltSvcWireFormat::AlternativeService alternative_service_;

 private:
  SpdySerializedFrame altsvc_frame_;
  std::vector<MockRead> reads_;
  std::unique_ptr<SequencedSocketData> data_;
};

TEST_F(AltSvcFrameTest, ProcessAltSvcFrame) {
  const char origin[] = "https://mail.example.org";
  SpdyAltSvcIR altsvc_ir(0);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());

  altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          url::SchemeHostPort(GURL(origin)));
  ASSERT_EQ(1u, altsvc_vector.size());
  EXPECT_EQ(kProtoQUIC, altsvc_vector[0].protocol);
  EXPECT_EQ("alternative.example.org", altsvc_vector[0].host);
  EXPECT_EQ(443u, altsvc_vector[0].port);
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameOnInsecureSession) {
  const char origin[] = "https://mail.example.org";
  SpdyAltSvcIR altsvc_ir(0);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateInsecureSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());

  altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          url::SchemeHostPort(GURL(origin)));
  ASSERT_TRUE(altsvc_vector.empty());
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameForOriginNotCoveredByCert) {
  const char origin[] = "https://invalid.example.org";
  SpdyAltSvcIR altsvc_ir(0);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());

  altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          url::SchemeHostPort(GURL(origin)));
  ASSERT_TRUE(altsvc_vector.empty());
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameWithEmptyOriginOnZeroStream) {
  SpdyAltSvcIR altsvc_ir(0);
  altsvc_ir.add_altsvc(alternative_service_);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());
}

TEST_F(AltSvcFrameTest, ProcessAltSvcFrameOnActiveStream) {
  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.add_altsvc(alternative_service_);

  SpdySerializedFrame altsvc_frame(spdy_util_.SerializeFrame(altsvc_ir));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_REFUSED_STREAM));
  MockRead reads[] = {
      CreateMockRead(altsvc_frame, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  const char request_origin[] = "https://mail.example.org";
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(request_origin, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, GURL(request_origin), MEDIUM,
      NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(request_origin));

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());

  altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          url::SchemeHostPort(GURL(request_origin)));
  ASSERT_EQ(1u, altsvc_vector.size());
  EXPECT_EQ(kProtoQUIC, altsvc_vector[0].protocol);
  EXPECT_EQ("alternative.example.org", altsvc_vector[0].host);
  EXPECT_EQ(443u, altsvc_vector[0].port);
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameOnStreamWithInsecureOrigin) {
  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.add_altsvc(alternative_service_);

  SpdySerializedFrame altsvc_frame(spdy_util_.SerializeFrame(altsvc_ir));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_REFUSED_STREAM));
  MockRead reads[] = {
      CreateMockRead(altsvc_frame, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  const char request_origin[] = "http://mail.example.org";
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(request_origin, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, GURL(request_origin), MEDIUM,
      NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(request_origin));

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());

  altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          url::SchemeHostPort(GURL(request_origin)));
  ASSERT_TRUE(altsvc_vector.empty());
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameOnNonExistentStream) {
  SpdyAltSvcIR altsvc_ir(1);
  altsvc_ir.add_altsvc(alternative_service_);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSecureSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceVector altsvc_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServices(
          session_origin);
  ASSERT_TRUE(altsvc_vector.empty());
}

TEST(MapFramerErrorToProtocolError, MapsValues) {
  CHECK_EQ(
      SPDY_ERROR_INVALID_CONTROL_FRAME,
      MapFramerErrorToProtocolError(SpdyFramer::SPDY_INVALID_CONTROL_FRAME));
  CHECK_EQ(
      SPDY_ERROR_INVALID_DATA_FRAME_FLAGS,
      MapFramerErrorToProtocolError(SpdyFramer::SPDY_INVALID_DATA_FRAME_FLAGS));
  CHECK_EQ(
      SPDY_ERROR_GOAWAY_FRAME_CORRUPT,
      MapFramerErrorToProtocolError(SpdyFramer::SPDY_GOAWAY_FRAME_CORRUPT));
  CHECK_EQ(SPDY_ERROR_UNEXPECTED_FRAME,
           MapFramerErrorToProtocolError(SpdyFramer::SPDY_UNEXPECTED_FRAME));
}

TEST(MapFramerErrorToNetError, MapsValue) {
  CHECK_EQ(ERR_SPDY_PROTOCOL_ERROR,
           MapFramerErrorToNetError(SpdyFramer::SPDY_INVALID_CONTROL_FRAME));
  CHECK_EQ(ERR_SPDY_COMPRESSION_ERROR,
           MapFramerErrorToNetError(SpdyFramer::SPDY_COMPRESS_FAILURE));
  CHECK_EQ(ERR_SPDY_COMPRESSION_ERROR,
           MapFramerErrorToNetError(SpdyFramer::SPDY_DECOMPRESS_FAILURE));
  CHECK_EQ(
      ERR_SPDY_FRAME_SIZE_ERROR,
      MapFramerErrorToNetError(SpdyFramer::SPDY_CONTROL_PAYLOAD_TOO_LARGE));
}

TEST(MapRstStreamStatusToProtocolError, MapsValues) {
  CHECK_EQ(STATUS_CODE_PROTOCOL_ERROR,
           MapRstStreamStatusToProtocolError(RST_STREAM_PROTOCOL_ERROR));
  CHECK_EQ(STATUS_CODE_FRAME_SIZE_ERROR,
           MapRstStreamStatusToProtocolError(RST_STREAM_FRAME_SIZE_ERROR));
  CHECK_EQ(STATUS_CODE_ENHANCE_YOUR_CALM,
           MapRstStreamStatusToProtocolError(RST_STREAM_ENHANCE_YOUR_CALM));
  CHECK_EQ(STATUS_CODE_INADEQUATE_SECURITY,
           MapRstStreamStatusToProtocolError(RST_STREAM_INADEQUATE_SECURITY));
  CHECK_EQ(STATUS_CODE_HTTP_1_1_REQUIRED,
           MapRstStreamStatusToProtocolError(RST_STREAM_HTTP_1_1_REQUIRED));
}

TEST(MapNetErrorToGoAwayStatus, MapsValue) {
  CHECK_EQ(GOAWAY_INADEQUATE_SECURITY,
           MapNetErrorToGoAwayStatus(ERR_SPDY_INADEQUATE_TRANSPORT_SECURITY));
  CHECK_EQ(GOAWAY_FLOW_CONTROL_ERROR,
           MapNetErrorToGoAwayStatus(ERR_SPDY_FLOW_CONTROL_ERROR));
  CHECK_EQ(GOAWAY_PROTOCOL_ERROR,
           MapNetErrorToGoAwayStatus(ERR_SPDY_PROTOCOL_ERROR));
  CHECK_EQ(GOAWAY_COMPRESSION_ERROR,
           MapNetErrorToGoAwayStatus(ERR_SPDY_COMPRESSION_ERROR));
  CHECK_EQ(GOAWAY_FRAME_SIZE_ERROR,
           MapNetErrorToGoAwayStatus(ERR_SPDY_FRAME_SIZE_ERROR));
  CHECK_EQ(GOAWAY_PROTOCOL_ERROR, MapNetErrorToGoAwayStatus(ERR_UNEXPECTED));
}

TEST(CanPoolTest, CanPool) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");

  EXPECT_TRUE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "www.example.org"));
  EXPECT_TRUE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.org"));
  EXPECT_TRUE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.com"));
  EXPECT_FALSE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.google.com"));
}

TEST(CanPoolTest, CanNotPoolWithCertErrors) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.cert_status = CERT_STATUS_REVOKED;

  EXPECT_FALSE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanNotPoolWithClientCerts) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.client_cert_sent = true;

  EXPECT_FALSE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanNotPoolAcrossETLDsWithChannelID) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.channel_id_sent = true;

  EXPECT_TRUE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.org"));
  EXPECT_FALSE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "www.example.com"));
}

TEST(CanPoolTest, CanNotPoolWithBadPins) {
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  uint8_t bad_pin = 3;
  TransportSecurityState tss;
  test::AddPin(&tss, "mail.example.org", primary_pin, backup_pin);

  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(bad_pin));

  EXPECT_FALSE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanNotPoolWithBadCTWhenCTRequired) {
  using testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(1));
  ssl_info.ct_cert_policy_compliance =
      ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS;

  MockRequireCTDelegate require_ct_delegate;
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("www.example.org"))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("mail.example.org"))
      .WillRepeatedly(Return(CTRequirementLevel::REQUIRED));

  TransportSecurityState tss;
  tss.SetRequireCTDelegate(&require_ct_delegate);

  EXPECT_FALSE(SpdySession::CanPool(&tss, ssl_info, "www.example.org",
                                    "mail.example.org"));
}

TEST(CanPoolTest, CanPoolWithBadCTWhenCTNotRequired) {
  using testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(1));
  ssl_info.ct_cert_policy_compliance =
      ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS;

  MockRequireCTDelegate require_ct_delegate;
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("www.example.org"))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("mail.example.org"))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));

  TransportSecurityState tss;
  tss.SetRequireCTDelegate(&require_ct_delegate);

  EXPECT_TRUE(SpdySession::CanPool(&tss, ssl_info, "www.example.org",
                                   "mail.example.org"));
}

TEST(CanPoolTest, CanPoolWithGoodCTWhenCTRequired) {
  using testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(1));
  ssl_info.ct_cert_policy_compliance =
      ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS;

  MockRequireCTDelegate require_ct_delegate;
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("www.example.org"))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("mail.example.org"))
      .WillRepeatedly(Return(CTRequirementLevel::REQUIRED));

  TransportSecurityState tss;
  tss.SetRequireCTDelegate(&require_ct_delegate);

  EXPECT_TRUE(SpdySession::CanPool(&tss, ssl_info, "www.example.org",
                                   "mail.example.org"));
}

TEST(CanPoolTest, CanPoolWithAcceptablePins) {
  uint8_t primary_pin = 1;
  uint8_t backup_pin = 2;
  TransportSecurityState tss;
  test::AddPin(&tss, "mail.example.org", primary_pin, backup_pin);

  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(primary_pin));

  EXPECT_TRUE(SpdySession::CanPool(
      &tss, ssl_info, "www.example.org", "mail.example.org"));
}

}  // namespace net
