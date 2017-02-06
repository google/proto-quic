// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/bidirectional_stream.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "base/timer/mock_timer.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kBodyData[] = "Body data";
const size_t kBodyDataSize = arraysize(kBodyData);
// Size of the buffer to be allocated for each read.
const size_t kReadBufferSize = 4096;

// Expects that fields of |load_timing_info| are valid time stamps.
void ExpectLoadTimingValid(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.request_start.is_null());
  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.receive_headers_end.is_null());
  EXPECT_FALSE(load_timing_info.send_start.is_null());
  EXPECT_FALSE(load_timing_info.send_end.is_null());
  EXPECT_TRUE(load_timing_info.request_start <
              load_timing_info.receive_headers_end);
  EXPECT_TRUE(load_timing_info.send_start <= load_timing_info.send_end);
}

// Tests the load timing of a stream that's connected and is not the first
// request sent on a connection.
void TestLoadTimingReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
  ExpectLoadTimingValid(load_timing_info);
}

// Tests the load timing of a stream that's connected and using a fresh
// connection.
void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.socket_reused);

  ExpectConnectTimingHasTimes(
      load_timing_info.connect_timing,
      CONNECT_TIMING_HAS_SSL_TIMES | CONNECT_TIMING_HAS_DNS_TIMES);
  ExpectLoadTimingValid(load_timing_info);
}

// Delegate that reads data but does not send any data.
class TestDelegateBase : public BidirectionalStream::Delegate {
 public:
  TestDelegateBase(IOBuffer* read_buf, int read_buf_len)
      : TestDelegateBase(read_buf,
                         read_buf_len,
                         base::MakeUnique<base::Timer>(false, false)) {}

  TestDelegateBase(IOBuffer* read_buf,
                   int read_buf_len,
                   std::unique_ptr<base::Timer> timer)
      : read_buf_(read_buf),
        read_buf_len_(read_buf_len),
        timer_(std::move(timer)),
        loop_(nullptr),
        received_bytes_(0),
        sent_bytes_(0),
        error_(OK),
        on_data_read_count_(0),
        on_data_sent_count_(0),
        do_not_start_read_(false),
        run_until_completion_(false),
        not_expect_callback_(false) {}

  ~TestDelegateBase() override {}

  void OnStreamReady(bool request_headers_sent) override {
    // Request headers should always be sent in H2's case, because the
    // functionality to combine header frame with data frames is not
    // implemented.
    EXPECT_TRUE(request_headers_sent);
    if (callback_.is_null())
      return;
    callback_.Run(OK);
  }

  void OnHeadersReceived(const SpdyHeaderBlock& response_headers) override {
    CHECK(!not_expect_callback_);

    response_headers_ = response_headers.Clone();

    if (!do_not_start_read_)
      StartOrContinueReading();
  }

  void OnDataRead(int bytes_read) override {
    CHECK(!not_expect_callback_);

    ++on_data_read_count_;
    CHECK_GE(bytes_read, OK);
    data_received_.append(read_buf_->data(), bytes_read);
    if (!do_not_start_read_)
      StartOrContinueReading();
  }

  void OnDataSent() override {
    CHECK(!not_expect_callback_);

    ++on_data_sent_count_;
  }

  void OnTrailersReceived(const SpdyHeaderBlock& trailers) override {
    CHECK(!not_expect_callback_);

    trailers_ = trailers.Clone();
    if (run_until_completion_)
      loop_->Quit();
  }

  void OnFailed(int error) override {
    CHECK(!not_expect_callback_);
    CHECK_EQ(OK, error_);
    CHECK_NE(OK, error);

    error_ = error;
    if (run_until_completion_)
      loop_->Quit();
  }

  void Start(std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
             HttpNetworkSession* session) {
    stream_.reset(new BidirectionalStream(std::move(request_info), session,
                                          true, this, std::move(timer_)));
    if (run_until_completion_)
      loop_->Run();
  }

  void Start(std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
             HttpNetworkSession* session,
             const CompletionCallback& cb) {
    callback_ = cb;
    stream_.reset(new BidirectionalStream(std::move(request_info), session,
                                          true, this, std::move(timer_)));
    if (run_until_completion_)
      WaitUntilCompletion();
  }

  void WaitUntilCompletion() { loop_->Run(); }

  void SendData(const scoped_refptr<IOBuffer>& data,
                int length,
                bool end_of_stream) {
    not_expect_callback_ = true;
    stream_->SendData(data, length, end_of_stream);
    not_expect_callback_ = false;
  }

  void SendvData(const std::vector<scoped_refptr<IOBuffer>>& data,
                 const std::vector<int>& length,
                 bool end_of_stream) {
    not_expect_callback_ = true;
    stream_->SendvData(data, length, end_of_stream);
    not_expect_callback_ = false;
  }

  // Starts or continues reading data from |stream_| until no more bytes
  // can be read synchronously.
  void StartOrContinueReading() {
    int rv = ReadData();
    while (rv > 0) {
      rv = ReadData();
    }
    if (run_until_completion_ && rv == 0)
      loop_->Quit();
  }

  // Calls ReadData on the |stream_| and updates internal states.
  int ReadData() {
    not_expect_callback_ = true;
    int rv = stream_->ReadData(read_buf_.get(), read_buf_len_);
    not_expect_callback_ = false;
    if (rv > 0)
      data_received_.append(read_buf_->data(), rv);
    return rv;
  }

  // Deletes |stream_|.
  void DeleteStream() {
    next_proto_ = stream_->GetProtocol();
    received_bytes_ = stream_->GetTotalReceivedBytes();
    sent_bytes_ = stream_->GetTotalSentBytes();
    stream_->GetLoadTimingInfo(&load_timing_info_);
    stream_.reset();
  }

  NextProto GetProtocol() const {
    if (stream_)
      return stream_->GetProtocol();
    return next_proto_;
  }

  int64_t GetTotalReceivedBytes() const {
    if (stream_)
      return stream_->GetTotalReceivedBytes();
    return received_bytes_;
  }

  int64_t GetTotalSentBytes() const {
    if (stream_)
      return stream_->GetTotalSentBytes();
    return sent_bytes_;
  }

  void GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const {
    if (stream_) {
      stream_->GetLoadTimingInfo(load_timing_info);
      return;
    }
    *load_timing_info = load_timing_info_;
  }

  // Const getters for internal states.
  const std::string& data_received() const { return data_received_; }
  int error() const { return error_; }
  const SpdyHeaderBlock& response_headers() const { return response_headers_; }
  const SpdyHeaderBlock& trailers() const { return trailers_; }
  int on_data_read_count() const { return on_data_read_count_; }
  int on_data_sent_count() const { return on_data_sent_count_; }

  // Sets whether the delegate should automatically start reading.
  void set_do_not_start_read(bool do_not_start_read) {
    do_not_start_read_ = do_not_start_read;
  }
  // Sets whether the delegate should wait until the completion of the stream.
  void SetRunUntilCompletion(bool run_until_completion) {
    run_until_completion_ = run_until_completion;
    loop_.reset(new base::RunLoop);
  }

 protected:
  // Quits |loop_|.
  void QuitLoop() { loop_->Quit(); }

 private:
  std::unique_ptr<BidirectionalStream> stream_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;
  std::unique_ptr<base::Timer> timer_;
  std::string data_received_;
  std::unique_ptr<base::RunLoop> loop_;
  SpdyHeaderBlock response_headers_;
  SpdyHeaderBlock trailers_;
  NextProto next_proto_;
  int64_t received_bytes_;
  int64_t sent_bytes_;
  LoadTimingInfo load_timing_info_;
  int error_;
  int on_data_read_count_;
  int on_data_sent_count_;
  bool do_not_start_read_;
  bool run_until_completion_;
  // This is to ensure that delegate callback is not invoked synchronously when
  // calling into |stream_|.
  bool not_expect_callback_;

  CompletionCallback callback_;
  DISALLOW_COPY_AND_ASSIGN(TestDelegateBase);
};

// A delegate that deletes the stream in a particular callback.
class DeleteStreamDelegate : public TestDelegateBase {
 public:
  // Specifies in which callback the stream can be deleted.
  enum Phase {
    ON_HEADERS_RECEIVED,
    ON_DATA_READ,
    ON_TRAILERS_RECEIVED,
    ON_FAILED,
  };

  DeleteStreamDelegate(IOBuffer* buf, int buf_len, Phase phase)
      : TestDelegateBase(buf, buf_len), phase_(phase) {}
  ~DeleteStreamDelegate() override {}

  void OnHeadersReceived(const SpdyHeaderBlock& response_headers) override {
    TestDelegateBase::OnHeadersReceived(response_headers);
    if (phase_ == ON_HEADERS_RECEIVED) {
      DeleteStream();
      QuitLoop();
    }
  }

  void OnDataSent() override { NOTREACHED(); }

  void OnDataRead(int bytes_read) override {
    if (phase_ == ON_HEADERS_RECEIVED) {
      NOTREACHED();
      return;
    }
    TestDelegateBase::OnDataRead(bytes_read);
    if (phase_ == ON_DATA_READ) {
      DeleteStream();
      QuitLoop();
    }
  }

  void OnTrailersReceived(const SpdyHeaderBlock& trailers) override {
    if (phase_ == ON_HEADERS_RECEIVED || phase_ == ON_DATA_READ) {
      NOTREACHED();
      return;
    }
    TestDelegateBase::OnTrailersReceived(trailers);
    if (phase_ == ON_TRAILERS_RECEIVED) {
      DeleteStream();
      QuitLoop();
    }
  }

  void OnFailed(int error) override {
    if (phase_ != ON_FAILED) {
      NOTREACHED();
      return;
    }
    TestDelegateBase::OnFailed(error);
    DeleteStream();
    QuitLoop();
  }

 private:
  // Indicates in which callback the delegate should cancel or delete the
  // stream.
  Phase phase_;

  DISALLOW_COPY_AND_ASSIGN(DeleteStreamDelegate);
};

// A Timer that does not start a delayed task unless the timer is fired.
class MockTimer : public base::MockTimer {
 public:
  MockTimer() : base::MockTimer(false, false) {}
  ~MockTimer() override {}

  void Start(const tracked_objects::Location& posted_from,
             base::TimeDelta delay,
             const base::Closure& user_task) override {
    // Sets a maximum delay, so the timer does not fire unless it is told to.
    base::TimeDelta infinite_delay = base::TimeDelta::Max();
    base::MockTimer::Start(posted_from, infinite_delay, user_task);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockTimer);
};

}  // namespace

class BidirectionalStreamTest : public testing::TestWithParam<bool> {
 public:
  BidirectionalStreamTest()
      : default_url_(kDefaultUrl),
        host_port_pair_(HostPortPair::FromURL(default_url_)),
        key_(host_port_pair_, ProxyServer::Direct(), PRIVACY_MODE_DISABLED),
        ssl_data_(SSLSocketDataProvider(ASYNC, OK)) {
    ssl_data_.next_proto = kProtoHTTP2;
    ssl_data_.cert = ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
    net_log_.SetCaptureMode(NetLogCaptureMode::IncludeSocketBytes());
  }

 protected:
  void TearDown() override {
    if (sequenced_data_) {
      EXPECT_TRUE(sequenced_data_->AllReadDataConsumed());
      EXPECT_TRUE(sequenced_data_->AllWriteDataConsumed());
    }
  }

  // Initializes the session using SequencedSocketData.
  void InitSession(MockRead* reads,
                   size_t reads_count,
                   MockWrite* writes,
                   size_t writes_count) {
    ASSERT_TRUE(ssl_data_.cert.get());
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data_);
    sequenced_data_.reset(
        new SequencedSocketData(reads, reads_count, writes, writes_count));
    session_deps_.socket_factory->AddSocketDataProvider(sequenced_data_.get());
    session_deps_.net_log = net_log_.bound().net_log();
    http_session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    session_ =
        CreateSecureSpdySession(http_session_.get(), key_, net_log_.bound());
  }

  BoundTestNetLog net_log_;
  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  const GURL default_url_;
  const HostPortPair host_port_pair_;
  const SpdySessionKey key_;
  std::unique_ptr<SequencedSocketData> sequenced_data_;
  std::unique_ptr<HttpNetworkSession> http_session_;

 private:
  SSLSocketDataProvider ssl_data_;
  base::WeakPtr<SpdySession> session_;
};

TEST_F(BidirectionalStreamTest, CreateInsecureStream) {
  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = GURL("http://www.example.org/");

  TestDelegateBase delegate(nullptr, 0);
  HttpNetworkSession::Params params =
      SpdySessionDependencies::CreateSessionParams(&session_deps_);
  std::unique_ptr<HttpNetworkSession> session(new HttpNetworkSession(params));
  delegate.SetRunUntilCompletion(true);
  delegate.Start(std::move(request_info), session.get());

  EXPECT_THAT(delegate.error(), IsError(ERR_DISALLOWED_URL_SCHEME));
}

TEST_F(BidirectionalStreamTest, SimplePostRequest) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize, LOW, nullptr, 0));
  SpdySerializedFrame data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, kBodyData, kBodyDataSize, /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame, 3),
  };
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, /*fin=*/true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 4), MockRead(ASYNC, 0, 5),
  };
  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize));
  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->Start(std::move(request_info), http_session_.get());
  sequenced_data_->RunUntilPaused();

  scoped_refptr<StringIOBuffer> write_buffer(
      new StringIOBuffer(std::string(kBodyData, kBodyDataSize)));
  delegate->SendData(write_buffer.get(), write_buffer->size(), true);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  LoadTimingInfo load_timing_info;
  delegate->GetLoadTimingInfo(&load_timing_info);
  TestLoadTimingNotReused(load_timing_info);

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, LoadTimingTwoRequests) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, /*stream_id=*/1, LOW, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, /*stream_id=*/3, LOW, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(req2, 2),
  };
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, /*stream_id=*/1));
  SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, /*stream_id=*/3));
  SpdySerializedFrame resp_body(
      spdy_util_.ConstructSpdyDataFrame(/*stream_id=*/1, /*fin=*/true));
  SpdySerializedFrame resp_body2(
      spdy_util_.ConstructSpdyDataFrame(/*stream_id=*/3, /*fin=*/true));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(resp_body, 3),
                      CreateMockRead(resp2, 4), CreateMockRead(resp_body2, 5),
                      MockRead(ASYNC, 0, 6)};
  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->end_stream_on_headers = true;
  std::unique_ptr<BidirectionalStreamRequestInfo> request_info2(
      new BidirectionalStreamRequestInfo);
  request_info2->method = "GET";
  request_info2->url = default_url_;
  request_info2->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  scoped_refptr<IOBuffer> read_buffer2(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate2(
      new TestDelegateBase(read_buffer2.get(), kReadBufferSize));
  delegate->Start(std::move(request_info), http_session_.get());
  delegate2->Start(std::move(request_info2), http_session_.get());
  delegate->SetRunUntilCompletion(true);
  delegate2->SetRunUntilCompletion(true);
  base::RunLoop().RunUntilIdle();

  delegate->WaitUntilCompletion();
  delegate2->WaitUntilCompletion();
  LoadTimingInfo load_timing_info;
  delegate->GetLoadTimingInfo(&load_timing_info);
  TestLoadTimingNotReused(load_timing_info);
  LoadTimingInfo load_timing_info2;
  delegate2->GetLoadTimingInfo(&load_timing_info2);
  TestLoadTimingReused(load_timing_info2);
}

// Creates a BidirectionalStream with an insecure scheme. Destroy the stream
// without waiting for the OnFailed task to be executed.
TEST_F(BidirectionalStreamTest,
       CreateInsecureStreamAndDestroyStreamRightAfter) {
  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = GURL("http://www.example.org/");

  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(nullptr, 0));
  HttpNetworkSession::Params params =
      SpdySessionDependencies::CreateSessionParams(&session_deps_);
  std::unique_ptr<HttpNetworkSession> session(new HttpNetworkSession(params));
  delegate->Start(std::move(request_info), session.get());
  // Reset stream right before the OnFailed task is executed.
  delegate.reset();

  base::RunLoop().RunUntilIdle();
}

// Simulates user calling ReadData after END_STREAM has been received in
// BidirectionalStreamSpdyImpl.
TEST_F(BidirectionalStreamTest, TestReadDataAfterClose) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  SpdySerializedFrame body_frame(spdy_util_.ConstructSpdyDataFrame(1, false));
  // Last body frame has END_STREAM flag set.
  SpdySerializedFrame last_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(body_frame, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause.
      CreateMockRead(body_frame, 5),
      CreateMockRead(last_body_frame, 6),
      MockRead(SYNCHRONOUS, 0, 7),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->end_stream_on_headers = true;
  request_info->priority = LOWEST;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  // Create a MockTimer. Retain a raw pointer since the underlying
  // BidirectionalStreamImpl owns it.
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->set_do_not_start_read(true);

  delegate->Start(std::move(request_info), http_session_.get());

  // Write request, and deliver response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer->IsRunning());
  // ReadData returns asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver a DATA frame.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  timer->Fire();
  // Asynchronous completion callback is invoke.
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 1,
            static_cast<int>(delegate->data_received().size()));

  // Deliver the rest. Note that user has not called a second ReadData.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  // ReadData now. Read should complete synchronously.
  rv = delegate->ReadData();
  EXPECT_EQ(kUploadDataSize * 2, rv);
  rv = delegate->ReadData();
  EXPECT_THAT(rv, IsOk());  // EOF.

  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

// Tests that the NetLog contains correct entries.
TEST_F(BidirectionalStreamTest, TestNetLogContainEntries) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  SpdySerializedFrame data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, kBodyData, kBodyDataSize, /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame, 3),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame response_body_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame response_body_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  SpdyHeaderBlock trailers;
  trailers["foo"] = "bar";
  SpdySerializedFrame response_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers), true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame1, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause.
      CreateMockRead(response_body_frame2, 6),
      CreateMockRead(response_trailers, 7),
      MockRead(ASYNC, 0, 8),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize * 3));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer->IsRunning());

  scoped_refptr<StringIOBuffer> buf(
      new StringIOBuffer(std::string(kBodyData, kBodyDataSize)));
  // Send a DATA frame.
  delegate->SendData(buf, buf->size(), true);
  // ReadData returns asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver the first DATA frame.
  sequenced_data_->Resume();
  sequenced_data_->RunUntilPaused();
  // |sequenced_data_| is now stopped after delivering first DATA frame but
  // before the second DATA frame.
  // Fire the timer to allow the first ReadData to complete asynchronously.
  timer->Fire();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_read_count());

  // Now let |sequenced_data_| run until completion.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  // All data has been delivered, and OnClosed() has been invoked.
  // Read now, and it should complete synchronously.
  rv = delegate->ReadData();
  EXPECT_EQ(kUploadDataSize, rv);
  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ("bar", delegate->trailers().find("foo")->second);
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());

  // Destroy the delegate will destroy the stream, so we can get an end event
  // for BIDIRECTIONAL_STREAM_ALIVE.
  delegate.reset();
  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);

  size_t index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE,
      NetLogEventPhase::BEGIN);
  // HTTP_STREAM_REQUEST is nested inside in BIDIRECTIONAL_STREAM_ALIVE.
  index = ExpectLogContainsSomewhere(entries, index,
                                     NetLogEventType::HTTP_STREAM_REQUEST,
                                     NetLogEventPhase::BEGIN);
  index = ExpectLogContainsSomewhere(entries, index,
                                     NetLogEventType::HTTP_STREAM_REQUEST,
                                     NetLogEventPhase::END);
  // Headers received should happen after HTTP_STREAM_REQUEST.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_RECV_HEADERS,
      NetLogEventPhase::NONE);
  // Trailers received should happen after headers received. It might happen
  // before the reads complete.
  ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_RECV_TRAILERS,
      NetLogEventPhase::NONE);
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_SEND_DATA,
      NetLogEventPhase::NONE);
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_READ_DATA,
      NetLogEventPhase::NONE);
  TestNetLogEntry entry = entries[index];
  int read_result = 0;
  EXPECT_TRUE(entry.params->GetInteger("rv", &read_result));
  EXPECT_EQ(ERR_IO_PENDING, read_result);

  // Sent bytes. Sending data is always asynchronous.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
      NetLogEventPhase::NONE);
  entry = entries[index];
  EXPECT_EQ(NetLogSourceType::BIDIRECTIONAL_STREAM, entry.source.type);
  // Received bytes for asynchronous read.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED,
      NetLogEventPhase::NONE);
  entry = entries[index];
  EXPECT_EQ(NetLogSourceType::BIDIRECTIONAL_STREAM, entry.source.type);
  // Received bytes for synchronous read.
  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED,
      NetLogEventPhase::NONE);
  entry = entries[index];
  EXPECT_EQ(NetLogSourceType::BIDIRECTIONAL_STREAM, entry.source.type);
  ExpectLogContainsSomewhere(entries, index,
                             NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE,
                             NetLogEventPhase::END);
}

TEST_F(BidirectionalStreamTest, TestInterleaveReadDataAndSendData) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  SpdySerializedFrame data_frame1(spdy_util_.ConstructSpdyDataFrame(
      1, kBodyData, kBodyDataSize, /*fin=*/false));
  SpdySerializedFrame data_frame2(spdy_util_.ConstructSpdyDataFrame(
      1, kBodyData, kBodyDataSize, /*fin=*/false));
  SpdySerializedFrame data_frame3(spdy_util_.ConstructSpdyDataFrame(
      1, kBodyData, kBodyDataSize, /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame1, 3),
      CreateMockWrite(data_frame2, 6), CreateMockWrite(data_frame3, 9),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame response_body_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame response_body_frame2(
      spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame1, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause.
      CreateMockRead(response_body_frame2, 7),
      MockRead(ASYNC, ERR_IO_PENDING, 8),  // Force a pause.
      MockRead(ASYNC, 0, 10),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize * 3));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer->IsRunning());

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf(
      new StringIOBuffer(std::string(kBodyData, kBodyDataSize)));

  // Send a DATA frame.
  delegate->SendData(buf, buf->size(), false);
  // ReadData and it should return asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver a DATA frame, and fire the timer.
  sequenced_data_->Resume();
  sequenced_data_->RunUntilPaused();
  timer->Fire();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(1, delegate->on_data_read_count());

  // Send a DATA frame.
  delegate->SendData(buf, buf->size(), false);
  // ReadData and it should return asynchronously because no data is buffered.
  rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver a DATA frame, and fire the timer.
  sequenced_data_->Resume();
  sequenced_data_->RunUntilPaused();
  timer->Fire();
  base::RunLoop().RunUntilIdle();
  // Last DATA frame is read. Server half closes.
  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(2, delegate->on_data_sent_count());

  // Send the last body frame. Client half closes.
  delegate->SendData(buf, buf->size(), true);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3, delegate->on_data_sent_count());

  // OnClose is invoked since both sides are closed.
  rv = delegate->ReadData();
  EXPECT_THAT(rv, IsOk());

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(3, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestCoalesceSmallDataBuffers) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 1, LOWEST, nullptr, 0));
  std::string body_data = "some really long piece of data";
  SpdySerializedFrame data_frame1(spdy_util_.ConstructSpdyDataFrame(
      1, body_data.c_str(), body_data.size(), /*fin=*/true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame1, 1),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame response_body_frame1(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),  // Force a pause.
      CreateMockRead(response_body_frame1, 4), MockRead(ASYNC, 0, 5),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize * 1));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->set_do_not_start_read(true);
  TestCompletionCallback callback;
  delegate->Start(std::move(request_info), http_session_.get(),
                  callback.callback());
  // Wait until the stream is ready.
  callback.WaitForResult();
  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf(new StringIOBuffer(body_data.substr(0, 5)));
  scoped_refptr<StringIOBuffer> buf2(
      new StringIOBuffer(body_data.substr(5, body_data.size() - 5)));
  delegate->SendvData({buf, buf2.get()}, {buf->size(), buf2->size()}, true);
  sequenced_data_->RunUntilPaused();  // OnHeadersReceived.
  // ReadData and it should return asynchronously because no data is buffered.
  EXPECT_THAT(delegate->ReadData(), IsError(ERR_IO_PENDING));
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(1, delegate->on_data_read_count());

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(1, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());

  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);
  size_t index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::BIDIRECTIONAL_STREAM_SENDV_DATA,
      NetLogEventPhase::NONE);
  TestNetLogEntry entry = entries[index];
  int num_buffers = 0;
  EXPECT_TRUE(entry.params->GetInteger("num_buffers", &num_buffers));
  EXPECT_EQ(2, num_buffers);

  index = ExpectLogContainsSomewhereAfter(
      entries, index,
      NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED,
      NetLogEventPhase::BEGIN);
  entry = entries[index];
  int num_buffers_coalesced = 0;
  EXPECT_TRUE(entry.params->GetInteger("num_buffers_coalesced",
                                       &num_buffers_coalesced));
  EXPECT_EQ(2, num_buffers_coalesced);

  index = ExpectLogContainsSomewhereAfter(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
      NetLogEventPhase::NONE);
  entry = entries[index];
  int byte_count = 0;
  EXPECT_TRUE(entry.params->GetInteger("byte_count", &byte_count));
  EXPECT_EQ(buf->size(), byte_count);

  index = ExpectLogContainsSomewhereAfter(
      entries, index + 1, NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
      NetLogEventPhase::NONE);
  entry = entries[index];
  byte_count = 0;
  EXPECT_TRUE(entry.params->GetInteger("byte_count", &byte_count));
  EXPECT_EQ(buf2->size(), byte_count);

  ExpectLogContainsSomewhere(
      entries, index,
      NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED,
      NetLogEventPhase::END);
}

// Tests that BidirectionalStreamSpdyImpl::OnClose will complete any remaining
// read even if the read queue is empty.
TEST_F(BidirectionalStreamTest, TestCompleteAsyncRead) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, nullptr, 0, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 3), MockRead(SYNCHRONOUS, 0, 4),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Write request, and deliver response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_FALSE(timer->IsRunning());

  // ReadData should return asynchronously because no data is buffered.
  int rv = delegate->ReadData();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Deliver END_STREAM.
  // OnClose should trigger completion of the remaining read.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(0u, delegate->data_received().size());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestBuffering) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  SpdySerializedFrame body_frame(spdy_util_.ConstructSpdyDataFrame(1, false));
  // Last body frame has END_STREAM flag set.
  SpdySerializedFrame last_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(body_frame, 2),
      CreateMockRead(body_frame, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause.
      CreateMockRead(last_body_frame, 5),
      MockRead(SYNCHRONOUS, 0, 6),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->Start(std::move(request_info), http_session_.get());
  // Deliver two DATA frames together.
  sequenced_data_->RunUntilPaused();
  EXPECT_TRUE(timer->IsRunning());
  timer->Fire();
  base::RunLoop().RunUntilIdle();
  // This should trigger |more_read_data_pending_| to execute the task at a
  // later time, and Delegate::OnReadComplete should not have been called.
  EXPECT_TRUE(timer->IsRunning());
  EXPECT_EQ(0, delegate->on_data_read_count());

  // Fire the timer now, the two DATA frame should be combined into one
  // single Delegate::OnReadComplete callback.
  timer->Fire();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 2,
            static_cast<int>(delegate->data_received().size()));

  // Deliver last DATA frame and EOF. There will be an additional
  // Delegate::OnReadComplete callback.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 3,
            static_cast<int>(delegate->data_received().size()));

  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestBufferingWithTrailers) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  SpdySerializedFrame body_frame(spdy_util_.ConstructSpdyDataFrame(1, false));

  SpdyHeaderBlock trailers;
  trailers["foo"] = "bar";
  SpdySerializedFrame response_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers), true));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      CreateMockRead(body_frame, 2),
      CreateMockRead(body_frame, 3),
      CreateMockRead(body_frame, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause.
      CreateMockRead(response_trailers, 6),
      MockRead(SYNCHRONOUS, 0, 7),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  delegate->Start(std::move(request_info), http_session_.get());
  // Deliver all three DATA frames together.
  sequenced_data_->RunUntilPaused();
  EXPECT_TRUE(timer->IsRunning());
  timer->Fire();
  base::RunLoop().RunUntilIdle();
  // This should trigger |more_read_data_pending_| to execute the task at a
  // later time, and Delegate::OnReadComplete should not have been called.
  EXPECT_TRUE(timer->IsRunning());
  EXPECT_EQ(0, delegate->on_data_read_count());

  // Deliver trailers. Remaining read should be completed, since OnClose is
  // called right after OnTrailersReceived. The three DATA frames should be
  // delivered in a single OnReadCompleted callback.
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, delegate->on_data_read_count());
  EXPECT_EQ(kUploadDataSize * 3,
            static_cast<int>(delegate->data_received().size()));
  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ("bar", delegate->trailers().find("foo")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamAfterSendData) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  SpdySerializedFrame data_frame(spdy_util_.ConstructSpdyDataFrame(
      1, kBodyData, kBodyDataSize, /*fin=*/false));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(data_frame, 3),
      CreateMockWrite(rst, 5),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause.
      MockRead(ASYNC, 0, 6),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize * 3));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  sequenced_data_->RunUntilPaused();
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());

  // Send a DATA frame.
  scoped_refptr<StringIOBuffer> buf(
      new StringIOBuffer(std::string(kBodyData, kBodyDataSize)));
  delegate->SendData(buf, buf->size(), false);
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  delegate->DeleteStream();
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  EXPECT_EQ(0, delegate->on_data_read_count());
  // OnDataSent may or may not have been invoked.
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes) - 1),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringReadData) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOWEST, nullptr, 0));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause.
      CreateMockRead(response_body_frame, 3), MockRead(ASYNC, 0, 5),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize * 3));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->set_do_not_start_read(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Send the request and receive response headers.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ("200", delegate->response_headers().find(":status")->second);
  // Delete the stream after ReadData returns ERR_IO_PENDING.
  int rv = delegate->ReadData();
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  delegate->DeleteStream();
  sequenced_data_->Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes) - 1),
            delegate->GetTotalSentBytes());
  // Response body frame isn't read becase stream is deleted once read returns
  // ERR_IO_PENDING.
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads) - 2),
            delegate->GetTotalReceivedBytes());
}

// Receiving a header with uppercase ASCII will result in a protocol error,
// which should be propagated via Delegate::OnFailed.
TEST_F(BidirectionalStreamTest, PropagateProtocolError) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kBodyDataSize * 3, LOW, nullptr, 0));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_PROTOCOL_ERROR));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "POST";
  request_info->url = default_url_;
  request_info->extra_headers.SetHeader(net::HttpRequestHeaders::kContentLength,
                                        base::SizeTToString(kBodyDataSize * 3));

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<TestDelegateBase> delegate(
      new TestDelegateBase(read_buffer.get(), kReadBufferSize));
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(delegate->error(), IsError(ERR_SPDY_PROTOCOL_ERROR));
  EXPECT_EQ(delegate->response_headers().end(),
            delegate->response_headers().find(":status"));
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // BidirectionalStreamSpdyStreamJob does not count the bytes sent for |rst|
  // because it is sent after SpdyStream::Delegate::OnClose is called.
  EXPECT_EQ(CountWriteBytes(writes, 1), delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());

  TestNetLogEntry::List entries;
  net_log_.GetEntries(&entries);

  size_t index = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::BIDIRECTIONAL_STREAM_READY,
      NetLogEventPhase::NONE);
  TestNetLogEntry entry = entries[index];
  bool request_headers_sent = false;
  EXPECT_TRUE(
      entry.params->GetBoolean("request_headers_sent", &request_headers_sent));
  EXPECT_TRUE(request_headers_sent);

  index = ExpectLogContainsSomewhere(
      entries, index, NetLogEventType::BIDIRECTIONAL_STREAM_FAILED,
      NetLogEventPhase::NONE);
  entry = entries[index];
  int net_error = OK;
  EXPECT_TRUE(entry.params->GetInteger("net_error", &net_error));
  EXPECT_THAT(net_error, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnHeadersReceived) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(new DeleteStreamDelegate(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::Phase::ON_HEADERS_RECEIVED));
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(0u, delegate->data_received().size());
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(0, delegate->on_data_read_count());

  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes) - 1),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnDataRead) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 3),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(response_body_frame, 2),
      MockRead(ASYNC, 0, 4),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(
      new DeleteStreamDelegate(read_buffer.get(), kReadBufferSize,
                               DeleteStreamDelegate::Phase::ON_DATA_READ));
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ(kUploadDataSize * 1,
            static_cast<int>(delegate->data_received().size()));
  EXPECT_EQ(0, delegate->on_data_sent_count());

  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes) - 1),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnTrailersReceived) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  const char* const kExtraResponseHeaders[] = {"header-name", "header-value"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));

  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, false));

  SpdyHeaderBlock trailers;
  trailers["foo"] = "bar";
  SpdySerializedFrame response_trailers(
      spdy_util_.ConstructSpdyResponseHeaders(1, std::move(trailers), true));

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(response_body_frame, 2),
      CreateMockRead(response_trailers, 3), MockRead(ASYNC, 0, 5),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(new DeleteStreamDelegate(
      read_buffer.get(), kReadBufferSize,
      DeleteStreamDelegate::Phase::ON_TRAILERS_RECEIVED));
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ("header-value", response_headers.find("header-name")->second);
  EXPECT_EQ("bar", delegate->trailers().find("foo")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  // OnDataRead may or may not have been fired before the stream is
  // deleted.
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes) - 1),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, DeleteStreamDuringOnFailed) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_PROTOCOL_ERROR));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const kExtraHeaders[] = {"X-UpperCase", "yes"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraHeaders, 1, 1));

  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),
  };

  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  std::unique_ptr<DeleteStreamDelegate> delegate(
      new DeleteStreamDelegate(read_buffer.get(), kReadBufferSize,
                               DeleteStreamDelegate::Phase::ON_FAILED));
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());
  // Makes sure delegate does not get called.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(delegate->response_headers().end(),
            delegate->response_headers().find(":status"));
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(0, delegate->on_data_read_count());
  EXPECT_THAT(delegate->error(), IsError(ERR_SPDY_PROTOCOL_ERROR));

  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  // Bytes sent excludes the RST frame.
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes) - 1),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());
}

TEST_F(BidirectionalStreamTest, TestHonorAlternativeServiceHeader) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(kDefaultUrl, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  std::string alt_svc_header_value = NextProtoToString(kProtoQUIC);
  alt_svc_header_value.append("=\"www.example.org:443\"");
  const char* const kExtraResponseHeaders[] = {"alt-svc",
                                               alt_svc_header_value.c_str()};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(kExtraResponseHeaders, 1, 1));
  SpdySerializedFrame body_frame(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body_frame, 2),
      MockRead(SYNCHRONOUS, 0, 3),
  };

  // Enable QUIC so that the alternative service header can be added to
  // HttpServerProperties.
  session_deps_.enable_quic = true;
  InitSession(reads, arraysize(reads), writes, arraysize(writes));

  std::unique_ptr<BidirectionalStreamRequestInfo> request_info(
      new BidirectionalStreamRequestInfo);
  request_info->method = "GET";
  request_info->url = default_url_;
  request_info->priority = LOWEST;
  request_info->end_stream_on_headers = true;

  scoped_refptr<IOBuffer> read_buffer(new IOBuffer(kReadBufferSize));
  MockTimer* timer = new MockTimer();
  std::unique_ptr<TestDelegateBase> delegate(new TestDelegateBase(
      read_buffer.get(), kReadBufferSize, base::WrapUnique(timer)));
  delegate->SetRunUntilCompletion(true);
  delegate->Start(std::move(request_info), http_session_.get());

  const SpdyHeaderBlock& response_headers = delegate->response_headers();
  EXPECT_EQ("200", response_headers.find(":status")->second);
  EXPECT_EQ(alt_svc_header_value, response_headers.find("alt-svc")->second);
  EXPECT_EQ(0, delegate->on_data_sent_count());
  EXPECT_EQ(kProtoHTTP2, delegate->GetProtocol());
  EXPECT_EQ(kUploadData, delegate->data_received());
  EXPECT_EQ(CountWriteBytes(writes, arraysize(writes)),
            delegate->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads, arraysize(reads)),
            delegate->GetTotalReceivedBytes());

  AlternativeServiceVector alternative_service_vector =
      http_session_->http_server_properties()->GetAlternativeServices(
          url::SchemeHostPort(default_url_));
  ASSERT_EQ(1u, alternative_service_vector.size());
  EXPECT_EQ(kProtoQUIC, alternative_service_vector[0].protocol);
  EXPECT_EQ("www.example.org", alternative_service_vector[0].host);
  EXPECT_EQ(443, alternative_service_vector[0].port);
}

}  // namespace net
