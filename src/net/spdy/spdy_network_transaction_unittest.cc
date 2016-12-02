// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cmath>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_piece.h"
#include "base/test/test_file_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/auth.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/proxy_delegate.h"
#include "net/base/request_priority.h"
#include "net/base/test_proxy_delegate.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_file_element_reader.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_transaction_test_util.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/proxy_server.h"
#include "net/socket/client_socket_pool_base.h"
#include "net/socket/next_proto.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

//-----------------------------------------------------------------------------

namespace net {

namespace {

using testing::Each;
using testing::Eq;

const int32_t kBufferSize = SpdyHttpStream::kRequestBodyBufferSize;

}  // namespace

class SpdyNetworkTransactionTest : public ::testing::Test {
 protected:
  SpdyNetworkTransactionTest()
      : default_url_(kDefaultUrl),
        host_port_pair_(HostPortPair::FromURL(default_url_)) {}

  ~SpdyNetworkTransactionTest() override {
    // UploadDataStream may post a deletion tasks back to the message loop on
    // destruction.
    upload_data_stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  void SetUp() override {
    get_request_initialized_ = false;
    post_request_initialized_ = false;
    chunked_post_request_initialized_ = false;
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
  }

  struct TransactionHelperResult {
    int rv;
    std::string status_line;
    std::string response_data;
    HttpResponseInfo response_info;
  };

  // A helper class that handles all the initial npn/ssl setup.
  class NormalSpdyTransactionHelper {
   public:
    NormalSpdyTransactionHelper(
        const HttpRequestInfo& request,
        RequestPriority priority,
        const NetLogWithSource& log,
        std::unique_ptr<SpdySessionDependencies> session_deps)
        : request_(request),
          priority_(priority),
          session_deps_(session_deps.get() == NULL
                            ? base::MakeUnique<SpdySessionDependencies>()
                            : std::move(session_deps)),
          session_(
              SpdySessionDependencies::SpdyCreateSession(session_deps_.get())),
          log_(log) {}

    ~NormalSpdyTransactionHelper() {
      // Any test which doesn't close the socket by sending it an EOF will
      // have a valid session left open, which leaks the entire session pool.
      // This is just fine - in fact, some of our tests intentionally do this
      // so that we can check consistency of the SpdySessionPool as the test
      // finishes.  If we had put an EOF on the socket, the SpdySession would
      // have closed and we wouldn't be able to check the consistency.

      // Forcefully close existing sessions here.
      session()->spdy_session_pool()->CloseAllSessions();
    }

    void RunPreTestSetup() {
      // We're now ready to use SSL-npn SPDY.
      trans_.reset(new HttpNetworkTransaction(priority_, session_.get()));
    }

    // Start the transaction, read some data, finish.
    void RunDefaultTest() {
      if (!StartDefaultTest())
        return;
      FinishDefaultTest();
    }

    bool StartDefaultTest() {
      output_.rv = trans_->Start(&request_, callback_.callback(), log_);

      // We expect an IO Pending or some sort of error.
      EXPECT_LT(output_.rv, 0);
      return output_.rv == ERR_IO_PENDING;
    }

    void FinishDefaultTest() {
      output_.rv = callback_.WaitForResult();
      if (output_.rv != OK) {
        session_->spdy_session_pool()->CloseCurrentSessions(ERR_ABORTED);
        return;
      }

      // Verify responses.
      const HttpResponseInfo* response = trans_->GetResponseInfo();
      ASSERT_TRUE(response);
      ASSERT_TRUE(response->headers);
      EXPECT_EQ(HttpResponseInfo::CONNECTION_INFO_HTTP2,
                response->connection_info);
      EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
      EXPECT_TRUE(response->was_fetched_via_spdy);
      EXPECT_TRUE(response->was_alpn_negotiated);
      EXPECT_EQ("127.0.0.1", response->socket_address.host());
      EXPECT_EQ(443, response->socket_address.port());
      output_.status_line = response->headers->GetStatusLine();
      output_.response_info = *response;  // Make a copy so we can verify.
      output_.rv = ReadTransaction(trans_.get(), &output_.response_data);
    }

    void FinishDefaultTestWithoutVerification() {
      output_.rv = callback_.WaitForResult();
      if (output_.rv != OK)
        session_->spdy_session_pool()->CloseCurrentSessions(ERR_ABORTED);
    }

    void WaitForCallbackToComplete() { output_.rv = callback_.WaitForResult(); }

    // Most tests will want to call this function. In particular, the MockReads
    // should end with an empty read, and that read needs to be processed to
    // ensure proper deletion of the spdy_session_pool.
    void VerifyDataConsumed() {
      for (const SocketDataProvider* provider : data_vector_) {
        EXPECT_TRUE(provider->AllReadDataConsumed());
        EXPECT_TRUE(provider->AllWriteDataConsumed());
      }
    }

    // Occasionally a test will expect to error out before certain reads are
    // processed. In that case we want to explicitly ensure that the reads were
    // not processed.
    void VerifyDataNotConsumed() {
      for (const SocketDataProvider* provider : data_vector_) {
        EXPECT_FALSE(provider->AllReadDataConsumed());
        EXPECT_FALSE(provider->AllWriteDataConsumed());
      }
    }

    void RunToCompletion(SocketDataProvider* data) {
      RunPreTestSetup();
      AddData(data);
      RunDefaultTest();
      VerifyDataConsumed();
    }

    void RunToCompletionWithSSLData(
        SocketDataProvider* data,
        std::unique_ptr<SSLSocketDataProvider> ssl_provider) {
      RunPreTestSetup();
      AddDataWithSSLSocketDataProvider(data, std::move(ssl_provider));
      RunDefaultTest();
      VerifyDataConsumed();
    }

    void AddData(SocketDataProvider* data) {
      std::unique_ptr<SSLSocketDataProvider> ssl_provider(
          new SSLSocketDataProvider(ASYNC, OK));
      ssl_provider->cert =
          ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
      AddDataWithSSLSocketDataProvider(data, std::move(ssl_provider));
    }

    void AddDataWithSSLSocketDataProvider(
        SocketDataProvider* data,
        std::unique_ptr<SSLSocketDataProvider> ssl_provider) {
      data_vector_.push_back(data);
      if (ssl_provider->next_proto == kProtoUnknown)
        ssl_provider->next_proto = kProtoHTTP2;

      session_deps_->socket_factory->AddSSLSocketDataProvider(
          ssl_provider.get());
      ssl_vector_.push_back(std::move(ssl_provider));

      session_deps_->socket_factory->AddSocketDataProvider(data);
    }

    HttpNetworkTransaction* trans() { return trans_.get(); }
    void ResetTrans() { trans_.reset(); }
    const TransactionHelperResult& output() { return output_; }
    const HttpRequestInfo& request() const { return request_; }
    HttpNetworkSession* session() const { return session_.get(); }
    SpdySessionDependencies* session_deps() { return session_deps_.get(); }

   private:
    typedef std::vector<SocketDataProvider*> DataVector;
    typedef std::vector<std::unique_ptr<SSLSocketDataProvider>> SSLVector;
    typedef std::vector<std::unique_ptr<SocketDataProvider>> AlternateVector;
    HttpRequestInfo request_;
    RequestPriority priority_;
    std::unique_ptr<SpdySessionDependencies> session_deps_;
    std::unique_ptr<HttpNetworkSession> session_;
    TransactionHelperResult output_;
    SSLVector ssl_vector_;
    TestCompletionCallback callback_;
    std::unique_ptr<HttpNetworkTransaction> trans_;
    DataVector data_vector_;
    const NetLogWithSource log_;
  };

  void ConnectStatusHelperWithExpectedStatus(const MockRead& status,
                                             int expected_status);

  void ConnectStatusHelper(const MockRead& status);

  const HttpRequestInfo& CreateGetPushRequest() {
    get_push_request_.method = "GET";
    get_push_request_.url = GURL(GetDefaultUrlWithPath("/foo.dat"));
    get_push_request_.load_flags = 0;
    return get_push_request_;
  }

  const HttpRequestInfo& CreateGetRequest() {
    if (!get_request_initialized_) {
      get_request_.method = "GET";
      get_request_.url = default_url_;
      get_request_.load_flags = 0;
      get_request_initialized_ = true;
    }
    return get_request_;
  }

  const HttpRequestInfo& CreateGetRequestWithUserAgent() {
    if (!get_request_initialized_) {
      get_request_.method = "GET";
      get_request_.url = default_url_;
      get_request_.load_flags = 0;
      get_request_.extra_headers.SetHeader("User-Agent", "Chrome");
      get_request_initialized_ = true;
    }
    return get_request_;
  }

  const HttpRequestInfo& CreatePostRequest() {
    if (!post_request_initialized_) {
      std::vector<std::unique_ptr<UploadElementReader>> element_readers;
      element_readers.push_back(base::MakeUnique<UploadBytesElementReader>(
          kUploadData, kUploadDataSize));
      upload_data_stream_.reset(
          new ElementsUploadDataStream(std::move(element_readers), 0));

      post_request_.method = "POST";
      post_request_.url = default_url_;
      post_request_.upload_data_stream = upload_data_stream_.get();
      post_request_initialized_ = true;
    }
    return post_request_;
  }

  const HttpRequestInfo& CreateFilePostRequest() {
    if (!post_request_initialized_) {
      base::FilePath file_path;
      CHECK(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &file_path));
      CHECK_EQ(static_cast<int>(kUploadDataSize),
               base::WriteFile(file_path, kUploadData, kUploadDataSize));

      std::vector<std::unique_ptr<UploadElementReader>> element_readers;
      element_readers.push_back(base::MakeUnique<UploadFileElementReader>(
          base::ThreadTaskRunnerHandle::Get().get(), file_path, 0,
          kUploadDataSize, base::Time()));
      upload_data_stream_.reset(
          new ElementsUploadDataStream(std::move(element_readers), 0));

      post_request_.method = "POST";
      post_request_.url = default_url_;
      post_request_.upload_data_stream = upload_data_stream_.get();
      post_request_initialized_ = true;
    }
    return post_request_;
  }

  const HttpRequestInfo& CreateUnreadableFilePostRequest() {
    if (post_request_initialized_)
      return post_request_;

    base::FilePath file_path;
    CHECK(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &file_path));
    CHECK_EQ(static_cast<int>(kUploadDataSize),
             base::WriteFile(file_path, kUploadData, kUploadDataSize));
    CHECK(base::MakeFileUnreadable(file_path));

    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(base::MakeUnique<UploadFileElementReader>(
        base::ThreadTaskRunnerHandle::Get().get(), file_path, 0,
        kUploadDataSize, base::Time()));
    upload_data_stream_.reset(
        new ElementsUploadDataStream(std::move(element_readers), 0));

    post_request_.method = "POST";
    post_request_.url = default_url_;
    post_request_.upload_data_stream = upload_data_stream_.get();
    post_request_initialized_ = true;
    return post_request_;
  }

  const HttpRequestInfo& CreateComplexPostRequest() {
    if (!post_request_initialized_) {
      const int kFileRangeOffset = 1;
      const int kFileRangeLength = 3;
      CHECK_LT(kFileRangeOffset + kFileRangeLength, kUploadDataSize);

      base::FilePath file_path;
      CHECK(base::CreateTemporaryFileInDir(temp_dir_.GetPath(), &file_path));
      CHECK_EQ(static_cast<int>(kUploadDataSize),
               base::WriteFile(file_path, kUploadData, kUploadDataSize));

      std::vector<std::unique_ptr<UploadElementReader>> element_readers;
      element_readers.push_back(base::MakeUnique<UploadBytesElementReader>(
          kUploadData, kFileRangeOffset));
      element_readers.push_back(base::MakeUnique<UploadFileElementReader>(
          base::ThreadTaskRunnerHandle::Get().get(), file_path,
          kFileRangeOffset, kFileRangeLength, base::Time()));
      element_readers.push_back(base::MakeUnique<UploadBytesElementReader>(
          kUploadData + kFileRangeOffset + kFileRangeLength,
          kUploadDataSize - (kFileRangeOffset + kFileRangeLength)));
      upload_data_stream_.reset(
          new ElementsUploadDataStream(std::move(element_readers), 0));

      post_request_.method = "POST";
      post_request_.url = default_url_;
      post_request_.upload_data_stream = upload_data_stream_.get();
      post_request_initialized_ = true;
    }
    return post_request_;
  }

  const HttpRequestInfo& CreateChunkedPostRequest() {
    if (!chunked_post_request_initialized_) {
      upload_chunked_data_stream_.reset(new ChunkedUploadDataStream(0));
      chunked_post_request_.method = "POST";
      chunked_post_request_.url = default_url_;
      chunked_post_request_.upload_data_stream =
          upload_chunked_data_stream_.get();
      chunked_post_request_initialized_ = true;
    }
    return chunked_post_request_;
  }

  // Read the result of a particular transaction, knowing that we've got
  // multiple transactions in the read pipeline; so as we read, we may have
  // to skip over data destined for other transactions while we consume
  // the data for |trans|.
  int ReadResult(HttpNetworkTransaction* trans,
                 std::string* result) {
    const int kSize = 3000;

    int bytes_read = 0;
    scoped_refptr<IOBufferWithSize> buf(new IOBufferWithSize(kSize));
    TestCompletionCallback callback;
    while (true) {
      int rv = trans->Read(buf.get(), kSize, callback.callback());
      if (rv == ERR_IO_PENDING) {
        rv = callback.WaitForResult();
      } else if (rv <= 0) {
        break;
      }
      result->append(buf->data(), rv);
      bytes_read += rv;
    }
    return bytes_read;
  }

  void VerifyStreamsClosed(const NormalSpdyTransactionHelper& helper) {
    // This lengthy block is reaching into the pool to dig out the active
    // session.  Once we have the session, we verify that the streams are
    // all closed and not leaked at this point.
    const GURL& url = helper.request().url;
    SpdySessionKey key(HostPortPair::FromURL(url), ProxyServer::Direct(),
                       PRIVACY_MODE_DISABLED);
    NetLogWithSource log;
    HttpNetworkSession* session = helper.session();
    base::WeakPtr<SpdySession> spdy_session =
        session->spdy_session_pool()->FindAvailableSession(key, url, log);
    ASSERT_TRUE(spdy_session);
    EXPECT_EQ(0u, spdy_session->num_active_streams());
    EXPECT_EQ(0u, spdy_session->num_unclaimed_pushed_streams());
  }

  void RunServerPushTest(SequencedSocketData* data,
                         HttpResponseInfo* response,
                         HttpResponseInfo* push_response,
                         const std::string& expected) {
    NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.RunPreTestSetup();
    helper.AddData(data);

    HttpNetworkTransaction* trans = helper.trans();

    // Start the transaction with basic parameters.
    TestCompletionCallback callback;
    int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                          NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    rv = callback.WaitForResult();

    // Request the pushed path.
    HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
    rv = trans2.Start(&CreateGetPushRequest(), callback.callback(),
                      NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    base::RunLoop().RunUntilIdle();

    // The data for the pushed path may be coming in more than 1 frame. Compile
    // the results into a single string.

    // Read the server push body.
    std::string result2;
    ReadResult(&trans2, &result2);
    // Read the response body.
    std::string result;
    ReadResult(trans, &result);

    // Verify that we consumed all test data.
    EXPECT_TRUE(data->AllReadDataConsumed());
    EXPECT_TRUE(data->AllWriteDataConsumed());

    LoadTimingInfo load_timing_info;
    EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
    EXPECT_TRUE(load_timing_info.push_start.is_null());
    EXPECT_TRUE(load_timing_info.push_end.is_null());

    LoadTimingInfo load_timing_info2;
    EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
    EXPECT_FALSE(load_timing_info2.push_start.is_null());
    EXPECT_FALSE(load_timing_info2.push_end.is_null());

    // Verify that the received push data is same as the expected push data.
    EXPECT_EQ(result2.compare(expected), 0) << "Received data: "
                                            << result2
                                            << "||||| Expected data: "
                                            << expected;

    // Verify the response HEADERS.
    // Copy the response info, because trans goes away.
    *response = *trans->GetResponseInfo();
    *push_response = *trans2.GetResponseInfo();

    VerifyStreamsClosed(helper);
  }

  static void DeleteSessionCallback(NormalSpdyTransactionHelper* helper,
                                    int result) {
    helper->ResetTrans();
  }

  static void StartTransactionCallback(HttpNetworkSession* session,
                                       GURL url,
                                       int result) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session);
    TestCompletionCallback callback;
    HttpRequestInfo request;
    request.method = "GET";
    request.url = url;
    request.load_flags = 0;
    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    callback.WaitForResult();
  }

  ChunkedUploadDataStream* upload_chunked_data_stream() const {
    return upload_chunked_data_stream_.get();
  }

  std::string GetDefaultUrlWithPath(const char* path) {
    return std::string(kDefaultUrl) + path;
  }

  const GURL default_url_;
  const HostPortPair host_port_pair_;
  SpdyTestUtil spdy_util_;

 private:
  std::unique_ptr<ChunkedUploadDataStream> upload_chunked_data_stream_;
  std::unique_ptr<UploadDataStream> upload_data_stream_;
  bool get_request_initialized_;
  bool post_request_initialized_;
  bool chunked_post_request_initialized_;
  HttpRequestInfo get_request_;
  HttpRequestInfo post_request_;
  HttpRequestInfo chunked_post_request_;
  HttpRequestInfo get_push_request_;
  base::ScopedTempDir temp_dir_;
};

// Verify HttpNetworkTransaction constructor.
TEST_F(SpdyNetworkTransactionTest, Constructor) {
  auto session_deps = base::MakeUnique<SpdySessionDependencies>();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(session_deps.get()));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
}

TEST_F(SpdyNetworkTransactionTest, Get) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

TEST_F(SpdyNetworkTransactionTest, GetAtEachPriority) {
  for (RequestPriority p = MINIMUM_PRIORITY; p <= MAXIMUM_PRIORITY;
       p = RequestPriority(p + 1)) {
    SpdyTestUtil spdy_test_util;

    // Construct the request.
    SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, p, true));
    MockWrite writes[] = {CreateMockWrite(req, 0)};

    SpdyPriority spdy_prio = 0;
    EXPECT_TRUE(GetSpdyPriority(req, &spdy_prio));
    // this repeats the RequestPriority-->SpdyPriority mapping from
    // SpdyFramer::ConvertRequestPriorityToSpdyPriority to make
    // sure it's being done right.
    switch (p) {
      case HIGHEST:
        EXPECT_EQ(0, spdy_prio);
        break;
      case MEDIUM:
        EXPECT_EQ(1, spdy_prio);
        break;
      case LOW:
        EXPECT_EQ(2, spdy_prio);
        break;
      case LOWEST:
        EXPECT_EQ(3, spdy_prio);
        break;
      case IDLE:
        EXPECT_EQ(4, spdy_prio);
        break;
      case THROTTLED:
        EXPECT_EQ(5, spdy_prio);
        break;
      default:
        FAIL();
    }

    SpdySerializedFrame resp(
        spdy_test_util.ConstructSpdyGetReply(nullptr, 0, 1));
    SpdySerializedFrame body(spdy_test_util.ConstructSpdyDataFrame(1, true));
    MockRead reads[] = {
        CreateMockRead(resp, 1), CreateMockRead(body, 2),
        MockRead(ASYNC, 0, 3)  // EOF
    };

    SequencedSocketData data(reads, arraysize(reads), writes,
                             arraysize(writes));
    HttpRequestInfo http_req = CreateGetRequest();

    NormalSpdyTransactionHelper helper(http_req, p, NetLogWithSource(), NULL);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!", out.response_data);
  }
}

// Start three gets simultaniously; making sure that multiplexed
// streams work properly.

// This can't use the TransactionHelper method, since it only
// handles a single transaction, and finishes them as soon
// as it launches them.

// TODO(gavinp): create a working generalized TransactionHelper that
// can allow multiple streams in flight.

TEST_F(SpdyNetworkTransactionTest, ThreeGets) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, LOWEST, true));
  SpdySerializedFrame resp3(spdy_util_.ConstructSpdyGetReply(NULL, 0, 5));
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, false));
  SpdySerializedFrame fbody3(spdy_util_.ConstructSpdyDataFrame(5, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(req2, 3),
      CreateMockWrite(req3, 6),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 1),    CreateMockRead(body, 2),
      CreateMockRead(resp2, 4),   CreateMockRead(body2, 5),
      CreateMockRead(resp3, 7),   CreateMockRead(body3, 8),

      CreateMockRead(fbody, 9),   CreateMockRead(fbody2, 10),
      CreateMockRead(fbody3, 11),

      MockRead(ASYNC, 0, 12),  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  SequencedSocketData data_placeholder1(NULL, 0, NULL, 0);
  SequencedSocketData data_placeholder2(NULL, 0, NULL, 0);

  NetLogWithSource log;
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  // We require placeholder data because three get requests are sent out at
  // the same time which results in three sockets being connected. The first
  // on will negotiate SPDY and will be used for all requests.
  helper.AddData(&data_placeholder1);
  helper.AddData(&data_placeholder2);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  TestCompletionCallback callback3;

  HttpRequestInfo httpreq1 = CreateGetRequest();
  HttpRequestInfo httpreq2 = CreateGetRequest();
  HttpRequestInfo httpreq3 = CreateGetRequest();

  out.rv = trans1.Start(&httpreq1, callback1.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans2.Start(&httpreq2, callback2.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans3.Start(&httpreq3, callback3.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());
  out.rv = callback3.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;

  trans2.GetResponseInfo();

  out.rv = ReadTransaction(&trans1, &out.response_data);
  helper.VerifyDataConsumed();
  EXPECT_THAT(out.rv, IsOk());

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);
}

TEST_F(SpdyNetworkTransactionTest, TwoGetsLateBinding) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(req2, 3),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 1),  CreateMockRead(body, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      CreateMockRead(fbody, 6), CreateMockRead(fbody2, 7),
      MockRead(ASYNC, 0, 8),  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData data_placeholder(NULL, 0, NULL, 0);
  data_placeholder.set_connect_data(never_finishing_connect);

  NetLogWithSource log;
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  // We require placeholder data because two requests are sent out at
  // the same time which results in two sockets being connected. The first
  // on will negotiate SPDY and will be used for all requests.
  helper.AddData(&data_placeholder);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;

  HttpRequestInfo httpreq1 = CreateGetRequest();
  HttpRequestInfo httpreq2 = CreateGetRequest();

  out.rv = trans1.Start(&httpreq1, callback1.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans2.Start(&httpreq2, callback2.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());
  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  EXPECT_TRUE(response2->headers);
  EXPECT_TRUE(response2->was_fetched_via_spdy);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, TwoGetsLateBindingFromPreconnect) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(req2, 3),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 1),  CreateMockRead(body, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      CreateMockRead(fbody, 6), CreateMockRead(fbody2, 7),
      MockRead(ASYNC, 0, 8),  // EOF
  };
  SequencedSocketData preconnect_data(reads, arraysize(reads), writes,
                                      arraysize(writes));

  MockConnect never_finishing_connect(ASYNC, ERR_IO_PENDING);

  SequencedSocketData data_placeholder(NULL, 0, NULL, 0);
  data_placeholder.set_connect_data(never_finishing_connect);

  NetLogWithSource log;
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&preconnect_data);
  // We require placeholder data because 3 connections are attempted (first is
  // the preconnect, 2nd and 3rd are the never finished connections.
  helper.AddData(&data_placeholder);
  helper.AddData(&data_placeholder);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;

  HttpRequestInfo httpreq = CreateGetRequest();

  // Preconnect the first.
  HttpStreamFactory* http_stream_factory =
      helper.session()->http_stream_factory();

  http_stream_factory->PreconnectStreams(1, httpreq);

  out.rv = trans1.Start(&httpreq, callback1.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans2.Start(&httpreq, callback2.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());
  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  EXPECT_TRUE(response2->headers);
  EXPECT_TRUE(response2->was_fetched_via_spdy);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  helper.VerifyDataConsumed();
}

// Similar to ThreeGets above, however this test adds a SETTINGS
// frame.  The SETTINGS frame is read during the IO loop waiting on
// the first transaction completion, and sets a maximum concurrent
// stream limit of 1.  This means that our IO loop exists after the
// second transaction completes, so we can assert on read_index().
TEST_F(SpdyNetworkTransactionTest, ThreeGetsWithMaxConcurrent) {
  // Construct the request.
  // Each request fully completes before the next starts.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));
  spdy_util_.UpdateWithStreamDestruction(3);

  SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, LOWEST, true));
  SpdySerializedFrame resp3(spdy_util_.ConstructSpdyGetReply(NULL, 0, 5));
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, false));
  SpdySerializedFrame fbody3(spdy_util_.ConstructSpdyDataFrame(5, true));

  SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, max_concurrent_streams);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(settings_ack, 5),
      CreateMockWrite(req2, 6), CreateMockWrite(req3, 10),
  };

  MockRead reads[] = {
      CreateMockRead(settings_frame, 1),
      CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
      CreateMockRead(fbody, 4),
      CreateMockRead(resp2, 7),
      CreateMockRead(body2, 8),
      CreateMockRead(fbody2, 9),
      CreateMockRead(resp3, 11),
      CreateMockRead(body3, 12),
      CreateMockRead(fbody3, 13),

      MockRead(ASYNC, 0, 14),  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NetLogWithSource log;
  TransactionHelperResult out;
  {
    NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.RunPreTestSetup();
    helper.AddData(&data);
    HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
    HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
    HttpNetworkTransaction trans3(DEFAULT_PRIORITY, helper.session());

    TestCompletionCallback callback1;
    TestCompletionCallback callback2;
    TestCompletionCallback callback3;

    HttpRequestInfo httpreq1 = CreateGetRequest();
    HttpRequestInfo httpreq2 = CreateGetRequest();
    HttpRequestInfo httpreq3 = CreateGetRequest();

    out.rv = trans1.Start(&httpreq1, callback1.callback(), log);
    ASSERT_EQ(out.rv, ERR_IO_PENDING);
    // Run transaction 1 through quickly to force a read of our SETTINGS
    // frame.
    out.rv = callback1.WaitForResult();
    ASSERT_THAT(out.rv, IsOk());

    out.rv = trans2.Start(&httpreq2, callback2.callback(), log);
    ASSERT_EQ(out.rv, ERR_IO_PENDING);
    out.rv = trans3.Start(&httpreq3, callback3.callback(), log);
    ASSERT_EQ(out.rv, ERR_IO_PENDING);
    out.rv = callback2.WaitForResult();
    ASSERT_THAT(out.rv, IsOk());

    out.rv = callback3.WaitForResult();
    ASSERT_THAT(out.rv, IsOk());

    const HttpResponseInfo* response1 = trans1.GetResponseInfo();
    ASSERT_TRUE(response1);
    EXPECT_TRUE(response1->headers);
    EXPECT_TRUE(response1->was_fetched_via_spdy);
    out.status_line = response1->headers->GetStatusLine();
    out.response_info = *response1;
    out.rv = ReadTransaction(&trans1, &out.response_data);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!hello!", out.response_data);

    const HttpResponseInfo* response2 = trans2.GetResponseInfo();
    out.status_line = response2->headers->GetStatusLine();
    out.response_info = *response2;
    out.rv = ReadTransaction(&trans2, &out.response_data);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!hello!", out.response_data);

    const HttpResponseInfo* response3 = trans3.GetResponseInfo();
    out.status_line = response3->headers->GetStatusLine();
    out.response_info = *response3;
    out.rv = ReadTransaction(&trans3, &out.response_data);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!hello!", out.response_data);

    helper.VerifyDataConsumed();
  }
  EXPECT_THAT(out.rv, IsOk());
}

// Similar to ThreeGetsWithMaxConcurrent above, however this test adds
// a fourth transaction.  The third and fourth transactions have
// different data ("hello!" vs "hello!hello!") and because of the
// user specified priority, we expect to see them inverted in
// the response from the server.
TEST_F(SpdyNetworkTransactionTest, FourGetsWithMaxConcurrentPriority) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));
  spdy_util_.UpdateWithStreamDestruction(3);

  SpdySerializedFrame req4(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, HIGHEST, true));
  SpdySerializedFrame resp4(spdy_util_.ConstructSpdyGetReply(NULL, 0, 5));
  SpdySerializedFrame fbody4(spdy_util_.ConstructSpdyDataFrame(5, true));
  spdy_util_.UpdateWithStreamDestruction(5);

  SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 7, LOWEST, true));
  SpdySerializedFrame resp3(spdy_util_.ConstructSpdyGetReply(NULL, 0, 7));
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(7, false));
  SpdySerializedFrame fbody3(spdy_util_.ConstructSpdyDataFrame(7, true));

  SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, max_concurrent_streams);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(settings_ack, 5),
      // By making these synchronous, it guarantees that they are not *started*
      // before their sequence number, which in turn verifies that only a single
      // request is in-flight at a time.
      CreateMockWrite(req2, 6, SYNCHRONOUS),
      CreateMockWrite(req4, 10, SYNCHRONOUS),
      CreateMockWrite(req3, 13, SYNCHRONOUS),
  };
  MockRead reads[] = {
      CreateMockRead(settings_frame, 1),
      CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
      CreateMockRead(fbody, 4),
      CreateMockRead(resp2, 7),
      CreateMockRead(body2, 8),
      CreateMockRead(fbody2, 9),
      CreateMockRead(resp4, 11),
      CreateMockRead(fbody4, 12),
      CreateMockRead(resp3, 14),
      CreateMockRead(body3, 15),
      CreateMockRead(fbody3, 16),

      MockRead(ASYNC, 0, 17),  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NetLogWithSource log;
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans4(HIGHEST, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  TestCompletionCallback callback3;
  TestCompletionCallback callback4;

  HttpRequestInfo httpreq1 = CreateGetRequest();
  HttpRequestInfo httpreq2 = CreateGetRequest();
  HttpRequestInfo httpreq3 = CreateGetRequest();
  HttpRequestInfo httpreq4 = CreateGetRequest();

  out.rv = trans1.Start(&httpreq1, callback1.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  // Run transaction 1 through quickly to force a read of our SETTINGS frame.
  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = trans2.Start(&httpreq2, callback2.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans3.Start(&httpreq3, callback3.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans4.Start(&httpreq4, callback4.callback(), log);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = callback3.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  // notice: response3 gets two hellos, response4 gets one
  // hello, so we know dequeuing priority was respected.
  const HttpResponseInfo* response3 = trans3.GetResponseInfo();
  out.status_line = response3->headers->GetStatusLine();
  out.response_info = *response3;
  out.rv = ReadTransaction(&trans3, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  out.rv = callback4.WaitForResult();
  EXPECT_THAT(out.rv, IsOk());
  const HttpResponseInfo* response4 = trans4.GetResponseInfo();
  out.status_line = response4->headers->GetStatusLine();
  out.response_info = *response4;
  out.rv = ReadTransaction(&trans4, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
  helper.VerifyDataConsumed();
  EXPECT_THAT(out.rv, IsOk());
}

// Similar to ThreeGetsMaxConcurrrent above, however, this test
// deletes a session in the middle of the transaction to ensure
// that we properly remove pendingcreatestream objects from
// the spdy_session
TEST_F(SpdyNetworkTransactionTest, ThreeGetsWithMaxConcurrentDelete) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, max_concurrent_streams);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(settings_ack, 5),
      CreateMockWrite(req2, 6),
  };
  MockRead reads[] = {
      CreateMockRead(settings_frame, 1), CreateMockRead(resp, 2),
      CreateMockRead(body, 3),           CreateMockRead(fbody, 4),
      CreateMockRead(resp2, 7),          CreateMockRead(body2, 8),
      CreateMockRead(fbody2, 9),         MockRead(ASYNC, 0, 10),  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NetLogWithSource log;
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  std::unique_ptr<HttpNetworkTransaction> trans1(
      new HttpNetworkTransaction(DEFAULT_PRIORITY, helper.session()));
  std::unique_ptr<HttpNetworkTransaction> trans2(
      new HttpNetworkTransaction(DEFAULT_PRIORITY, helper.session()));
  std::unique_ptr<HttpNetworkTransaction> trans3(
      new HttpNetworkTransaction(DEFAULT_PRIORITY, helper.session()));

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  TestCompletionCallback callback3;

  HttpRequestInfo httpreq1 = CreateGetRequest();
  HttpRequestInfo httpreq2 = CreateGetRequest();
  HttpRequestInfo httpreq3 = CreateGetRequest();

  out.rv = trans1->Start(&httpreq1, callback1.callback(), log);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  // Run transaction 1 through quickly to force a read of our SETTINGS frame.
  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = trans2->Start(&httpreq2, callback2.callback(), log);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = trans3->Start(&httpreq3, callback3.callback(), log);
  trans3.reset();
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(trans1.get(), &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(trans2.get(), &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);
  helper.VerifyDataConsumed();
  EXPECT_THAT(out.rv, IsOk());
}

namespace {

// The KillerCallback will delete the transaction on error as part of the
// callback.
class KillerCallback : public TestCompletionCallbackBase {
 public:
  explicit KillerCallback(HttpNetworkTransaction* transaction)
      : transaction_(transaction),
        callback_(base::Bind(&KillerCallback::OnComplete,
                             base::Unretained(this))) {
  }

  ~KillerCallback() override {}

  const CompletionCallback& callback() const { return callback_; }

 private:
  void OnComplete(int result) {
    if (result < 0)
      delete transaction_;

    SetResult(result);
  }

  HttpNetworkTransaction* transaction_;
  CompletionCallback callback_;
};

}  // namespace

// Similar to ThreeGetsMaxConcurrrentDelete above, however, this test
// closes the socket while we have a pending transaction waiting for
// a pending stream creation.  http://crbug.com/52901
TEST_F(SpdyNetworkTransactionTest, ThreeGetsWithMaxConcurrentSocketClose) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame fin_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));

  SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, max_concurrent_streams);
  SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(settings_ack, 5),
      CreateMockWrite(req2, 6),
  };
  MockRead reads[] = {
      CreateMockRead(settings_frame, 1),
      CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
      CreateMockRead(fin_body, 4),
      CreateMockRead(resp2, 7),
      MockRead(ASYNC, ERR_CONNECTION_RESET, 8),  // Abort!
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  SequencedSocketData data_placeholder(NULL, 0, NULL, 0);

  NetLogWithSource log;
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  // We require placeholder data because three get requests are sent out, so
  // there needs to be three sets of SSL connection data.
  helper.AddData(&data_placeholder);
  helper.AddData(&data_placeholder);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction* trans3(
      new HttpNetworkTransaction(DEFAULT_PRIORITY, helper.session()));

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  KillerCallback callback3(trans3);

  HttpRequestInfo httpreq1 = CreateGetRequest();
  HttpRequestInfo httpreq2 = CreateGetRequest();
  HttpRequestInfo httpreq3 = CreateGetRequest();

  out.rv = trans1.Start(&httpreq1, callback1.callback(), log);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  // Run transaction 1 through quickly to force a read of our SETTINGS frame.
  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = trans2.Start(&httpreq2, callback2.callback(), log);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = trans3->Start(&httpreq3, callback3.callback(), log);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = callback3.WaitForResult();
  ASSERT_THAT(out.rv, IsError(ERR_ABORTED));

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsError(ERR_CONNECTION_RESET));

  helper.VerifyDataConsumed();
}

// Test that a simple PUT request works.
TEST_F(SpdyNetworkTransactionTest, Put) {
  // Setup the request
  HttpRequestInfo request;
  request.method = "PUT";
  request.url = default_url_;

  SpdyHeaderBlock put_headers(
      spdy_util_.ConstructPutHeaderBlock(kDefaultUrl, 0));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(put_headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
}

// Test that a simple HEAD request works.
TEST_F(SpdyNetworkTransactionTest, Head) {
  // Setup the request
  HttpRequestInfo request;
  request.method = "HEAD";
  request.url = default_url_;

  SpdyHeaderBlock head_headers(
      spdy_util_.ConstructHeadHeaderBlock(kDefaultUrl, 0));
  SpdySerializedFrame req(spdy_util_.ConstructSpdyHeaders(
      1, std::move(head_headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
}

// Test that a simple POST works.
TEST_F(SpdyNetworkTransactionTest, Post) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),  // POST upload frame
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreatePostRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a POST with a file works.
TEST_F(SpdyNetworkTransactionTest, FilePost) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),  // POST upload frame
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateFilePostRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a POST with a unreadable file fails.
TEST_F(SpdyNetworkTransactionTest, UnreadableFilePost) {
  MockWrite writes[] = {
      MockWrite(ASYNC, 0, 0)  // EOF
  };
  MockRead reads[] = {
      MockRead(ASYNC, 0, 1)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateUnreadableFilePostRequest(),
                                     DEFAULT_PRIORITY, NetLogWithSource(),
                                     NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.RunDefaultTest();

  base::RunLoop().RunUntilIdle();
  helper.VerifyDataNotConsumed();
  EXPECT_THAT(helper.output().rv, IsError(ERR_ACCESS_DENIED));
}

// Test that a complex POST works.
TEST_F(SpdyNetworkTransactionTest, ComplexPost) {
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),  // POST upload frame
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(
      CreateComplexPostRequest(), DEFAULT_PRIORITY, NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a chunked POST works.
TEST_F(SpdyNetworkTransactionTest, ChunkedPost) {
  SpdySerializedFrame req(spdy_util_.ConstructChunkedSpdyPost(NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(
      CreateChunkedPostRequest(), DEFAULT_PRIORITY, NetLogWithSource(), NULL);

  // These chunks get merged into a single frame when being sent.
  const int kFirstChunkSize = kUploadDataSize/2;
  upload_chunked_data_stream()->AppendData(kUploadData, kFirstChunkSize, false);
  upload_chunked_data_stream()->AppendData(
      kUploadData + kFirstChunkSize, kUploadDataSize - kFirstChunkSize, true);

  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ(kUploadData, out.response_data);
}

// Test that a chunked POST works with chunks appended after transaction starts.
TEST_F(SpdyNetworkTransactionTest, DelayedChunkedPost) {
  SpdySerializedFrame req(spdy_util_.ConstructChunkedSpdyPost(NULL, 0));
  SpdySerializedFrame chunk1(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame chunk2(spdy_util_.ConstructSpdyDataFrame(1, false));
  SpdySerializedFrame chunk3(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(chunk1, 1),
      CreateMockWrite(chunk2, 2), CreateMockWrite(chunk3, 3),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 4), CreateMockRead(chunk1, 5),
      CreateMockRead(chunk2, 6), CreateMockRead(chunk3, 7),
      MockRead(ASYNC, 0, 8)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(
      CreateChunkedPostRequest(), DEFAULT_PRIORITY, NetLogWithSource(), NULL);

  upload_chunked_data_stream()->AppendData(kUploadData, kUploadDataSize, false);

  helper.RunPreTestSetup();
  helper.AddData(&data);
  ASSERT_TRUE(helper.StartDefaultTest());

  base::RunLoop().RunUntilIdle();
  upload_chunked_data_stream()->AppendData(kUploadData, kUploadDataSize, false);
  base::RunLoop().RunUntilIdle();
  upload_chunked_data_stream()->AppendData(kUploadData, kUploadDataSize, true);

  helper.FinishDefaultTest();
  helper.VerifyDataConsumed();

  std::string expected_response;
  expected_response += kUploadData;
  expected_response += kUploadData;
  expected_response += kUploadData;

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ(expected_response, out.response_data);
}

// Test that a POST without any post data works.
TEST_F(SpdyNetworkTransactionTest, NullPost) {
  // Setup the request
  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  // Create an empty UploadData.
  request.upload_data_stream = NULL;

  // When request.upload_data_stream is NULL for post, content-length is
  // expected to be 0.
  SpdyHeaderBlock req_block(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, 0));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block), LOWEST, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a simple POST works.
TEST_F(SpdyNetworkTransactionTest, EmptyPost) {
  // Create an empty UploadDataStream.
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  ElementsUploadDataStream stream(std::move(element_readers), 0);

  // Setup the request
  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  request.upload_data_stream = &stream;

  const uint64_t kContentLength = 0;

  SpdyHeaderBlock req_block(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kContentLength));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block), LOWEST, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// While we're doing a post, the server sends the reply before upload completes.
TEST_F(SpdyNetworkTransactionTest, ResponseBeforePostCompletes) {
  SpdySerializedFrame req(spdy_util_.ConstructChunkedSpdyPost(NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 3),
  };
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  // Write the request headers, and read the complete response
  // while still waiting for chunked request data.
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(
      CreateChunkedPostRequest(), DEFAULT_PRIORITY, NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  ASSERT_TRUE(helper.StartDefaultTest());

  base::RunLoop().RunUntilIdle();

  // Process the request headers, response headers, and response body.
  // The request body is still in flight.
  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  // Finish sending the request body.
  upload_chunked_data_stream()->AppendData(kUploadData, kUploadDataSize, true);
  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  std::string response_body;
  EXPECT_THAT(ReadTransaction(helper.trans(), &response_body), IsOk());
  EXPECT_EQ(kUploadData, response_body);
  helper.VerifyDataConsumed();
}

// The client upon cancellation tries to send a RST_STREAM frame. The mock
// socket causes the TCP write to return zero. This test checks that the client
// tries to queue up the RST_STREAM frame again.
TEST_F(SpdyNetworkTransactionTest, SocketWriteReturnsZero) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0, SYNCHRONOUS), MockWrite(SYNCHRONOUS, 0, 0, 2),
      CreateMockWrite(rst, 3, SYNCHRONOUS),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, 0, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  helper.ResetTrans();
  base::RunLoop().RunUntilIdle();

  helper.VerifyDataConsumed();
}

// Test that the transaction doesn't crash when we don't have a reply.
TEST_F(SpdyNetworkTransactionTest, ResponseWithoutHeaders) {
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(body, 1), MockRead(ASYNC, 0, 3)  // EOF
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

// Test that the transaction doesn't crash when we get two replies on the same
// stream ID. See http://crbug.com/45639.
TEST_F(SpdyNetworkTransactionTest, ResponseWithTwoSynReplies) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  SpdySerializedFrame resp0(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp0, 1), CreateMockRead(resp1, 2),
      CreateMockRead(body, 3), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  std::string response_data;
  rv = ReadTransaction(trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_SPDY_PROTOCOL_ERROR));

  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, ResetReplyWithTransferEncoding) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
  };

  const char* const headers[] = {
    "transfer-encoding", "chunked"
  };
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(headers, 1, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));

  helper.session()->spdy_session_pool()->CloseAllSessions();
  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, ResetPushWithTransferEncoding) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  const char* const headers[] = {
    "transfer-encoding", "chunked"
  };
  SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPush(headers, arraysize(headers) / 2, 2, 1,
                                   GetDefaultUrlWithPath("/1").c_str()));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(push, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  helper.session()->spdy_session_pool()->CloseAllSessions();
  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, CancelledTransaction) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp),
      // This following read isn't used by the test, except during the
      // RunUntilIdle() call at the end since the SpdySession survives the
      // HttpNetworkTransaction and still tries to continue Read()'ing.  Any
      // MockRead will do here.
      MockRead(ASYNC, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, arraysize(reads),
                                writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  helper.ResetTrans();  // Cancel the transaction.

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataNotConsumed();
}

// Verify that the client sends a Rst Frame upon cancelling the stream.
TEST_F(SpdyNetworkTransactionTest, CancelledTransactionSendRst) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0, SYNCHRONOUS),
      CreateMockWrite(rst, 2, SYNCHRONOUS),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, 0, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;

  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  helper.ResetTrans();
  base::RunLoop().RunUntilIdle();

  helper.VerifyDataConsumed();
}

// Verify that the client can correctly deal with the user callback attempting
// to start another transaction on a session that is closing down. See
// http://crbug.com/47455
TEST_F(SpdyNetworkTransactionTest, StartTransactionOnReadCallback) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req)};
  MockWrite writes2[] = {CreateMockWrite(req, 0)};

  // The indicated length of this frame is longer than its actual length. When
  // the session receives an empty frame after this one, it shuts down the
  // session, and calls the read callback with the incomplete data.
  const uint8_t kGetBodyFrame2[] = {
      0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
      0x07, 'h',  'e',  'l',  'l',  'o',  '!',
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause
      MockRead(ASYNC, reinterpret_cast<const char*>(kGetBodyFrame2),
               arraysize(kGetBodyFrame2), 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause
      MockRead(ASYNC, 0, 0, 5),            // EOF
  };
  MockRead reads2[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 0, 2),  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                            arraysize(writes2));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.AddData(&data2);
  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();

  const int kSize = 3000;
  scoped_refptr<IOBuffer> buf(new IOBuffer(kSize));
  rv = trans->Read(
      buf.get(), kSize,
      base::Bind(&SpdyNetworkTransactionTest::StartTransactionCallback,
                 helper.session(), default_url_));
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  // This forces an err_IO_pending, which sets the callback.
  data.Resume();
  data.RunUntilPaused();

  // This finishes the read.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

// Verify that the client can correctly deal with the user callback deleting the
// transaction. Failures will usually be valgrind errors. See
// http://crbug.com/46925
TEST_F(SpdyNetworkTransactionTest, DeleteSessionOnReadCallback) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),                 // Force a pause
      CreateMockRead(body, 3), MockRead(ASYNC, 0, 0, 4),  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();

  // Setup a user callback which will delete the session, and clear out the
  // memory holding the stream object. Note that the callback deletes trans.
  const int kSize = 3000;
  scoped_refptr<IOBuffer> buf(new IOBuffer(kSize));
  rv = trans->Read(
      buf.get(),
      kSize,
      base::Bind(&SpdyNetworkTransactionTest::DeleteSessionCallback,
                 base::Unretained(&helper)));
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  data.Resume();

  // Finish running rest of tasks.
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, TestRawHeaderSizeSuccessfullRequest) {
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers["user-agent"] = "";
  headers["accept-encoding"] = "gzip, deflate";

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "should not include", 18, true));

  MockRead response_headers(CreateMockRead(resp, 1));
  MockRead reads[] = {
      response_headers, CreateMockRead(response_body_frame, 2),
      MockRead(ASYNC, 0, 0, 3)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  TestDelegate delegate;
  SpdyURLRequestContext spdy_url_request_context;
  TestNetworkDelegate network_delegate;
  spdy_url_request_context.set_network_delegate(&network_delegate);
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;

  std::unique_ptr<URLRequest> request(spdy_url_request_context.CreateRequest(
      GURL(kDefaultUrl), DEFAULT_PRIORITY, &delegate));
  spdy_url_request_context.socket_factory().AddSSLSocketDataProvider(&ssl_data);
  spdy_url_request_context.socket_factory().AddSocketDataProvider(&data);

  request->Start();
  base::RunLoop().Run();

  EXPECT_LT(0, request->GetTotalSentBytes());
  EXPECT_LT(0, request->GetTotalReceivedBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_sent(),
            request->GetTotalSentBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_received(),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(response_headers.data_len, request->raw_header_size());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyNetworkTransactionTest,
       TestRawHeaderSizeSuccessfullPushHeadersFirst) {
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers["user-agent"] = "";
  headers["accept-encoding"] = "gzip, deflate";

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame response_body_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "should not include", 18, true));

  SpdyHeaderBlock push_headers;
  spdy_util_.AddUrlToHeaderBlock(std::string(kDefaultUrl) + "b.dat",
                                 &push_headers);

  SpdySerializedFrame push_init_frame(
      spdy_util_.ConstructInitialSpdyPushFrame(std::move(push_headers), 2, 1));

  SpdySerializedFrame push_headers_frame(
      spdy_util_.ConstructSpdyPushHeaders(2, nullptr, 0));

  SpdySerializedFrame push_body_frame(spdy_util_.ConstructSpdyDataFrame(
      2, "should not include either", 25, false));

  MockRead push_init_read(CreateMockRead(push_init_frame, 1));
  MockRead response_headers(CreateMockRead(resp, 4));
  // raw_header_size() will contain the size of the push promise frame
  // initialization.
  int expected_response_headers_size =
      response_headers.data_len + push_init_read.data_len;

  MockRead reads[] = {
      push_init_read,
      CreateMockRead(push_headers_frame, 2),
      CreateMockRead(push_body_frame, 3),
      response_headers,
      CreateMockRead(response_body_frame, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  TestDelegate delegate;
  SpdyURLRequestContext spdy_url_request_context;
  TestNetworkDelegate network_delegate;
  spdy_url_request_context.set_network_delegate(&network_delegate);
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.next_proto = kProtoHTTP2;

  std::unique_ptr<URLRequest> request(spdy_url_request_context.CreateRequest(
      GURL(kDefaultUrl), DEFAULT_PRIORITY, &delegate));
  spdy_url_request_context.socket_factory().AddSSLSocketDataProvider(&ssl_data);
  spdy_url_request_context.socket_factory().AddSocketDataProvider(&data);

  request->Start();
  base::RunLoop().Run();

  EXPECT_LT(0, request->GetTotalSentBytes());
  EXPECT_LT(0, request->GetTotalReceivedBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_sent(),
            request->GetTotalSentBytes());
  EXPECT_EQ(network_delegate.total_network_bytes_received(),
            request->GetTotalReceivedBytes());
  EXPECT_EQ(expected_response_headers_size, request->raw_header_size());
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Send a spdy request to www.example.org that gets redirected to www.foo.com.
TEST_F(SpdyNetworkTransactionTest, DISABLED_RedirectGetRequest) {
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers["user-agent"] = "";
  headers["accept-encoding"] = "gzip, deflate";

  // Setup writes/reads to www.example.org
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReplyRedirect(1));
  MockWrite writes[] = {
      CreateMockWrite(req, 1),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 2), MockRead(ASYNC, 0, 0, 3)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  // Setup writes/reads to www.foo.com
  SpdyHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock("http://www.foo.com/index.php"));
  headers2["user-agent"] = "";
  headers2["accept-encoding"] = "gzip, deflate";
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers2), LOWEST, true));
  MockWrite writes2[] = {
      CreateMockWrite(req2, 1),
  };

  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {
      CreateMockRead(resp2, 2), CreateMockRead(body2, 3),
      MockRead(ASYNC, 0, 0, 4)  // EOF
  };

  SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                            arraysize(writes2));

  // TODO(erikchen): Make test support SPDYSSL, SPDYNPN
  TestDelegate d;
  {
    SpdyURLRequestContext spdy_url_request_context;
    std::unique_ptr<URLRequest> r(spdy_url_request_context.CreateRequest(
        default_url_, DEFAULT_PRIORITY, &d));
    spdy_url_request_context.socket_factory().
        AddSocketDataProvider(&data);
    spdy_url_request_context.socket_factory().
        AddSocketDataProvider(&data2);

    d.set_quit_on_redirect(true);
    r->Start();
    base::RunLoop().Run();

    EXPECT_EQ(1, d.received_redirect_count());

    r->FollowDeferredRedirect();
    base::RunLoop().Run();
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(OK, d.request_status());
    std::string contents("hello!");
    EXPECT_EQ(contents, d.data_received());
  }
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data2.AllReadDataConsumed());
  EXPECT_TRUE(data2.AllWriteDataConsumed());
}

// Send a spdy request to www.example.org. Get a pushed stream that redirects to
// www.foo.com.
TEST_F(SpdyNetworkTransactionTest, DISABLED_RedirectServerPush) {
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers["user-agent"] = "";
  headers["accept-encoding"] = "gzip, deflate";

  // Setup writes/reads to www.example.org
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame rep(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str(),
      "301 Moved Permanently", "http://www.foo.com/index.php"));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 1), CreateMockWrite(rst, 6),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(rep, 3), CreateMockRead(body, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5),  // Force a pause
      MockRead(ASYNC, 0, 0, 7)             // EOF
  };

  // Setup writes/reads to www.foo.com
  SpdyHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlock("http://www.foo.com/index.php"));
  headers2["user-agent"] = "";
  headers2["accept-encoding"] = "gzip, deflate";
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers2), LOWEST, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes2[] = {
      CreateMockWrite(req2, 1),
  };
  MockRead reads2[] = {
      CreateMockRead(resp2, 2), CreateMockRead(body2, 3),
      MockRead(ASYNC, 0, 0, 5)  // EOF
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                            arraysize(writes2));

  TestDelegate d;
  TestDelegate d2;
  SpdyURLRequestContext spdy_url_request_context;
  {
    std::unique_ptr<URLRequest> r(spdy_url_request_context.CreateRequest(
        default_url_, DEFAULT_PRIORITY, &d));
    spdy_url_request_context.socket_factory().
        AddSocketDataProvider(&data);

    r->Start();
    base::RunLoop().Run();

    EXPECT_EQ(0, d.received_redirect_count());
    std::string contents("hello!");
    EXPECT_EQ(contents, d.data_received());

    std::unique_ptr<URLRequest> r2(spdy_url_request_context.CreateRequest(
        GURL(GetDefaultUrlWithPath("/foo.dat")), DEFAULT_PRIORITY, &d2));
    spdy_url_request_context.socket_factory().
        AddSocketDataProvider(&data2);

    d2.set_quit_on_redirect(true);
    r2->Start();
    base::RunLoop().Run();
    EXPECT_EQ(1, d2.received_redirect_count());

    r2->FollowDeferredRedirect();
    base::RunLoop().Run();
    EXPECT_EQ(1, d2.response_started_count());
    EXPECT_FALSE(d2.received_data_before_response());
    EXPECT_EQ(OK, d2.request_status());
    std::string contents2("hello!");
    EXPECT_EQ(contents2, d2.data_received());
  }
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data2.AllReadDataConsumed());
  EXPECT_TRUE(data2.AllWriteDataConsumed());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushSingleDataFrame) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream1_body, 3, SYNCHRONOUS),
      CreateMockRead(stream2_body, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),  // Force a pause
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data,
                    &response,
                    &response2,
                    expected_push_result);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushBeforeHeaders) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  MockRead reads[] = {
      CreateMockRead(stream2_syn, 1),
      CreateMockRead(stream1_reply, 2),
      CreateMockRead(stream1_body, 3, SYNCHRONOUS),
      CreateMockRead(stream2_body, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),  // Force a pause
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data,
                    &response,
                    &response2,
                    expected_push_result);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushSingleDataFrame2) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream2_body, 3),
      CreateMockRead(stream1_body, 4, SYNCHRONOUS),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),  // Force a pause
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data,
                    &response,
                    &response2,
                    expected_push_result);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushServerAborted) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  SpdySerializedFrame stream2_rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_PROTOCOL_ERROR));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream2_rst, 3),
      CreateMockRead(stream1_body, 4, SYNCHRONOUS),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),  // Force a pause
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
}

// Verify that we don't leak streams and that we properly send a reset
// if the server pushes the same stream twice.
TEST_F(SpdyNetworkTransactionTest, ServerPushDuplicate) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame stream3_rst(
      spdy_util_.ConstructSpdyRstStream(4, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(stream3_rst, 4),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  SpdySerializedFrame stream3_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 4, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream3_syn, 3),
      CreateMockRead(stream1_body, 5),
      CreateMockRead(stream2_body, 6),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 7),  // Force a pause
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data,
                    &response,
                    &response2,
                    expected_push_result);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushMultipleDataFrame) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  static const char kPushedData[] = "pushed my darling hello my baby";
  SpdySerializedFrame stream2_body_base(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  const size_t kChunkSize = strlen(kPushedData) / 4;
  SpdySerializedFrame stream2_body1(stream2_body_base.data(), kChunkSize,
                                    false);
  SpdySerializedFrame stream2_body2(stream2_body_base.data() + kChunkSize,
                                    kChunkSize, false);
  SpdySerializedFrame stream2_body3(stream2_body_base.data() + 2 * kChunkSize,
                                    kChunkSize, false);
  SpdySerializedFrame stream2_body4(stream2_body_base.data() + 3 * kChunkSize,
                                    stream2_body_base.size() - 3 * kChunkSize,
                                    false);
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream2_body1, 3),
      CreateMockRead(stream2_body2, 4),
      CreateMockRead(stream2_body3, 5),
      CreateMockRead(stream2_body4, 6),
      CreateMockRead(stream1_body, 7, SYNCHRONOUS),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 8),  // Force a pause
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed my darling hello my baby");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data, &response, &response2, kPushedData);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushMultipleDataFrameInterrupted) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  static const char kPushedData[] = "pushed my darling hello my baby";
  SpdySerializedFrame stream2_body_base(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  const size_t kChunkSize = strlen(kPushedData) / 4;
  SpdySerializedFrame stream2_body1(stream2_body_base.data(), kChunkSize,
                                    false);
  SpdySerializedFrame stream2_body2(stream2_body_base.data() + kChunkSize,
                                    kChunkSize, false);
  SpdySerializedFrame stream2_body3(stream2_body_base.data() + 2 * kChunkSize,
                                    kChunkSize, false);
  SpdySerializedFrame stream2_body4(stream2_body_base.data() + 3 * kChunkSize,
                                    stream2_body_base.size() - 3 * kChunkSize,
                                    false);
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream2_body1, 3),
      CreateMockRead(stream2_body2, 4),
      CreateMockRead(stream2_body3, 5),
      CreateMockRead(stream2_body4, 6),
      CreateMockRead(stream1_body, 7, SYNCHRONOUS),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 8)  // Force a pause.
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data, &response, &response2, kPushedData);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushInvalidAssociatedStreamID0) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_PROTOCOL_ERROR, "Framer error: 1 (INVALID_STREAM_ID)."));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(goaway, 3),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 0, GetDefaultUrlWithPath("/foo.dat").c_str()));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream2_syn, 2),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushInvalidAssociatedStreamID9) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame stream2_rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_INVALID_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(stream2_rst, 3),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 9, GetDefaultUrlWithPath("/foo.dat").c_str()));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream1_body, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),  // Force a pause
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushNoURL) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame stream2_rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(stream2_rst, 3),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdyHeaderBlock incomplete_headers;
  incomplete_headers[spdy_util_.GetStatusKey()] = "200 OK";
  incomplete_headers["hello"] = "bye";
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructInitialSpdyPushFrame(
      std::move(incomplete_headers), 2, 1));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream1_body, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5)  // Force a pause
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
}

// PUSH_PROMISE on a server-initiated stream should trigger GOAWAY.
TEST_F(SpdyNetworkTransactionTest, ServerPushOnPushedStream) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      2, GOAWAY_PROTOCOL_ERROR, "Push on even stream id."));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(goaway, 4),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  SpdySerializedFrame stream3_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 2, GetDefaultUrlWithPath("/bar.dat").c_str()));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream3_syn, 3),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);
  helper.RunToCompletion(&data);
}

// PUSH_PROMISE on a closed client-initiated stream should trigger RST_STREAM.
TEST_F(SpdyNetworkTransactionTest, ServerPushOnClosedStream) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_INVALID_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(rst, 5),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream1_body, 2),
      CreateMockRead(stream2_syn, 3), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 4),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsOk());
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
  VerifyStreamsClosed(helper);
}

// PUSH_PROMISE on a server-initiated stream should trigger GOAWAY even if
// stream is closed.
TEST_F(SpdyNetworkTransactionTest, ServerPushOnClosedPushedStream) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      2, GOAWAY_PROTOCOL_ERROR, "Push on even stream id."));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0), CreateMockWrite(goaway, 7),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, GetDefaultUrlWithPath("/foo.dat").c_str()));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  SpdySerializedFrame stream3_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 4, 2, GetDefaultUrlWithPath("/bar.dat").c_str()));

  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),   CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream1_body, 3),    CreateMockRead(stream2_body, 4),
      MockRead(ASYNC, ERR_IO_PENDING, 5), CreateMockRead(stream3_syn, 6),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans1 = helper.trans();
  TestCompletionCallback callback1;
  int rv = trans1->Start(&CreateGetRequest(), callback1.callback(),
                         NetLogWithSource());
  rv = callback1.GetResult(rv);
  EXPECT_THAT(rv, IsOk());
  HttpResponseInfo response = *trans1->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  TestCompletionCallback callback2;
  rv = trans2.Start(&CreateGetPushRequest(), callback2.callback(),
                    NetLogWithSource());
  rv = callback2.GetResult(rv);
  EXPECT_THAT(rv, IsOk());
  response = *trans2.GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
  std::string result;
  ReadResult(&trans2, &result);
  EXPECT_EQ(kPushedData, result);

  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

// Verify that various response headers parse correctly through the HTTP layer.
TEST_F(SpdyNetworkTransactionTest, ResponseHeaders) {
  struct ResponseHeadersTests {
    int num_headers;
    const char* extra_headers[5];
    SpdyHeaderBlock expected_headers;
  } test_cases[] = {
    // This uses a multi-valued cookie header.
    { 2,
      { "cookie", "val1",
        "cookie", "val2",  // will get appended separated by NULL
        NULL
      },
    },
    // This is the minimalist set of headers.
    { 0,
      { NULL },
    },
    // Headers with a comma separated list.
    { 1,
      { "cookie", "val1,val2",
        NULL
      },
    }
  };

  test_cases[0].expected_headers["status"] = "200";
  test_cases[1].expected_headers["status"] = "200";
  test_cases[2].expected_headers["status"] = "200";

  test_cases[0].expected_headers["hello"] = "bye";
  test_cases[1].expected_headers["hello"] = "bye";
  test_cases[2].expected_headers["hello"] = "bye";

  test_cases[0].expected_headers["cookie"] = base::StringPiece("val1\0val2", 9);
  test_cases[2].expected_headers["cookie"] = "val1,val2";

  for (size_t i = 0; i < arraysize(test_cases); ++i) {
    SpdyTestUtil spdy_test_util;
    SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
    MockWrite writes[] = {CreateMockWrite(req, 0)};

    SpdySerializedFrame resp(spdy_test_util.ConstructSpdyGetReply(
        test_cases[i].extra_headers, test_cases[i].num_headers, 1));
    SpdySerializedFrame body(spdy_test_util.ConstructSpdyDataFrame(1, true));
    MockRead reads[] = {
        CreateMockRead(resp, 1), CreateMockRead(body, 2),
        MockRead(ASYNC, 0, 3)  // EOF
    };

    SequencedSocketData data(reads, arraysize(reads), writes,
                             arraysize(writes));
    NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();

    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!", out.response_data);

    scoped_refptr<HttpResponseHeaders> headers = out.response_info.headers;
    EXPECT_TRUE(headers);
    size_t iter = 0;
    std::string name, value;
    SpdyHeaderBlock header_block;
    while (headers->EnumerateHeaderLines(&iter, &name, &value)) {
      auto value_it = header_block.find(name);
      if (value_it == header_block.end() || value_it->second.empty()) {
        header_block[name] = value;
      } else {
        std::string joint_value = value_it->second.as_string();
        joint_value.append(1, '\0');
        joint_value.append(value);
        header_block[name] = joint_value;
      }
    }
    EXPECT_EQ(test_cases[i].expected_headers, header_block);
  }
}

// Verify that various response headers parse vary fields correctly through the
// HTTP layer, and the response matches the request.
TEST_F(SpdyNetworkTransactionTest, ResponseHeadersVary) {
  // Modify the following data to change/add test cases:
  struct ResponseTests {
    bool vary_matches;
    int num_headers[2];
    const char* extra_headers[2][16];
  } test_cases[] = {
      // Test the case of a multi-valued cookie.  When the value is delimited
      // with NUL characters, it needs to be unfolded into multiple headers.
      {true,
       {1, 3},
       {{"cookie", "val1,val2", NULL},
        {spdy_util_.GetStatusKey(), "200", spdy_util_.GetPathKey(),
         "/index.php", "vary", "cookie", NULL}}},
      {// Multiple vary fields.
       true,
       {2, 4},
       {{"friend", "barney", "enemy", "snaggletooth", NULL},
        {spdy_util_.GetStatusKey(), "200", spdy_util_.GetPathKey(),
         "/index.php", "vary", "friend", "vary", "enemy", NULL}}},
      {// Test a '*' vary field.
       false,
       {1, 3},
       {{"cookie", "val1,val2", NULL},
        {spdy_util_.GetStatusKey(), "200", spdy_util_.GetPathKey(),
         "/index.php", "vary", "*", NULL}}},
      {// Multiple comma-separated vary fields.
       true,
       {2, 3},
       {{"friend", "barney", "enemy", "snaggletooth", NULL},
        {spdy_util_.GetStatusKey(), "200", spdy_util_.GetPathKey(),
         "/index.php", "vary", "friend,enemy", NULL}}}};

  for (size_t i = 0; i < arraysize(test_cases); ++i) {
    SpdyTestUtil spdy_test_util;

    // Construct the request.
    SpdySerializedFrame frame_req(spdy_test_util.ConstructSpdyGet(
        test_cases[i].extra_headers[0], test_cases[i].num_headers[0], 1, LOWEST,
        true));

    MockWrite writes[] = {
        CreateMockWrite(frame_req, 0),
    };

    // Construct the reply.
    SpdyHeaderBlock reply_headers;
    AppendToHeaderBlock(test_cases[i].extra_headers[1],
                        test_cases[i].num_headers[1],
                        &reply_headers);
    // Construct the expected header reply string before moving |reply_headers|.
    std::string expected_reply =
        spdy_test_util.ConstructSpdyReplyString(reply_headers);

    SpdySerializedFrame frame_reply(
        spdy_test_util.ConstructSpdyReply(1, std::move(reply_headers)));

    SpdySerializedFrame body(spdy_test_util.ConstructSpdyDataFrame(1, true));
    MockRead reads[] = {
        CreateMockRead(frame_reply, 1), CreateMockRead(body, 2),
        MockRead(ASYNC, 0, 3)  // EOF
    };

    // Attach the headers to the request.
    int header_count = test_cases[i].num_headers[0];

    HttpRequestInfo request = CreateGetRequest();
    for (int ct = 0; ct < header_count; ct++) {
      const char* header_key = test_cases[i].extra_headers[0][ct * 2];
      const char* header_value = test_cases[i].extra_headers[0][ct * 2 + 1];
      request.extra_headers.SetHeader(header_key, header_value);
    }

    SequencedSocketData data(reads, arraysize(reads), writes,
                             arraysize(writes));
    NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();

    EXPECT_EQ(OK, out.rv) << i;
    EXPECT_EQ("HTTP/1.1 200", out.status_line) << i;
    EXPECT_EQ("hello!", out.response_data) << i;

    // Test the response information.
    EXPECT_EQ(out.response_info.vary_data.is_valid(),
              test_cases[i].vary_matches) << i;

    // Check the headers.
    scoped_refptr<HttpResponseHeaders> headers = out.response_info.headers;
    ASSERT_TRUE(headers) << i;
    size_t iter = 0;
    std::string name, value, lines;
    while (headers->EnumerateHeaderLines(&iter, &name, &value)) {
      lines.append(name);
      lines.append(": ");
      lines.append(value);
      lines.append("\n");
    }

    EXPECT_EQ(expected_reply, lines) << i;
  }
}

// Verify that we don't crash on invalid response headers.
TEST_F(SpdyNetworkTransactionTest, InvalidResponseHeaders) {
  struct InvalidResponseHeadersTests {
    int num_headers;
    const char* headers[10];
  } test_cases[] = {
      // Response headers missing status header
      {
          3,
          {spdy_util_.GetPathKey(), "/index.php", "cookie", "val1", "cookie",
           "val2", NULL},
      },
      // Response headers missing version header
      {
          1, {spdy_util_.GetPathKey(), "/index.php", "status", "200", NULL},
      },
      // Response headers with no headers
      {
          0, {NULL},
      },
  };

  for (size_t i = 0; i < arraysize(test_cases); ++i) {
    SpdyTestUtil spdy_test_util;

    SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
    SpdySerializedFrame rst(
        spdy_test_util.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
    MockWrite writes[] = {
        CreateMockWrite(req, 0), CreateMockWrite(rst, 2),
    };

    // Construct the reply.
    SpdyHeaderBlock reply_headers;
    AppendToHeaderBlock(
        test_cases[i].headers, test_cases[i].num_headers, &reply_headers);
    SpdySerializedFrame resp(
        spdy_test_util.ConstructSpdyReply(1, std::move(reply_headers)));
    MockRead reads[] = {
        CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3)  // EOF
    };

    SequencedSocketData data(reads, arraysize(reads), writes,
                             arraysize(writes));
    NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
  }
}

TEST_F(SpdyNetworkTransactionTest, CorruptFrameSessionError) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_COMPRESSION_ERROR, "Framer error: 6 (DECOMPRESS_FAILURE)."));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  // This is the length field that's too short.
  SpdySerializedFrame reply_wrong_length(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  size_t right_size =
      reply_wrong_length.size() - SpdyConstants::kFrameHeaderSize;
  size_t wrong_size = right_size - 4;
  test::SetFrameLength(&reply_wrong_length, wrong_size);

  MockRead reads[] = {
      MockRead(ASYNC, reply_wrong_length.data(), reply_wrong_length.size() - 4,
               1),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_COMPRESSION_ERROR));
}

TEST_F(SpdyNetworkTransactionTest, GoAwayOnDecompressionFailure) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_COMPRESSION_ERROR, "Framer error: 6 (DECOMPRESS_FAILURE)."));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  // Read HEADERS with corrupted payload.
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  memset(resp.data() + 12, 0xcf, resp.size() - 12);
  MockRead reads[] = {CreateMockRead(resp, 1)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_COMPRESSION_ERROR));
}

TEST_F(SpdyNetworkTransactionTest, GoAwayOnFrameSizeError) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_FRAME_SIZE_ERROR,
      "Framer error: 15 (INVALID_CONTROL_FRAME_SIZE)."));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  // Read WINDOW_UPDATE with incorrectly-sized payload.
  SpdySerializedFrame bad_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, 1));
  test::SetFrameLength(&bad_window_update, bad_window_update.size() - 1);
  MockRead reads[] = {CreateMockRead(bad_window_update, 1)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_FRAME_SIZE_ERROR));
}

// Test that we shutdown correctly on write errors.
TEST_F(SpdyNetworkTransactionTest, WriteError) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      // We'll write 10 bytes successfully
      MockWrite(ASYNC, req.data(), 10, 1),
      // Followed by ERROR!
      MockWrite(ASYNC, ERR_FAILED, 2),
      // Session drains and attempts to write a GOAWAY: Another ERROR!
      MockWrite(ASYNC, ERR_FAILED, 3),
  };

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  EXPECT_TRUE(helper.StartDefaultTest());
  helper.FinishDefaultTest();
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_FAILED));
}

// Test that partial writes work.
TEST_F(SpdyNetworkTransactionTest, PartialWrite) {
  // Chop the HEADERS frame into 5 chunks.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  const int kChunks = 5;
  std::unique_ptr<MockWrite[]> writes(ChopWriteFrame(req, kChunks));
  for (int i = 0; i < kChunks; ++i) {
    writes[i].sequence_number = i;
  }

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, kChunks), CreateMockRead(body, kChunks + 1),
      MockRead(ASYNC, 0, kChunks + 2)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes.get(), kChunks);
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that the NetLog contains good data for a simple GET request.
TEST_F(SpdyNetworkTransactionTest, NetLog) {
  static const char* const kExtraHeaders[] = {
    "user-agent",   "Chrome",
  };
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kExtraHeaders, 1, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  BoundTestNetLog log;

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequestWithUserAgent(),
                                     DEFAULT_PRIORITY, log.bound(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // Check that the NetLog was filled reasonably.
  // This test is intentionally non-specific about the exact ordering of the
  // log; instead we just check to make sure that certain events exist, and that
  // they are in the right order.
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);

  EXPECT_LT(0u, entries.size());
  int pos = 0;
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST,
      NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos + 1, NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST,
      NetLogEventPhase::END);
  pos = ExpectLogContainsSomewhere(
      entries, pos + 1, NetLogEventType::HTTP_TRANSACTION_READ_HEADERS,
      NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos + 1, NetLogEventType::HTTP_TRANSACTION_READ_HEADERS,
      NetLogEventPhase::END);
  pos = ExpectLogContainsSomewhere(entries, pos + 1,
                                   NetLogEventType::HTTP_TRANSACTION_READ_BODY,
                                   NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(entries, pos + 1,
                                   NetLogEventType::HTTP_TRANSACTION_READ_BODY,
                                   NetLogEventPhase::END);

  // Check that we logged all the headers correctly
  pos = ExpectLogContainsSomewhere(entries, 0,
                                   NetLogEventType::HTTP2_SESSION_SEND_HEADERS,
                                   NetLogEventPhase::NONE);

  base::ListValue* header_list;
  ASSERT_TRUE(entries[pos].params.get());
  ASSERT_TRUE(entries[pos].params->GetList("headers", &header_list));

  std::vector<std::string> expected;
  expected.push_back(std::string(spdy_util_.GetHostKey()) +
                     ": www.example.org");
  expected.push_back(std::string(spdy_util_.GetPathKey()) + ": /");
  expected.push_back(std::string(spdy_util_.GetSchemeKey()) + ": " +
                     default_url_.scheme());
  expected.push_back(std::string(spdy_util_.GetMethodKey()) + ": GET");
  expected.push_back("user-agent: Chrome");
  EXPECT_EQ(expected.size(), header_list->GetSize());
  for (std::vector<std::string>::const_iterator it = expected.begin();
       it != expected.end();
       ++it) {
    base::StringValue header(*it);
    EXPECT_NE(header_list->end(), header_list->Find(header)) <<
        "Header not found: " << *it;
  }
}

// Since we buffer the IO from the stream to the renderer, this test verifies
// that when we read out the maximum amount of data (e.g. we received 50 bytes
// on the network, but issued a Read for only 5 of those bytes) that the data
// flow still works correctly.
TEST_F(SpdyNetworkTransactionTest, BufferFull) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // 2 data frames in a single read.
  SpdySerializedFrame data_frame_1(
      spdy_util_.ConstructSpdyDataFrame(1, "goodby", 6, /*fin=*/false));
  SpdySerializedFrame data_frame_2(
      spdy_util_.ConstructSpdyDataFrame(1, "e worl", 6, /*fin=*/false));
  const SpdySerializedFrame* data_frames[2] = {
      &data_frame_1, &data_frame_2,
  };
  char combined_data_frames[100];
  int combined_data_frames_len =
      CombineFrames(data_frames, arraysize(data_frames),
                    combined_data_frames, arraysize(combined_data_frames));
  SpdySerializedFrame last_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "d", 1, /*fin=*/true));

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause
      MockRead(ASYNC, combined_data_frames, combined_data_frames_len, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause
      CreateMockRead(last_frame, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  TestCompletionCallback callback;

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 3;
    scoped_refptr<IOBuffer> buf(new IOBuffer(kSmallReadSize));
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv == ERR_IO_PENDING) {
      data.Resume();
      rv = read_callback.WaitForResult();
    }
    if (rv > 0) {
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      NOTREACHED();
    }
  } while (rv > 0);

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("goodbye world", out.response_data);
}

// Verify that basic buffering works; when multiple data frames arrive
// at the same time, ensure that we don't notify a read completion for
// each data frame individually.
TEST_F(SpdyNetworkTransactionTest, Buffering) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // 4 data frames in a single read.
  SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", 7, /*fin=*/false));
  SpdySerializedFrame data_frame_fin(
      spdy_util_.ConstructSpdyDataFrame(1, "message", 7, /*fin=*/true));
  const SpdySerializedFrame* data_frames[4] = {&data_frame, &data_frame,
                                               &data_frame, &data_frame_fin};
  char combined_data_frames[100];
  int combined_data_frames_len =
      CombineFrames(data_frames, arraysize(data_frames),
                    combined_data_frames, arraysize(combined_data_frames));

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause
      MockRead(ASYNC, combined_data_frames, combined_data_frames_len, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  int reads_completed = 0;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 14;
    scoped_refptr<IOBuffer> buf(new IOBuffer(kSmallReadSize));
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv == ERR_IO_PENDING) {
      data.Resume();
      rv = read_callback.WaitForResult();
    }
    if (rv > 0) {
      EXPECT_EQ(kSmallReadSize, rv);
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      FAIL() << "Unexpected read error: " << rv;
    }
    reads_completed++;
  } while (rv > 0);

  EXPECT_EQ(3, reads_completed);  // Reads are: 14 bytes, 14 bytes, 0 bytes.

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("messagemessagemessagemessage", out.response_data);
}

// Verify the case where we buffer data but read it after it has been buffered.
TEST_F(SpdyNetworkTransactionTest, BufferedAll) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // 5 data frames in a single read.
  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", 7, /*fin=*/false));
  SpdySerializedFrame data_frame_fin(
      spdy_util_.ConstructSpdyDataFrame(1, "message", 7, /*fin=*/true));
  const SpdySerializedFrame* frames[5] = {&reply, &data_frame, &data_frame,
                                          &data_frame, &data_frame_fin};
  char combined_frames[200];
  int combined_frames_len =
      CombineFrames(frames, arraysize(frames),
                    combined_frames, arraysize(combined_frames));

  MockRead reads[] = {
      MockRead(ASYNC, combined_frames, combined_frames_len, 1),
      MockRead(ASYNC, 0, 2)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  int reads_completed = 0;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 14;
    scoped_refptr<IOBuffer> buf(new IOBuffer(kSmallReadSize));
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv > 0) {
      EXPECT_EQ(kSmallReadSize, rv);
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      FAIL() << "Unexpected read error: " << rv;
    }
    reads_completed++;
  } while (rv > 0);

  EXPECT_EQ(3, reads_completed);

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("messagemessagemessagemessage", out.response_data);
}

// Verify the case where we buffer data and close the connection.
TEST_F(SpdyNetworkTransactionTest, BufferedClosed) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // All data frames in a single read.
  // NOTE: We don't FIN the stream.
  SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", 7, /*fin=*/false));
  const SpdySerializedFrame* data_frames[4] = {&data_frame, &data_frame,
                                               &data_frame, &data_frame};
  char combined_data_frames[100];
  int combined_data_frames_len =
      CombineFrames(data_frames, arraysize(data_frames),
                    combined_data_frames, arraysize(combined_data_frames));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a wait
      MockRead(ASYNC, combined_data_frames, combined_data_frames_len, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;

  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  int reads_completed = 0;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 14;
    scoped_refptr<IOBuffer> buf(new IOBuffer(kSmallReadSize));
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv == ERR_IO_PENDING) {
      data.Resume();
      rv = read_callback.WaitForResult();
    }
    if (rv > 0) {
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      // This test intentionally closes the connection, and will get an error.
      EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
      break;
    }
    reads_completed++;
  } while (rv > 0);

  EXPECT_EQ(0, reads_completed);

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

// Verify the case where we buffer data and cancel the transaction.
TEST_F(SpdyNetworkTransactionTest, BufferedCancelled) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_CANCEL));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 4)};

  // NOTE: We don't FIN the stream.
  SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", 7, /*fin=*/false));

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),                   // Force a wait
      CreateMockRead(data_frame, 3), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();
  TestCompletionCallback callback;

  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  const int kReadSize = 256;
  scoped_refptr<IOBuffer> buf(new IOBuffer(kReadSize));
  rv = trans->Read(buf.get(), kReadSize, read_callback.callback());
  ASSERT_EQ(ERR_IO_PENDING, rv) << "Unexpected read: " << rv;

  // Complete the read now, which causes buffering to start.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  // Destroy the transaction, causing the stream to get cancelled
  // and orphaning the buffered IO task.
  helper.ResetTrans();

  // Flush the MessageLoop; this will cause the buffered IO task
  // to run for the final time.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, GoAwayWithActiveStream) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame go_away(spdy_util_.ConstructSpdyGoAway());
  MockRead reads[] = {
      CreateMockRead(go_away, 1),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.AddData(&data);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_ABORTED));
}

TEST_F(SpdyNetworkTransactionTest, CloseWithActiveStream) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1), MockRead(SYNCHRONOUS, 0, 2)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsError(ERR_CONNECTION_CLOSED));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

// Retry with HTTP/1.1 when receiving HTTP_1_1_REQUIRED.  Note that no actual
// protocol negotiation happens, instead this test forces protocols for both
// sockets.
TEST_F(SpdyNetworkTransactionTest, HTTP11RequiredRetry) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = default_url_;
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);

  // First socket: HTTP/2 request rejected with HTTP_1_1_REQUIRED.
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes0[] = {CreateMockWrite(req, 0)};
  SpdySerializedFrame go_away(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_HTTP_1_1_REQUIRED, "Try again using HTTP/1.1 please."));
  MockRead reads0[] = {CreateMockRead(go_away, 1)};
  SequencedSocketData data0(reads0, arraysize(reads0), writes0,
                            arraysize(writes0));

  std::unique_ptr<SSLSocketDataProvider> ssl_provider0(
      new SSLSocketDataProvider(ASYNC, OK));
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config.push_back(kProtoHTTP2);
  ssl_provider0->next_protos_expected_in_ssl_config.push_back(kProtoHTTP11);
  // Force SPDY.
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // Second socket: falling back to HTTP/1.1.
  MockWrite writes1[] = {MockWrite(ASYNC, 0,
                                   "GET / HTTP/1.1\r\n"
                                   "Host: www.example.org\r\n"
                                   "Connection: keep-alive\r\n\r\n")};
  MockRead reads1[] = {MockRead(ASYNC, 1,
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Length: 5\r\n\r\n"
                                "hello")};
  SequencedSocketData data1(reads1, arraysize(reads1), writes1,
                            arraysize(writes1));

  std::unique_ptr<SSLSocketDataProvider> ssl_provider1(
      new SSLSocketDataProvider(ASYNC, OK));
  // Expect only HTTP/1.1 protocol in SSLConfig.
  ssl_provider1->next_protos_expected_in_ssl_config.push_back(kProtoHTTP11);
  // Force HTTP/1.1.
  ssl_provider1->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(host_port_pair_));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(host_port_pair_));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpResponseInfo::CONNECTION_INFO_HTTP1_1,
            response->connection_info);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_TRUE(request.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->socket_address.host());
  EXPECT_EQ(443, response->socket_address.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Retry with HTTP/1.1 to the proxy when receiving HTTP_1_1_REQUIRED from the
// proxy.  Note that no actual protocol negotiation happens, instead this test
// forces protocols for both sockets.
TEST_F(SpdyNetworkTransactionTest, HTTP11RequiredProxyRetry) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = default_url_;
  auto session_deps = base::MakeUnique<SpdySessionDependencies>(
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy:70"));
  // Do not force SPDY so that second socket can negotiate HTTP/1.1.
  NormalSpdyTransactionHelper helper(
      request, DEFAULT_PRIORITY, NetLogWithSource(), std::move(session_deps));

  // First socket: HTTP/2 CONNECT rejected with HTTP_1_1_REQUIRED.
  SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  MockWrite writes0[] = {CreateMockWrite(req, 0)};
  SpdySerializedFrame go_away(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_HTTP_1_1_REQUIRED, "Try again using HTTP/1.1 please."));
  MockRead reads0[] = {CreateMockRead(go_away, 1)};
  SequencedSocketData data0(reads0, arraysize(reads0), writes0,
                            arraysize(writes0));

  std::unique_ptr<SSLSocketDataProvider> ssl_provider0(
      new SSLSocketDataProvider(ASYNC, OK));
  // Expect HTTP/2 protocols too in SSLConfig.
  ssl_provider0->next_protos_expected_in_ssl_config.push_back(kProtoHTTP2);
  ssl_provider0->next_protos_expected_in_ssl_config.push_back(kProtoHTTP11);
  // Force SPDY.
  ssl_provider0->next_proto = kProtoHTTP2;
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // Second socket: retry using HTTP/1.1.
  MockWrite writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      MockWrite(ASYNC, 2,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads1[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
      MockRead(ASYNC, 3,
               "HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
  };
  SequencedSocketData data1(reads1, arraysize(reads1), writes1,
                            arraysize(writes1));

  std::unique_ptr<SSLSocketDataProvider> ssl_provider1(
      new SSLSocketDataProvider(ASYNC, OK));
  // Expect only HTTP/1.1 protocol in SSLConfig.
  ssl_provider1->next_protos_expected_in_ssl_config.push_back(kProtoHTTP11);
  // Force HTTP/1.1.
  ssl_provider1->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  // A third socket is needed for the tunnelled connection.
  std::unique_ptr<SSLSocketDataProvider> ssl_provider2(
      new SSLSocketDataProvider(ASYNC, OK));
  helper.session_deps()->socket_factory->AddSSLSocketDataProvider(
      ssl_provider2.get());

  HttpServerProperties* http_server_properties =
      helper.session()->spdy_session_pool()->http_server_properties();
  const HostPortPair proxy_host_port_pair = HostPortPair("myproxy", 70);
  EXPECT_FALSE(http_server_properties->RequiresHTTP11(proxy_host_port_pair));

  helper.RunPreTestSetup();
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  helper.VerifyDataConsumed();
  EXPECT_TRUE(http_server_properties->RequiresHTTP11(proxy_host_port_pair));

  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_EQ(HttpResponseInfo::CONNECTION_INFO_HTTP1_1,
            response->connection_info);
  EXPECT_FALSE(response->was_alpn_negotiated);
  EXPECT_TRUE(request.url.SchemeIs("https"));
  EXPECT_EQ("127.0.0.1", response->socket_address.host());
  EXPECT_EQ(70, response->socket_address.port());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(helper.trans(), &response_data), IsOk());
  EXPECT_EQ("hello", response_data);
}

// Test to make sure we can correctly connect through a proxy.
TEST_F(SpdyNetworkTransactionTest, ProxyConnect) {
  auto session_deps = base::MakeUnique<SpdySessionDependencies>(
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70"));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(),
                                     std::move(session_deps));
  helper.RunPreTestSetup();
  HttpNetworkTransaction* trans = helper.trans();

  const char kConnect443[] = {
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n\r\n"};
  const char kHTTP200[] = {"HTTP/1.1 200 OK\r\n\r\n"};
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kConnect443, arraysize(kConnect443) - 1, 0),
      CreateMockWrite(req, 2),
  };
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, kHTTP200, arraysize(kHTTP200) - 1, 1),
      CreateMockRead(resp, 3), CreateMockRead(body, 4),
      MockRead(ASYNC, 0, 0, 5),
  };
  std::unique_ptr<SequencedSocketData> data(new SequencedSocketData(
      reads, arraysize(reads), writes, arraysize(writes)));

  helper.AddData(data.get());
  TestCompletionCallback callback;

  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_EQ(0, rv);

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  ASSERT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  helper.VerifyDataConsumed();
}

// Test to make sure we can correctly connect through a proxy to
// www.example.org, if there already exists a direct spdy connection to
// www.example.org. See https://crbug.com/49874.
TEST_F(SpdyNetworkTransactionTest, DirectConnectProxyReconnect) {
  // Use a proxy service which returns a proxy fallback list from DIRECT to
  // myproxy:70. For this test there will be no fallback, so it is equivalent
  // to simply DIRECT. The reason for appending the second proxy is to verify
  // that the session pool key used does is just "DIRECT".
  auto session_deps = base::MakeUnique<SpdySessionDependencies>(
      ProxyService::CreateFixedFromPacResult("DIRECT; PROXY myproxy:70"));
  // When setting up the first transaction, we store the SpdySessionPool so that
  // we can use the same pool in the second transaction.
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(),
                                     std::move(session_deps));

  SpdySessionPool* spdy_session_pool = helper.session()->spdy_session_pool();
  helper.RunPreTestSetup();

  // Construct and send a simple GET request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),  // Force a pause
  };
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  TransactionHelperResult out;
  out.rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());

  EXPECT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.rv = ReadTransaction(trans, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  out.status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // Check that the SpdySession is still in the SpdySessionPool.
  SpdySessionKey session_pool_key_direct(host_port_pair_, ProxyServer::Direct(),
                                         PRIVACY_MODE_DISABLED);
  EXPECT_TRUE(HasSpdySession(spdy_session_pool, session_pool_key_direct));
  SpdySessionKey session_pool_key_proxy(
      host_port_pair_,
      ProxyServer::FromURI("www.foo.com", ProxyServer::SCHEME_HTTP),
      PRIVACY_MODE_DISABLED);
  EXPECT_FALSE(HasSpdySession(spdy_session_pool, session_pool_key_proxy));

  // New SpdyTestUtil instance for the session that will be used for the
  // proxy connection.
  SpdyTestUtil spdy_util_2;

  // Set up data for the proxy connection.
  const char kConnect443[] = {
      "CONNECT www.example.org:443 HTTP/1.1\r\n"
      "Host: www.example.org:443\r\n"
      "Proxy-Connection: keep-alive\r\n\r\n"};
  const char kHTTP200[] = {"HTTP/1.1 200 OK\r\n\r\n"};
  SpdySerializedFrame req2(spdy_util_2.ConstructSpdyGet(
      GetDefaultUrlWithPath("/foo.dat").c_str(), 1, LOWEST));
  SpdySerializedFrame resp2(spdy_util_2.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body2(spdy_util_2.ConstructSpdyDataFrame(1, true));

  MockWrite writes2[] = {
      MockWrite(SYNCHRONOUS, kConnect443, arraysize(kConnect443) - 1, 0),
      CreateMockWrite(req2, 2),
  };
  MockRead reads2[] = {
      MockRead(SYNCHRONOUS, kHTTP200, arraysize(kHTTP200) - 1, 1),
      CreateMockRead(resp2, 3), CreateMockRead(body2, 4),
      MockRead(ASYNC, 0, 5)  // EOF
  };

  std::unique_ptr<SequencedSocketData> data_proxy(new SequencedSocketData(
      reads2, arraysize(reads2), writes2, arraysize(writes2)));

  // Create another request to www.example.org, but this time through a proxy.
  HttpRequestInfo request_proxy;
  request_proxy.method = "GET";
  request_proxy.url = GURL(GetDefaultUrlWithPath("/foo.dat"));
  request_proxy.load_flags = 0;
  auto session_deps_proxy = base::MakeUnique<SpdySessionDependencies>(
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70"));
  NormalSpdyTransactionHelper helper_proxy(request_proxy, DEFAULT_PRIORITY,
                                           NetLogWithSource(),
                                           std::move(session_deps_proxy));
  helper_proxy.RunPreTestSetup();
  helper_proxy.AddData(data_proxy.get());

  HttpNetworkTransaction* trans_proxy = helper_proxy.trans();
  TestCompletionCallback callback_proxy;
  int rv = trans_proxy->Start(&request_proxy, callback_proxy.callback(),
                              NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback_proxy.WaitForResult();
  EXPECT_EQ(0, rv);

  HttpResponseInfo response_proxy = *trans_proxy->GetResponseInfo();
  ASSERT_TRUE(response_proxy.headers);
  EXPECT_EQ("HTTP/1.1 200", response_proxy.headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans_proxy, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  helper_proxy.VerifyDataConsumed();
}

// When we get a TCP-level RST, we need to retry a HttpNetworkTransaction
// on a new connection, if the connection was previously known to be good.
// This can happen when a server reboots without saying goodbye, or when
// we're behind a NAT that masked the RST.
TEST_F(SpdyNetworkTransactionTest, VerifyRetryOnConnectionReset) {
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      MockRead(ASYNC, ERR_CONNECTION_RESET, 4),
  };

  MockRead reads2[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  // In all cases the connection will be reset before req3 can be
  // dispatched, destroying both streams.
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  MockWrite writes1[] = {CreateMockWrite(req, 0), CreateMockWrite(req3, 5)};
  MockWrite writes2[] = {CreateMockWrite(req, 0)};

  // This test has a couple of variants.
  enum {
    // Induce the RST while waiting for our transaction to send.
    VARIANT_RST_DURING_SEND_COMPLETION = 0,
    // Induce the RST while waiting for our transaction to read.
    // In this case, the send completed - everything copied into the SNDBUF.
    VARIANT_RST_DURING_READ_COMPLETION = 1
  };

  for (int variant = VARIANT_RST_DURING_SEND_COMPLETION;
       variant <= VARIANT_RST_DURING_READ_COMPLETION;
       ++variant) {
    SequencedSocketData data1(reads, arraysize(reads), writes1, 1 + variant);

    SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                              arraysize(writes2));

    NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.AddData(&data1);
    helper.AddData(&data2);
    helper.RunPreTestSetup();

    for (int i = 0; i < 2; ++i) {
      HttpNetworkTransaction trans(DEFAULT_PRIORITY, helper.session());

      TestCompletionCallback callback;
      int rv = trans.Start(&helper.request(), callback.callback(),
                           NetLogWithSource());
      EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
      // On the second transaction, we trigger the RST.
      if (i == 1) {
        if (variant == VARIANT_RST_DURING_READ_COMPLETION) {
          // Writes to the socket complete asynchronously on SPDY by running
          // through the message loop.  Complete the write here.
          base::RunLoop().RunUntilIdle();
        }

        // Now schedule the ERR_CONNECTION_RESET.
        data1.Resume();
      }
      rv = callback.WaitForResult();
      EXPECT_THAT(rv, IsOk());

      const HttpResponseInfo* response = trans.GetResponseInfo();
      ASSERT_TRUE(response);
      EXPECT_TRUE(response->headers);
      EXPECT_TRUE(response->was_fetched_via_spdy);
      std::string response_data;
      rv = ReadTransaction(&trans, &response_data);
      EXPECT_THAT(rv, IsOk());
      EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
      EXPECT_EQ("hello!", response_data);
      base::RunLoop().RunUntilIdle();
    }

    helper.VerifyDataConsumed();
    base::RunLoop().RunUntilIdle();
  }
}

// Tests that Basic authentication works over SPDY
TEST_F(SpdyNetworkTransactionTest, SpdyBasicAuth) {
  // The first request will be a bare GET, the second request will be a
  // GET with an Authorization header.
  SpdySerializedFrame req_get(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  // Will be refused for lack of auth.
  spdy_util_.UpdateWithStreamDestruction(1);
  const char* const kExtraAuthorizationHeaders[] = {
    "authorization", "Basic Zm9vOmJhcg=="
  };
  SpdySerializedFrame req_get_authorization(spdy_util_.ConstructSpdyGet(
      kExtraAuthorizationHeaders, arraysize(kExtraAuthorizationHeaders) / 2, 3,
      LOWEST, true));
  MockWrite spdy_writes[] = {
      CreateMockWrite(req_get, 0), CreateMockWrite(req_get_authorization, 3),
  };

  // The first response is a 401 authentication challenge, and the second
  // response will be a 200 response since the second request includes a valid
  // Authorization header.
  const char* const kExtraAuthenticationHeaders[] = {
    "www-authenticate",
    "Basic realm=\"MyRealm\""
  };
  SpdySerializedFrame resp_authentication(spdy_util_.ConstructSpdyReplyError(
      "401 Authentication Required", kExtraAuthenticationHeaders,
      arraysize(kExtraAuthenticationHeaders) / 2, 1));
  SpdySerializedFrame body_authentication(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame resp_data(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body_data(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp_authentication, 1),
      CreateMockRead(body_authentication, 2),
      CreateMockRead(resp_data, 4),
      CreateMockRead(body_data, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                           arraysize(spdy_writes));
  HttpRequestInfo request(CreateGetRequest());
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);

  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  // Make sure the response has an auth challenge.
  HttpNetworkTransaction* trans = helper.trans();
  const HttpResponseInfo* const response_start = trans->GetResponseInfo();
  ASSERT_TRUE(response_start);
  ASSERT_TRUE(response_start->headers);
  EXPECT_EQ(401, response_start->headers->response_code());
  EXPECT_TRUE(response_start->was_fetched_via_spdy);
  AuthChallengeInfo* auth_challenge = response_start->auth_challenge.get();
  ASSERT_TRUE(auth_challenge);
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  EXPECT_EQ("MyRealm", auth_challenge->realm);

  // Restart with a username/password.
  AuthCredentials credentials(base::ASCIIToUTF16("foo"),
                              base::ASCIIToUTF16("bar"));
  TestCompletionCallback callback_restart;
  const int rv_restart = trans->RestartWithAuth(
      credentials, callback_restart.callback());
  EXPECT_THAT(rv_restart, IsError(ERR_IO_PENDING));
  const int rv_restart_complete = callback_restart.WaitForResult();
  EXPECT_THAT(rv_restart_complete, IsOk());
  // TODO(cbentzel): This is actually the same response object as before, but
  // data has changed.
  const HttpResponseInfo* const response_restart = trans->GetResponseInfo();
  ASSERT_TRUE(response_restart);
  ASSERT_TRUE(response_restart->headers);
  EXPECT_EQ(200, response_restart->headers->response_code());
  EXPECT_TRUE(response_restart->auth_challenge.get() == NULL);
}

TEST_F(SpdyNetworkTransactionTest, ServerPushWithHeaders) {
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  SpdyHeaderBlock initial_headers;
  spdy_util_.AddUrlToHeaderBlock(GetDefaultUrlWithPath("/foo.dat"),
                                 &initial_headers);
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructInitialSpdyPushFrame(
      std::move(initial_headers), 2, 1));

  SpdyHeaderBlock late_headers;
  late_headers[spdy_util_.GetStatusKey()] = "200";
  late_headers["hello"] = "bye";
  SpdySerializedFrame stream2_headers(spdy_util_.ConstructSpdyResponseHeaders(
      2, std::move(late_headers), false));

  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));

  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));

  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),
      CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream2_headers, 3),
      CreateMockRead(stream1_body, 4, SYNCHRONOUS),
      CreateMockRead(stream2_body, 5),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),  // Force a pause
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  RunServerPushTest(&data,
                    &response,
                    &response2,
                    expected_push_result);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, ServerPushClaimBeforeHeaders) {
  // We push a stream and attempt to claim it before the headers come down.
  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(stream1_syn, 0, SYNCHRONOUS),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdyHeaderBlock initial_headers;
  spdy_util_.AddUrlToHeaderBlock(GetDefaultUrlWithPath("/foo.dat"),
                                 &initial_headers);
  SpdySerializedFrame stream2_syn(spdy_util_.ConstructInitialSpdyPushFrame(
      std::move(initial_headers), 2, 1));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdyHeaderBlock late_headers;
  late_headers[spdy_util_.GetStatusKey()] = "200";
  late_headers["hello"] = "bye";
  SpdySerializedFrame stream2_headers(spdy_util_.ConstructSpdyResponseHeaders(
      2, std::move(late_headers), false));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1),   CreateMockRead(stream2_syn, 2),
      CreateMockRead(stream1_body, 3),    MockRead(ASYNC, ERR_IO_PENDING, 4),
      CreateMockRead(stream2_headers, 5), CreateMockRead(stream2_body, 6),
      MockRead(ASYNC, ERR_IO_PENDING, 7), MockRead(ASYNC, 0, 8),  // EOF
  };

  HttpResponseInfo response;
  HttpResponseInfo response2;
  std::string expected_push_result("pushed");
  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.AddData(&data);
  helper.RunPreTestSetup();

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction.
  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Run until we've received the primary HEADERS, the pushed HEADERS,
  // and the body of the primary stream, but before we've received the HEADERS
  // for the pushed stream.
  data.RunUntilPaused();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Request the pushed path.  At this point, we've received the push, but the
  // headers are not yet complete.
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  rv = trans2.Start(&CreateGetPushRequest(), callback.callback(),
                    NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  data.Resume();
  data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();

  // Read the server push body.
  std::string result2;
  ReadResult(&trans2, &result2);
  // Read the response body.
  std::string result;
  ReadResult(trans, &result);

  // Verify that the received push data is same as the expected push data.
  EXPECT_EQ(result2.compare(expected_push_result), 0)
      << "Received data: "
      << result2
      << "||||| Expected data: "
      << expected_push_result;

  // Verify the response headers.
  // Copy the response info, because trans goes away.
  response = *trans->GetResponseInfo();
  response2 = *trans2.GetResponseInfo();

  VerifyStreamsClosed(helper);

  // Verify the response headers.
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  // Verify the pushed stream.
  EXPECT_TRUE(response2.headers);
  EXPECT_EQ("HTTP/1.1 200", response2.headers->GetStatusLine());

  // Read the final EOF (which will close the session)
  data.Resume();
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());
}

TEST_F(SpdyNetworkTransactionTest, ResponseHeadersTwice) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 4),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));

  SpdyHeaderBlock late_headers;
  late_headers["hello"] = "bye";
  SpdySerializedFrame stream1_headers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(late_headers), false));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream1_headers, 2),
      CreateMockRead(stream1_body, 3), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

// Tests that receiving HEADERS, DATA, HEADERS, and DATA in that sequence will
// trigger a ERR_SPDY_PROTOCOL_ERROR because trailing HEADERS must not be
// followed by any DATA frames.
TEST_F(SpdyNetworkTransactionTest, SyncReplyDataAfterTrailers) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(rst, 5),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, false));

  SpdyHeaderBlock late_headers;
  late_headers["hello"] = "bye";
  SpdySerializedFrame stream1_headers(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(late_headers), false));
  SpdySerializedFrame stream1_body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(stream1_reply, 1), CreateMockRead(stream1_body, 2),
      CreateMockRead(stream1_headers, 3), CreateMockRead(stream1_body2, 4),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

TEST_F(SpdyNetworkTransactionTest, ServerPushCrossOriginCorrectness) {
  // In this test we want to verify that we can't accidentally push content
  // which can't be pushed by this content server.
  // This test assumes that:
  //   - if we're requesting http://www.foo.com/barbaz
  //   - the browser has made a connection to "www.foo.com".

  // A list of the URL to fetch, followed by the URL being pushed.
  static const char* const kTestCases[] = {
      "https://www.example.org/foo.html",
      "http://www.example.org/foo.js",  // Bad protocol

      "https://www.example.org/foo.html",
      "ftp://www.example.org/foo.js",  // Invalid Protocol

      "https://www.example.org/foo.html",
      "https://blat.www.example.org/foo.js",  // Cross subdomain

      "https://www.example.org/foo.html",
      "https://www.foo.com/foo.js",  // Cross domain
  };

  for (size_t index = 0; index < arraysize(kTestCases); index += 2) {
    const char* url_to_fetch = kTestCases[index];
    const char* url_to_push = kTestCases[index + 1];

    SpdyTestUtil spdy_test_util;
    SpdySerializedFrame stream1_syn(
        spdy_test_util.ConstructSpdyGet(url_to_fetch, 1, LOWEST));
    SpdySerializedFrame stream1_body(
        spdy_test_util.ConstructSpdyDataFrame(1, true));
    SpdySerializedFrame push_rst(
        spdy_test_util.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
    MockWrite writes[] = {
        CreateMockWrite(stream1_syn, 0), CreateMockWrite(push_rst, 3),
    };

    SpdySerializedFrame stream1_reply(
        spdy_test_util.ConstructSpdyGetReply(nullptr, 0, 1));
    SpdySerializedFrame stream2_syn(
        spdy_test_util.ConstructSpdyPush(nullptr, 0, 2, 1, url_to_push));
    const char kPushedData[] = "pushed";
    SpdySerializedFrame stream2_body(spdy_test_util.ConstructSpdyDataFrame(
        2, kPushedData, strlen(kPushedData), true));
    SpdySerializedFrame rst(
        spdy_test_util.ConstructSpdyRstStream(2, RST_STREAM_CANCEL));

    MockRead reads[] = {
        CreateMockRead(stream1_reply, 1),
        CreateMockRead(stream2_syn, 2),
        CreateMockRead(stream1_body, 4),
        CreateMockRead(stream2_body, 5),
        MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),  // Force a pause
    };

    HttpResponseInfo response;
    SequencedSocketData data(reads, arraysize(reads), writes,
                             arraysize(writes));

    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL(url_to_fetch);
    request.load_flags = 0;

    // Enable cross-origin push. Since we are not using a proxy, this should
    // not actually enable cross-origin SPDY push.
    auto session_deps = base::MakeUnique<SpdySessionDependencies>();
    std::unique_ptr<TestProxyDelegate> proxy_delegate(new TestProxyDelegate());
    proxy_delegate->set_trusted_spdy_proxy(net::ProxyServer::FromURI(
        "https://123.45.67.89:443", net::ProxyServer::SCHEME_HTTP));
    session_deps->proxy_delegate.reset(proxy_delegate.release());
    NormalSpdyTransactionHelper helper(
        request, DEFAULT_PRIORITY, NetLogWithSource(), std::move(session_deps));
    helper.RunPreTestSetup();
    helper.AddData(&data);

    HttpNetworkTransaction* trans = helper.trans();

    // Start the transaction with basic parameters.
    TestCompletionCallback callback;

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    rv = callback.WaitForResult();

    // Read the response body.
    std::string result;
    ReadResult(trans, &result);

    // Verify that we consumed all test data.
    EXPECT_TRUE(data.AllReadDataConsumed());
    EXPECT_TRUE(data.AllWriteDataConsumed());

    // Verify the response headers.
    // Copy the response info, because trans goes away.
    response = *trans->GetResponseInfo();

    VerifyStreamsClosed(helper);

    // Verify the response headers.
    EXPECT_TRUE(response.headers);
    EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
  }
}

// Verify that push works cross origin as long as the certificate is valid for
// the pushed authority.
TEST_F(SpdyNetworkTransactionTest, ServerPushValidCrossOrigin) {
  // "spdy_pooling.pem" is valid for both www.example.org and mail.example.org.
  const char* url_to_fetch = "https://www.example.org";
  const char* url_to_push = "https://mail.example.org";

  SpdySerializedFrame headers(
      spdy_util_.ConstructSpdyGet(url_to_fetch, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(headers, 0),
  };

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPush(nullptr, 0, 2, 1, url_to_push));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame pushed_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  MockRead reads[] = {
      CreateMockRead(reply, 1),
      CreateMockRead(push, 2),
      CreateMockRead(body, 3),
      CreateMockRead(pushed_body, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(url_to_fetch);
  request.load_flags = 0;

  NetLogWithSource log;
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY, log, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans0 = helper.trans();
  TestCompletionCallback callback0;
  int rv = trans0->Start(&request, callback0.callback(), log);
  rv = callback0.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  SpdySessionPool* spdy_session_pool = helper.session()->spdy_session_pool();
  SpdySessionKey key(host_port_pair_, ProxyServer::Direct(),
                     PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session =
      spdy_session_pool->FindAvailableSession(key, GURL(), log);

  EXPECT_FALSE(spdy_session->unclaimed_pushed_streams_.empty());
  EXPECT_EQ(1u, spdy_session->unclaimed_pushed_streams_.size());
  EXPECT_EQ(1u,
            spdy_session->unclaimed_pushed_streams_.count(GURL(url_to_push)));

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo push_request;
  push_request.method = "GET";
  push_request.url = GURL(url_to_push);
  push_request.load_flags = 0;
  TestCompletionCallback callback1;
  rv = trans1.Start(&push_request, callback1.callback(), log);
  rv = callback1.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(spdy_session->unclaimed_pushed_streams_.empty());
  EXPECT_EQ(0u, spdy_session->unclaimed_pushed_streams_.size());

  helper.VerifyDataConsumed();
  VerifyStreamsClosed(helper);

  HttpResponseInfo response = *trans0->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());

  std::string result0;
  ReadResult(trans0, &result0);
  EXPECT_EQ("hello!", result0);

  HttpResponseInfo push_response = *trans1.GetResponseInfo();
  EXPECT_TRUE(push_response.headers);
  EXPECT_EQ("HTTP/1.1 200", push_response.headers->GetStatusLine());

  std::string result1;
  ReadResult(&trans1, &result1);
  EXPECT_EQ(kPushedData, result1);
}

// Verify that push works cross origin, even if there is already a connection
// open to origin of pushed resource.
TEST_F(SpdyNetworkTransactionTest, ServerPushValidCrossOriginWithOpenSession) {
  const char* url_to_fetch0 = "https://mail.example.org/foo";
  const char* url_to_fetch1 = "https://docs.example.org";
  const char* url_to_push = "https://mail.example.org/bar";

  SpdyTestUtil spdy_util_0;

  SpdySerializedFrame headers0(
      spdy_util_0.ConstructSpdyGet(url_to_fetch0, 1, LOWEST));
  MockWrite writes0[] = {
      CreateMockWrite(headers0, 0),
  };

  SpdySerializedFrame reply0(spdy_util_0.ConstructSpdyGetReply(nullptr, 0, 1));
  const char kData0[] = "first";
  SpdySerializedFrame body0(
      spdy_util_0.ConstructSpdyDataFrame(1, kData0, strlen(kData0), true));
  MockRead reads0[] = {CreateMockRead(reply0, 1), CreateMockRead(body0, 2),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3)};

  SequencedSocketData data0(reads0, arraysize(reads0), writes0,
                            arraysize(writes0));

  SpdyTestUtil spdy_util_1;

  SpdySerializedFrame headers1(
      spdy_util_1.ConstructSpdyGet(url_to_fetch1, 1, LOWEST));
  MockWrite writes1[] = {
      CreateMockWrite(headers1, 0),
  };

  SpdySerializedFrame reply1(spdy_util_1.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame push(
      spdy_util_1.ConstructSpdyPush(nullptr, 0, 2, 1, url_to_push));
  const char kData1[] = "second";
  SpdySerializedFrame body1(
      spdy_util_1.ConstructSpdyDataFrame(1, kData1, strlen(kData1), true));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame pushed_body(spdy_util_1.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));

  MockRead reads1[] = {
      CreateMockRead(reply1, 1),
      CreateMockRead(push, 2),
      CreateMockRead(body1, 3),
      CreateMockRead(pushed_body, 4),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  SequencedSocketData data1(reads1, arraysize(reads1), writes1,
                            arraysize(writes1));

  // Request |url_to_fetch0| to open connection to mail.example.org.
  HttpRequestInfo request0;
  request0.method = "GET";
  request0.url = GURL(url_to_fetch0);
  request0.load_flags = 0;

  NetLogWithSource log;
  NormalSpdyTransactionHelper helper(request0, DEFAULT_PRIORITY, log, nullptr);
  helper.RunPreTestSetup();

  // "spdy_pooling.pem" is valid for www.example.org, but not for
  // docs.example.org.
  std::unique_ptr<SSLSocketDataProvider> ssl_provider0(
      new SSLSocketDataProvider(ASYNC, OK));
  ssl_provider0->cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  helper.AddDataWithSSLSocketDataProvider(&data0, std::move(ssl_provider0));

  // "wildcard.pem" is valid for both www.example.org and docs.example.org.
  std::unique_ptr<SSLSocketDataProvider> ssl_provider1(
      new SSLSocketDataProvider(ASYNC, OK));
  ssl_provider1->cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  helper.AddDataWithSSLSocketDataProvider(&data1, std::move(ssl_provider1));

  HttpNetworkTransaction* trans0 = helper.trans();
  TestCompletionCallback callback0;
  int rv = trans0->Start(&request0, callback0.callback(), log);
  rv = callback0.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  // Request |url_to_fetch1|, during which docs.example.org pushes
  // |url_to_push|, which happens to be for www.example.org, to which there is
  // already an open connection.
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(url_to_fetch1);
  request1.load_flags = 0;
  TestCompletionCallback callback1;
  rv = trans1.Start(&request1, callback1.callback(), log);
  rv = callback1.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  SpdySessionPool* spdy_session_pool = helper.session()->spdy_session_pool();
  HostPortPair host_port_pair0("mail.example.org", 443);
  SpdySessionKey key0(host_port_pair0, ProxyServer::Direct(),
                      PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session0 =
      spdy_session_pool->FindAvailableSession(key0, GURL(), log);

  EXPECT_TRUE(spdy_session0->unclaimed_pushed_streams_.empty());
  EXPECT_EQ(0u, spdy_session0->unclaimed_pushed_streams_.size());

  HostPortPair host_port_pair1("docs.example.org", 443);
  SpdySessionKey key1(host_port_pair1, ProxyServer::Direct(),
                      PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session1 =
      spdy_session_pool->FindAvailableSession(key1, GURL(), log);

  EXPECT_FALSE(spdy_session1->unclaimed_pushed_streams_.empty());
  EXPECT_EQ(1u, spdy_session1->unclaimed_pushed_streams_.size());
  EXPECT_EQ(1u,
            spdy_session1->unclaimed_pushed_streams_.count(GURL(url_to_push)));

  // Request |url_to_push|, which should be served from the pushed resource.
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpRequestInfo push_request;
  push_request.method = "GET";
  push_request.url = GURL(url_to_push);
  push_request.load_flags = 0;
  TestCompletionCallback callback2;
  rv = trans2.Start(&push_request, callback2.callback(), log);
  rv = callback2.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(spdy_session0->unclaimed_pushed_streams_.empty());
  EXPECT_EQ(0u, spdy_session0->unclaimed_pushed_streams_.size());

  EXPECT_TRUE(spdy_session1->unclaimed_pushed_streams_.empty());
  EXPECT_EQ(0u, spdy_session1->unclaimed_pushed_streams_.size());

  helper.VerifyDataConsumed();
  VerifyStreamsClosed(helper);

  HttpResponseInfo response0 = *trans0->GetResponseInfo();
  EXPECT_TRUE(response0.headers);
  EXPECT_EQ("HTTP/1.1 200", response0.headers->GetStatusLine());

  std::string result0;
  ReadResult(trans0, &result0);
  EXPECT_EQ(kData0, result0);

  HttpResponseInfo response1 = *trans1.GetResponseInfo();
  EXPECT_TRUE(response1.headers);
  EXPECT_EQ("HTTP/1.1 200", response1.headers->GetStatusLine());

  std::string result1;
  ReadResult(&trans1, &result1);
  EXPECT_EQ(kData1, result1);

  HttpResponseInfo push_response = *trans2.GetResponseInfo();
  EXPECT_TRUE(push_response.headers);
  EXPECT_EQ("HTTP/1.1 200", push_response.headers->GetStatusLine());

  std::string result2;
  ReadResult(&trans2, &result2);
  EXPECT_EQ(kPushedData, result2);
}

TEST_F(SpdyNetworkTransactionTest, ServerPushInvalidCrossOrigin) {
  // "spdy_pooling.pem" is valid for www.example.org,
  // but not for invalid.example.org.
  const char* url_to_fetch = "https://www.example.org";
  const char* url_to_push = "https://invalid.example.org";

  SpdySerializedFrame headers(
      spdy_util_.ConstructSpdyGet(url_to_fetch, 1, LOWEST));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(2, RST_STREAM_REFUSED_STREAM));
  MockWrite writes[] = {
      CreateMockWrite(headers, 0), CreateMockWrite(rst, 3),
  };

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPush(nullptr, 0, 2, 1, url_to_push));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame pushed_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));
  MockRead reads[] = {
      CreateMockRead(reply, 1),
      CreateMockRead(push, 2),
      CreateMockRead(body, 4),
      CreateMockRead(pushed_body, 5),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(url_to_fetch);
  request.load_flags = 0;

  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

TEST_F(SpdyNetworkTransactionTest, RetryAfterRefused) {
  // Construct the request.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  // Will be destroyed by the RST before stream 3 starts.
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(req2, 2),
  };

  SpdySerializedFrame refused(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_REFUSED_STREAM));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads[] = {
      CreateMockRead(refused, 1), CreateMockRead(resp, 3),
      CreateMockRead(body, 4), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&CreateGetRequest(), callback.callback(),
                        NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify that we consumed all test data.
  EXPECT_TRUE(data.AllReadDataConsumed());
  EXPECT_TRUE(data.AllWriteDataConsumed());

  // Verify the response headers.
  HttpResponseInfo response = *trans->GetResponseInfo();
  EXPECT_TRUE(response.headers);
  EXPECT_EQ("HTTP/1.1 200", response.headers->GetStatusLine());
}

TEST_F(SpdyNetworkTransactionTest, OutOfOrderHeaders) {
  // This first request will start to establish the SpdySession.
  // Then we will start the second (MEDIUM priority) and then third
  // (HIGHEST priority) request in such a way that the third will actually
  // start before the second, causing the second to be numbered differently
  // than the order they were created.
  //
  // Note that the requests and responses created below are expectations
  // of what the above will produce on the wire, and hence are in the
  // initial->HIGHEST->LOWEST priority.
  //
  // Frames are created by SpdySession just before the write associated
  // with the frame is attempted, so stream dependencies will be based
  // on the streams alive at the point of the request write attempt.  Thus
  // req1 is alive when req2 is attempted (during but not after the
  // |data.RunFor(2);| statement below) but not when req3 is attempted.
  // The call to spdy_util_.UpdateWithStreamDestruction() reflects this.
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, HIGHEST, true));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, MEDIUM, true));
  MockWrite writes[] = {
      MockWrite(ASYNC, ERR_IO_PENDING, 0), CreateMockWrite(req1, 1),
      CreateMockWrite(req2, 5), CreateMockWrite(req3, 6),
  };

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  SpdySerializedFrame resp3(spdy_util_.ConstructSpdyGetReply(NULL, 0, 5));
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, true));
  MockRead reads[] = {
      CreateMockRead(resp1, 2),  MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(body1, 4),  CreateMockRead(resp2, 7),
      CreateMockRead(body2, 8),  CreateMockRead(resp3, 9),
      CreateMockRead(body3, 10), MockRead(ASYNC, 0, 11)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), LOWEST,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  // Start the first transaction to set up the SpdySession
  HttpNetworkTransaction* trans = helper.trans();
  TestCompletionCallback callback;
  HttpRequestInfo info1 = CreateGetRequest();
  int rv = trans->Start(&info1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Run the message loop, but do not allow the write to complete.
  // This leaves the SpdySession with a write pending, which prevents
  // SpdySession from attempting subsequent writes until this write completes.
  base::RunLoop().RunUntilIdle();

  // Now, start both new transactions
  HttpRequestInfo info2 = CreateGetRequest();
  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  rv = trans2.Start(&info2, callback2.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  HttpRequestInfo info3 = CreateGetRequest();
  TestCompletionCallback callback3;
  HttpNetworkTransaction trans3(HIGHEST, helper.session());
  rv = trans3.Start(&info3, callback3.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  // We now have two HEADERS frames queued up which will be
  // dequeued only once the first write completes, which we
  // now allow to happen.
  ASSERT_TRUE(data.IsPaused());
  data.Resume();
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // And now we can allow everything else to run to completion.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_THAT(callback3.WaitForResult(), IsOk());

  helper.VerifyDataConsumed();
}

// Test that sent data frames and received WINDOW_UPDATE frames change
// the send_window_size_ correctly.

// WINDOW_UPDATE is different than most other frames in that it can arrive
// while the client is still sending the request body.  In order to enforce
// this scenario, we feed a couple of dummy frames and give a delay of 0 to
// socket data provider, so that initial read that is done as soon as the
// stream is created, succeeds and schedules another read.  This way reads
// and writes are interleaved; after doing a full frame write, SpdyStream
// will break out of DoLoop and will read and process a WINDOW_UPDATE.
// Once our WINDOW_UPDATE is read, we cannot send HEADERS right away
// since request has not been completely written, therefore we feed
// enough number of WINDOW_UPDATEs to finish the first read and cause a
// write, leading to a complete write of request body; after that we send
// a reply with a body, to cause a graceful shutdown.

// TODO(agayev): develop a socket data provider where both, reads and
// writes are ordered so that writing tests like these are easy and rewrite
// all these tests using it.  Right now we are working around the
// limitations as described above and it's not deterministic, tests may
// fail under specific circumstances.
TEST_F(SpdyNetworkTransactionTest, WindowUpdateReceived) {
  static int kFrameCount = 2;
  std::unique_ptr<std::string> content(
      new std::string(kMaxSpdyFrameChunkSize, 'a'));
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMaxSpdyFrameChunkSize * kFrameCount, LOWEST, NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(
      1, content->c_str(), content->size(), false));
  SpdySerializedFrame body_end(spdy_util_.ConstructSpdyDataFrame(
      1, content->c_str(), content->size(), true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),
      CreateMockWrite(body_end, 2),
  };

  static const int32_t kDeltaWindowSize = 0xff;
  static const int kDeltaCount = 4;
  SpdySerializedFrame window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, kDeltaWindowSize));
  SpdySerializedFrame window_update_dummy(
      spdy_util_.ConstructSpdyWindowUpdate(2, kDeltaWindowSize));
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  MockRead reads[] = {
      CreateMockRead(window_update_dummy, 3),
      CreateMockRead(window_update_dummy, 4),
      CreateMockRead(window_update_dummy, 5),
      CreateMockRead(window_update, 6),  // Four updates, therefore window
      CreateMockRead(window_update, 7),  // size should increase by
      CreateMockRead(window_update, 8),  // kDeltaWindowSize * 4
      CreateMockRead(window_update, 9),
      CreateMockRead(resp, 10),
      MockRead(ASYNC, ERR_IO_PENDING, 11),
      CreateMockRead(body_end, 12),
      MockRead(ASYNC, 0, 13)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  for (int i = 0; i < kFrameCount; ++i) {
    element_readers.push_back(base::WrapUnique(
        new UploadBytesElementReader(content->c_str(), content->size())));
  }
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  // Setup the request
  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  request.upload_data_stream = &upload_data_stream;

  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.AddData(&data);
  helper.RunPreTestSetup();

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();
  base::RunLoop().RunUntilIdle();

  SpdyHttpStream* stream = static_cast<SpdyHttpStream*>(trans->stream_.get());
  ASSERT_TRUE(stream);
  ASSERT_TRUE(stream->stream());
  EXPECT_EQ(static_cast<int>(kDefaultInitialWindowSize) +
                kDeltaWindowSize * kDeltaCount -
                kMaxSpdyFrameChunkSize * kFrameCount,
            stream->stream()->send_window_size());

  data.Resume();
  base::RunLoop().RunUntilIdle();

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  helper.VerifyDataConsumed();
}

// Test that received data frames and sent WINDOW_UPDATE frames change
// the recv_window_size_ correctly.
TEST_F(SpdyNetworkTransactionTest, WindowUpdateSent) {
  // Session level maximum window size that is more than twice the default
  // initial window size so that an initial window update is sent.
  const int32_t session_max_recv_window_size = 5 * 64 * 1024;
  ASSERT_LT(2 * kDefaultInitialWindowSize, session_max_recv_window_size);
  // Stream level maximum window size that is less than the session level
  // maximum window size so that we test for confusion between the two.
  const int32_t stream_max_recv_window_size = 4 * 64 * 1024;
  ASSERT_GT(session_max_recv_window_size, stream_max_recv_window_size);
  // Size of body to be sent.  Has to be less than or equal to both window sizes
  // so that we do not run out of receiving window.  Also has to be greater than
  // half of them so that it triggers both a session level and a stream level
  // window update frame.
  const int32_t kTargetSize = 3 * 64 * 1024;
  ASSERT_GE(session_max_recv_window_size, kTargetSize);
  ASSERT_GE(stream_max_recv_window_size, kTargetSize);
  ASSERT_LT(session_max_recv_window_size / 2, kTargetSize);
  ASSERT_LT(stream_max_recv_window_size / 2, kTargetSize);
  // Size of each DATA frame.
  const int32_t kChunkSize = 4096;
  // Size of window updates.
  ASSERT_EQ(0, session_max_recv_window_size / 2 % kChunkSize);
  const int32_t session_window_update_delta =
      session_max_recv_window_size / 2 + kChunkSize;
  ASSERT_EQ(0, stream_max_recv_window_size / 2 % kChunkSize);
  const int32_t stream_window_update_delta =
      stream_max_recv_window_size / 2 + kChunkSize;

  SettingsMap initial_settings;
  initial_settings[SETTINGS_HEADER_TABLE_SIZE] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, kMaxHeaderTableSize);
  initial_settings[SETTINGS_MAX_CONCURRENT_STREAMS] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, kMaxConcurrentPushedStreams);
  initial_settings[SETTINGS_INITIAL_WINDOW_SIZE] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, stream_max_recv_window_size);
  SpdySerializedFrame initial_settings_frame(
      spdy_util_.ConstructSpdySettings(initial_settings));
  SpdySerializedFrame initial_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(
          kSessionFlowControlStreamId,
          session_max_recv_window_size - kDefaultInitialWindowSize));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame session_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(0, session_window_update_delta));
  SpdySerializedFrame stream_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, stream_window_update_delta));

  std::vector<MockWrite> writes;
  writes.push_back(MockWrite(ASYNC, kHttp2ConnectionHeaderPrefix,
                             kHttp2ConnectionHeaderPrefixSize, 0));
  writes.push_back(CreateMockWrite(initial_settings_frame, writes.size()));
  writes.push_back(CreateMockWrite(initial_window_update, writes.size()));
  writes.push_back(CreateMockWrite(req, writes.size()));

  std::vector<MockRead> reads;
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  reads.push_back(CreateMockRead(resp, writes.size() + reads.size()));

  std::vector<SpdySerializedFrame> body_frames;
  const std::string body_data(kChunkSize, 'x');
  for (size_t remaining = kTargetSize; remaining != 0;) {
    size_t frame_size = std::min(remaining, body_data.size());
    body_frames.push_back(spdy_util_.ConstructSpdyDataFrame(1, body_data.data(),
                                                            frame_size, false));
    reads.push_back(
        CreateMockRead(body_frames.back(), writes.size() + reads.size()));
    remaining -= frame_size;
  }
  // Yield.
  reads.push_back(
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, writes.size() + reads.size()));

  writes.push_back(
      CreateMockWrite(session_window_update, writes.size() + reads.size()));
  writes.push_back(
      CreateMockWrite(stream_window_update, writes.size() + reads.size()));

  SequencedSocketData data(reads.data(), reads.size(), writes.data(),
                           writes.size());

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.AddData(&data);
  helper.RunPreTestSetup();

  SpdySessionPool* spdy_session_pool = helper.session()->spdy_session_pool();
  SpdySessionPoolPeer pool_peer(spdy_session_pool);
  pool_peer.SetEnableSendingInitialData(true);
  pool_peer.SetSessionMaxRecvWindowSize(session_max_recv_window_size);
  pool_peer.SetStreamInitialRecvWindowSize(stream_max_recv_window_size);

  HttpNetworkTransaction* trans = helper.trans();
  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  SpdyHttpStream* stream =
      static_cast<SpdyHttpStream*>(trans->stream_.get());
  ASSERT_TRUE(stream);
  ASSERT_TRUE(stream->stream());

  // All data has been read, but not consumed. The window reflects this.
  EXPECT_EQ(static_cast<int>(stream_max_recv_window_size - kTargetSize),
            stream->stream()->recv_window_size());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);

  // Issue a read which will cause a WINDOW_UPDATE to be sent and window
  // size increased to default.
  scoped_refptr<IOBuffer> buf(new IOBuffer(kTargetSize));
  EXPECT_EQ(static_cast<int>(kTargetSize),
            trans->Read(buf.get(), kTargetSize, CompletionCallback()));
  EXPECT_EQ(static_cast<int>(stream_max_recv_window_size),
            stream->stream()->recv_window_size());
  EXPECT_THAT(base::StringPiece(buf->data(), kTargetSize), Each(Eq('x')));

  // Allow scheduled WINDOW_UPDATE frames to write.
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

// Test that WINDOW_UPDATE frame causing overflow is handled correctly.
TEST_F(SpdyNetworkTransactionTest, WindowUpdateOverflow) {
  // Number of full frames we hope to write (but will not, used to
  // set content-length header correctly)
  static int kFrameCount = 3;

  std::unique_ptr<std::string> content(
      new std::string(kMaxSpdyFrameChunkSize, 'a'));
  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kMaxSpdyFrameChunkSize * kFrameCount, LOWEST, NULL, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(
      1, content->c_str(), content->size(), false));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_FLOW_CONTROL_ERROR));

  // We're not going to write a data frame with FIN, we'll receive a bad
  // WINDOW_UPDATE while sending a request and will send a RST_STREAM frame.
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 2),
      CreateMockWrite(rst, 3),
  };

  static const int32_t kDeltaWindowSize = 0x7fffffff;  // cause an overflow
  SpdySerializedFrame window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, kDeltaWindowSize));
  MockRead reads[] = {
      CreateMockRead(window_update, 1), MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  for (int i = 0; i < kFrameCount; ++i) {
    element_readers.push_back(base::WrapUnique(
        new UploadBytesElementReader(content->c_str(), content->size())));
  }
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  // Setup the request
  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  request.upload_data_stream = &upload_data_stream;

  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_SPDY_PROTOCOL_ERROR));
  helper.VerifyDataConsumed();
}

// Test that after hitting a send window size of 0, the write process
// stalls and upon receiving WINDOW_UPDATE frame write resumes.

// This test constructs a POST request followed by enough data frames
// containing 'a' that would make the window size 0, followed by another
// data frame containing default content (which is "hello!") and this frame
// also contains a FIN flag.  SequencedSocketData is used to enforce all
// writes, save the last, go through before a read could happen.  The last frame
// ("hello!") is not permitted to go through since by the time its turn
// arrives, window size is 0.  At this point MessageLoop::Run() called via
// callback would block.  Therefore we call MessageLoop::RunUntilIdle()
// which returns after performing all possible writes.  We use DCHECKS to
// ensure that last data frame is still there and stream has stalled.
// After that, next read is artifically enforced, which causes a
// WINDOW_UPDATE to be read and I/O process resumes.
TEST_F(SpdyNetworkTransactionTest, FlowControlStallResume) {
  const int32_t initial_window_size = kDefaultInitialWindowSize;
  // Number of upload data buffers we need to send to zero out the window size
  // is the minimal number of upload buffers takes to be bigger than
  // |initial_window_size|.
  size_t num_upload_buffers =
      ceil(static_cast<double>(initial_window_size) / kBufferSize);
  // Each upload data buffer consists of |num_frames_in_one_upload_buffer|
  // frames, each with |kMaxSpdyFrameChunkSize| bytes except the last frame,
  // which has kBufferSize % kMaxSpdyChunkSize bytes.
  size_t num_frames_in_one_upload_buffer =
      ceil(static_cast<double>(kBufferSize) / kMaxSpdyFrameChunkSize);

  // Construct content for a data frame of maximum size.
  std::string content(kMaxSpdyFrameChunkSize, 'a');

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1,
      /*content_length=*/kBufferSize * num_upload_buffers + kUploadDataSize,
      LOWEST, NULL, 0));

  // Full frames.
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(), content.size(), false));

  // Last frame in each upload data buffer.
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(), kBufferSize % kMaxSpdyFrameChunkSize, false));

  // The very last frame before the stalled frames.
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(),
      initial_window_size % kBufferSize % kMaxSpdyFrameChunkSize, false));

  // Data frames to be sent once WINDOW_UPDATE frame is received.

  // If kBufferSize * num_upload_buffers > initial_window_size,
  // we need one additional frame to send the rest of 'a'.
  std::string last_body(kBufferSize * num_upload_buffers - initial_window_size,
                        'a');
  SpdySerializedFrame body4(spdy_util_.ConstructSpdyDataFrame(
      1, last_body.c_str(), last_body.size(), false));

  // Also send a "hello!" after WINDOW_UPDATE.
  SpdySerializedFrame body5(spdy_util_.ConstructSpdyDataFrame(1, true));

  // Fill in mock writes.
  size_t i = 0;
  std::vector<MockWrite> writes;
  writes.push_back(CreateMockWrite(req, i++));
  for (size_t j = 0; j < num_upload_buffers; j++) {
    for (size_t k = 0; k < num_frames_in_one_upload_buffer; k++) {
      if (k == num_frames_in_one_upload_buffer - 1 &&
          kBufferSize % kMaxSpdyFrameChunkSize != 0) {
        if (j == num_upload_buffers - 1 &&
            (initial_window_size % kBufferSize != 0)) {
          writes.push_back(CreateMockWrite(body3, i++));
        } else {
          writes.push_back(CreateMockWrite(body2, i++));
        }
      } else {
        writes.push_back(CreateMockWrite(body1, i++));
      }
    }
  }

  // Fill in mock reads.
  std::vector<MockRead> reads;
  // Force a pause.
  reads.push_back(MockRead(ASYNC, ERR_IO_PENDING, i++));
  // Construct read frame for window updates that gives enough space to upload
  // the rest of the data.
  SpdySerializedFrame session_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(0,
                                           kUploadDataSize + last_body.size()));
  SpdySerializedFrame window_update(spdy_util_.ConstructSpdyWindowUpdate(
      1, kUploadDataSize + last_body.size()));

  reads.push_back(CreateMockRead(session_window_update, i++));
  reads.push_back(CreateMockRead(window_update, i++));

  // Stalled frames which can be sent after receiving window updates.
  if (last_body.size() > 0)
    writes.push_back(CreateMockWrite(body4, i++));
  writes.push_back(CreateMockWrite(body5, i++));

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  reads.push_back(CreateMockRead(reply, i++));
  reads.push_back(CreateMockRead(body2, i++));
  reads.push_back(CreateMockRead(body5, i++));
  reads.push_back(MockRead(ASYNC, 0, i++));  // EOF

  SequencedSocketData data(reads.data(), reads.size(), writes.data(),
                           writes.size());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  std::string upload_data_string(kBufferSize * num_upload_buffers, 'a');
  upload_data_string.append(kUploadData, kUploadDataSize);
  element_readers.push_back(base::WrapUnique(new UploadBytesElementReader(
      upload_data_string.c_str(), upload_data_string.size())));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  request.upload_data_stream = &upload_data_stream;
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.AddData(&data);
  helper.RunPreTestSetup();

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();  // Write as much as we can.

  SpdyHttpStream* stream = static_cast<SpdyHttpStream*>(trans->stream_.get());
  ASSERT_TRUE(stream);
  ASSERT_TRUE(stream->stream());
  EXPECT_EQ(0, stream->stream()->send_window_size());
  if (initial_window_size % kBufferSize != 0) {
    // If it does not take whole number of full upload buffer to zero out
    // initial window size, then the upload data is not at EOF, because the
    // last read must be stalled.
    EXPECT_FALSE(upload_data_stream.IsEOF());
  } else {
    // All the body data should have been read.
    // TODO(satorux): This is because of the weirdness in reading the request
    // body in OnSendBodyComplete(). See crbug.com/113107.
    EXPECT_TRUE(upload_data_stream.IsEOF());
  }
  // But the body is not yet fully sent (kUploadData is not yet sent)
  // since we're send-stalled.
  EXPECT_TRUE(stream->stream()->send_stalled_by_flow_control());

  data.Resume();  // Read in WINDOW_UPDATE frame.
  rv = callback.WaitForResult();
  helper.VerifyDataConsumed();
}

// Test we correctly handle the case where the SETTINGS frame results in
// unstalling the send window.
TEST_F(SpdyNetworkTransactionTest, FlowControlStallResumeAfterSettings) {
  const int32_t initial_window_size = kDefaultInitialWindowSize;
  // Number of upload data buffers we need to send to zero out the window size
  // is the minimal number of upload buffers takes to be bigger than
  // |initial_window_size|.
  size_t num_upload_buffers =
      ceil(static_cast<double>(initial_window_size) / kBufferSize);
  // Each upload data buffer consists of |num_frames_in_one_upload_buffer|
  // frames, each with |kMaxSpdyFrameChunkSize| bytes except the last frame,
  // which has kBufferSize % kMaxSpdyChunkSize bytes.
  size_t num_frames_in_one_upload_buffer =
      ceil(static_cast<double>(kBufferSize) / kMaxSpdyFrameChunkSize);

  // Construct content for a data frame of maximum size.
  std::string content(kMaxSpdyFrameChunkSize, 'a');

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1,
      /*content_length=*/kBufferSize * num_upload_buffers + kUploadDataSize,
      LOWEST, NULL, 0));

  // Full frames.
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(), content.size(), false));

  // Last frame in each upload data buffer.
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(), kBufferSize % kMaxSpdyFrameChunkSize, false));

  // The very last frame before the stalled frames.
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(),
      initial_window_size % kBufferSize % kMaxSpdyFrameChunkSize, false));

  // Data frames to be sent once WINDOW_UPDATE frame is received.

  // If kBufferSize * num_upload_buffers > initial_window_size,
  // we need one additional frame to send the rest of 'a'.
  std::string last_body(kBufferSize * num_upload_buffers - initial_window_size,
                        'a');
  SpdySerializedFrame body4(spdy_util_.ConstructSpdyDataFrame(
      1, last_body.c_str(), last_body.size(), false));

  // Also send a "hello!" after WINDOW_UPDATE.
  SpdySerializedFrame body5(spdy_util_.ConstructSpdyDataFrame(1, true));

  // Fill in mock writes.
  size_t i = 0;
  std::vector<MockWrite> writes;
  writes.push_back(CreateMockWrite(req, i++));
  for (size_t j = 0; j < num_upload_buffers; j++) {
    for (size_t k = 0; k < num_frames_in_one_upload_buffer; k++) {
      if (k == num_frames_in_one_upload_buffer - 1 &&
          kBufferSize % kMaxSpdyFrameChunkSize != 0) {
        if (j == num_upload_buffers - 1 &&
            (initial_window_size % kBufferSize != 0)) {
          writes.push_back(CreateMockWrite(body3, i++));
        } else {
          writes.push_back(CreateMockWrite(body2, i++));
        }
      } else {
        writes.push_back(CreateMockWrite(body1, i++));
      }
    }
  }

  // Fill in mock reads.
  std::vector<MockRead> reads;
  // Force a pause.
  reads.push_back(MockRead(ASYNC, ERR_IO_PENDING, i++));

  // Construct read frame for SETTINGS that gives enough space to upload the
  // rest of the data.
  SettingsMap settings;
  settings[SETTINGS_INITIAL_WINDOW_SIZE] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, initial_window_size * 2);
  SpdySerializedFrame settings_frame_large(
      spdy_util_.ConstructSpdySettings(settings));

  reads.push_back(CreateMockRead(settings_frame_large, i++));

  SpdySerializedFrame session_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(0,
                                           last_body.size() + kUploadDataSize));
  reads.push_back(CreateMockRead(session_window_update, i++));

  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  writes.push_back(CreateMockWrite(settings_ack, i++));

  // Stalled frames which can be sent after |settings_ack|.
  if (last_body.size() > 0)
    writes.push_back(CreateMockWrite(body4, i++));
  writes.push_back(CreateMockWrite(body5, i++));

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  reads.push_back(CreateMockRead(reply, i++));
  reads.push_back(CreateMockRead(body2, i++));
  reads.push_back(CreateMockRead(body5, i++));
  reads.push_back(MockRead(ASYNC, 0, i++));  // EOF

  // Force all writes to happen before any read, last write will not
  // actually queue a frame, due to window size being 0.
  SequencedSocketData data(reads.data(), reads.size(), writes.data(),
                           writes.size());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  std::string upload_data_string(kBufferSize * num_upload_buffers, 'a');
  upload_data_string.append(kUploadData, kUploadDataSize);
  element_readers.push_back(base::WrapUnique(new UploadBytesElementReader(
      upload_data_string.c_str(), upload_data_string.size())));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  request.upload_data_stream = &upload_data_stream;
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();  // Write as much as we can.
  base::RunLoop().RunUntilIdle();

  SpdyHttpStream* stream = static_cast<SpdyHttpStream*>(trans->stream_.get());
  ASSERT_TRUE(stream);
  ASSERT_TRUE(stream->stream());
  EXPECT_EQ(0, stream->stream()->send_window_size());

  if (initial_window_size % kBufferSize != 0) {
    // If it does not take whole number of full upload buffer to zero out
    // initial window size, then the upload data is not at EOF, because the
    // last read must be stalled.
    EXPECT_FALSE(upload_data_stream.IsEOF());
  } else {
    // All the body data should have been read.
    // TODO(satorux): This is because of the weirdness in reading the request
    // body in OnSendBodyComplete(). See crbug.com/113107.
    EXPECT_TRUE(upload_data_stream.IsEOF());
  }
  // But the body is not yet fully sent (kUploadData is not yet sent)
  // since we're send-stalled.
  EXPECT_TRUE(stream->stream()->send_stalled_by_flow_control());

  // Read in SETTINGS frame to unstall.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  rv = callback.WaitForResult();
  helper.VerifyDataConsumed();
  // If stream is NULL, that means it was unstalled and closed.
  EXPECT_TRUE(stream->stream() == NULL);
}

// Test we correctly handle the case where the SETTINGS frame results in a
// negative send window size.
TEST_F(SpdyNetworkTransactionTest, FlowControlNegativeSendWindowSize) {
  const int32_t initial_window_size = kDefaultInitialWindowSize;
  // Number of upload data buffers we need to send to zero out the window size
  // is the minimal number of upload buffers takes to be bigger than
  // |initial_window_size|.
  size_t num_upload_buffers =
      ceil(static_cast<double>(initial_window_size) / kBufferSize);
  // Each upload data buffer consists of |num_frames_in_one_upload_buffer|
  // frames, each with |kMaxSpdyFrameChunkSize| bytes except the last frame,
  // which has kBufferSize % kMaxSpdyChunkSize bytes.
  size_t num_frames_in_one_upload_buffer =
      ceil(static_cast<double>(kBufferSize) / kMaxSpdyFrameChunkSize);

  // Construct content for a data frame of maximum size.
  std::string content(kMaxSpdyFrameChunkSize, 'a');

  SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1,
      /*content_length=*/kBufferSize * num_upload_buffers + kUploadDataSize,
      LOWEST, NULL, 0));

  // Full frames.
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(), content.size(), false));

  // Last frame in each upload data buffer.
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(), kBufferSize % kMaxSpdyFrameChunkSize, false));

  // The very last frame before the stalled frames.
  SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(
      1, content.c_str(),
      initial_window_size % kBufferSize % kMaxSpdyFrameChunkSize, false));

  // Data frames to be sent once WINDOW_UPDATE frame is received.

  // If kBufferSize * num_upload_buffers > initial_window_size,
  // we need one additional frame to send the rest of 'a'.
  std::string last_body(kBufferSize * num_upload_buffers - initial_window_size,
                        'a');
  SpdySerializedFrame body4(spdy_util_.ConstructSpdyDataFrame(
      1, last_body.c_str(), last_body.size(), false));

  // Also send a "hello!" after WINDOW_UPDATE.
  SpdySerializedFrame body5(spdy_util_.ConstructSpdyDataFrame(1, true));

  // Fill in mock writes.
  size_t i = 0;
  std::vector<MockWrite> writes;
  writes.push_back(CreateMockWrite(req, i++));
  for (size_t j = 0; j < num_upload_buffers; j++) {
    for (size_t k = 0; k < num_frames_in_one_upload_buffer; k++) {
      if (k == num_frames_in_one_upload_buffer - 1 &&
          kBufferSize % kMaxSpdyFrameChunkSize != 0) {
        if (j == num_upload_buffers - 1 &&
            (initial_window_size % kBufferSize != 0)) {
          writes.push_back(CreateMockWrite(body3, i++));
        } else {
          writes.push_back(CreateMockWrite(body2, i++));
        }
      } else {
        writes.push_back(CreateMockWrite(body1, i++));
      }
    }
  }

  // Fill in mock reads.
  std::vector<MockRead> reads;
  // Force a pause.
  reads.push_back(MockRead(ASYNC, ERR_IO_PENDING, i++));
  // Construct read frame for SETTINGS that makes the send_window_size
  // negative.
  SettingsMap new_settings;
  new_settings[SETTINGS_INITIAL_WINDOW_SIZE] =
      SettingsFlagsAndValue(SETTINGS_FLAG_NONE, initial_window_size / 2);
  SpdySerializedFrame settings_frame_small(
      spdy_util_.ConstructSpdySettings(new_settings));
  // Construct read frames for WINDOW_UPDATE that makes the send_window_size
  // positive.
  SpdySerializedFrame session_window_update_init_size(
      spdy_util_.ConstructSpdyWindowUpdate(0, initial_window_size));
  SpdySerializedFrame window_update_init_size(
      spdy_util_.ConstructSpdyWindowUpdate(1, initial_window_size));

  reads.push_back(CreateMockRead(settings_frame_small, i++));
  reads.push_back(CreateMockRead(session_window_update_init_size, i++));
  reads.push_back(CreateMockRead(window_update_init_size, i++));

  SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  writes.push_back(CreateMockWrite(settings_ack, i++));

  // Stalled frames which can be sent after |settings_ack|.
  if (last_body.size() > 0)
    writes.push_back(CreateMockWrite(body4, i++));
  writes.push_back(CreateMockWrite(body5, i++));

  SpdySerializedFrame reply(spdy_util_.ConstructSpdyPostReply(NULL, 0));
  reads.push_back(CreateMockRead(reply, i++));
  reads.push_back(CreateMockRead(body2, i++));
  reads.push_back(CreateMockRead(body5, i++));
  reads.push_back(MockRead(ASYNC, 0, i++));  // EOF

  // Force all writes to happen before any read, last write will not
  // actually queue a frame, due to window size being 0.
  SequencedSocketData data(reads.data(), reads.size(), writes.data(),
                           writes.size());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  std::string upload_data_string(kBufferSize * num_upload_buffers, 'a');
  upload_data_string.append(kUploadData, kUploadDataSize);
  element_readers.push_back(base::WrapUnique(new UploadBytesElementReader(
      upload_data_string.c_str(), upload_data_string.size())));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = default_url_;
  request.upload_data_stream = &upload_data_stream;
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv =
      trans->Start(&helper.request(), callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();  // Write as much as we can.
  base::RunLoop().RunUntilIdle();

  SpdyHttpStream* stream = static_cast<SpdyHttpStream*>(trans->stream_.get());
  ASSERT_TRUE(stream);
  ASSERT_TRUE(stream->stream());
  EXPECT_EQ(0, stream->stream()->send_window_size());

  if (initial_window_size % kBufferSize != 0) {
    // If it does not take whole number of full upload buffer to zero out
    // initial window size, then the upload data is not at EOF, because the
    // last read must be stalled.
    EXPECT_FALSE(upload_data_stream.IsEOF());
  } else {
    // All the body data should have been read.
    // TODO(satorux): This is because of the weirdness in reading the request
    // body in OnSendBodyComplete(). See crbug.com/113107.
    EXPECT_TRUE(upload_data_stream.IsEOF());
  }

  // Read in WINDOW_UPDATE or SETTINGS frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  rv = callback.WaitForResult();
  helper.VerifyDataConsumed();
}

TEST_F(SpdyNetworkTransactionTest, GoAwayOnOddPushStreamId) {
  SpdyHeaderBlock push_headers;
  spdy_util_.AddUrlToHeaderBlock("http://www.example.org/a.dat", &push_headers);
  SpdySerializedFrame push(
      spdy_util_.ConstructInitialSpdyPushFrame(std::move(push_headers), 3, 1));
  MockRead reads[] = {CreateMockRead(push, 1)};

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, GOAWAY_PROTOCOL_ERROR, "Odd push stream id."));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(goaway, 2),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

TEST_F(SpdyNetworkTransactionTest,
       GoAwayOnPushStreamIdLesserOrEqualThanLastAccepted) {
  SpdySerializedFrame push_a(spdy_util_.ConstructSpdyPush(
      NULL, 0, 4, 1, GetDefaultUrlWithPath("/a.dat").c_str()));
  SpdyHeaderBlock push_b_headers;
  spdy_util_.AddUrlToHeaderBlock(GetDefaultUrlWithPath("/b.dat"),
                                 &push_b_headers);
  SpdySerializedFrame push_b(spdy_util_.ConstructInitialSpdyPushFrame(
      std::move(push_b_headers), 2, 1));
  MockRead reads[] = {
      CreateMockRead(push_a, 1), CreateMockRead(push_b, 2),
  };

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      4, GOAWAY_PROTOCOL_ERROR,
      "New push stream id must be greater than the last accepted."));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(goaway, 3),
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), NULL);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

// Regression test for https://crbug.com/493348: request header exceeds 16 kB
// and thus sent in multiple frames when using HTTP/2.
TEST_F(SpdyNetworkTransactionTest, LargeRequest) {
  const std::string kKey("foo");
  const std::string kValue(1 << 15, 'z');

  HttpRequestInfo request;
  request.method = "GET";
  request.url = default_url_;
  request.extra_headers.SetHeader(kKey, kValue);

  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers[kKey] = kValue;
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Regression test for https://crbug.com/535629: response header exceeds 16 kB.
TEST_F(SpdyNetworkTransactionTest, LargeResponseHeader) {
  SpdyHeaderBlock headers(spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  // HPACK decoder implementation limits string literal length to 16 kB.
  const char* response_headers[2];
  const std::string kKey(16 * 1024, 'a');
  response_headers[0] = kKey.data();
  const std::string kValue(16 * 1024, 'b');
  response_headers[1] = kValue.data();

  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(response_headers, 1, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = default_url_;
  NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
  ASSERT_TRUE(out.response_info.headers->HasHeaderValue(kKey, kValue));
}

// End of line delimiter is forbidden according to RFC 7230 Section 3.2.
TEST_F(SpdyNetworkTransactionTest, CRLFInHeaderValue) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_PROTOCOL_ERROR));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 2)};

  const char* response_headers[] = {"folded", "foo\r\nbar"};
  SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(response_headers, 1, 1));
  MockRead reads[] = {CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));

  NormalSpdyTransactionHelper helper(CreateGetRequest(), DEFAULT_PRIORITY,
                                     NetLogWithSource(), nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

// Regression test for https://crbug.com/603182.
// No response headers received before RST_STREAM: error.
TEST_F(SpdyNetworkTransactionTest, RstStreamNoError) {
  SpdySerializedFrame req(spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0, ASYNC)};

  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_NO_ERROR));
  MockRead reads[] = {CreateMockRead(rst, 1), MockRead(ASYNC, 0, 2)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateChunkedPostRequest(),
                                     DEFAULT_PRIORITY, NetLogWithSource(),
                                     nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_SPDY_PROTOCOL_ERROR));
}

// Regression test for https://crbug.com/603182.
// Response headers and data, then RST_STREAM received,
// before request body is sent: success.
TEST_F(SpdyNetworkTransactionTest, RstStreamNoErrorAfterResponse) {
  SpdySerializedFrame req(spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0, ASYNC)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, RST_STREAM_NO_ERROR));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                      CreateMockRead(rst, 3), MockRead(ASYNC, 0, 4)};

  SequencedSocketData data(reads, arraysize(reads), writes, arraysize(writes));
  NormalSpdyTransactionHelper helper(CreateChunkedPostRequest(),
                                     DEFAULT_PRIORITY, NetLogWithSource(),
                                     nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

class SpdyNetworkTransactionTLSUsageCheckTest
    : public SpdyNetworkTransactionTest {
 protected:
  void RunTLSUsageCheckTest(
      std::unique_ptr<SSLSocketDataProvider> ssl_provider) {
    SpdySerializedFrame goaway(
        spdy_util_.ConstructSpdyGoAway(0, GOAWAY_INADEQUATE_SECURITY, ""));
    MockWrite writes[] = {CreateMockWrite(goaway)};

    StaticSocketDataProvider data(NULL, 0, writes, arraysize(writes));
    HttpRequestInfo request;
    request.method = "GET";
    request.url = default_url_;
    NormalSpdyTransactionHelper helper(request, DEFAULT_PRIORITY,
                                       NetLogWithSource(), NULL);
    helper.RunToCompletionWithSSLData(&data, std::move(ssl_provider));
    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsError(ERR_SPDY_INADEQUATE_TRANSPORT_SECURITY));
  }
};

TEST_F(SpdyNetworkTransactionTLSUsageCheckTest, TLSVersionTooOld) {
  std::unique_ptr<SSLSocketDataProvider> ssl_provider(
      new SSLSocketDataProvider(ASYNC, OK));
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_SSL3,
                                &ssl_provider->connection_status);

  RunTLSUsageCheckTest(std::move(ssl_provider));
}

TEST_F(SpdyNetworkTransactionTLSUsageCheckTest, TLSCipherSuiteSucky) {
  std::unique_ptr<SSLSocketDataProvider> ssl_provider(
      new SSLSocketDataProvider(ASYNC, OK));
  // Set to TLS_RSA_WITH_NULL_MD5
  SSLConnectionStatusSetCipherSuite(0x1, &ssl_provider->connection_status);

  RunTLSUsageCheckTest(std::move(ssl_provider));
}

}  // namespace net
