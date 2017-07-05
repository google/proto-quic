// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_network_transaction.h"

#include <math.h>  // ceil
#include <stdarg.h>
#include <stdint.h>

#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/scoped_task_environment.h"
#include "base/test/test_file_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/auth.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/completion_callback.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/network_throttle_manager.h"
#include "net/base/proxy_delegate.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_proxy_delegate.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_file_element_reader.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/host_cache.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_handler_digest.h"
#include "net/http/http_auth_handler_mock.h"
#include "net/http/http_auth_handler_ntlm.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_basic_state.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_parser.h"
#include "net/http/http_transaction_test_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy/mock_proxy_resolver.h"
#include "net/proxy/proxy_config_service_fixed.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_resolver_factory.h"
#include "net/proxy/proxy_server.h"
#include "net/proxy/proxy_service.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/mock_client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/chromium/spdy_session.h"
#include "net/spdy/chromium/spdy_session_pool.h"
#include "net/spdy/chromium/spdy_test_util_common.h"
#include "net/spdy/core/spdy_framer.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/net_test_suite.h"
#include "net/test/test_data_directory.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"

using net::test::IsError;
using net::test::IsOk;

using base::ASCIIToUTF16;

//-----------------------------------------------------------------------------

namespace net {

namespace {

class TestNetworkStreamThrottler : public NetworkThrottleManager {
 public:
  TestNetworkStreamThrottler()
      : throttle_new_requests_(false),
        num_set_priority_calls_(0),
        last_priority_set_(IDLE) {}

  ~TestNetworkStreamThrottler() override {
    EXPECT_TRUE(outstanding_throttles_.empty());
  }

  // NetworkThrottleManager
  std::unique_ptr<Throttle> CreateThrottle(ThrottleDelegate* delegate,
                                           RequestPriority priority,
                                           bool ignore_limits) override {
    auto test_throttle =
        base::MakeUnique<TestThrottle>(throttle_new_requests_, delegate, this);
    outstanding_throttles_.insert(test_throttle.get());
    return std::move(test_throttle);
  }

  void UnthrottleAllRequests() {
    std::set<TestThrottle*> outstanding_throttles_copy(outstanding_throttles_);
    for (auto* throttle : outstanding_throttles_copy) {
      if (throttle->IsBlocked())
        throttle->Unthrottle();
    }
  }

  void set_throttle_new_requests(bool throttle_new_requests) {
    throttle_new_requests_ = throttle_new_requests;
  }

  // Includes both throttled and unthrottled throttles.
  size_t num_outstanding_requests() const {
    return outstanding_throttles_.size();
  }

  int num_set_priority_calls() const { return num_set_priority_calls_; }
  RequestPriority last_priority_set() const { return last_priority_set_; }
  void set_priority_change_closure(
      const base::Closure& priority_change_closure) {
    priority_change_closure_ = priority_change_closure;
  }

 private:
  class TestThrottle : public NetworkThrottleManager::Throttle {
   public:
    ~TestThrottle() override { throttler_->OnThrottleDestroyed(this); }

    // Throttle
    bool IsBlocked() const override { return throttled_; }
    RequestPriority Priority() const override {
      NOTREACHED();
      return IDLE;
    }
    void SetPriority(RequestPriority priority) override {
      throttler_->SetPriorityCalled(priority);
    }

    TestThrottle(bool throttled,
                 ThrottleDelegate* delegate,
                 TestNetworkStreamThrottler* throttler)
        : throttled_(throttled), delegate_(delegate), throttler_(throttler) {}

    void Unthrottle() {
      EXPECT_TRUE(throttled_);

      throttled_ = false;
      delegate_->OnThrottleUnblocked(this);
    }

    bool throttled_;
    ThrottleDelegate* delegate_;
    TestNetworkStreamThrottler* throttler_;
  };

  void OnThrottleDestroyed(TestThrottle* throttle) {
    EXPECT_NE(0u, outstanding_throttles_.count(throttle));
    outstanding_throttles_.erase(throttle);
  }

  void SetPriorityCalled(RequestPriority priority) {
    ++num_set_priority_calls_;
    last_priority_set_ = priority;
    if (!priority_change_closure_.is_null())
      priority_change_closure_.Run();
  }

  // Includes both throttled and unthrottled throttles.
  std::set<TestThrottle*> outstanding_throttles_;
  bool throttle_new_requests_;
  int num_set_priority_calls_;
  RequestPriority last_priority_set_;
  base::Closure priority_change_closure_;

  DISALLOW_COPY_AND_ASSIGN(TestNetworkStreamThrottler);
};

const base::string16 kBar(ASCIIToUTF16("bar"));
const base::string16 kBar2(ASCIIToUTF16("bar2"));
const base::string16 kBar3(ASCIIToUTF16("bar3"));
const base::string16 kBaz(ASCIIToUTF16("baz"));
const base::string16 kFirst(ASCIIToUTF16("first"));
const base::string16 kFoo(ASCIIToUTF16("foo"));
const base::string16 kFoo2(ASCIIToUTF16("foo2"));
const base::string16 kFoo3(ASCIIToUTF16("foo3"));
const base::string16 kFou(ASCIIToUTF16("fou"));
const base::string16 kSecond(ASCIIToUTF16("second"));
const base::string16 kTestingNTLM(ASCIIToUTF16("testing-ntlm"));
const base::string16 kWrongPassword(ASCIIToUTF16("wrongpassword"));

const char kAlternativeServiceHttpHeader[] =
    "Alt-Svc: h2=\"mail.example.org:443\"\r\n";

int GetIdleSocketCountInTransportSocketPool(HttpNetworkSession* session) {
  return session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)
      ->IdleSocketCount();
}

int GetIdleSocketCountInSSLSocketPool(HttpNetworkSession* session) {
  return session->GetSSLSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)
      ->IdleSocketCount();
}

bool IsTransportSocketPoolStalled(HttpNetworkSession* session) {
  return session->GetTransportSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL)
      ->IsStalled();
}

// Takes in a Value created from a NetLogHttpResponseParameter, and returns
// a JSONified list of headers as a single string.  Uses single quotes instead
// of double quotes for easier comparison.  Returns false on failure.
bool GetHeaders(base::DictionaryValue* params, std::string* headers) {
  if (!params)
    return false;
  base::ListValue* header_list;
  if (!params->GetList("headers", &header_list))
    return false;
  std::string double_quote_headers;
  base::JSONWriter::Write(*header_list, &double_quote_headers);
  base::ReplaceChars(double_quote_headers, "\"", "'", headers);
  return true;
}

// Tests LoadTimingInfo in the case a socket is reused and no PAC script is
// used.
void TestLoadTimingReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
  EXPECT_FALSE(load_timing_info.send_start.is_null());

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests LoadTimingInfo in the case a new socket is used and no PAC script is
// used.
void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info,
                             int connect_timing_flags) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());

  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              connect_timing_flags);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests LoadTimingInfo in the case a socket is reused and a PAC script is
// used.
void TestLoadTimingReusedWithPac(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);

  EXPECT_FALSE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end,
            load_timing_info.send_start);
  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests LoadTimingInfo in the case a new socket is used and a PAC script is
// used.
void TestLoadTimingNotReusedWithPac(const LoadTimingInfo& load_timing_info,
                                    int connect_timing_flags) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end,
            load_timing_info.connect_timing.connect_start);
  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              connect_timing_flags);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

void AddWebSocketHeaders(HttpRequestHeaders* headers) {
  headers->SetHeader("Connection", "Upgrade");
  headers->SetHeader("Upgrade", "websocket");
  headers->SetHeader("Origin", "http://www.example.org");
  headers->SetHeader("Sec-WebSocket-Version", "13");
  headers->SetHeader("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
}

std::unique_ptr<HttpNetworkSession> CreateSession(
    SpdySessionDependencies* session_deps) {
  return SpdySessionDependencies::SpdyCreateSession(session_deps);
}

// Note that the pointer written into |*throttler| will only be valid
// for the lifetime of the returned HttpNetworkSession.
std::unique_ptr<HttpNetworkSession> CreateSessionWithThrottler(
    SpdySessionDependencies* session_deps,
    TestNetworkStreamThrottler** throttler) {
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(session_deps));

  auto owned_throttler = base::MakeUnique<TestNetworkStreamThrottler>();
  *throttler = owned_throttler.get();

  HttpNetworkSessionPeer peer(session.get());
  peer.SetNetworkStreamThrottler(std::move(owned_throttler));

  return session;
}

class FailingProxyResolverFactory : public ProxyResolverFactory {
 public:
  FailingProxyResolverFactory() : ProxyResolverFactory(false) {}

  // ProxyResolverFactory override.
  int CreateProxyResolver(
      const scoped_refptr<ProxyResolverScriptData>& script_data,
      std::unique_ptr<ProxyResolver>* result,
      const CompletionCallback& callback,
      std::unique_ptr<Request>* request) override {
    return ERR_PAC_SCRIPT_FAILED;
  }
};

}  // namespace

class HttpNetworkTransactionTest : public PlatformTest {
 public:
  ~HttpNetworkTransactionTest() override {
    // Important to restore the per-pool limit first, since the pool limit must
    // always be greater than group limit, and the tests reduce both limits.
    ClientSocketPoolManager::set_max_sockets_per_pool(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_pool_sockets_);
    ClientSocketPoolManager::set_max_sockets_per_group(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_group_sockets_);
  }

 protected:
  HttpNetworkTransactionTest()
      : ssl_(ASYNC, OK),
        old_max_group_sockets_(ClientSocketPoolManager::max_sockets_per_group(
            HttpNetworkSession::NORMAL_SOCKET_POOL)),
        old_max_pool_sockets_(ClientSocketPoolManager::max_sockets_per_pool(
            HttpNetworkSession::NORMAL_SOCKET_POOL)) {
    session_deps_.enable_http2_alternative_service = true;
  }

  struct SimpleGetHelperResult {
    int rv;
    std::string status_line;
    std::string response_data;
    int64_t total_received_bytes;
    int64_t total_sent_bytes;
    LoadTimingInfo load_timing_info;
    ConnectionAttempts connection_attempts;
    IPEndPoint remote_endpoint_after_start;
  };

  void SetUp() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
  }

  void TearDown() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    // Empty the current queue.
    base::RunLoop().RunUntilIdle();
    PlatformTest::TearDown();
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
  }

  // Either |write_failure| specifies a write failure or |read_failure|
  // specifies a read failure when using a reused socket.  In either case, the
  // failure should cause the network transaction to resend the request, and the
  // other argument should be NULL.
  void KeepAliveConnectionResendRequestTest(const MockWrite* write_failure,
                                            const MockRead* read_failure);

  // Either |write_failure| specifies a write failure or |read_failure|
  // specifies a read failure when using a reused socket.  In either case, the
  // failure should cause the network transaction to resend the request, and the
  // other argument should be NULL.
  void PreconnectErrorResendRequestTest(const MockWrite* write_failure,
                                        const MockRead* read_failure,
                                        bool use_spdy);

  SimpleGetHelperResult SimpleGetHelperForData(StaticSocketDataProvider* data[],
                                               size_t data_count) {
    SimpleGetHelperResult out;

    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");

    BoundTestNetLog log;
    session_deps_.net_log = log.bound().net_log();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    for (size_t i = 0; i < data_count; ++i) {
      session_deps_.socket_factory->AddSocketDataProvider(data[i]);
    }

    TestCompletionCallback callback;

    EXPECT_TRUE(log.bound().IsCapturing());
    int rv = trans.Start(&request, callback.callback(), log.bound());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    out.rv = callback.WaitForResult();
    out.total_received_bytes = trans.GetTotalReceivedBytes();
    out.total_sent_bytes = trans.GetTotalSentBytes();

    // Even in the failure cases that use this function, connections are always
    // successfully established before the error.
    EXPECT_TRUE(trans.GetLoadTimingInfo(&out.load_timing_info));
    TestLoadTimingNotReused(out.load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);

    if (out.rv != OK)
      return out;

    const HttpResponseInfo* response = trans.GetResponseInfo();
    // Can't use ASSERT_* inside helper functions like this, so
    // return an error.
    if (!response || !response->headers) {
      out.rv = ERR_UNEXPECTED;
      return out;
    }
    out.status_line = response->headers->GetStatusLine();

    EXPECT_EQ("127.0.0.1", response->socket_address.host());
    EXPECT_EQ(80, response->socket_address.port());

    bool got_endpoint =
        trans.GetRemoteEndpoint(&out.remote_endpoint_after_start);
    EXPECT_EQ(got_endpoint,
              out.remote_endpoint_after_start.address().size() > 0);

    rv = ReadTransaction(&trans, &out.response_data);
    EXPECT_THAT(rv, IsOk());

    TestNetLogEntry::List entries;
    log.GetEntries(&entries);
    size_t pos = ExpectLogContainsSomewhere(
        entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST_HEADERS,
        NetLogEventPhase::NONE);
    ExpectLogContainsSomewhere(
        entries, pos, NetLogEventType::HTTP_TRANSACTION_READ_RESPONSE_HEADERS,
        NetLogEventPhase::NONE);

    std::string line;
    EXPECT_TRUE(entries[pos].GetStringValue("line", &line));
    EXPECT_EQ("GET / HTTP/1.1\r\n", line);

    HttpRequestHeaders request_headers;
    EXPECT_TRUE(trans.GetFullRequestHeaders(&request_headers));
    std::string value;
    EXPECT_TRUE(request_headers.GetHeader("Host", &value));
    EXPECT_EQ("www.example.org", value);
    EXPECT_TRUE(request_headers.GetHeader("Connection", &value));
    EXPECT_EQ("keep-alive", value);

    std::string response_headers;
    EXPECT_TRUE(GetHeaders(entries[pos].params.get(), &response_headers));
    EXPECT_EQ("['Host: www.example.org','Connection: keep-alive']",
              response_headers);

    out.total_received_bytes = trans.GetTotalReceivedBytes();
    // The total number of sent bytes should not have changed.
    EXPECT_EQ(out.total_sent_bytes, trans.GetTotalSentBytes());

    trans.GetConnectionAttempts(&out.connection_attempts);
    return out;
  }

  SimpleGetHelperResult SimpleGetHelper(MockRead data_reads[],
                                        size_t reads_count) {
    MockWrite data_writes[] = {
        MockWrite("GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    StaticSocketDataProvider reads(data_reads, reads_count, data_writes,
                                   arraysize(data_writes));
    StaticSocketDataProvider* data[] = {&reads};
    SimpleGetHelperResult out = SimpleGetHelperForData(data, 1);

    EXPECT_EQ(CountWriteBytes(data_writes, arraysize(data_writes)),
              out.total_sent_bytes);
    return out;
  }

  void AddSSLSocketData() {
    ssl_.next_proto = kProtoHTTP2;
    ssl_.cert = ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  void ConnectStatusHelperWithExpectedStatus(const MockRead& status,
                                             int expected_status);

  void ConnectStatusHelper(const MockRead& status);

  void BypassHostCacheOnRefreshHelper(int load_flags);

  void CheckErrorIsPassedBack(int error, IoMode mode);

  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  SSLSocketDataProvider ssl_;

  // Original socket limits.  Some tests set these.  Safest to always restore
  // them once each test has been run.
  int old_max_group_sockets_;
  int old_max_pool_sockets_;
};

namespace {

class BeforeHeadersSentHandler {
 public:
  BeforeHeadersSentHandler()
      : observed_before_headers_sent_with_proxy_(false),
        observed_before_headers_sent_(false) {}

  void OnBeforeHeadersSent(const ProxyInfo& proxy_info,
                           HttpRequestHeaders* request_headers) {
    observed_before_headers_sent_ = true;
    if (!proxy_info.is_http() && !proxy_info.is_https() &&
        !proxy_info.is_quic()) {
      return;
    }
    observed_before_headers_sent_with_proxy_ = true;
    observed_proxy_server_uri_ = proxy_info.proxy_server().ToURI();
  }

  bool observed_before_headers_sent_with_proxy() const {
    return observed_before_headers_sent_with_proxy_;
  }

  bool observed_before_headers_sent() const {
    return observed_before_headers_sent_;
  }

  std::string observed_proxy_server_uri() const {
    return observed_proxy_server_uri_;
  }

 private:
  bool observed_before_headers_sent_with_proxy_;
  bool observed_before_headers_sent_;
  std::string observed_proxy_server_uri_;

  DISALLOW_COPY_AND_ASSIGN(BeforeHeadersSentHandler);
};

// Fill |str| with a long header list that consumes >= |size| bytes.
void FillLargeHeadersString(std::string* str, int size) {
  const char row[] =
      "SomeHeaderName: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n";
  const int sizeof_row = strlen(row);
  const int num_rows = static_cast<int>(
      ceil(static_cast<float>(size) / sizeof_row));
  const int sizeof_data = num_rows * sizeof_row;
  DCHECK(sizeof_data >= size);
  str->reserve(sizeof_data);

  for (int i = 0; i < num_rows; ++i)
    str->append(row, sizeof_row);
}

#if defined(NTLM_PORTABLE)
// Alternative functions that eliminate randomness and dependency on the local
// host name so that the generated NTLM messages are reproducible.
void MockGenerateRandom1(uint8_t* output, size_t n) {
  static const uint8_t bytes[] = {0x55, 0x29, 0x66, 0x26,
                                  0x6b, 0x9c, 0x73, 0x54};
  static size_t current_byte = 0;
  for (size_t i = 0; i < n; ++i) {
    output[i] = bytes[current_byte++];
    current_byte %= arraysize(bytes);
  }
}

void MockGenerateRandom2(uint8_t* output, size_t n) {
  static const uint8_t bytes[] = {0x96, 0x79, 0x85, 0xe7, 0x49, 0x93,
                                  0x70, 0xa1, 0x4e, 0xe7, 0x87, 0x45,
                                  0x31, 0x5b, 0xd3, 0x1f};
  static size_t current_byte = 0;
  for (size_t i = 0; i < n; ++i) {
    output[i] = bytes[current_byte++];
    current_byte %= arraysize(bytes);
  }
}

std::string MockGetHostName() {
  return "WTC-WIN7";
}
#endif  // defined(NTLM_PORTABLE)

template<typename ParentPool>
class CaptureGroupNameSocketPool : public ParentPool {
 public:
  CaptureGroupNameSocketPool(HostResolver* host_resolver,
                             CertVerifier* cert_verifier);

  const std::string last_group_name_received() const {
    return last_group_name_;
  }

  int RequestSocket(const std::string& group_name,
                    const void* socket_params,
                    RequestPriority priority,
                    ClientSocketPool::RespectLimits respect_limits,
                    ClientSocketHandle* handle,
                    const CompletionCallback& callback,
                    const NetLogWithSource& net_log) override {
    last_group_name_ = group_name;
    return ERR_IO_PENDING;
  }
  void CancelRequest(const std::string& group_name,
                     ClientSocketHandle* handle) override {}
  void ReleaseSocket(const std::string& group_name,
                     std::unique_ptr<StreamSocket> socket,
                     int id) override {}
  void CloseIdleSockets() override {}
  void CloseIdleSocketsInGroup(const std::string& group_name) override {}
  int IdleSocketCount() const override { return 0; }
  int IdleSocketCountInGroup(const std::string& group_name) const override {
    return 0;
  }
  LoadState GetLoadState(const std::string& group_name,
                         const ClientSocketHandle* handle) const override {
    return LOAD_STATE_IDLE;
  }
  base::TimeDelta ConnectionTimeout() const override {
    return base::TimeDelta();
  }

 private:
  std::string last_group_name_;
};

typedef CaptureGroupNameSocketPool<TransportClientSocketPool>
CaptureGroupNameTransportSocketPool;
typedef CaptureGroupNameSocketPool<HttpProxyClientSocketPool>
CaptureGroupNameHttpProxySocketPool;
typedef CaptureGroupNameSocketPool<SOCKSClientSocketPool>
CaptureGroupNameSOCKSSocketPool;
typedef CaptureGroupNameSocketPool<SSLClientSocketPool>
CaptureGroupNameSSLSocketPool;

template <typename ParentPool>
CaptureGroupNameSocketPool<ParentPool>::CaptureGroupNameSocketPool(
    HostResolver* host_resolver,
    CertVerifier* /* cert_verifier */)
    : ParentPool(0, 0, host_resolver, NULL, NULL, NULL) {}

template <>
CaptureGroupNameHttpProxySocketPool::CaptureGroupNameSocketPool(
    HostResolver* /* host_resolver */,
    CertVerifier* /* cert_verifier */)
    : HttpProxyClientSocketPool(0, 0, NULL, NULL, NULL, NULL) {}

template <>
CaptureGroupNameSSLSocketPool::CaptureGroupNameSocketPool(
    HostResolver* /* host_resolver */,
    CertVerifier* cert_verifier)
    : SSLClientSocketPool(0,
                          0,
                          cert_verifier,
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          std::string(),
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          NULL) {
}

//-----------------------------------------------------------------------------

// Helper functions for validating that AuthChallengeInfo's are correctly
// configured for common cases.
bool CheckBasicServerAuth(const AuthChallengeInfo* auth_challenge) {
  if (!auth_challenge)
    return false;
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckBasicProxyAuth(const AuthChallengeInfo* auth_challenge) {
  if (!auth_challenge)
    return false;
  EXPECT_TRUE(auth_challenge->is_proxy);
  EXPECT_EQ("http://myproxy:70", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckBasicSecureProxyAuth(const AuthChallengeInfo* auth_challenge) {
  if (!auth_challenge)
    return false;
  EXPECT_TRUE(auth_challenge->is_proxy);
  EXPECT_EQ("https://myproxy:70", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckDigestServerAuth(const AuthChallengeInfo* auth_challenge) {
  if (!auth_challenge)
    return false;
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", auth_challenge->challenger.Serialize());
  EXPECT_EQ("digestive", auth_challenge->realm);
  EXPECT_EQ(kDigestAuthScheme, auth_challenge->scheme);
  return true;
}

#if defined(NTLM_PORTABLE)
bool CheckNTLMServerAuth(const AuthChallengeInfo* auth_challenge) {
  if (!auth_challenge)
    return false;
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("http://172.22.68.17", auth_challenge->challenger.Serialize());
  EXPECT_EQ(std::string(), auth_challenge->realm);
  EXPECT_EQ(kNtlmAuthScheme, auth_challenge->scheme);
  return true;
}
#endif  // defined(NTLM_PORTABLE)

}  // namespace

TEST_F(HttpNetworkTransactionTest, Basic) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
}

TEST_F(HttpNetworkTransactionTest, SimpleGET) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 200 OK", out.status_line);
  EXPECT_EQ("hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
  EXPECT_EQ(0u, out.connection_attempts.size());

  EXPECT_FALSE(out.remote_endpoint_after_start.address().empty());
}

// Response with no status line.
TEST_F(HttpNetworkTransactionTest, SimpleGETNoHeaders) {
  MockRead data_reads[] = {
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/0.9 200 OK", out.status_line);
  EXPECT_EQ("hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Response with no status line, and a weird port.  Should fail by default.
TEST_F(HttpNetworkTransactionTest, SimpleGETNoHeadersWeirdPort) {
  MockRead data_reads[] = {
      MockRead("hello world"), MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  request.method = "GET";
  request.url = GURL("http://www.example.com:2000/");
  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_INVALID_HTTP_RESPONSE));
}

// Response with no status line, and a weird port.  Option to allow weird ports
// enabled.
TEST_F(HttpNetworkTransactionTest, SimpleGETNoHeadersWeirdPortAllowed) {
  MockRead data_reads[] = {
      MockRead("hello world"), MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.http_09_on_non_default_ports_enabled = true;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  request.method = "GET";
  request.url = GURL("http://www.example.com:2000/");
  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* info = trans->GetResponseInfo();
  ASSERT_TRUE(info->headers);
  EXPECT_EQ("HTTP/0.9 200 OK", info->headers->GetStatusLine());

  // Don't bother to read the body - that's verified elsewhere, important thing
  // is that the option to allow HTTP/0.9 on non-default ports is respected.
}

// Allow up to 4 bytes of junk to precede status line.
TEST_F(HttpNetworkTransactionTest, StatusLineJunk3Bytes) {
  MockRead data_reads[] = {
    MockRead("xxxHTTP/1.0 404 Not Found\nServer: blah\n\nDATA"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 404 Not Found", out.status_line);
  EXPECT_EQ("DATA", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Allow up to 4 bytes of junk to precede status line.
TEST_F(HttpNetworkTransactionTest, StatusLineJunk4Bytes) {
  MockRead data_reads[] = {
    MockRead("\n\nQJHTTP/1.0 404 Not Found\nServer: blah\n\nDATA"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 404 Not Found", out.status_line);
  EXPECT_EQ("DATA", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Beyond 4 bytes of slop and it should fail to find a status line.
TEST_F(HttpNetworkTransactionTest, StatusLineJunk5Bytes) {
  MockRead data_reads[] = {
    MockRead("xxxxxHTTP/1.1 404 Not Found\nServer: blah"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/0.9 200 OK", out.status_line);
  EXPECT_EQ("xxxxxHTTP/1.1 404 Not Found\nServer: blah", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Same as StatusLineJunk4Bytes, except the read chunks are smaller.
TEST_F(HttpNetworkTransactionTest, StatusLineJunk4Bytes_Slow) {
  MockRead data_reads[] = {
    MockRead("\n"),
    MockRead("\n"),
    MockRead("Q"),
    MockRead("J"),
    MockRead("HTTP/1.0 404 Not Found\nServer: blah\n\nDATA"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.0 404 Not Found", out.status_line);
  EXPECT_EQ("DATA", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Close the connection before enough bytes to have a status line.
TEST_F(HttpNetworkTransactionTest, StatusLinePartial) {
  MockRead data_reads[] = {
    MockRead("HTT"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/0.9 200 OK", out.status_line);
  EXPECT_EQ("HTT", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, out.total_received_bytes);
}

// Simulate a 204 response, lacking a Content-Length header, sent over a
// persistent connection.  The response should still terminate since a 204
// cannot have a response body.
TEST_F(HttpNetworkTransactionTest, StopsReading204) {
  char junk[] = "junk";
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 204 No Content\r\n\r\n"),
    MockRead(junk),  // Should not be read!!
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 204 No Content", out.status_line);
  EXPECT_EQ("", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  int64_t response_size = reads_size - strlen(junk);
  EXPECT_EQ(response_size, out.total_received_bytes);
}

// A simple request using chunked encoding with some extra data after.
TEST_F(HttpNetworkTransactionTest, ChunkedEncoding) {
  std::string final_chunk = "0\r\n\r\n";
  std::string extra_data = "HTTP/1.1 200 OK\r\n";
  std::string last_read = final_chunk + extra_data;
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
    MockRead("5\r\nHello\r\n"),
    MockRead("1\r\n"),
    MockRead(" \r\n"),
    MockRead("5\r\nworld\r\n"),
    MockRead(last_read.data()),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello world", out.response_data);
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  int64_t response_size = reads_size - extra_data.size();
  EXPECT_EQ(response_size, out.total_received_bytes);
}

// Next tests deal with http://crbug.com/56344.

TEST_F(HttpNetworkTransactionTest,
       MultipleContentLengthHeadersNoTransferEncoding) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 10\r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH));
}

TEST_F(HttpNetworkTransactionTest,
       DuplicateContentLengthHeadersNoTransferEncoding) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 5\r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello", out.response_data);
}

TEST_F(HttpNetworkTransactionTest,
       ComplexContentLengthHeadersNoTransferEncoding) {
  // More than 2 dupes.
  {
    MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 5\r\n"),
      MockRead("Content-Length: 5\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("Hello"),
    };
    SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                                arraysize(data_reads));
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
    EXPECT_EQ("Hello", out.response_data);
  }
  // HTTP/1.0
  {
    MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 5\r\n"),
      MockRead("Content-Length: 5\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead("Hello"),
    };
    SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                                arraysize(data_reads));
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.0 200 OK", out.status_line);
    EXPECT_EQ("Hello", out.response_data);
  }
  // 2 dupes and one mismatched.
  {
    MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 10\r\n"),
      MockRead("Content-Length: 10\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
    };
    SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                                arraysize(data_reads));
    EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_LENGTH));
  }
}

TEST_F(HttpNetworkTransactionTest,
       MultipleContentLengthHeadersTransferEncoding) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 666\r\n"),
    MockRead("Content-Length: 1337\r\n"),
    MockRead("Transfer-Encoding: chunked\r\n\r\n"),
    MockRead("5\r\nHello\r\n"),
    MockRead("1\r\n"),
    MockRead(" \r\n"),
    MockRead("5\r\nworld\r\n"),
    MockRead("0\r\n\r\nHTTP/1.1 200 OK\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello world", out.response_data);
}

// Next tests deal with http://crbug.com/98895.

// Checks that a single Content-Disposition header results in no error.
TEST_F(HttpNetworkTransactionTest, SingleContentDispositionHeader) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Disposition: attachment;filename=\"salutations.txt\"r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello", out.response_data);
}

// Checks that two identical Content-Disposition headers result in no error.
TEST_F(HttpNetworkTransactionTest, TwoIdenticalContentDispositionHeaders) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Disposition: attachment;filename=\"greetings.txt\"r\n"),
    MockRead("Content-Disposition: attachment;filename=\"greetings.txt\"r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200 OK", out.status_line);
  EXPECT_EQ("Hello", out.response_data);
}

// Checks that two distinct Content-Disposition headers result in an error.
TEST_F(HttpNetworkTransactionTest, TwoDistinctContentDispositionHeaders) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Disposition: attachment;filename=\"greetings.txt\"r\n"),
    MockRead("Content-Disposition: attachment;filename=\"hi.txt\"r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("Hello"),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv,
              IsError(ERR_RESPONSE_HEADERS_MULTIPLE_CONTENT_DISPOSITION));
}

// Checks that two identical Location headers result in no error.
// Also tests Location header behavior.
TEST_F(HttpNetworkTransactionTest, TwoIdenticalLocationHeaders) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 302 Redirect\r\n"),
    MockRead("Location: http://good.com/\r\n"),
    MockRead("Location: http://good.com/\r\n"),
    MockRead("Content-Length: 0\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://redirect.com/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 302 Redirect", response->headers->GetStatusLine());
  std::string url;
  EXPECT_TRUE(response->headers->IsRedirect(&url));
  EXPECT_EQ("http://good.com/", url);
  EXPECT_TRUE(response->proxy_server.is_direct());
}

// Checks that two distinct Location headers result in an error.
TEST_F(HttpNetworkTransactionTest, TwoDistinctLocationHeaders) {
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 302 Redirect\r\n"),
    MockRead("Location: http://good.com/\r\n"),
    MockRead("Location: http://evil.com/\r\n"),
    MockRead("Content-Length: 0\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION));
}

// Do a request using the HEAD method. Verify that we don't try to read the
// message body (since HEAD has none).
TEST_F(HttpNetworkTransactionTest, Head) {
  HttpRequestInfo request;
  request.method = "HEAD";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  BeforeHeadersSentHandler headers_handler;
  trans.SetBeforeHeadersSentCallback(
      base::Bind(&BeforeHeadersSentHandler::OnBeforeHeadersSent,
                 base::Unretained(&headers_handler)));

  MockWrite data_writes1[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 404 Not Found\r\n"), MockRead("Server: Blah\r\n"),
      MockRead("Content-Length: 1234\r\n\r\n"),

      // No response body because the test stops reading here.
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // Check that the headers got parsed.
  EXPECT_TRUE(response->headers);
  EXPECT_EQ(1234, response->headers->GetContentLength());
  EXPECT_EQ("HTTP/1.1 404 Not Found", response->headers->GetStatusLine());
  EXPECT_TRUE(response->proxy_server.is_direct());
  EXPECT_TRUE(headers_handler.observed_before_headers_sent());
  EXPECT_FALSE(headers_handler.observed_before_headers_sent_with_proxy());

  std::string server_header;
  size_t iter = 0;
  bool has_server_header = response->headers->EnumerateHeader(
      &iter, "Server", &server_header);
  EXPECT_TRUE(has_server_header);
  EXPECT_EQ("Blah", server_header);

  // Reading should give EOF right away, since there is no message body
  // (despite non-zero content-length).
  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);
}

TEST_F(HttpNetworkTransactionTest, ReuseConnection) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
    MockRead("hello"),
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
    MockRead("world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  const char* const kExpectedResponseData[] = {
    "hello", "world"
  };

  for (int i = 0; i < 2; ++i) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    TestCompletionCallback callback;

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_TRUE(response->proxy_server.is_direct());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(kExpectedResponseData[i], response_data);
  }
}

TEST_F(HttpNetworkTransactionTest, Ignores100) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  // Check the upload progress returned before initialization is correct.
  UploadProgress progress = request.upload_data_stream->GetUploadProgress();
  EXPECT_EQ(0u, progress.size());
  EXPECT_EQ(0u, progress.position());

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
    MockRead("HTTP/1.0 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This test is almost the same as Ignores100 above, but the response contains
// a 102 instead of a 100. Also, instead of HTTP/1.0 the response is
// HTTP/1.1 and the two status headers are read in one read.
TEST_F(HttpNetworkTransactionTest, Ignores1xx) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 102 Unspecified status code\r\n\r\n"
             "HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_F(HttpNetworkTransactionTest, Incomplete100ThenEOF) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead(SYNCHRONOUS, "HTTP/1.0 100 Continue\r\n"),
    MockRead(ASYNC, 0),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);
}

TEST_F(HttpNetworkTransactionTest, EmptyResponse) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead(ASYNC, 0),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_EMPTY_RESPONSE));
}

void HttpNetworkTransactionTest::KeepAliveConnectionResendRequestTest(
    const MockWrite* write_failure,
    const MockRead* read_failure) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");

  TestNetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Written data for successfully sending both requests.
  MockWrite data1_writes[] = {
    MockWrite("GET / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n\r\n"),
    MockWrite("GET / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n\r\n")
  };

  // Read results for the first request.
  MockRead data1_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
    MockRead("hello"),
    MockRead(ASYNC, OK),
  };

  if (write_failure) {
    ASSERT_FALSE(read_failure);
    data1_writes[1] = *write_failure;
  } else {
    ASSERT_TRUE(read_failure);
    data1_reads[2] = *read_failure;
  }

  StaticSocketDataProvider data1(data1_reads, arraysize(data1_reads),
                                 data1_writes, arraysize(data1_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  MockRead data2_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
    MockRead("world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider data2(data2_reads, arraysize(data2_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  const char* const kExpectedResponseData[] = {
    "hello", "world"
  };

  uint32_t first_socket_log_id = NetLogSource::kInvalidId;
  for (int i = 0; i < 2; ++i) {
    TestCompletionCallback callback;

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    LoadTimingInfo load_timing_info;
    EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
    TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
    if (i == 0) {
      first_socket_log_id = load_timing_info.socket_log_id;
    } else {
      // The second request should be using a new socket.
      EXPECT_NE(first_socket_log_id, load_timing_info.socket_log_id);
    }

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_TRUE(response->headers);
    EXPECT_TRUE(response->proxy_server.is_direct());
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(kExpectedResponseData[i], response_data);
  }
}

void HttpNetworkTransactionTest::PreconnectErrorResendRequestTest(
    const MockWrite* write_failure,
    const MockRead* read_failure,
    bool use_spdy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.foo.com/");

  TestNetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SSLSocketDataProvider ssl1(ASYNC, OK);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  if (use_spdy) {
    ssl1.next_proto = kProtoHTTP2;
    ssl2.next_proto = kProtoHTTP2;
  }
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  // SPDY versions of the request and response.
  SpdySerializedFrame spdy_request(spdy_util_.ConstructSpdyGet(
      request.url.spec().c_str(), 1, DEFAULT_PRIORITY));
  SpdySerializedFrame spdy_response(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame spdy_data(
      spdy_util_.ConstructSpdyDataFrame(1, "hello", 5, true));

  // HTTP/1.1 versions of the request and response.
  const char kHttpRequest[] = "GET / HTTP/1.1\r\n"
      "Host: www.foo.com\r\n"
      "Connection: keep-alive\r\n\r\n";
  const char kHttpResponse[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
  const char kHttpData[] = "hello";

  std::vector<MockRead> data1_reads;
  std::vector<MockWrite> data1_writes;
  if (write_failure) {
    ASSERT_FALSE(read_failure);
    data1_writes.push_back(*write_failure);
    data1_reads.push_back(MockRead(ASYNC, OK));
  } else {
    ASSERT_TRUE(read_failure);
    if (use_spdy) {
      data1_writes.push_back(CreateMockWrite(spdy_request));
    } else {
      data1_writes.push_back(MockWrite(kHttpRequest));
    }
    data1_reads.push_back(*read_failure);
  }

  StaticSocketDataProvider data1(&data1_reads[0], data1_reads.size(),
                                 &data1_writes[0], data1_writes.size());
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  std::vector<MockRead> data2_reads;
  std::vector<MockWrite> data2_writes;

  if (use_spdy) {
    data2_writes.push_back(CreateMockWrite(spdy_request, 0, ASYNC));

    data2_reads.push_back(CreateMockRead(spdy_response, 1, ASYNC));
    data2_reads.push_back(CreateMockRead(spdy_data, 2, ASYNC));
    data2_reads.push_back(MockRead(ASYNC, OK, 3));
  } else {
    data2_writes.push_back(
        MockWrite(ASYNC, kHttpRequest, strlen(kHttpRequest), 0));

    data2_reads.push_back(
        MockRead(ASYNC, kHttpResponse, strlen(kHttpResponse), 1));
    data2_reads.push_back(MockRead(ASYNC, kHttpData, strlen(kHttpData), 2));
    data2_reads.push_back(MockRead(ASYNC, OK, 3));
  }
  SequencedSocketData data2(&data2_reads[0], data2_reads.size(),
                            &data2_writes[0], data2_writes.size());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // Preconnect a socket.
  session->http_stream_factory()->PreconnectStreams(1, request);
  // Wait for the preconnect to complete.
  // TODO(davidben): Some way to wait for an idle socket count might be handy.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, GetIdleSocketCountInSSLSocketPool(session.get()));

  // Make the request.
  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(
      load_timing_info,
      CONNECT_TIMING_HAS_DNS_TIMES|CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  if (response->was_fetched_via_spdy) {
    EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  } else {
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  }

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ(kHttpData, response_data);
}

TEST_F(HttpNetworkTransactionTest, KeepAliveConnectionNotConnectedOnWrite) {
  MockWrite write_failure(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  KeepAliveConnectionResendRequestTest(&write_failure, NULL);
}

TEST_F(HttpNetworkTransactionTest, KeepAliveConnectionReset) {
  MockRead read_failure(ASYNC, ERR_CONNECTION_RESET);
  KeepAliveConnectionResendRequestTest(NULL, &read_failure);
}

TEST_F(HttpNetworkTransactionTest, KeepAliveConnectionEOF) {
  MockRead read_failure(SYNCHRONOUS, OK);  // EOF
  KeepAliveConnectionResendRequestTest(NULL, &read_failure);
}

// Make sure that on a 408 response (Request Timeout), the request is retried,
// if the socket was a reused keep alive socket.
TEST_F(HttpNetworkTransactionTest, KeepAlive408) {
  MockRead read_failure(SYNCHRONOUS,
                        "HTTP/1.1 408 Request Timeout\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 6\r\n\r\n"
                        "Pickle");
  KeepAliveConnectionResendRequestTest(NULL, &read_failure);
}

TEST_F(HttpNetworkTransactionTest, PreconnectErrorNotConnectedOnWrite) {
  MockWrite write_failure(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  PreconnectErrorResendRequestTest(&write_failure, NULL, false);
}

TEST_F(HttpNetworkTransactionTest, PreconnectErrorReset) {
  MockRead read_failure(ASYNC, ERR_CONNECTION_RESET);
  PreconnectErrorResendRequestTest(NULL, &read_failure, false);
}

TEST_F(HttpNetworkTransactionTest, PreconnectErrorEOF) {
  MockRead read_failure(SYNCHRONOUS, OK);  // EOF
  PreconnectErrorResendRequestTest(NULL, &read_failure, false);
}

TEST_F(HttpNetworkTransactionTest, PreconnectErrorAsyncEOF) {
  MockRead read_failure(ASYNC, OK);  // EOF
  PreconnectErrorResendRequestTest(NULL, &read_failure, false);
}

// Make sure that on a 408 response (Request Timeout), the request is retried,
// if the socket was a preconnected (UNUSED_IDLE) socket.
TEST_F(HttpNetworkTransactionTest, RetryOnIdle408) {
  MockRead read_failure(SYNCHRONOUS,
                        "HTTP/1.1 408 Request Timeout\r\n"
                        "Connection: Keep-Alive\r\n"
                        "Content-Length: 6\r\n\r\n"
                        "Pickle");
  KeepAliveConnectionResendRequestTest(NULL, &read_failure);
  PreconnectErrorResendRequestTest(NULL, &read_failure, false);
}

TEST_F(HttpNetworkTransactionTest, SpdyPreconnectErrorNotConnectedOnWrite) {
  MockWrite write_failure(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  PreconnectErrorResendRequestTest(&write_failure, NULL, true);
}

TEST_F(HttpNetworkTransactionTest, SpdyPreconnectErrorReset) {
  MockRead read_failure(ASYNC, ERR_CONNECTION_RESET);
  PreconnectErrorResendRequestTest(NULL, &read_failure, true);
}

TEST_F(HttpNetworkTransactionTest, SpdyPreconnectErrorEOF) {
  MockRead read_failure(SYNCHRONOUS, OK);  // EOF
  PreconnectErrorResendRequestTest(NULL, &read_failure, true);
}

TEST_F(HttpNetworkTransactionTest, SpdyPreconnectErrorAsyncEOF) {
  MockRead read_failure(ASYNC, OK);  // EOF
  PreconnectErrorResendRequestTest(NULL, &read_failure, true);
}

TEST_F(HttpNetworkTransactionTest, NonKeepAliveConnectionReset) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead(ASYNC, ERR_CONNECTION_RESET),
    MockRead("HTTP/1.0 200 OK\r\n\r\n"),  // Should not be used
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_LT(0u, endpoint.address().size());
}

// What do various browsers do when the server closes a non-keepalive
// connection without sending any response header or body?
//
// IE7: error page
// Safari 3.1.2 (Windows): error page
// Firefox 3.0.1: blank page
// Opera 9.52: after five attempts, blank page
// Us with WinHTTP: error page (ERR_INVALID_RESPONSE)
// Us: error page (EMPTY_RESPONSE)
TEST_F(HttpNetworkTransactionTest, NonKeepAliveConnectionEOF) {
  MockRead data_reads[] = {
    MockRead(SYNCHRONOUS, OK),  // EOF
    MockRead("HTTP/1.0 200 OK\r\n\r\n"),  // Should not be used
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  SimpleGetHelperResult out = SimpleGetHelper(data_reads,
                                              arraysize(data_reads));
  EXPECT_THAT(out.rv, IsError(ERR_EMPTY_RESPONSE));
}

// Next 2 cases (KeepAliveEarlyClose and KeepAliveEarlyClose2) are regression
// tests. There was a bug causing HttpNetworkTransaction to hang in the
// destructor in such situations.
// See http://crbug.com/154712 and http://crbug.com/156609.
TEST_F(HttpNetworkTransactionTest, KeepAliveEarlyClose) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Connection: keep-alive\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead("hello"),
    MockRead(SYNCHRONOUS, 0),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  scoped_refptr<IOBufferWithSize> io_buf(new IOBufferWithSize(100));
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_EQ(5, rv);
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));

  trans.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_F(HttpNetworkTransactionTest, KeepAliveEarlyClose2) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Connection: keep-alive\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, 0),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  scoped_refptr<IOBufferWithSize> io_buf(new IOBufferWithSize(100));
  rv = trans->Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));

  trans.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test that we correctly reuse a keep-alive connection after not explicitly
// reading the body.
TEST_F(HttpNetworkTransactionTest, KeepAliveAfterUnreadBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");

  TestNetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  const char* request_data =
      "GET / HTTP/1.1\r\n"
      "Host: www.foo.com\r\n"
      "Connection: keep-alive\r\n\r\n";
  MockWrite data_writes[] = {
      MockWrite(ASYNC, 0, request_data),  MockWrite(ASYNC, 2, request_data),
      MockWrite(ASYNC, 4, request_data),  MockWrite(ASYNC, 6, request_data),
      MockWrite(ASYNC, 8, request_data),  MockWrite(ASYNC, 10, request_data),
      MockWrite(ASYNC, 12, request_data), MockWrite(ASYNC, 14, request_data),
      MockWrite(ASYNC, 17, request_data), MockWrite(ASYNC, 20, request_data),
  };

  // Note that because all these reads happen in the same
  // StaticSocketDataProvider, it shows that the same socket is being reused for
  // all transactions.
  MockRead data_reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 204 No Content\r\n\r\n"),
      MockRead(ASYNC, 3, "HTTP/1.1 205 Reset Content\r\n\r\n"),
      MockRead(ASYNC, 5, "HTTP/1.1 304 Not Modified\r\n\r\n"),
      MockRead(ASYNC, 7,
               "HTTP/1.1 302 Found\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(ASYNC, 9,
               "HTTP/1.1 302 Found\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),
      MockRead(ASYNC, 11,
               "HTTP/1.1 301 Moved Permanently\r\n"
               "Content-Length: 0\r\n\r\n"),
      MockRead(ASYNC, 13,
               "HTTP/1.1 301 Moved Permanently\r\n"
               "Content-Length: 5\r\n\r\n"
               "hello"),

      // In the next two rounds, IsConnectedAndIdle returns false, due to
      // the set_busy_before_sync_reads(true) call, while the
      // HttpNetworkTransaction is being shut down, but the socket is still
      // reuseable.  See http://crbug.com/544255.
      MockRead(ASYNC, 15,
               "HTTP/1.1 200 Hunky-Dory\r\n"
               "Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, 16, "hello"),

      MockRead(ASYNC, 18,
               "HTTP/1.1 200 Hunky-Dory\r\n"
               "Content-Length: 5\r\n\r\n"
               "he"),
      MockRead(SYNCHRONOUS, 19, "llo"),

      // The body of the final request is actually read.
      MockRead(ASYNC, 21, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead(ASYNC, 22, "hello"),
  };
  SequencedSocketData data(data_reads, arraysize(data_reads), data_writes,
                           arraysize(data_writes));
  data.set_busy_before_sync_reads(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  const int kNumUnreadBodies = arraysize(data_writes) - 1;
  std::string response_lines[kNumUnreadBodies];

  uint32_t first_socket_log_id = NetLogSource::kInvalidId;
  for (size_t i = 0; i < kNumUnreadBodies; ++i) {
    TestCompletionCallback callback;

    auto trans = base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                          session.get());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info;
    EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
    if (i == 0) {
      TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);
      first_socket_log_id = load_timing_info.socket_log_id;
    } else {
      TestLoadTimingReused(load_timing_info);
      EXPECT_EQ(first_socket_log_id, load_timing_info.socket_log_id);
    }

    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response);

    ASSERT_TRUE(response->headers);
    response_lines[i] = response->headers->GetStatusLine();

    // Delete the transaction without reading the response bodies.  Then spin
    // the message loop, so the response bodies are drained.
    trans.reset();
    base::RunLoop().RunUntilIdle();
  }

  const char* const kStatusLines[] = {
      "HTTP/1.1 204 No Content",
      "HTTP/1.1 205 Reset Content",
      "HTTP/1.1 304 Not Modified",
      "HTTP/1.1 302 Found",
      "HTTP/1.1 302 Found",
      "HTTP/1.1 301 Moved Permanently",
      "HTTP/1.1 301 Moved Permanently",
      "HTTP/1.1 200 Hunky-Dory",
      "HTTP/1.1 200 Hunky-Dory",
  };

  static_assert(kNumUnreadBodies == arraysize(kStatusLines),
                "forgot to update kStatusLines");

  for (int i = 0; i < kNumUnreadBodies; ++i)
    EXPECT_EQ(kStatusLines[i], response_lines[i]);

  TestCompletionCallback callback;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello", response_data);
}

// Sockets that receive extra data after a response is complete should not be
// reused.
TEST_F(HttpNetworkTransactionTest, KeepAliveWithUnusedData1) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 22\r\n\r\n"
               "This server is borked."),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "HEAD";
  request1.url = GURL("http://www.borked.com/");

  auto trans1 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");

  auto trans2 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

TEST_F(HttpNetworkTransactionTest, KeepAliveWithUnusedData2) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 22\r\n\r\n"
               "This server is borked."
               "Bonus data!"),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");

  auto trans1 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("This server is borked.", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");

  auto trans2 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

TEST_F(HttpNetworkTransactionTest, KeepAliveWithUnusedData3) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("16\r\nThis server is borked.\r\n"),
      MockRead("0\r\n\r\nBonus data!"),
  };

  MockWrite data_writes2[] = {
      MockWrite("GET /foo HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 3\r\n\r\n"
               "foo"),
  };
  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");

  auto trans1 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  std::string response_data1;
  EXPECT_THAT(ReadTransaction(trans1.get(), &response_data1), IsOk());
  EXPECT_EQ("This server is borked.", response_data1);
  // Deleting the transaction attempts to release the socket back into the
  // socket pool.
  trans1.reset();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://www.borked.com/foo");

  auto trans2 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(200, response2->headers->response_code());

  std::string response_data2;
  EXPECT_THAT(ReadTransaction(trans2.get(), &response_data2), IsOk());
  EXPECT_EQ("foo", response_data2);
}

// This is a little different from the others - it tests the case that the
// HttpStreamParser doesn't know if there's extra data on a socket or not when
// the HttpNetworkTransaction is torn down, because the response body hasn't
// been read from yet, but the request goes through the HttpResponseBodyDrainer.
TEST_F(HttpNetworkTransactionTest, KeepAliveWithUnusedData4) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.borked.com\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Transfer-Encoding: chunked\r\n\r\n"),
      MockRead("16\r\nThis server is borked.\r\n"),
      MockRead("0\r\n\r\nBonus data!"),
  };
  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.borked.com/");

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response1 = trans->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(200, response1->headers->response_code());
  EXPECT_TRUE(response1->headers->IsKeepAlive());

  // Deleting the transaction creates an HttpResponseBodyDrainer to read the
  // response body.
  trans.reset();

  // Let the HttpResponseBodyDrainer drain the socket.  It should determine the
  // socket can't be reused, rather than returning it to the socket pool.
  base::RunLoop().RunUntilIdle();

  // There should be no idle sockets in the pool.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test the request-challenge-retry sequence for basic auth.
// (basic auth is the easiest to mock, because it has no randomness).
TEST_F(HttpNetworkTransactionTest, BasicAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  TestNetLog log;
  session_deps_.net_log = &log;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    // Give a couple authenticate options (only the middle one is actually
    // supported).
    MockRead("WWW-Authenticate: Basic invalid\r\n"),  // Malformed.
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("WWW-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    // Large content-length -- won't matter, as connection will be reset.
    MockRead("Content-Length: 10000\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans->RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_DNS_TIMES);

  int64_t writes_size1 = CountWriteBytes(data_writes1, arraysize(data_writes1));
  EXPECT_EQ(writes_size1, trans.GetTotalSentBytes());
  int64_t reads_size1 = CountReadBytes(data_reads1, arraysize(data_reads1));
  EXPECT_EQ(reads_size1, trans.GetTotalReceivedBytes());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_DNS_TIMES);
  // The load timing after restart should have a new socket ID, and times after
  // those of the first load timing.
  EXPECT_LE(load_timing_info1.receive_headers_end,
            load_timing_info2.connect_timing.connect_start);
  EXPECT_NE(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  int64_t writes_size2 = CountWriteBytes(data_writes2, arraysize(data_writes2));
  EXPECT_EQ(writes_size1 + writes_size2, trans.GetTotalSentBytes());
  int64_t reads_size2 = CountReadBytes(data_reads2, arraysize(data_reads2));
  EXPECT_EQ(reads_size1 + reads_size2, trans.GetTotalReceivedBytes());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth.
// (basic auth is the easiest to mock, because it has no randomness).
TEST_F(HttpNetworkTransactionTest, BasicAuthWithAddressChange) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  TestNetLog log;
  MockHostResolver* resolver = new MockHostResolver();
  session_deps_.net_log = &log;
  session_deps_.host_resolver.reset(resolver);
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  resolver->rules()->ClearRules();
  resolver->rules()->AddRule("www.example.org", "127.0.0.1");

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      // Give a couple authenticate options (only the middle one is actually
      // supported).
      MockRead("WWW-Authenticate: Basic invalid\r\n"),  // Malformed.
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("WWW-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      // Large content-length -- won't matter, as connection will be reset.
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans->RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"), MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  EXPECT_EQ(OK, callback1.GetResult(trans.Start(&request, callback1.callback(),
                                                NetLogWithSource())));

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_DNS_TIMES);

  int64_t writes_size1 = CountWriteBytes(data_writes1, arraysize(data_writes1));
  EXPECT_EQ(writes_size1, trans.GetTotalSentBytes());
  int64_t reads_size1 = CountReadBytes(data_reads1, arraysize(data_reads1));
  EXPECT_EQ(reads_size1, trans.GetTotalReceivedBytes());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  ASSERT_FALSE(endpoint.address().empty());
  EXPECT_EQ("127.0.0.1:80", endpoint.ToString());

  resolver->rules()->ClearRules();
  resolver->rules()->AddRule("www.example.org", "127.0.0.2");

  TestCompletionCallback callback2;

  EXPECT_EQ(OK, callback2.GetResult(trans.RestartWithAuth(
                    AuthCredentials(kFoo, kBar), callback2.callback())));

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_DNS_TIMES);
  // The load timing after restart should have a new socket ID, and times after
  // those of the first load timing.
  EXPECT_LE(load_timing_info1.receive_headers_end,
            load_timing_info2.connect_timing.connect_start);
  EXPECT_NE(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  int64_t writes_size2 = CountWriteBytes(data_writes2, arraysize(data_writes2));
  EXPECT_EQ(writes_size1 + writes_size2, trans.GetTotalSentBytes());
  int64_t reads_size2 = CountReadBytes(data_reads2, arraysize(data_reads2));
  EXPECT_EQ(reads_size1 + reads_size2, trans.GetTotalReceivedBytes());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(100, response->headers->GetContentLength());

  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  ASSERT_FALSE(endpoint.address().empty());
  EXPECT_EQ("127.0.0.2:80", endpoint.ToString());
}

TEST_F(HttpNetworkTransactionTest, DoNotSendAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    // Large content-length -- won't matter, as connection will be reset.
    MockRead("Content-Length: 10000\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_EQ(0, rv);

  int64_t writes_size = CountWriteBytes(data_writes, arraysize(data_writes));
  EXPECT_EQ(writes_size, trans.GetTotalSentBytes());
  int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
  EXPECT_EQ(reads_size, trans.GetTotalReceivedBytes());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection.
TEST_F(HttpNetworkTransactionTest, BasicAuthKeepAlive) {
  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused.  See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");

    TestNetLog log;
    session_deps_.net_log = &log;
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    MockWrite data_writes[] = {
        MockWrite(ASYNC, 0,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),

        // After calling trans.RestartWithAuth(), this is the request we should
        // be issuing -- the final header line contains the credentials.
        MockWrite(ASYNC, 6,
                  "GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n"
                  "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    MockRead data_reads[] = {
        MockRead(ASYNC, 1, "HTTP/1.1 401 Unauthorized\r\n"),
        MockRead(ASYNC, 2, "WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead(ASYNC, 3, "Content-Type: text/html; charset=iso-8859-1\r\n"),
        MockRead(ASYNC, 4, "Content-Length: 14\r\n\r\n"),
        MockRead(i == 0 ? ASYNC : SYNCHRONOUS, 5, "Unauthorized\r\n"),

        // Lastly, the server responds with the actual content.
        MockRead(ASYNC, 7, "HTTP/1.1 200 OK\r\n"),
        MockRead(ASYNC, 8, "Content-Type: text/html; charset=iso-8859-1\r\n"),
        MockRead(ASYNC, 9, "Content-Length: 5\r\n\r\n"),
        MockRead(ASYNC, 10, "Hello"),
    };

    SequencedSocketData data(data_reads, arraysize(data_reads), data_writes,
                             arraysize(data_writes));
    data.set_busy_before_sync_reads(true);
    session_deps_.socket_factory->AddSocketDataProvider(&data);

    TestCompletionCallback callback1;

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    ASSERT_THAT(callback1.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info1;
    EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info1));
    TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_DNS_TIMES);

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                               callback2.callback());
    ASSERT_THAT(callback2.GetResult(rv), IsOk());

    LoadTimingInfo load_timing_info2;
    EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info2));
    TestLoadTimingReused(load_timing_info2);
    // The load timing after restart should have the same socket ID, and times
    // those of the first load timing.
    EXPECT_LE(load_timing_info1.receive_headers_end,
              load_timing_info2.send_start);
    EXPECT_EQ(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
    EXPECT_EQ(5, response->headers->GetContentLength());

    std::string response_data;
    EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

    int64_t writes_size = CountWriteBytes(data_writes, arraysize(data_writes));
    EXPECT_EQ(writes_size, trans.GetTotalSentBytes());
    int64_t reads_size = CountReadBytes(data_reads, arraysize(data_reads));
    EXPECT_EQ(reads_size, trans.GetTotalReceivedBytes());
  }
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection and with no response body to drain.
TEST_F(HttpNetworkTransactionTest, BasicAuthKeepAliveNoBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Length: 0\r\n\r\n"),  // No response body.

    // Lastly, the server responds with the actual content.
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("hello"),
  };

  // An incorrect reconnect would cause this to be read.
  MockRead data_reads2[] = {
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(5, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection and with a large response body to drain.
TEST_F(HttpNetworkTransactionTest, BasicAuthKeepAliveLargeBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Respond with 5 kb of response body.
  std::string large_body_string("Unauthorized");
  large_body_string.append(5 * 1024, ' ');
  large_body_string.append("\r\n");

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    // 5134 = 12 + 5 * 1024 + 2
    MockRead("Content-Length: 5134\r\n\r\n"),
    MockRead(ASYNC, large_body_string.data(), large_body_string.size()),

    // Lastly, the server responds with the actual content.
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("hello"),
  };

  // An incorrect reconnect would cause this to be read.
  MockRead data_reads2[] = {
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(5, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// connection, but the server gets impatient and closes the connection.
TEST_F(HttpNetworkTransactionTest, BasicAuthKeepAliveImpatientServer) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
      // This simulates the seemingly successful write to a closed connection
      // if the bug is not fixed.
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 14\r\n\r\n"),
    // Tell MockTCPClientSocket to simulate the server closing the connection.
    MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
    MockRead("Unauthorized\r\n"),
    MockRead(SYNCHRONOUS, OK),  // The server closes the connection.
  };

  // After calling trans.RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 5\r\n\r\n"),
    MockRead("hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(5, response->headers->GetContentLength());
}

// Test the request-challenge-retry sequence for basic auth, over a connection
// that requires a restart when setting up an SSL tunnel.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyNoKeepAliveHttp10) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // when the no authentication data flag is set.
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.0 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n\r\n"),
  };

  // Since the first connection couldn't be reused, need to establish another
  // once given credentials.
  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->headers->IsKeepAlive());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 0) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  TestCompletionCallback callback2;

  rv =
      trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections();
}

// Test the request-challenge-retry sequence for basic auth, over a connection
// that requires a restart when setting up an SSL tunnel.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyNoKeepAliveHttp11) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // when the no authentication data flag is set.
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->headers->IsKeepAlive());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  TestCompletionCallback callback2;

  rv = trans->RestartWithAuth(
      AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections();
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// proxy connection with HTTP/1.0 responses, when setting up an SSL tunnel.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveHttp10) {
  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused.  See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("https://www.example.org/");
    // Ensure that proxy authentication is attempted even
    // when the no authentication data flag is set.
    request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

    // Configure against proxy server "myproxy:70".
    session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
    BoundTestNetLog log;
    session_deps_.net_log = log.bound().net_log();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    // Since we have proxy, should try to establish tunnel.
    MockWrite data_writes1[] = {
        MockWrite(ASYNC, 0,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n\r\n"),

        // After calling trans.RestartWithAuth(), this is the request we should
        // be issuing -- the final header line contains the credentials.
        MockWrite(ASYNC, 3,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJheg==\r\n\r\n"),
    };

    // The proxy responds to the connect with a 407, using a persistent
    // connection. (Since it's HTTP/1.0, keep-alive has to be explicit.)
    MockRead data_reads1[] = {
        // No credentials.
        MockRead(ASYNC, 1,
                 "HTTP/1.0 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Proxy-Connection: keep-alive\r\n"
                 "Content-Length: 10\r\n\r\n"),
        MockRead(i == 0 ? ASYNC : SYNCHRONOUS, 2, "0123456789"),

        // Wrong credentials (wrong password).
        MockRead(ASYNC, 4,
                 "HTTP/1.0 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Proxy-Connection: keep-alive\r\n"
                 "Content-Length: 10\r\n\r\n"),
        // No response body because the test stops reading here.
        MockRead(SYNCHRONOUS, ERR_UNEXPECTED, 5),
    };

    SequencedSocketData data1(data_reads1, arraysize(data_reads1), data_writes1,
                              arraysize(data_writes1));
    data1.set_busy_before_sync_reads(true);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), log.bound());
    EXPECT_THAT(callback1.GetResult(rv), IsOk());

    TestNetLogEntry::List entries;
    log.GetEntries(&entries);
    size_t pos = ExpectLogContainsSomewhere(
        entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
        NetLogEventPhase::NONE);
    ExpectLogContainsSomewhere(
        entries, pos,
        NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
        NetLogEventPhase::NONE);

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 0) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

    TestCompletionCallback callback2;

    // Wrong password (should be "bar").
    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBaz),
                               callback2.callback());
    EXPECT_THAT(callback2.GetResult(rv), IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 0) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

    // Flush the idle socket before the NetLog and HttpNetworkTransaction go
    // out of scope.
    session->CloseAllConnections();
  }
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// proxy connection with HTTP/1.1 responses, when setting up an SSL tunnel.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveHttp11) {
  // On the second pass, the body read of the auth challenge is synchronous, so
  // IsConnectedAndIdle returns false.  The socket should still be drained and
  // reused.  See http://crbug.com/544255.
  for (int i = 0; i < 2; ++i) {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("https://www.example.org/");
    // Ensure that proxy authentication is attempted even
    // when the no authentication data flag is set.
    request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

    // Configure against proxy server "myproxy:70".
    session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
    BoundTestNetLog log;
    session_deps_.net_log = log.bound().net_log();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    // Since we have proxy, should try to establish tunnel.
    MockWrite data_writes1[] = {
        MockWrite(ASYNC, 0,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n\r\n"),

        // After calling trans.RestartWithAuth(), this is the request we should
        // be issuing -- the final header line contains the credentials.
        MockWrite(ASYNC, 3,
                  "CONNECT www.example.org:443 HTTP/1.1\r\n"
                  "Host: www.example.org:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJheg==\r\n\r\n"),
    };

    // The proxy responds to the connect with a 407, using a persistent
    // connection. (Since it's HTTP/1.0, keep-alive has to be explicit.)
    MockRead data_reads1[] = {
        // No credentials.
        MockRead(ASYNC, 1,
                 "HTTP/1.1 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Content-Length: 10\r\n\r\n"),
        MockRead(i == 0 ? ASYNC : SYNCHRONOUS, 2, "0123456789"),

        // Wrong credentials (wrong password).
        MockRead(ASYNC, 4,
                 "HTTP/1.1 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Content-Length: 10\r\n\r\n"),
        // No response body because the test stops reading here.
        MockRead(SYNCHRONOUS, ERR_UNEXPECTED, 5),
    };

    SequencedSocketData data1(data_reads1, arraysize(data_reads1), data_writes1,
                              arraysize(data_writes1));
    data1.set_busy_before_sync_reads(true);
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), log.bound());
    EXPECT_THAT(callback1.GetResult(rv), IsOk());

    TestNetLogEntry::List entries;
    log.GetEntries(&entries);
    size_t pos = ExpectLogContainsSomewhere(
        entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
        NetLogEventPhase::NONE);
    ExpectLogContainsSomewhere(
        entries, pos,
        NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
        NetLogEventPhase::NONE);

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

    TestCompletionCallback callback2;

    // Wrong password (should be "bar").
    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBaz),
                               callback2.callback());
    EXPECT_THAT(callback2.GetResult(rv), IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_TRUE(response->headers->IsKeepAlive());
    EXPECT_EQ(407, response->headers->response_code());
    EXPECT_EQ(10, response->headers->GetContentLength());
    EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
    EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

    // Flush the idle socket before the NetLog and HttpNetworkTransaction go
    // out of scope.
    session->CloseAllConnections();
  }
}

// Test the request-challenge-retry sequence for basic auth, over a keep-alive
// proxy connection with HTTP/1.1 responses, when setting up an SSL tunnel, in
// the case the server sends extra data on the original socket, so it can't be
// reused.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveExtraData) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // when the no authentication data flag is set.
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent, but sends
  // extra data, so the socket cannot be reused.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead(ASYNC, 1,
               "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, 2, "0123456789"),
      MockRead(SYNCHRONOUS, 3, "I'm broken!"),
  };

  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite(ASYNC, 2,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead(ASYNC, 3,
               "HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 5\r\n\r\n"),
      // No response body because the test stops reading here.
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED, 4),
  };

  SequencedSocketData data1(data_reads1, arraysize(data_reads1), data_writes1,
                            arraysize(data_writes1));
  data1.set_busy_before_sync_reads(true);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SequencedSocketData data2(data_reads2, arraysize(data_reads2), data_writes2,
                            arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(callback1.GetResult(rv), IsOk());

  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  TestCompletionCallback callback2;

  rv =
      trans->RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(callback2.GetResult(rv), IsOk());

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections();
}

// Test the case a proxy closes a socket while the challenge body is being
// drained.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyKeepAliveHangupDuringBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // Ensure that proxy authentication is attempted even
  // when the no authentication data flag is set.
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"), MockRead("spam!"),
      // Server hands up in the middle of the body.
      MockRead(ASYNC, ERR_CONNECTION_CLOSED),
  };

  MockWrite data_writes2[] = {
      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  std::string body;
  EXPECT_THAT(ReadTransaction(&trans, &body), IsOk());
  EXPECT_EQ("hello", body);
}

// Test that we don't read the response body when we fail to establish a tunnel,
// even if the user cancels the proxy's auth attempt.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyCancelTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead("0123456789"),
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // Flush the idle socket before the HttpNetworkTransaction goes out of scope.
  session->CloseAllConnections();
}

// Test that we don't pass extraneous headers from the proxy's response to the
// caller when the proxy responds to CONNECT with 407.
TEST_F(HttpNetworkTransactionTest, SanitizeProxyAuthHeaders) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("X-Foo: bar\r\n"),
      MockRead("Set-Cookie: foo=bar\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_FALSE(response->headers->HasHeader("X-Foo"));
  EXPECT_FALSE(response->headers->HasHeader("Set-Cookie"));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // Flush the idle socket before the HttpNetworkTransaction goes out of scope.
  session->CloseAllConnections();
}

// Test when a server (non-proxy) returns a 407 (proxy-authenticate).
// The request should fail with ERR_UNEXPECTED_PROXY_AUTH.
TEST_F(HttpNetworkTransactionTest, UnexpectedProxyAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // We are using a DIRECT connection (i.e. no proxy) for this session.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.0 407 Proxy Auth required\r\n"),
    MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    // Large content-length -- won't matter, as connection will be reset.
    MockRead("Content-Length: 10000\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_UNEXPECTED_PROXY_AUTH));
}

// Tests when an HTTPS server (non-proxy) returns a 407 (proxy-authentication)
// through a non-authenticating proxy. The request should fail with
// ERR_UNEXPECTED_PROXY_AUTH.
// Note that it is impossible to detect if an HTTP server returns a 407 through
// a non-authenticating proxy - there is nothing to indicate whether the
// response came from the proxy or the server, so it is treated as if the proxy
// issued the challenge.
TEST_F(HttpNetworkTransactionTest, HttpsServerRequestsProxyAuthThroughProxy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

    MockRead("HTTP/1.1 407 Unauthorized\r\n"),
    MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_UNEXPECTED_PROXY_AUTH));
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);
}

// Test a proxy auth scheme that allows default credentials and a proxy server
// that uses non-persistent connections.
TEST_F(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelConnectionClose) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  auto auth_handler_factory = base::MakeUnique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  NetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  // Since the first connection couldn't be reused, need to establish another
  // once given credentials.
  MockWrite data_writes2[] = {
      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_FALSE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge);

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections();
}

// Test a proxy auth scheme that allows default credentials and a proxy server
// that hangs up when credentials are initially sent.
TEST_F(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelServerClosesConnection) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  auto auth_handler_factory = base::MakeUnique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  NetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  // Since the first connection was closed, need to establish another once given
  // credentials.
  MockWrite data_writes2[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 5\r\n\r\n"),
      MockRead(SYNCHRONOUS, "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge);

  LoadTimingInfo load_timing_info;
  // CONNECT requests and responses are handled at the connect job level, so
  // the transaction does not yet have a connection.
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections();
}

// Test a proxy auth scheme that allows default credentials and a proxy server
// that hangs up when credentials are initially sent, and hangs up again when
// they are retried.
TEST_F(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelServerClosesConnectionTwice) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  auto auth_handler_factory = base::MakeUnique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  NetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, and then hangs up after the
  // second request is sent.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Content-Length: 0\r\n"),
      MockRead("Proxy-Connection: keep-alive\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  // HttpNetworkTransaction sees a reused connection that was closed with
  // ERR_CONNECTION_CLOSED, realized it might have been a race, so retries the
  // request.
  MockWrite data_writes2[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy, having had more than enough of us, just hangs up.
  MockRead data_reads2[] = {
      // No credentials.
      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge);

  LoadTimingInfo load_timing_info;
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_EMPTY_RESPONSE));

  trans.reset();
  session->CloseAllConnections();
}

// Test a proxy auth scheme that allows default credentials and a proxy server
// that hangs up when credentials are initially sent, and sends a challenge
// again they are retried.
TEST_F(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelServerChallengesTwice) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  auto auth_handler_factory = base::MakeUnique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_PROXY);
  // Add another handler for the second challenge. It supports default
  // credentials, but they shouldn't be used, since they were already tried.
  mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  NetLog net_log;
  session_deps_.net_log = &net_log;
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  // Since the first connection was closed, need to establish another once given
  // credentials.
  MockWrite data_writes2[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge);

  LoadTimingInfo load_timing_info;
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_FALSE(trans->IsReadyToRestartForAuth());
  EXPECT_TRUE(response->auth_challenge);

  trans.reset();
  session->CloseAllConnections();
}

// A more nuanced test than GenerateAuthToken test which asserts that
// ERR_INVALID_AUTH_CREDENTIALS does not cause the auth scheme to be
// unnecessarily invalidated, and that if the server co-operates, the
// authentication handshake can continue with the same scheme but with a
// different identity.
TEST_F(HttpNetworkTransactionTest, NonPermanentGenerateAuthTokenError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  auto auth_handler_factory = base::MakeUnique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);

  // First handler. Uses default credentials, but barfs at generate auth token.
  auto mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  mock_handler->set_allows_explicit_credentials(true);
  mock_handler->set_connection_based(true);
  mock_handler->SetGenerateExpectation(true, ERR_INVALID_AUTH_CREDENTIALS);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_SERVER);

  // Add another handler for the second challenge. It supports default
  // credentials, but they shouldn't be used, since they were already tried.
  mock_handler = base::MakeUnique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  mock_handler->set_allows_explicit_credentials(true);
  mock_handler->set_connection_based(true);
  auth_handler_factory->AddMockHandler(mock_handler.release(),
                                       HttpAuth::AUTH_SERVER);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Authentication Required\r\n"
               "WWW-Authenticate: Mock\r\n"
               "Connection: keep-alive\r\n\r\n"),
  };

  // Identical to data_writes1[]. The AuthHandler encounters a
  // ERR_INVALID_AUTH_CREDENTIALS during the GenerateAuthToken stage, so the
  // transaction procceds without an authorization header.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 401 Authentication Required\r\n"
               "WWW-Authenticate: Mock\r\n"
               "Connection: keep-alive\r\n\r\n"),
  };

  MockWrite data_writes3[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: auth_token\r\n\r\n"),
  };

  MockRead data_reads3[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n"
               "Content-Type: text/plain\r\n"
               "Connection: keep-alive\r\n\r\n"
               "Hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                 data_writes3, arraysize(data_writes3));
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The following three tests assert that an authentication challenge was
  // received and that the stack is ready to respond to the challenge using
  // ambient credentials.
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge);

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);

  // The following three tests assert that an authentication challenge was
  // received and that the stack needs explicit credentials before it is ready
  // to respond to the challenge.
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_FALSE(trans->IsReadyToRestartForAuth());
  EXPECT_TRUE(response->auth_challenge);

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());

  trans.reset();
  session->CloseAllConnections();
}

// Test the load timing for HTTPS requests with an HTTP proxy.
TEST_F(HttpNetworkTransactionTest, HttpProxyLoadTimingNoPacTwoRequests) {
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/1");

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 1\r\n\r\n"),
    MockRead(SYNCHRONOUS, "1"),

    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 2\r\n\r\n"),
    MockRead(SYNCHRONOUS, "22"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;
  auto trans1 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans1->Start(&request1, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  EXPECT_TRUE(response1->proxy_server.is_http());
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(1, response1->headers->GetContentLength());

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans1->GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_SSL_TIMES);

  trans1.reset();

  TestCompletionCallback callback2;
  auto trans2 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans2->Start(&request2, callback2.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  EXPECT_TRUE(response2->proxy_server.is_http());
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(2, response2->headers->GetContentLength());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  EXPECT_EQ(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  trans2.reset();
  session->CloseAllConnections();
}

// Test the load timing for HTTPS requests with an HTTP proxy and a PAC script.
TEST_F(HttpNetworkTransactionTest, HttpProxyLoadTimingWithPacTwoRequests) {
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/1");

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 1\r\n\r\n"),
    MockRead(SYNCHRONOUS, "1"),

    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 2\r\n\r\n"),
    MockRead(SYNCHRONOUS, "22"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;
  auto trans1 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans1->Start(&request1, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(1, response1->headers->GetContentLength());

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans1->GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReusedWithPac(load_timing_info1,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans1.reset();

  TestCompletionCallback callback2;
  auto trans2 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans2->Start(&request2, callback2.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(2, response2->headers->GetContentLength());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReusedWithPac(load_timing_info2);

  EXPECT_EQ(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  trans2.reset();
  session->CloseAllConnections();
}

// Test a simple get through an HTTPS Proxy.
TEST_F(HttpNetworkTransactionTest, HttpsProxyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite(
          "GET http://www.example.org/ HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->proxy_server.is_https());
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);
}

// Test a SPDY get through an HTTPS Proxy.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyGet) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // fetch http://www.example.org/ via SPDY
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(data, 2), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->proxy_server.is_https());
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Verifies that a session which races and wins against the owning transaction
// (completing prior to host resolution), doesn't fail the transaction.
// Regression test for crbug.com/334413.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyGetWithSessionRace) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // Configure SPDY proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Fetch http://www.example.org/ through the SPDY proxy.
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(data, 2), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Stall the hostname resolution begun by the transaction.
  session_deps_.host_resolver->set_synchronous_mode(false);
  session_deps_.host_resolver->set_ondemand_mode(true);

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Race a session to the proxy, which completes first.
  session_deps_.host_resolver->set_ondemand_mode(false);
  SpdySessionKey key(
      HostPortPair("proxy", 70), ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, log.bound());

  // Unstall the resolution begun by the transaction.
  session_deps_.host_resolver->set_ondemand_mode(true);
  session_deps_.host_resolver->ResolveAllPending();

  EXPECT_FALSE(callback1.have_result());
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test a SPDY get through an HTTPS Proxy.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyGetWithProxyAuth) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // The first request will be a bare GET, the second request will be a
  // GET with a Proxy-Authorization header.
  spdy_util_.set_default_url(request.url);
  SpdySerializedFrame req_get(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, false));
  spdy_util_.UpdateWithStreamDestruction(1);
  const char* const kExtraAuthorizationHeaders[] = {
    "proxy-authorization", "Basic Zm9vOmJhcg=="
  };
  SpdySerializedFrame req_get_authorization(spdy_util_.ConstructSpdyGet(
      kExtraAuthorizationHeaders, arraysize(kExtraAuthorizationHeaders) / 2, 3,
      LOWEST, false));
  MockWrite spdy_writes[] = {
      CreateMockWrite(req_get, 0), CreateMockWrite(req_get_authorization, 3),
  };

  // The first response is a 407 proxy authentication challenge, and the second
  // response will be a 200 response since the second request includes a valid
  // Authorization header.
  const char* const kExtraAuthenticationHeaders[] = {
    "proxy-authenticate", "Basic realm=\"MyRealm1\""
  };
  SpdySerializedFrame resp_authentication(spdy_util_.ConstructSpdyReplyError(
      "407", kExtraAuthenticationHeaders,
      arraysize(kExtraAuthenticationHeaders) / 2, 1));
  SpdySerializedFrame body_authentication(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame resp_data(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body_data(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp_authentication, 1),
      CreateMockRead(body_authentication, 2, SYNCHRONOUS),
      CreateMockRead(resp_data, 4),
      CreateMockRead(body_data, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                           arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* const response = trans.GetResponseInfo();

  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* const response_restart = trans.GetResponseInfo();

  ASSERT_TRUE(response_restart);
  ASSERT_TRUE(response_restart->headers);
  EXPECT_EQ(200, response_restart->headers->response_code());
  // The password prompt info should not be set.
  EXPECT_FALSE(response_restart->auth_challenge);
}

// Test a SPDY CONNECT through an HTTPS Proxy to an HTTPS (non-SPDY) Server.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyConnectHttps) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to www.example.org:443 via SPDY
  SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP

  const char get[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructSpdyDataFrame(1, get, strlen(get), false));
  SpdySerializedFrame conn_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  const char resp[] = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 10\r\n\r\n";
  SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructSpdyDataFrame(1, resp, strlen(resp), false));
  SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructSpdyDataFrame(1, "1234567890", 10, false));
  SpdySerializedFrame window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp.size()));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0), CreateMockWrite(wrapped_get, 2),
      CreateMockWrite(window_update, 6),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      CreateMockRead(wrapped_get_resp, 3, ASYNC),
      CreateMockRead(wrapped_body, 4, ASYNC),
      CreateMockRead(wrapped_body, 5, ASYNC),
      MockRead(ASYNC, 0, 7),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("1234567890", response_data);
}

// Test a SPDY CONNECT through an HTTPS Proxy to a SPDY server.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyConnectSpdy) {
  SpdyTestUtil spdy_util_wrapped;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to www.example.org:443 via SPDY
  SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via SPDY
  const char kMyUrl[] = "https://www.example.org/";
  SpdySerializedFrame get(
      spdy_util_wrapped.ConstructSpdyGet(kMyUrl, 1, LOWEST));
  SpdySerializedFrame wrapped_get(spdy_util_.ConstructWrappedSpdyFrame(get, 1));
  SpdySerializedFrame conn_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame get_resp(
      spdy_util_wrapped.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructWrappedSpdyFrame(get_resp, 1));
  SpdySerializedFrame body(spdy_util_wrapped.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructWrappedSpdyFrame(body, 1));
  SpdySerializedFrame window_update_get_resp(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp.size()));
  SpdySerializedFrame window_update_body(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_body.size()));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0), CreateMockWrite(wrapped_get, 2),
      CreateMockWrite(window_update_get_resp, 6),
      CreateMockWrite(window_update_body, 7),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_get_resp, 4, ASYNC),
      CreateMockRead(wrapped_body, 5, ASYNC),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Allow the SpdyProxyClientSocket's write callback to complete.
  base::RunLoop().RunUntilIdle();
  // Now allow the read of the response to complete.
  spdy_data.Resume();
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ(kUploadData, response_data);
}

// Test a SPDY CONNECT failure through an HTTPS Proxy.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyConnectFailure) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // CONNECT to www.example.org:443 via SPDY
  SpdySerializedFrame connect(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  SpdySerializedFrame get(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0), CreateMockWrite(get, 2),
  };

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // TODO(juliatuttle): Anything else to check here?
}

// Test load timing in the case of two HTTPS (non-SPDY) requests through a SPDY
// HTTPS Proxy to different servers.
TEST_F(HttpNetworkTransactionTest,
       HttpsProxySpdyConnectHttpsLoadTimingTwoRequestsTwoServers) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;

  // CONNECT to www.example.org:443 via SPDY.
  SpdySerializedFrame connect1(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  SpdySerializedFrame conn_resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));

  // Fetch https://www.example.org/ via HTTP.
  const char get1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdySerializedFrame wrapped_get1(
      spdy_util_.ConstructSpdyDataFrame(1, get1, strlen(get1), false));
  const char resp1[] = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n\r\n";
  SpdySerializedFrame wrapped_get_resp1(
      spdy_util_.ConstructSpdyDataFrame(1, resp1, strlen(resp1), false));
  SpdySerializedFrame wrapped_body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", 1, false));
  SpdySerializedFrame window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp1.size()));

  // CONNECT to mail.example.org:443 via SPDY.
  SpdyHeaderBlock connect2_block;
  connect2_block[spdy_util_.GetMethodKey()] = "CONNECT";
  connect2_block[spdy_util_.GetHostKey()] = "mail.example.org:443";
  SpdySerializedFrame connect2(spdy_util_.ConstructSpdyHeaders(
      3, std::move(connect2_block), LOWEST, false));

  SpdySerializedFrame conn_resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));

  // Fetch https://mail.example.org/ via HTTP.
  const char get2[] =
      "GET / HTTP/1.1\r\n"
      "Host: mail.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdySerializedFrame wrapped_get2(
      spdy_util_.ConstructSpdyDataFrame(3, get2, strlen(get2), false));
  const char resp2[] = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 2\r\n\r\n";
  SpdySerializedFrame wrapped_get_resp2(
      spdy_util_.ConstructSpdyDataFrame(3, resp2, strlen(resp2), false));
  SpdySerializedFrame wrapped_body2(
      spdy_util_.ConstructSpdyDataFrame(3, "22", 2, false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect1, 0), CreateMockWrite(wrapped_get1, 2),
      CreateMockWrite(connect2, 5), CreateMockWrite(wrapped_get2, 7),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp1, 1, ASYNC),
      CreateMockRead(wrapped_get_resp1, 3, ASYNC),
      CreateMockRead(wrapped_body1, 4, ASYNC),
      CreateMockRead(conn_resp2, 6, ASYNC),
      CreateMockRead(wrapped_get_resp2, 8, ASYNC),
      CreateMockRead(wrapped_body2, 9, ASYNC),
      MockRead(ASYNC, 0, 10),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  SSLSocketDataProvider ssl3(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl3);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  scoped_refptr<IOBuffer> buf(new IOBuffer(256));
  rv = trans.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(1, callback.GetResult(rv));

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  // Even though the SPDY connection is reused, a new tunnelled connection has
  // to be created, so the socket's load timing looks like a fresh connection.
  TestLoadTimingNotReused(load_timing_info2, CONNECT_TIMING_HAS_SSL_TIMES);

  // The requests should have different IDs, since they each are using their own
  // separate stream.
  EXPECT_NE(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  rv = trans2.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(2, callback.GetResult(rv));
}

// Test load timing in the case of two HTTPS (non-SPDY) requests through a SPDY
// HTTPS Proxy to the same server.
TEST_F(HttpNetworkTransactionTest,
       HttpsProxySpdyConnectHttpsLoadTimingTwoRequestsSameServer) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");
  request2.load_flags = 0;

  // CONNECT to www.example.org:443 via SPDY.
  SpdySerializedFrame connect1(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  SpdySerializedFrame conn_resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));

  // Fetch https://www.example.org/ via HTTP.
  const char get1[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdySerializedFrame wrapped_get1(
      spdy_util_.ConstructSpdyDataFrame(1, get1, strlen(get1), false));
  const char resp1[] = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 1\r\n\r\n";
  SpdySerializedFrame wrapped_get_resp1(
      spdy_util_.ConstructSpdyDataFrame(1, resp1, strlen(resp1), false));
  SpdySerializedFrame wrapped_body1(
      spdy_util_.ConstructSpdyDataFrame(1, "1", 1, false));
  SpdySerializedFrame window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, wrapped_get_resp1.size()));

  // Fetch https://www.example.org/2 via HTTP.
  const char get2[] =
      "GET /2 HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdySerializedFrame wrapped_get2(
      spdy_util_.ConstructSpdyDataFrame(1, get2, strlen(get2), false));
  const char resp2[] = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 2\r\n\r\n";
  SpdySerializedFrame wrapped_get_resp2(
      spdy_util_.ConstructSpdyDataFrame(1, resp2, strlen(resp2), false));
  SpdySerializedFrame wrapped_body2(
      spdy_util_.ConstructSpdyDataFrame(1, "22", 2, false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(connect1, 0), CreateMockWrite(wrapped_get1, 2),
      CreateMockWrite(wrapped_get2, 5),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(conn_resp1, 1, ASYNC),
      CreateMockRead(wrapped_get_resp1, 3, ASYNC),
      CreateMockRead(wrapped_body1, 4, SYNCHRONOUS),
      CreateMockRead(wrapped_get_resp2, 6, ASYNC),
      CreateMockRead(wrapped_body2, 7, SYNCHRONOUS),
      MockRead(ASYNC, 0, 8),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  TestCompletionCallback callback;

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info, CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  scoped_refptr<IOBuffer> buf(new IOBuffer(256));
  EXPECT_EQ(1, trans->Read(buf.get(), 256, callback.callback()));
  trans.reset();

  auto trans2 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = trans2->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  // The requests should have the same ID.
  EXPECT_EQ(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  EXPECT_EQ(2, trans2->Read(buf.get(), 256, callback.callback()));
}

// Test load timing in the case of of two HTTP requests through a SPDY HTTPS
// Proxy to different servers.
TEST_F(HttpNetworkTransactionTest, HttpsProxySpdyLoadTimingTwoHttpRequests) {
  // Configure against https proxy server "proxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.example.org/");
  request1.load_flags = 0;

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("http://mail.example.org/");
  request2.load_flags = 0;

  // http://www.example.org/
  SpdyHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://www.example.org/"));
  SpdySerializedFrame get1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  SpdySerializedFrame get_resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, "1", 1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  // http://mail.example.org/
  SpdyHeaderBlock headers2(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://mail.example.org/"));
  SpdySerializedFrame get2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(headers2), LOWEST, true));
  SpdySerializedFrame get_resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(3, "22", 2, true));

  MockWrite spdy_writes[] = {
      CreateMockWrite(get1, 0), CreateMockWrite(get2, 3),
  };

  MockRead spdy_reads[] = {
      CreateMockRead(get_resp1, 1, ASYNC),
      CreateMockRead(body1, 2, ASYNC),
      CreateMockRead(get_resp2, 4, ASYNC),
      CreateMockRead(body2, 5, ASYNC),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  scoped_refptr<IOBuffer> buf(new IOBuffer(256));
  rv = trans->Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(1, callback.GetResult(rv));
  // Delete the first request, so the second one can reuse the socket.
  trans.reset();

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  // The requests should have the same ID.
  EXPECT_EQ(load_timing_info.socket_log_id, load_timing_info2.socket_log_id);

  rv = trans2.Read(buf.get(), 256, callback.callback());
  EXPECT_EQ(2, callback.GetResult(rv));
}

// Test the challenge-response-retry sequence through an HTTPS Proxy
TEST_F(HttpNetworkTransactionTest, HttpsProxyAuthRetry) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  // when the no authentication data flag is set.
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should use full url
  MockWrite data_writes1[] = {
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      // After calling trans.RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("GET http://www.example.org/ HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // The proxy responds to the GET with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
    // No credentials.
    MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
    MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Proxy-Connection: keep-alive\r\n"),
    MockRead("Content-Length: 0\r\n\r\n"),

    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  load_timing_info = LoadTimingInfo();
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  // Retrying with HTTP AUTH is considered to be reusing a socket.
  TestLoadTimingReused(load_timing_info);

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);
}

void HttpNetworkTransactionTest::ConnectStatusHelperWithExpectedStatus(
    const MockRead& status, int expected_status) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      status, MockRead("Content-Length: 10\r\n\r\n"),
      // No response body because the test stops reading here.
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_EQ(expected_status, rv);
}

void HttpNetworkTransactionTest::ConnectStatusHelper(
    const MockRead& status) {
  ConnectStatusHelperWithExpectedStatus(
      status, ERR_TUNNEL_CONNECTION_FAILED);
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus100) {
  ConnectStatusHelper(MockRead("HTTP/1.1 100 Continue\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus101) {
  ConnectStatusHelper(MockRead("HTTP/1.1 101 Switching Protocols\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus201) {
  ConnectStatusHelper(MockRead("HTTP/1.1 201 Created\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus202) {
  ConnectStatusHelper(MockRead("HTTP/1.1 202 Accepted\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus203) {
  ConnectStatusHelper(
      MockRead("HTTP/1.1 203 Non-Authoritative Information\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus204) {
  ConnectStatusHelper(MockRead("HTTP/1.1 204 No Content\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus205) {
  ConnectStatusHelper(MockRead("HTTP/1.1 205 Reset Content\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus206) {
  ConnectStatusHelper(MockRead("HTTP/1.1 206 Partial Content\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus300) {
  ConnectStatusHelper(MockRead("HTTP/1.1 300 Multiple Choices\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus301) {
  ConnectStatusHelper(MockRead("HTTP/1.1 301 Moved Permanently\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus302) {
  ConnectStatusHelper(MockRead("HTTP/1.1 302 Found\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus303) {
  ConnectStatusHelper(MockRead("HTTP/1.1 303 See Other\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus304) {
  ConnectStatusHelper(MockRead("HTTP/1.1 304 Not Modified\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus305) {
  ConnectStatusHelper(MockRead("HTTP/1.1 305 Use Proxy\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus306) {
  ConnectStatusHelper(MockRead("HTTP/1.1 306\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus307) {
  ConnectStatusHelper(MockRead("HTTP/1.1 307 Temporary Redirect\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus308) {
  ConnectStatusHelper(MockRead("HTTP/1.1 308 Permanent Redirect\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus400) {
  ConnectStatusHelper(MockRead("HTTP/1.1 400 Bad Request\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus401) {
  ConnectStatusHelper(MockRead("HTTP/1.1 401 Unauthorized\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus402) {
  ConnectStatusHelper(MockRead("HTTP/1.1 402 Payment Required\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus403) {
  ConnectStatusHelper(MockRead("HTTP/1.1 403 Forbidden\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus404) {
  ConnectStatusHelper(MockRead("HTTP/1.1 404 Not Found\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus405) {
  ConnectStatusHelper(MockRead("HTTP/1.1 405 Method Not Allowed\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus406) {
  ConnectStatusHelper(MockRead("HTTP/1.1 406 Not Acceptable\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus407) {
  ConnectStatusHelperWithExpectedStatus(
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      ERR_PROXY_AUTH_UNSUPPORTED);
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus408) {
  ConnectStatusHelper(MockRead("HTTP/1.1 408 Request Timeout\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus409) {
  ConnectStatusHelper(MockRead("HTTP/1.1 409 Conflict\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus410) {
  ConnectStatusHelper(MockRead("HTTP/1.1 410 Gone\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus411) {
  ConnectStatusHelper(MockRead("HTTP/1.1 411 Length Required\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus412) {
  ConnectStatusHelper(MockRead("HTTP/1.1 412 Precondition Failed\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus413) {
  ConnectStatusHelper(MockRead("HTTP/1.1 413 Request Entity Too Large\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus414) {
  ConnectStatusHelper(MockRead("HTTP/1.1 414 Request-URI Too Long\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus415) {
  ConnectStatusHelper(MockRead("HTTP/1.1 415 Unsupported Media Type\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus416) {
  ConnectStatusHelper(
      MockRead("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus417) {
  ConnectStatusHelper(MockRead("HTTP/1.1 417 Expectation Failed\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus500) {
  ConnectStatusHelper(MockRead("HTTP/1.1 500 Internal Server Error\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus501) {
  ConnectStatusHelper(MockRead("HTTP/1.1 501 Not Implemented\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus502) {
  ConnectStatusHelper(MockRead("HTTP/1.1 502 Bad Gateway\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus503) {
  ConnectStatusHelper(MockRead("HTTP/1.1 503 Service Unavailable\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus504) {
  ConnectStatusHelper(MockRead("HTTP/1.1 504 Gateway Timeout\r\n"));
}

TEST_F(HttpNetworkTransactionTest, ConnectStatus505) {
  ConnectStatusHelper(MockRead("HTTP/1.1 505 HTTP Version Not Supported\r\n"));
}

// Test the flow when both the proxy server AND origin server require
// authentication. Again, this uses basic auth for both since that is
// the simplest to mock.
TEST_F(HttpNetworkTransactionTest, BasicAuthProxyThenServer) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite(
          "GET http://www.example.org/ HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.0 407 Unauthorized\r\n"),
    // Give a couple authenticate options (only the middle one is actually
    // supported).
    MockRead("Proxy-Authenticate: Basic invalid\r\n"),  // Malformed.
    MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Proxy-Authenticate: UNSUPPORTED realm=\"FOO\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    // Large content-length -- won't matter, as connection will be reset.
    MockRead("Content-Length: 10000\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After calling trans.RestartWithAuth() the first time, this is the
  // request we should be issuing -- the final header line contains the
  // proxy's credentials.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET http://www.example.org/ HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Now the proxy server lets the request pass through to origin server.
  // The origin server responds with a 401.
  MockRead data_reads2[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    // Note: We are using the same realm-name as the proxy server. This is
    // completely valid, as realms are unique across hosts.
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 2000\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),  // Won't be reached.
  };

  // After calling trans.RestartWithAuth() the second time, we should send
  // the credentials for both the proxy and origin server.
  MockWrite data_writes3[] = {
      MockWrite(
          "GET http://www.example.org/ HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n"
          "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
  };

  // Lastly we get the desired content.
  MockRead data_reads3[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                 data_writes3, arraysize(data_writes3));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicProxyAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback3;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo2, kBar2),
                             callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// For the NTLM implementation using SSPI, we skip the NTLM tests since we
// can't hook into its internals to cause it to generate predictable NTLM
// authorization headers.
#if defined(NTLM_PORTABLE)
// The NTLM authentication unit tests were generated by capturing the HTTP
// requests and responses using Fiddler 2 and inspecting the generated random
// bytes in the debugger.

// Enter the correct password and authenticate successfully.
TEST_F(HttpNetworkTransactionTest, NTLMAuth1) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://172.22.68.17/kids/login.aspx");

  // Ensure load is not disrupted by flags which suppress behaviour specific
  // to other auth schemes.
  request.load_flags = LOAD_DO_NOT_USE_EMBEDDED_IDENTITY;

  HttpAuthHandlerNTLM::ScopedProcSetter proc_setter(MockGenerateRandom1,
                                                    MockGetHostName);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
    MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
              "Host: 172.22.68.17\r\n"
              "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Access Denied\r\n"),
    // Negotiate and NTLM are often requested together.  However, we only want
    // to test NTLM. Since Negotiate is preferred over NTLM, we have to skip
    // the header that requests Negotiate for this test.
    MockRead("WWW-Authenticate: NTLM\r\n"),
    MockRead("Connection: close\r\n"),
    MockRead("Content-Length: 42\r\n"),
    MockRead("Content-Type: text/html\r\n\r\n"),
    // Missing content -- won't matter, as connection will be reset.
    MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  MockWrite data_writes2[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: 172.22.68.17\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "
                "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: 172.22.68.17\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGgAAAAYABgAgA"
                "AAAAAAAABAAAAAGAAYAEAAAAAQABAAWAAAAAAAAAAAAAAABYIIAHQA"
                "ZQBzAHQAaQBuAGcALQBuAHQAbABtAFcAVABDAC0AVwBJAE4ANwBVKW"
                "Yma5xzVAAAAAAAAAAAAAAAAAAAAACH+gWcm+YsP9Tqb9zCR3WAeZZX"
                "ahlhx5I=\r\n\r\n"),
  };

  MockRead data_reads2[] = {
    // The origin server responds with a Type 2 message.
    MockRead("HTTP/1.1 401 Access Denied\r\n"),
    MockRead("WWW-Authenticate: NTLM "
             "TlRMTVNTUAACAAAADAAMADgAAAAFgokCjGpMpPGlYKkAAAAAAAAAALo"
             "AugBEAAAABQEoCgAAAA9HAE8ATwBHAEwARQACAAwARwBPAE8ARwBMAE"
             "UAAQAaAEEASwBFAEUAUwBBAFIAQQAtAEMATwBSAFAABAAeAGMAbwByA"
             "HAALgBnAG8AbwBnAGwAZQAuAGMAbwBtAAMAQABhAGsAZQBlAHMAYQBy"
             "AGEALQBjAG8AcgBwAC4AYQBkAC4AYwBvAHIAcAAuAGcAbwBvAGcAbAB"
             "lAC4AYwBvAG0ABQAeAGMAbwByAHAALgBnAG8AbwBnAGwAZQAuAGMAbw"
             "BtAAAAAAA=\r\n"),
    MockRead("Content-Length: 42\r\n"),
    MockRead("Content-Type: text/html\r\n\r\n"),
    MockRead("You are not authorized to view this page\r\n"),

    // Lastly we get the desired content.
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=utf-8\r\n"),
    MockRead("Content-Length: 13\r\n\r\n"),
    MockRead("Please Login\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kTestingNTLM, kTestingNTLM),
                             callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);

  TestCompletionCallback callback3;

  rv = trans.RestartWithAuth(AuthCredentials(), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(13, response->headers->GetContentLength());
}

// Enter a wrong password, and then the correct one.
TEST_F(HttpNetworkTransactionTest, NTLMAuth2) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://172.22.68.17/kids/login.aspx");

  HttpAuthHandlerNTLM::ScopedProcSetter proc_setter(MockGenerateRandom2,
                                                    MockGetHostName);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes1[] = {
    MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
              "Host: 172.22.68.17\r\n"
              "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Access Denied\r\n"),
    // Negotiate and NTLM are often requested together.  However, we only want
    // to test NTLM. Since Negotiate is preferred over NTLM, we have to skip
    // the header that requests Negotiate for this test.
    MockRead("WWW-Authenticate: NTLM\r\n"),
    MockRead("Connection: close\r\n"),
    MockRead("Content-Length: 42\r\n"),
    MockRead("Content-Type: text/html\r\n\r\n"),
    // Missing content -- won't matter, as connection will be reset.
    MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  MockWrite data_writes2[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: 172.22.68.17\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "
                "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: 172.22.68.17\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGgAAAAYABgAgA"
                "AAAAAAAABAAAAAGAAYAEAAAAAQABAAWAAAAAAAAAAAAAAABYIIAHQA"
                "ZQBzAHQAaQBuAGcALQBuAHQAbABtAFcAVABDAC0AVwBJAE4ANwCWeY"
                "XnSZNwoQAAAAAAAAAAAAAAAAAAAADLa34/phTTKzNTWdub+uyFleOj"
                "4Ww7b7E=\r\n\r\n"),
  };

  MockRead data_reads2[] = {
    // The origin server responds with a Type 2 message.
    MockRead("HTTP/1.1 401 Access Denied\r\n"),
    MockRead("WWW-Authenticate: NTLM "
             "TlRMTVNTUAACAAAADAAMADgAAAAFgokCbVWUZezVGpAAAAAAAAAAALo"
             "AugBEAAAABQEoCgAAAA9HAE8ATwBHAEwARQACAAwARwBPAE8ARwBMAE"
             "UAAQAaAEEASwBFAEUAUwBBAFIAQQAtAEMATwBSAFAABAAeAGMAbwByA"
             "HAALgBnAG8AbwBnAGwAZQAuAGMAbwBtAAMAQABhAGsAZQBlAHMAYQBy"
             "AGEALQBjAG8AcgBwAC4AYQBkAC4AYwBvAHIAcAAuAGcAbwBvAGcAbAB"
             "lAC4AYwBvAG0ABQAeAGMAbwByAHAALgBnAG8AbwBnAGwAZQAuAGMAbw"
             "BtAAAAAAA=\r\n"),
    MockRead("Content-Length: 42\r\n"),
    MockRead("Content-Type: text/html\r\n\r\n"),
    MockRead("You are not authorized to view this page\r\n"),

    // Wrong password.
    MockRead("HTTP/1.1 401 Access Denied\r\n"),
    MockRead("WWW-Authenticate: NTLM\r\n"),
    MockRead("Connection: close\r\n"),
    MockRead("Content-Length: 42\r\n"),
    MockRead("Content-Type: text/html\r\n\r\n"),
    // Missing content -- won't matter, as connection will be reset.
    MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  MockWrite data_writes3[] = {
      // After restarting with a null identity, this is the
      // request we should be issuing -- the final header line contains a Type
      // 1 message.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: 172.22.68.17\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM "
                "TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n"),

      // After calling trans.RestartWithAuth(), we should send a Type 3 message
      // (the credentials for the origin server).  The second request continues
      // on the same connection.
      MockWrite("GET /kids/login.aspx HTTP/1.1\r\n"
                "Host: 172.22.68.17\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: NTLM TlRMTVNTUAADAAAAGAAYAGgAAAAYABgAgA"
                "AAAAAAAABAAAAAGAAYAEAAAAAQABAAWAAAAAAAAAAAAAAABYIIAHQA"
                "ZQBzAHQAaQBuAGcALQBuAHQAbABtAFcAVABDAC0AVwBJAE4ANwBO54"
                "dFMVvTHwAAAAAAAAAAAAAAAAAAAACS7sT6Uzw7L0L//WUqlIaVWpbI"
                "+4MUm7c=\r\n\r\n"),
  };

  MockRead data_reads3[] = {
    // The origin server responds with a Type 2 message.
    MockRead("HTTP/1.1 401 Access Denied\r\n"),
    MockRead("WWW-Authenticate: NTLM "
             "TlRMTVNTUAACAAAADAAMADgAAAAFgokCL24VN8dgOR8AAAAAAAAAALo"
             "AugBEAAAABQEoCgAAAA9HAE8ATwBHAEwARQACAAwARwBPAE8ARwBMAE"
             "UAAQAaAEEASwBFAEUAUwBBAFIAQQAtAEMATwBSAFAABAAeAGMAbwByA"
             "HAALgBnAG8AbwBnAGwAZQAuAGMAbwBtAAMAQABhAGsAZQBlAHMAYQBy"
             "AGEALQBjAG8AcgBwAC4AYQBkAC4AYwBvAHIAcAAuAGcAbwBvAGcAbAB"
             "lAC4AYwBvAG0ABQAeAGMAbwByAHAALgBnAG8AbwBnAGwAZQAuAGMAbw"
             "BtAAAAAAA=\r\n"),
    MockRead("Content-Length: 42\r\n"),
    MockRead("Content-Type: text/html\r\n\r\n"),
    MockRead("You are not authorized to view this page\r\n"),

    // Lastly we get the desired content.
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=utf-8\r\n"),
    MockRead("Content-Length: 13\r\n\r\n"),
    MockRead("Please Login\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                 data_writes3, arraysize(data_writes3));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  // Enter the wrong password.
  rv = trans.RestartWithAuth(AuthCredentials(kTestingNTLM, kWrongPassword),
                             callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckNTLMServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback4;

  // Now enter the right password.
  rv = trans.RestartWithAuth(AuthCredentials(kTestingNTLM, kTestingNTLM),
                             callback4.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback4.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  TestCompletionCallback callback5;

  // One more roundtrip
  rv = trans.RestartWithAuth(AuthCredentials(), callback5.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback5.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(13, response->headers->GetContentLength());
}
#endif  // NTLM_PORTABLE

// Test reading a server response which has only headers, and no body.
// After some maximum number of bytes is consumed, the transaction should
// fail with ERR_RESPONSE_HEADERS_TOO_BIG.
TEST_F(HttpNetworkTransactionTest, LargeHeadersNoBody) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Respond with 300 kb of headers (we should fail after 256 kb).
  std::string large_headers_string;
  FillLargeHeadersString(&large_headers_string, 300 * 1024);

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead(ASYNC, large_headers_string.data(), large_headers_string.size()),
    MockRead("\r\nBODY"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_RESPONSE_HEADERS_TOO_BIG));
}

// Make sure that we don't try to reuse a TCPClientSocket when failing to
// establish tunnel.
// http://code.google.com/p/chromium/issues/detail?id=3772
TEST_F(HttpNetworkTransactionTest, DontRecycleTransportSocketForSSLTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 404, using a persistent
  // connection. Usually a proxy would return 501 (not implemented),
  // or 200 (tunnel established).
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 404 Not Found\r\n"),
      MockRead("Content-Length: 10\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  int rv = trans->Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the TCPClientSocket was not added back to
  // the pool.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
  trans.reset();
  base::RunLoop().RunUntilIdle();
  // Make sure that the socket didn't get recycled after calling the destructor.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Make sure that we recycle a socket after reading all of the response body.
TEST_F(HttpNetworkTransactionTest, RecycleSocket) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    // A part of the response body is received with the response headers.
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel"),
    // The rest of the response body is received in two parts.
    MockRead("lo"),
    MockRead(" world"),
    MockRead("junk"),  // Should not be read!!
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200 OK", status_line);

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Make sure that we recycle a SSL socket after reading all of the response
// body.
TEST_F(HttpNetworkTransactionTest, RecycleSSLSocket) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 11\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInSSLSocketPool(session.get()));
}

// Grab a SSL socket, use it, and put it back into the pool.  Then, reuse it
// from the pool and make sure that we recover okay.
TEST_F(HttpNetworkTransactionTest, RecycleDeadSSLSocket) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"), MockRead(ASYNC, ERR_CONNECTION_CLOSED)};

  SSLSocketDataProvider ssl(ASYNC, OK);
  SSLSocketDataProvider ssl2(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  StaticSocketDataProvider data2(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInSSLSocketPool(session.get()));

  // Now start the second transaction, which should reuse the previous socket.

  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInSSLSocketPool(session.get()));
}

// Grab a socket, use it, and put it back into the pool. Then, make
// low memory notification and ensure the socket pool is flushed.
TEST_F(HttpNetworkTransactionTest, FlushSocketPoolOnLowMemoryNotifications) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
      // A part of the response body is received with the response headers.
      MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhel"),
      // The rest of the response body is received in two parts.
      MockRead("lo"), MockRead(" world"),
      MockRead("junk"),  // Should not be read!!
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 200 OK", status_line);

  // Make memory critical notification and ensure the transaction still has been
  // operating right.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  // Socket should not be flushed as long as it is not idle.
  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));

  // Idle sockets should be flushed now.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Grab an SSL socket, use it, and put it back into the pool. Then, make
// low memory notification and ensure the socket pool is flushed.
TEST_F(HttpNetworkTransactionTest, FlushSSLSocketPoolOnLowMemoryNotifications) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.load_flags = 0;

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead("Content-Length: 11\r\n\r\n"),
      MockRead("hello world"), MockRead(ASYNC, ERR_CONNECTION_CLOSED)};

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  EXPECT_EQ(0, GetIdleSocketCountInSSLSocketPool(session.get()));
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  // Make memory critical notification and ensure the transaction still has been
  // operating right.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, GetIdleSocketCountInSSLSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInSSLSocketPool(session.get()));

  // Make memory notification once again and ensure idle socket is closed.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0, GetIdleSocketCountInSSLSocketPool(session.get()));
}

// Make sure that we recycle a socket after a zero-length response.
// http://crbug.com/9880
TEST_F(HttpNetworkTransactionTest, RecycleSocketAfterZeroContentLength) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(
      "http://www.example.org/csi?v=3&s=web&action=&"
      "tran=undefined&ei=mAXcSeegAo-SMurloeUN&"
      "e=17259,18167,19592,19773,19981,20133,20173,20233&"
      "rt=prt.2642,ol.2649,xjs.2951");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 204 No Content\r\n"
             "Content-Length: 0\r\n"
             "Content-Type: text/html\r\n\r\n"),
    MockRead("junk"),  // Should not be read!!
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Transaction must be created after the MockReads, so it's destroyed before
  // them.
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  std::string status_line = response->headers->GetStatusLine();
  EXPECT_EQ("HTTP/1.1 204 No Content", status_line);

  EXPECT_EQ(0, GetIdleSocketCountInTransportSocketPool(session.get()));

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);

  // Empty the current queue.  This is necessary because idle sockets are
  // added to the connection pool asynchronously with a PostTask.
  base::RunLoop().RunUntilIdle();

  // We now check to make sure the socket was added back to the pool.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_F(HttpNetworkTransactionTest, ResendRequestOnWriteBodyError) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request[2];
  // Transaction 1: a GET request that succeeds.  The socket is recycled
  // after use.
  request[0].method = "GET";
  request[0].url = GURL("http://www.google.com/");
  request[0].load_flags = 0;
  // Transaction 2: a POST request.  Reuses the socket kept alive from
  // transaction 1.  The first attempts fails when writing the POST data.
  // This causes the transaction to retry with a new socket.  The second
  // attempt succeeds.
  request[1].method = "POST";
  request[1].url = GURL("http://www.google.com/login.cgi");
  request[1].upload_data_stream = &upload_data_stream;
  request[1].load_flags = 0;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // The first socket is used for transaction 1 and the first attempt of
  // transaction 2.

  // The response of transaction 1.
  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  // The mock write results of transaction 1 and the first attempt of
  // transaction 2.
  MockWrite data_writes1[] = {
    MockWrite(SYNCHRONOUS, 64),  // GET
    MockWrite(SYNCHRONOUS, 93),  // POST
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_ABORTED),  // POST data
  };
  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));

  // The second socket is used for the second attempt of transaction 2.

  // The response of transaction 2.
  MockRead data_reads2[] = {
    MockRead("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n"),
    MockRead("welcome"),
    MockRead(SYNCHRONOUS, OK),
  };
  // The mock write results of the second attempt of transaction 2.
  MockWrite data_writes2[] = {
    MockWrite(SYNCHRONOUS, 93),  // POST
    MockWrite(SYNCHRONOUS, 3),  // POST data
  };
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));

  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  const char* const kExpectedResponseData[] = {
    "hello world", "welcome"
  };

  for (int i = 0; i < 2; ++i) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    TestCompletionCallback callback;

    int rv = trans.Start(&request[i], callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    std::string response_data;
    rv = ReadTransaction(&trans, &response_data);
    EXPECT_THAT(rv, IsOk());
    EXPECT_EQ(kExpectedResponseData[i], response_data);
  }
}

// Test the request-challenge-retry sequence for basic auth when there is
// an identity in the URL. The request should be sent as normal, but when
// it fails the identity from the URL is used to answer the challenge.
TEST_F(HttpNetworkTransactionTest, AuthIdentityInURL) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://foo:b@r@www.example.org/");
  request.load_flags = LOAD_NORMAL;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // The password contains an escaped character -- for this test to pass it
  // will need to be unescaped by HttpNetworkTransaction.
  EXPECT_EQ("b%40r", request.url.password());

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Length: 10\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity from the url (foo, b@r) to answer the challenge.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJAcg==\r\n\r\n"),
  };

  MockRead data_reads2[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(trans.IsReadyToRestartForAuth());

  TestCompletionCallback callback2;
  rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // There is no challenge info, since the identity in URL worked.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_EQ(100, response->headers->GetContentLength());

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
}

// Test the request-challenge-retry sequence for basic auth when there is an
// incorrect identity in the URL. The identity from the URL should be used only
// once.
TEST_F(HttpNetworkTransactionTest, WrongAuthIdentityInURL) {
  HttpRequestInfo request;
  request.method = "GET";
  // Note: the URL has a username:password in it.  The password "baz" is
  // wrong (should be "bar").
  request.url = GURL("http://foo:baz@www.example.org/");

  request.load_flags = LOAD_NORMAL;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Length: 10\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity from the url (foo, baz) to answer the challenge.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJheg==\r\n\r\n"),
  };

  MockRead data_reads2[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Length: 10\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity supplied by the user (foo, bar) to answer the challenge.
  MockWrite data_writes3[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads3[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                 data_writes3, arraysize(data_writes3));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(trans.IsReadyToRestartForAuth());
  TestCompletionCallback callback2;
  rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // There is no challenge info, since the identity worked.
  EXPECT_FALSE(response->auth_challenge);

  EXPECT_EQ(100, response->headers->GetContentLength());

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
}


// Test the request-challenge-retry sequence for basic auth when there is a
// correct identity in the URL, but its use is being suppressed. The identity
// from the URL should never be used.
TEST_F(HttpNetworkTransactionTest, AuthIdentityInURLSuppressed) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://foo:bar@www.example.org/");
  request.load_flags = LOAD_DO_NOT_USE_EMBEDDED_IDENTITY;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.0 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Length: 10\r\n\r\n"),
    MockRead(SYNCHRONOUS, ERR_FAILED),
  };

  // After the challenge above, the transaction will be restarted using the
  // identity supplied by the user, not the one in the URL, to answer the
  // challenge.
  MockWrite data_writes3[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  MockRead data_reads3[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                 data_writes3, arraysize(data_writes3));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  TestCompletionCallback callback1;
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(trans.IsReadyToRestartForAuth());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  // There is no challenge info, since the identity worked.
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(100, response->headers->GetContentLength());

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
}

// Test that previously tried username/passwords for a realm get re-used.
TEST_F(HttpNetworkTransactionTest, BasicAuthCacheAndPreauth) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Transaction 1: authenticate (foo, bar) on MyRealm1
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/y/z");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/y/z HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization (username=foo, password=bar)
    MockWrite data_writes2[] = {
        MockWrite(
            "GET /x/y/z HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                   data_writes2, arraysize(data_writes2));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                               callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 2: authenticate (foo2, bar2) on MyRealm2
  {
    HttpRequestInfo request;
    request.method = "GET";
    // Note that Transaction 1 was at /x/y/z, so this is in the same
    // protection space as MyRealm1.
    request.url = GURL("http://www.example.org/x/y/a/b");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/y/a/b HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            // Send preemptive authorization for MyRealm1
            "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // The server didn't like the preemptive authorization, and
    // challenges us for a different realm (MyRealm2).
    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm2\"\r\n"),
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization for MyRealm2 (username=foo2, password=bar2)
    MockWrite data_writes2[] = {
        MockWrite(
            "GET /x/y/a/b HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Basic Zm9vMjpiYXIy\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                   data_writes2, arraysize(data_writes2));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->auth_challenge);
    EXPECT_FALSE(response->auth_challenge->is_proxy);
    EXPECT_EQ("http://www.example.org",
              response->auth_challenge->challenger.Serialize());
    EXPECT_EQ("MyRealm2", response->auth_challenge->realm);
    EXPECT_EQ(kBasicAuthScheme, response->auth_challenge->scheme);

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo2, kBar2),
                               callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 3: Resend a request in MyRealm's protection space --
  // succeed with preemptive authorization.
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/y/z2");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/y/z2 HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            // The authorization for MyRealm1 gets sent preemptively
            // (since the url is in the same protection space)
            "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever accepts the preemptive authorization
    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);

    EXPECT_FALSE(response->auth_challenge);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 4: request another URL in MyRealm (however the
  // url is not known to belong to the protection space, so no pre-auth).
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/1");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/1 HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization from MyRealm's cache.
    MockWrite data_writes2[] = {
        MockWrite(
            "GET /x/1 HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                   data_writes2, arraysize(data_writes2));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    EXPECT_TRUE(trans.IsReadyToRestartForAuth());
    TestCompletionCallback callback2;
    rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(trans.IsReadyToRestartForAuth());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }

  // ------------------------------------------------------------------------

  // Transaction 5: request a URL in MyRealm, but the server rejects the
  // cached identity. Should invalidate and re-prompt.
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/p/q/t");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /p/q/t HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // Resend with authorization from cache for MyRealm.
    MockWrite data_writes2[] = {
        MockWrite(
            "GET /p/q/t HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };

    // Sever rejects the authorization.
    MockRead data_reads2[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 10000\r\n\r\n"),
      MockRead(SYNCHRONOUS, ERR_FAILED),
    };

    // At this point we should prompt for new credentials for MyRealm.
    // Restart with username=foo3, password=foo4.
    MockWrite data_writes3[] = {
        MockWrite(
            "GET /p/q/t HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Basic Zm9vMzpiYXIz\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads3[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                   data_writes2, arraysize(data_writes2));
    StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                   data_writes3, arraysize(data_writes3));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);
    session_deps_.socket_factory->AddSocketDataProvider(&data3);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    EXPECT_TRUE(trans.IsReadyToRestartForAuth());
    TestCompletionCallback callback2;
    rv = trans.RestartWithAuth(AuthCredentials(), callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());
    EXPECT_FALSE(trans.IsReadyToRestartForAuth());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

    TestCompletionCallback callback3;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo3, kBar3),
                               callback3.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback3.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }
}

// Tests that nonce count increments when multiple auth attempts
// are started with the same nonce.
TEST_F(HttpNetworkTransactionTest, DigestPreAuthNonceCount) {
  HttpAuthHandlerDigest::Factory* digest_factory =
      new HttpAuthHandlerDigest::Factory();
  HttpAuthHandlerDigest::FixedNonceGenerator* nonce_generator =
      new HttpAuthHandlerDigest::FixedNonceGenerator("0123456789abcdef");
  digest_factory->set_nonce_generator(nonce_generator);
  session_deps_.http_auth_handler_factory.reset(digest_factory);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Transaction 1: authenticate (foo, bar) on MyRealm1
  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/x/y/z");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/y/z HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n\r\n"),
    };

    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 401 Unauthorized\r\n"),
      MockRead("WWW-Authenticate: Digest realm=\"digestive\", nonce=\"OU812\", "
               "algorithm=MD5, qop=\"auth\"\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    // Resend with authorization (username=foo, password=bar)
    MockWrite data_writes2[] = {
        MockWrite(
            "GET /x/y/z HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Digest username=\"foo\", realm=\"digestive\", "
            "nonce=\"OU812\", uri=\"/x/y/z\", algorithm=MD5, "
            "response=\"03ffbcd30add722589c1de345d7a927f\", qop=auth, "
            "nc=00000001, cnonce=\"0123456789abcdef\"\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads2[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                   data_writes2, arraysize(data_writes2));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);
    session_deps_.socket_factory->AddSocketDataProvider(&data2);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(CheckDigestServerAuth(response->auth_challenge.get()));

    TestCompletionCallback callback2;

    rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar),
                               callback2.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback2.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
  }

  // ------------------------------------------------------------------------

  // Transaction 2: Request another resource in digestive's protection space.
  // This will preemptively add an Authorization header which should have an
  // "nc" value of 2 (as compared to 1 in the first use.
  {
    HttpRequestInfo request;
    request.method = "GET";
    // Note that Transaction 1 was at /x/y/z, so this is in the same
    // protection space as digest.
    request.url = GURL("http://www.example.org/x/y/a/b");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    MockWrite data_writes1[] = {
        MockWrite(
            "GET /x/y/a/b HTTP/1.1\r\n"
            "Host: www.example.org\r\n"
            "Connection: keep-alive\r\n"
            "Authorization: Digest username=\"foo\", realm=\"digestive\", "
            "nonce=\"OU812\", uri=\"/x/y/a/b\", algorithm=MD5, "
            "response=\"d6f9a2c07d1c5df7b89379dca1269b35\", qop=auth, "
            "nc=00000002, cnonce=\"0123456789abcdef\"\r\n\r\n"),
    };

    // Sever accepts the authorization.
    MockRead data_reads1[] = {
      MockRead("HTTP/1.0 200 OK\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
    };

    StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                   data_writes1, arraysize(data_writes1));
    session_deps_.socket_factory->AddSocketDataProvider(&data1);

    TestCompletionCallback callback1;

    int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback1.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_FALSE(response->auth_challenge);
  }
}

// Test the ResetStateForRestart() private method.
TEST_F(HttpNetworkTransactionTest, ResetStateForRestart) {
  // Create a transaction (the dependencies aren't important).
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Setup some state (which we expect ResetStateForRestart() will clear).
  trans.read_buf_ = new IOBuffer(15);
  trans.read_buf_len_ = 15;
  trans.request_headers_.SetHeader("Authorization", "NTLM");

  // Setup state in response_
  HttpResponseInfo* response = &trans.response_;
  response->auth_challenge = new AuthChallengeInfo();
  response->ssl_info.cert_status = static_cast<CertStatus>(-1);  // Nonsensical.
  response->response_time = base::Time::Now();
  response->was_cached = true;  // (Wouldn't ever actually be true...)

  { // Setup state for response_.vary_data
    HttpRequestInfo request;
    std::string temp("HTTP/1.1 200 OK\nVary: foo, bar\n\n");
    std::replace(temp.begin(), temp.end(), '\n', '\0');
    scoped_refptr<HttpResponseHeaders> headers(new HttpResponseHeaders(temp));
    request.extra_headers.SetHeader("Foo", "1");
    request.extra_headers.SetHeader("bar", "23");
    EXPECT_TRUE(response->vary_data.Init(request, *headers.get()));
  }

  // Cause the above state to be reset.
  trans.ResetStateForRestart();

  // Verify that the state that needed to be reset, has been reset.
  EXPECT_FALSE(trans.read_buf_);
  EXPECT_EQ(0, trans.read_buf_len_);
  EXPECT_TRUE(trans.request_headers_.IsEmpty());
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_FALSE(response->headers);
  EXPECT_FALSE(response->was_cached);
  EXPECT_EQ(0U, response->ssl_info.cert_status);
  EXPECT_FALSE(response->vary_data.is_valid());
}

// Test HTTPS connections to a site with a bad certificate
TEST_F(HttpNetworkTransactionTest, HTTPSBadCertificate) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider ssl_bad_certificate;
  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  SSLSocketDataProvider ssl_bad(ASYNC, ERR_CERT_AUTHORITY_INVALID);
  SSLSocketDataProvider ssl(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(&ssl_bad_certificate);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bad);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CERT_AUTHORITY_INVALID));

  rv = trans.RestartIgnoringLastError(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// Test HTTPS connections to a site with a bad certificate, going through a
// proxy
TEST_F(HttpNetworkTransactionTest, HTTPSBadCertificateViaProxy) {
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite proxy_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead proxy_reads[] = {
    MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK)
  };

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider ssl_bad_certificate(
      proxy_reads, arraysize(proxy_reads),
      proxy_writes, arraysize(proxy_writes));
  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  SSLSocketDataProvider ssl_bad(ASYNC, ERR_CERT_AUTHORITY_INVALID);
  SSLSocketDataProvider ssl(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(&ssl_bad_certificate);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bad);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  for (int i = 0; i < 2; i++) {
    session_deps_.socket_factory->ResetNextMockIndexes();

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsError(ERR_CERT_AUTHORITY_INVALID));

    rv = trans.RestartIgnoringLastError(callback.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());

    const HttpResponseInfo* response = trans.GetResponseInfo();

    ASSERT_TRUE(response);
    EXPECT_EQ(100, response->headers->GetContentLength());
  }
}


// Test HTTPS connections to a site, going through an HTTPS proxy
TEST_F(HttpNetworkTransactionTest, HTTPSViaHttpsProxy) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS proxy:70");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy
  SSLSocketDataProvider tunnel_ssl(ASYNC, OK);  // SSL through the tunnel

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&tunnel_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);

  EXPECT_TRUE(response->proxy_server.is_https());
  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test an HTTPS Proxy's ability to redirect a CONNECT request
TEST_F(HttpNetworkTransactionTest, RedirectOfHttpsConnectViaHttpsProxy) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS proxy:70");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 302 Redirect\r\n"),
    MockRead("Location: http://login.example.com/\r\n"),
    MockRead("Content-Length: 0\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);

  EXPECT_EQ(302, response->headers->response_code());
  std::string url;
  EXPECT_TRUE(response->headers->IsRedirect(&url));
  EXPECT_EQ("http://login.example.com/", url);

  // In the case of redirects from proxies, HttpNetworkTransaction returns
  // timing for the proxy connection instead of the connection to the host,
  // and no send / receive times.
  // See HttpNetworkTransaction::OnHttpsProxyTunnelResponse.
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));

  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end,
            load_timing_info.connect_timing.connect_start);
  ExpectConnectTimingHasTimes(
      load_timing_info.connect_timing,
      CONNECT_TIMING_HAS_DNS_TIMES | CONNECT_TIMING_HAS_SSL_TIMES);

  EXPECT_TRUE(load_timing_info.send_start.is_null());
  EXPECT_TRUE(load_timing_info.send_end.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Test an HTTPS (SPDY) Proxy's ability to redirect a CONNECT request
TEST_F(HttpNetworkTransactionTest, RedirectOfHttpsConnectViaSpdyProxy) {
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  SpdySerializedFrame conn(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  SpdySerializedFrame goaway(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));
  MockWrite data_writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
      CreateMockWrite(goaway, 2, SYNCHRONOUS),
  };

  static const char* const kExtraHeaders[] = {
    "location",
    "http://login.example.com/",
  };
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(
      "302", kExtraHeaders, arraysize(kExtraHeaders) / 2, 1));
  MockRead data_reads[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3),  // EOF
  };

  SequencedSocketData data(data_reads, arraysize(data_reads), data_writes,
                           arraysize(data_writes));
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy
  proxy_ssl.next_proto = kProtoHTTP2;

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);

  EXPECT_EQ(302, response->headers->response_code());
  std::string url;
  EXPECT_TRUE(response->headers->IsRedirect(&url));
  EXPECT_EQ("http://login.example.com/", url);
}

// Test that an HTTPS proxy's response to a CONNECT request is filtered.
TEST_F(HttpNetworkTransactionTest, ErrorResponseToHttpsConnectViaHttpsProxy) {
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 404 Not Found\r\n"),
    MockRead("Content-Length: 23\r\n\r\n"),
    MockRead("The host does not exist"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // TODO(juliatuttle): Anything else to check here?
}

// Test that a SPDY proxy's response to a CONNECT request is filtered.
TEST_F(HttpNetworkTransactionTest, ErrorResponseToHttpsConnectViaSpdyProxy) {
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  SpdySerializedFrame conn(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));
  MockWrite data_writes[] = {
      CreateMockWrite(conn, 0), CreateMockWrite(rst, 3),
  };

  static const char* const kExtraHeaders[] = {
    "location",
    "http://login.example.com/",
  };
  SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(
      "404", kExtraHeaders, arraysize(kExtraHeaders) / 2, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(
      1, "The host does not exist", 23, true));
  MockRead data_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 4),  // EOF
  };

  SequencedSocketData data(data_reads, arraysize(data_reads), data_writes,
                           arraysize(data_writes));
  SSLSocketDataProvider proxy_ssl(ASYNC, OK);  // SSL to the proxy
  proxy_ssl.next_proto = kProtoHTTP2;

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy_ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));

  // TODO(juliatuttle): Anything else to check here?
}

// Test the request-challenge-retry sequence for basic auth, through
// a SPDY proxy over a single SPDY session.
TEST_F(HttpNetworkTransactionTest, BasicAuthSpdyProxy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  // when the no authentication data flag is set.
  request.load_flags = LOAD_DO_NOT_SEND_AUTH_DATA;

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      NULL, 0, 1, LOWEST, HostPortPair("www.example.org", 443)));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, ERROR_CODE_CANCEL));
  spdy_util_.UpdateWithStreamDestruction(1);

  // After calling trans.RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  const char* const kAuthCredentials[] = {
      "proxy-authorization", "Basic Zm9vOmJhcg==",
  };
  SpdySerializedFrame connect2(spdy_util_.ConstructSpdyConnect(
      kAuthCredentials, arraysize(kAuthCredentials) / 2, 3, LOWEST,
      HostPortPair("www.example.org", 443)));
  // fetch https://www.example.org/ via HTTP
  const char get[] =
      "GET / HTTP/1.1\r\n"
      "Host: www.example.org\r\n"
      "Connection: keep-alive\r\n\r\n";
  SpdySerializedFrame wrapped_get(
      spdy_util_.ConstructSpdyDataFrame(3, get, strlen(get), false));

  MockWrite spdy_writes[] = {
      CreateMockWrite(req, 0, ASYNC), CreateMockWrite(rst, 2, ASYNC),
      CreateMockWrite(connect2, 3), CreateMockWrite(wrapped_get, 5),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  const char kAuthStatus[] = "407";
  const char* const kAuthChallenge[] = {
    "proxy-authenticate", "Basic realm=\"MyRealm1\"",
  };
  SpdySerializedFrame conn_auth_resp(spdy_util_.ConstructSpdyReplyError(
      kAuthStatus, kAuthChallenge, arraysize(kAuthChallenge) / 2, 1));

  SpdySerializedFrame conn_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  const char resp[] = "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n\r\n";

  SpdySerializedFrame wrapped_get_resp(
      spdy_util_.ConstructSpdyDataFrame(3, resp, strlen(resp), false));
  SpdySerializedFrame wrapped_body(
      spdy_util_.ConstructSpdyDataFrame(3, "hello", 5, false));
  MockRead spdy_reads[] = {
      CreateMockRead(conn_auth_resp, 1, ASYNC),
      CreateMockRead(conn_resp, 4, ASYNC),
      CreateMockRead(wrapped_get_resp, 6, ASYNC),
      CreateMockRead(wrapped_body, 7, ASYNC),
      MockRead(ASYNC, OK, 8),  // EOF.  May or may not be read.
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);
  // Negotiate SPDY to the proxy
  SSLSocketDataProvider proxy(ASYNC, OK);
  proxy.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy);
  // Vanilla SSL to the server
  SSLSocketDataProvider server(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&server);

  TestCompletionCallback callback1;

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->auth_challenge);
  EXPECT_TRUE(CheckBasicSecureProxyAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans->RestartWithAuth(AuthCredentials(kFoo, kBar),
                              callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(5, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The password prompt info should not be set.
  EXPECT_FALSE(response->auth_challenge);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans.reset();
  session->CloseAllConnections();
}

// Test that an explicitly trusted SPDY proxy can push a resource from an
// origin that is different from that of its associated resource.
TEST_F(HttpNetworkTransactionTest, CrossOriginSPDYProxyPush) {
  // Configure the proxy delegate to allow cross-origin SPDY pushes.
  auto proxy_delegate = base::MakeUnique<TestProxyDelegate>();
  proxy_delegate->set_trusted_spdy_proxy(net::ProxyServer::FromURI(
      "https://myproxy:443", net::ProxyServer::SCHEME_HTTP));
  HttpRequestInfo request;
  HttpRequestInfo push_request;

  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  push_request.method = "GET";
  push_request.url = GURL("http://www.another-origin.com/foo.dat");

  // Configure against https proxy server "myproxy:443".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS myproxy:443");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();

  session_deps_.proxy_delegate = std::move(proxy_delegate);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));
  SpdySerializedFrame stream2_priority(
      spdy_util_.ConstructSpdyPriority(2, 1, IDLE, true));

  MockWrite spdy_writes[] = {
      CreateMockWrite(stream1_syn, 0, ASYNC),
      CreateMockWrite(stream2_priority, 3, ASYNC),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));

  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, "http://www.another-origin.com/foo.dat"));
  const char kPushedData[] = "pushed";
  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(
      2, kPushedData, strlen(kPushedData), true));

  MockRead spdy_reads[] = {
      CreateMockRead(stream1_reply, 1, ASYNC),
      CreateMockRead(stream2_syn, 2, ASYNC),
      CreateMockRead(stream1_body, 4, ASYNC),
      CreateMockRead(stream2_body, 5, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),  // Force a hang
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);
  // Negotiate SPDY to the proxy
  SSLSocketDataProvider proxy(ASYNC, OK);
  proxy.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans->GetResponseInfo();

  auto push_trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  rv = push_trans->Start(&push_request, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* push_response = push_trans->GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers->IsKeepAlive());

  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  std::string response_data;
  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  // Verify the pushed stream.
  EXPECT_TRUE(push_response->headers);
  EXPECT_EQ(200, push_response->headers->response_code());

  rv = ReadTransaction(push_trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("pushed", response_data);

  LoadTimingInfo push_load_timing_info;
  EXPECT_TRUE(push_trans->GetLoadTimingInfo(&push_load_timing_info));
  TestLoadTimingReusedWithPac(push_load_timing_info);
  // The transactions should share a socket ID, despite being for different
  // origins.
  EXPECT_EQ(load_timing_info.socket_log_id,
            push_load_timing_info.socket_log_id);

  trans.reset();
  push_trans.reset();
  session->CloseAllConnections();
}

// Test that an explicitly trusted SPDY proxy cannot push HTTPS content.
TEST_F(HttpNetworkTransactionTest, CrossOriginProxyPushCorrectness) {
  // Configure the proxy delegate to allow cross-origin SPDY pushes.
  auto proxy_delegate = base::MakeUnique<TestProxyDelegate>();
  proxy_delegate->set_trusted_spdy_proxy(net::ProxyServer::FromURI(
      "https://myproxy:443", net::ProxyServer::SCHEME_HTTP));
  HttpRequestInfo request;

  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixed("https://myproxy:443");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();

  // Enable cross-origin push.
  session_deps_.proxy_delegate = std::move(proxy_delegate);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));

  SpdySerializedFrame push_rst(
      spdy_util_.ConstructSpdyRstStream(2, ERROR_CODE_REFUSED_STREAM));

  MockWrite spdy_writes[] = {
      CreateMockWrite(stream1_syn, 0, ASYNC), CreateMockWrite(push_rst, 3),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));

  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      NULL, 0, 2, 1, "https://www.another-origin.com/foo.dat"));

  MockRead spdy_reads[] = {
      CreateMockRead(stream1_reply, 1, ASYNC),
      CreateMockRead(stream2_syn, 2, ASYNC),
      CreateMockRead(stream1_body, 4, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),  // Force a hang
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);
  // Negotiate SPDY to the proxy
  SSLSocketDataProvider proxy(ASYNC, OK);
  proxy.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans->GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers->IsKeepAlive());

  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  std::string response_data;
  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  trans.reset();
  session->CloseAllConnections();
}

// Test that an explicitly trusted SPDY proxy can push same-origin HTTPS
// resources.
TEST_F(HttpNetworkTransactionTest, SameOriginProxyPushCorrectness) {
  // Configure the proxy delegate to allow cross-origin SPDY pushes.
  auto proxy_delegate = base::MakeUnique<TestProxyDelegate>();
  proxy_delegate->set_trusted_spdy_proxy(
      net::ProxyServer::FromURI("myproxy:70", net::ProxyServer::SCHEME_HTTP));

  HttpRequestInfo request;

  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // Configure against https proxy server "myproxy:70".
  session_deps_.proxy_service = ProxyService::CreateFixed("https://myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();

  // Enable cross-origin push.
  session_deps_.proxy_delegate = std::move(proxy_delegate);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SpdySerializedFrame stream1_syn(
      spdy_util_.ConstructSpdyGet("http://www.example.org/", 1, LOWEST));
  SpdySerializedFrame stream2_priority(
      spdy_util_.ConstructSpdyPriority(2, 1, IDLE, true));

  MockWrite spdy_writes[] = {
      CreateMockWrite(stream1_syn, 0, ASYNC),
      CreateMockWrite(stream2_priority, 3, ASYNC),
  };

  SpdySerializedFrame stream1_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  SpdySerializedFrame stream2_syn(spdy_util_.ConstructSpdyPush(
      nullptr, 0, 2, 1, "https://myproxy:70/foo.dat"));

  SpdySerializedFrame stream1_body(spdy_util_.ConstructSpdyDataFrame(1, true));

  SpdySerializedFrame stream2_reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));

  SpdySerializedFrame stream2_body(spdy_util_.ConstructSpdyDataFrame(1, true));

  MockRead spdy_reads[] = {
      CreateMockRead(stream1_reply, 1, ASYNC),
      CreateMockRead(stream2_syn, 2, ASYNC),
      CreateMockRead(stream1_body, 4, ASYNC),
      CreateMockRead(stream2_body, 5, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),  // Force a hang
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);
  // Negotiate SPDY to the proxy
  SSLSocketDataProvider proxy(ASYNC, OK);
  proxy.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&proxy);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans->GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers->IsKeepAlive());

  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  std::string response_data;
  rv = ReadTransaction(trans.get(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  trans.reset();
  session->CloseAllConnections();
}

// Test HTTPS connections to a site with a bad certificate, going through an
// HTTPS proxy
TEST_F(HttpNetworkTransactionTest, HTTPSBadCertificateViaHttpsProxy) {
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Attempt to fetch the URL from a server with a bad cert
  MockWrite bad_cert_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead bad_cert_reads[] = {
    MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK)
  };

  // Attempt to fetch the URL with a good cert
  MockWrite good_data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead good_cert_reads[] = {
    MockRead("HTTP/1.0 200 Connected\r\n\r\n"),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider ssl_bad_certificate(
      bad_cert_reads, arraysize(bad_cert_reads),
      bad_cert_writes, arraysize(bad_cert_writes));
  StaticSocketDataProvider data(good_cert_reads, arraysize(good_cert_reads),
                                good_data_writes, arraysize(good_data_writes));
  SSLSocketDataProvider ssl_bad(ASYNC, ERR_CERT_AUTHORITY_INVALID);
  SSLSocketDataProvider ssl(ASYNC, OK);

  // SSL to the proxy, then CONNECT request, then SSL with bad certificate
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_bad_certificate);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_bad);

  // SSL to the proxy, then CONNECT request, then valid SSL certificate
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CERT_AUTHORITY_INVALID));

  rv = trans.RestartIgnoringLastError(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();

  ASSERT_TRUE(response);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_UserAgent) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent,
                                  "Chromium Ultra Awesome X Edition");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "User-Agent: Chromium Ultra Awesome X Edition\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_UserAgentOverTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent,
                                  "Chromium Ultra Awesome X Edition");

  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: Chromium Ultra Awesome X Edition\r\n\r\n"),
  };
  MockRead data_reads[] = {
    // Return an error, so the transaction stops here (this test isn't
    // interested in the rest).
    MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
    MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_Referer) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kReferer,
                                  "http://the.previous.site.com/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Referer: http://the.previous.site.com/\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_PostContentLengthZero) {
  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "POST / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Content-Length: 0\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_PutContentLengthZero) {
  HttpRequestInfo request;
  request.method = "PUT";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "PUT / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Content-Length: 0\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_HeadContentLengthZero) {
  HttpRequestInfo request;
  request.method = "HEAD";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("HEAD / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_CacheControlNoCache) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = LOAD_BYPASS_CACHE;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Pragma: no-cache\r\n"
          "Cache-Control: no-cache\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_CacheControlValidateCache) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = LOAD_VALIDATE_CACHE;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Cache-Control: max-age=0\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_ExtraHeaders) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader("FooHeader", "Bar");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "FooHeader: Bar\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, BuildRequest_ExtraHeadersStripped) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader("referer", "www.foo.com");
  request.extra_headers.SetHeader("hEllo", "Kitty");
  request.extra_headers.SetHeader("FoO", "bar");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "referer: www.foo.com\r\n"
          "hEllo: Kitty\r\n"
          "FoO: bar\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(HttpNetworkTransactionTest, SOCKS4_HTTP_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("SOCKS myproxy:1080");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  char write_buffer[] = { 0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0 };
  char read_buffer[] = { 0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0 };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, write_buffer, arraysize(write_buffer)),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
    MockRead(ASYNC, read_buffer, arraysize(read_buffer)),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
    MockRead("Payload"),
    MockRead(SYNCHRONOUS, OK)
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_EQ(ProxyServer::SCHEME_SOCKS4, response->proxy_server.scheme());
  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_F(HttpNetworkTransactionTest, SOCKS4_SSL_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("SOCKS myproxy:1080");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  unsigned char write_buffer[] = { 0x04, 0x01, 0x01, 0xBB, 127, 0, 0, 1, 0 };
  unsigned char read_buffer[] = { 0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0 };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, reinterpret_cast<char*>(write_buffer),
                arraysize(write_buffer)),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
    MockRead(ASYNC, reinterpret_cast<char*>(read_buffer),
             arraysize(read_buffer)),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
    MockRead("Payload"),
    MockRead(SYNCHRONOUS, OK)
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS4, response->proxy_server.scheme());

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_F(HttpNetworkTransactionTest, SOCKS4_HTTP_GET_no_PAC) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixed("socks4://myproxy:1080");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  char write_buffer[] = { 0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 0 };
  char read_buffer[] = { 0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0 };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, write_buffer, arraysize(write_buffer)),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
    MockRead(ASYNC, read_buffer, arraysize(read_buffer)),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
    MockRead("Payload"),
    MockRead(SYNCHRONOUS, OK)
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReused(load_timing_info,
                          CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_F(HttpNetworkTransactionTest, SOCKS5_HTTP_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("SOCKS5 myproxy:1080");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  const char kSOCKS5GreetRequest[] = { 0x05, 0x01, 0x00 };
  const char kSOCKS5GreetResponse[] = { 0x05, 0x00 };
  const char kSOCKS5OkRequest[] = {
      0x05,  // Version
      0x01,  // Command (CONNECT)
      0x00,  // Reserved.
      0x03,  // Address type (DOMAINNAME).
      0x0F,  // Length of domain (15)
      'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',  // Domain string
      '.', 'o', 'r', 'g', 0x00, 0x50,  // 16-bit port (80)
  };
  const char kSOCKS5OkResponse[] =
      { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, kSOCKS5GreetRequest, arraysize(kSOCKS5GreetRequest)),
      MockWrite(ASYNC, kSOCKS5OkRequest, arraysize(kSOCKS5OkRequest)),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
    MockRead(ASYNC, kSOCKS5GreetResponse, arraysize(kSOCKS5GreetResponse)),
    MockRead(ASYNC, kSOCKS5OkResponse, arraysize(kSOCKS5OkResponse)),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
    MockRead("Payload"),
    MockRead(SYNCHRONOUS, OK)
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS5, response->proxy_server.scheme());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

TEST_F(HttpNetworkTransactionTest, SOCKS5_SSL_GET) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("SOCKS5 myproxy:1080");
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  const char kSOCKS5GreetRequest[] = { 0x05, 0x01, 0x00 };
  const char kSOCKS5GreetResponse[] = { 0x05, 0x00 };
  const unsigned char kSOCKS5OkRequest[] = {
      0x05,  // Version
      0x01,  // Command (CONNECT)
      0x00,  // Reserved.
      0x03,  // Address type (DOMAINNAME).
      0x0F,  // Length of domain (15)
      'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',  // Domain string
      '.', 'o', 'r', 'g', 0x01, 0xBB,  // 16-bit port (443)
  };

  const char kSOCKS5OkResponse[] =
      { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00 };

  MockWrite data_writes[] = {
      MockWrite(ASYNC, kSOCKS5GreetRequest, arraysize(kSOCKS5GreetRequest)),
      MockWrite(ASYNC, reinterpret_cast<const char*>(kSOCKS5OkRequest),
                arraysize(kSOCKS5OkRequest)),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n")};

  MockRead data_reads[] = {
    MockRead(ASYNC, kSOCKS5GreetResponse, arraysize(kSOCKS5GreetResponse)),
    MockRead(ASYNC, kSOCKS5OkResponse, arraysize(kSOCKS5OkResponse)),
    MockRead("HTTP/1.0 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n\r\n"),
    MockRead("Payload"),
    MockRead(SYNCHRONOUS, OK)
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_EQ(ProxyServer::SCHEME_SOCKS5, response->proxy_server.scheme());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  std::string response_text;
  rv = ReadTransaction(&trans, &response_text);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("Payload", response_text);
}

namespace {

// Tests that for connection endpoints the group names are correctly set.

struct GroupNameTest {
  std::string proxy_server;
  std::string url;
  std::string expected_group_name;
  bool ssl;
};

std::unique_ptr<HttpNetworkSession> SetupSessionForGroupNameTests(
    SpdySessionDependencies* session_deps_) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, "", 444);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort("https", "host.with.alternate", 443),
      alternative_service, expiration);

  return session;
}

int GroupNameTransactionHelper(const std::string& url,
                               HttpNetworkSession* session) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL(url);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session);

  TestCompletionCallback callback;

  // We do not complete this request, the dtor will clean the transaction up.
  return trans.Start(&request, callback.callback(), NetLogWithSource());
}

}  // namespace

TEST_F(HttpNetworkTransactionTest, GroupNameForDirectConnections) {
  const GroupNameTest tests[] = {
      {
       "",  // unused
       "http://www.example.org/direct",
       "www.example.org:80",
       false,
      },
      {
       "",  // unused
       "http://[2001:1418:13:1::25]/direct",
       "[2001:1418:13:1::25]:80",
       false,
      },

      // SSL Tests
      {
       "",  // unused
       "https://www.example.org/direct_ssl",
       "ssl/www.example.org:443",
       true,
      },
      {
       "",  // unused
       "https://[2001:1418:13:1::25]/direct",
       "ssl/[2001:1418:13:1::25]:443",
       true,
      },
      {
       "",  // unused
       "https://host.with.alternate/direct",
       "ssl/host.with.alternate:443",
       true,
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    session_deps_.proxy_service =
        ProxyService::CreateFixed(tests[i].proxy_server);
    std::unique_ptr<HttpNetworkSession> session(
        SetupSessionForGroupNameTests(&session_deps_));

    HttpNetworkSessionPeer peer(session.get());
    CaptureGroupNameTransportSocketPool* transport_conn_pool =
        new CaptureGroupNameTransportSocketPool(nullptr, nullptr);
    CaptureGroupNameSSLSocketPool* ssl_conn_pool =
        new CaptureGroupNameSSLSocketPool(nullptr, nullptr);
    auto mock_pool_manager = base::MakeUnique<MockClientSocketPoolManager>();
    mock_pool_manager->SetTransportSocketPool(transport_conn_pool);
    mock_pool_manager->SetSSLSocketPool(ssl_conn_pool);
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    EXPECT_EQ(ERR_IO_PENDING,
              GroupNameTransactionHelper(tests[i].url, session.get()));
    if (tests[i].ssl)
      EXPECT_EQ(tests[i].expected_group_name,
                ssl_conn_pool->last_group_name_received());
    else
      EXPECT_EQ(tests[i].expected_group_name,
                transport_conn_pool->last_group_name_received());
  }
}

TEST_F(HttpNetworkTransactionTest, GroupNameForHTTPProxyConnections) {
  const GroupNameTest tests[] = {
      {
       "http_proxy",
       "http://www.example.org/http_proxy_normal",
       "www.example.org:80",
       false,
      },

      // SSL Tests
      {
       "http_proxy",
       "https://www.example.org/http_connect_ssl",
       "ssl/www.example.org:443",
       true,
      },

      {
       "http_proxy",
       "https://host.with.alternate/direct",
       "ssl/host.with.alternate:443",
       true,
      },

      {
       "http_proxy",
       "ftp://ftp.google.com/http_proxy_normal",
       "ftp/ftp.google.com:21",
       false,
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    session_deps_.proxy_service =
        ProxyService::CreateFixed(tests[i].proxy_server);
    std::unique_ptr<HttpNetworkSession> session(
        SetupSessionForGroupNameTests(&session_deps_));

    HttpNetworkSessionPeer peer(session.get());

    HostPortPair proxy_host("http_proxy", 80);
    CaptureGroupNameHttpProxySocketPool* http_proxy_pool =
        new CaptureGroupNameHttpProxySocketPool(NULL, NULL);
    CaptureGroupNameSSLSocketPool* ssl_conn_pool =
        new CaptureGroupNameSSLSocketPool(NULL, NULL);
    auto mock_pool_manager = base::MakeUnique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPoolForHTTPProxy(
        proxy_host, base::WrapUnique(http_proxy_pool));
    mock_pool_manager->SetSocketPoolForSSLWithProxy(
        proxy_host, base::WrapUnique(ssl_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    EXPECT_EQ(ERR_IO_PENDING,
              GroupNameTransactionHelper(tests[i].url, session.get()));
    if (tests[i].ssl)
      EXPECT_EQ(tests[i].expected_group_name,
                ssl_conn_pool->last_group_name_received());
    else
      EXPECT_EQ(tests[i].expected_group_name,
                http_proxy_pool->last_group_name_received());
  }
}

TEST_F(HttpNetworkTransactionTest, GroupNameForSOCKSConnections) {
  const GroupNameTest tests[] = {
      {
       "socks4://socks_proxy:1080",
       "http://www.example.org/socks4_direct",
       "socks4/www.example.org:80",
       false,
      },
      {
       "socks5://socks_proxy:1080",
       "http://www.example.org/socks5_direct",
       "socks5/www.example.org:80",
       false,
      },

      // SSL Tests
      {
       "socks4://socks_proxy:1080",
       "https://www.example.org/socks4_ssl",
       "socks4/ssl/www.example.org:443",
       true,
      },
      {
       "socks5://socks_proxy:1080",
       "https://www.example.org/socks5_ssl",
       "socks5/ssl/www.example.org:443",
       true,
      },

      {
       "socks4://socks_proxy:1080",
       "https://host.with.alternate/direct",
       "socks4/ssl/host.with.alternate:443",
       true,
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    session_deps_.proxy_service =
        ProxyService::CreateFixed(tests[i].proxy_server);
    std::unique_ptr<HttpNetworkSession> session(
        SetupSessionForGroupNameTests(&session_deps_));

    HttpNetworkSessionPeer peer(session.get());

    HostPortPair proxy_host("socks_proxy", 1080);
    CaptureGroupNameSOCKSSocketPool* socks_conn_pool =
        new CaptureGroupNameSOCKSSocketPool(NULL, NULL);
    CaptureGroupNameSSLSocketPool* ssl_conn_pool =
        new CaptureGroupNameSSLSocketPool(NULL, NULL);
    auto mock_pool_manager = base::MakeUnique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPoolForSOCKSProxy(
        proxy_host, base::WrapUnique(socks_conn_pool));
    mock_pool_manager->SetSocketPoolForSSLWithProxy(
        proxy_host, base::WrapUnique(ssl_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    EXPECT_EQ(ERR_IO_PENDING,
              GroupNameTransactionHelper(tests[i].url, session.get()));
    if (tests[i].ssl)
      EXPECT_EQ(tests[i].expected_group_name,
                ssl_conn_pool->last_group_name_received());
    else
      EXPECT_EQ(tests[i].expected_group_name,
                socks_conn_pool->last_group_name_received());
  }
}

TEST_F(HttpNetworkTransactionTest, ReconsiderProxyAfterFailedConnection) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  session_deps_.proxy_service =
      ProxyService::CreateFixed("myproxy:70;foobar:80");

  // This simulates failure resolving all hostnames; that means we will fail
  // connecting to both proxies (myproxy:70 and foobar:80).
  session_deps_.host_resolver->rules()->AddSimulatedFailure("*");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_PROXY_CONNECTION_FAILED));
}

// Base test to make sure that when the load flags for a request specify to
// bypass the cache, the DNS cache is not used.
void HttpNetworkTransactionTest::BypassHostCacheOnRefreshHelper(
    int load_flags) {
  // Issue a request, asking to bypass the cache(s).
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.load_flags = load_flags;
  request_info.url = GURL("http://www.example.org/");

  // Select a host resolver that does caching.
  session_deps_.host_resolver = base::MakeUnique<MockCachingHostResolver>();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Warm up the host cache so it has an entry for "www.example.org".
  AddressList addrlist;
  TestCompletionCallback callback;
  std::unique_ptr<HostResolver::Request> request1;
  int rv = session_deps_.host_resolver->Resolve(
      HostResolver::RequestInfo(HostPortPair("www.example.org", 80)),
      DEFAULT_PRIORITY, &addrlist, callback.callback(), &request1,
      NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // Verify that it was added to host cache, by doing a subsequent async lookup
  // and confirming it completes synchronously.
  std::unique_ptr<HostResolver::Request> request2;
  rv = session_deps_.host_resolver->Resolve(
      HostResolver::RequestInfo(HostPortPair("www.example.org", 80)),
      DEFAULT_PRIORITY, &addrlist, callback.callback(), &request2,
      NetLogWithSource());
  ASSERT_THAT(rv, IsOk());

  // Inject a failure the next time that "www.example.org" is resolved. This way
  // we can tell if the next lookup hit the cache, or the "network".
  // (cache --> success, "network" --> failure).
  session_deps_.host_resolver->rules()->AddSimulatedFailure("www.example.org");

  // Connect up a mock socket which will fail with ERR_UNEXPECTED during the
  // first read -- this won't be reached as the host resolution will fail first.
  MockRead data_reads[] = { MockRead(SYNCHRONOUS, ERR_UNEXPECTED) };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Run the request.
  rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();

  // If we bypassed the cache, we would have gotten a failure while resolving
  // "www.example.org".
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));
}

// There are multiple load flags that should trigger the host cache bypass.
// Test each in isolation:
TEST_F(HttpNetworkTransactionTest, BypassHostCacheOnRefresh1) {
  BypassHostCacheOnRefreshHelper(LOAD_BYPASS_CACHE);
}

TEST_F(HttpNetworkTransactionTest, BypassHostCacheOnRefresh2) {
  BypassHostCacheOnRefreshHelper(LOAD_VALIDATE_CACHE);
}

TEST_F(HttpNetworkTransactionTest, BypassHostCacheOnRefresh3) {
  BypassHostCacheOnRefreshHelper(LOAD_DISABLE_CACHE);
}

// Make sure we can handle an error when writing the request.
TEST_F(HttpNetworkTransactionTest, RequestWriteError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");

  MockWrite write_failure[] = {
    MockWrite(ASYNC, ERR_CONNECTION_RESET),
  };
  StaticSocketDataProvider data(NULL, 0,
                                write_failure, arraysize(write_failure));
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_LT(0u, endpoint.address().size());
}

// Check that a connection closed after the start of the headers finishes ok.
TEST_F(HttpNetworkTransactionTest, ConnectionClosedAfterStartOfHeaders) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");

  MockRead data_reads[] = {
    MockRead("HTTP/1."),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("", response_data);

  IPEndPoint endpoint;
  EXPECT_TRUE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_LT(0u, endpoint.address().size());
}

// Make sure that a dropped connection while draining the body for auth
// restart does the right thing.
TEST_F(HttpNetworkTransactionTest, DrainResetOK) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"),
    MockRead("WWW-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 14\r\n\r\n"),
    MockRead("Unauth"),
    MockRead(ASYNC, ERR_CONNECTION_RESET),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // After calling trans.RestartWithAuth(), this is the request we should
  // be issuing -- the final header line contains the credentials.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };

  // Lastly, the server responds with the actual content.
  MockRead data_reads2[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(CheckBasicServerAuth(response->auth_challenge.get()));

  TestCompletionCallback callback2;

  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(100, response->headers->GetContentLength());
}

// Test HTTPS connections going through a proxy that sends extra data.
TEST_F(HttpNetworkTransactionTest, HTTPSViaProxyWithExtraData) {
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockRead proxy_reads[] = {
    MockRead("HTTP/1.0 200 Connected\r\n\r\nExtra data"),
    MockRead(SYNCHRONOUS, OK)
  };

  StaticSocketDataProvider data(proxy_reads, arraysize(proxy_reads), NULL, 0);
  SSLSocketDataProvider ssl(ASYNC, OK);

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  session_deps_.socket_factory->ResetNextMockIndexes();

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_TUNNEL_CONNECTION_FAILED));
}

TEST_F(HttpNetworkTransactionTest, LargeContentLengthThenClose) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\nContent-Length:6719476739\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_CONTENT_LENGTH_MISMATCH));
}

TEST_F(HttpNetworkTransactionTest, UploadFileSmallerThanLength) {
  base::FilePath temp_file_path;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file_path));
  const uint64_t kFakeSize = 100000;  // file is actually blank
  UploadFileElementReader::ScopedOverridingContentLengthForTests
      overriding_content_length(kFakeSize);

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(base::MakeUnique<UploadFileElementReader>(
      base::ThreadTaskRunnerHandle::Get().get(), temp_file_path, 0,
      std::numeric_limits<uint64_t>::max(), base::Time()));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/upload");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_UPLOAD_FILE_CHANGED));

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_FALSE(response->headers);

  base::DeleteFile(temp_file_path, false);
}

TEST_F(HttpNetworkTransactionTest, UploadUnreadableFile) {
  base::FilePath temp_file;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file));
  std::string temp_file_content("Unreadable file.");
  ASSERT_EQ(static_cast<int>(temp_file_content.length()),
            base::WriteFile(temp_file, temp_file_content.c_str(),
                            temp_file_content.length()));
  ASSERT_TRUE(base::MakeFileUnreadable(temp_file));

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(base::MakeUnique<UploadFileElementReader>(
      base::ThreadTaskRunnerHandle::Get().get(), temp_file, 0,
      std::numeric_limits<uint64_t>::max(), base::Time()));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/upload");
  request.upload_data_stream = &upload_data_stream;

  // If we try to upload an unreadable file, the transaction should fail.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_ACCESS_DENIED));

  base::DeleteFile(temp_file, false);
}

TEST_F(HttpNetworkTransactionTest, CancelDuringInitRequestBody) {
  class FakeUploadElementReader : public UploadElementReader {
   public:
    FakeUploadElementReader() {}
    ~FakeUploadElementReader() override {}

    const CompletionCallback& callback() const { return callback_; }

    // UploadElementReader overrides:
    int Init(const CompletionCallback& callback) override {
      callback_ = callback;
      return ERR_IO_PENDING;
    }
    uint64_t GetContentLength() const override { return 0; }
    uint64_t BytesRemaining() const override { return 0; }
    int Read(IOBuffer* buf,
             int buf_length,
             const CompletionCallback& callback) override {
      return ERR_FAILED;
    }

   private:
    CompletionCallback callback_;
  };

  FakeUploadElementReader* fake_reader = new FakeUploadElementReader;
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(base::WrapUnique(fake_reader));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.example.org/upload");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  base::RunLoop().RunUntilIdle();

  // Transaction is pending on request body initialization.
  ASSERT_FALSE(fake_reader->callback().is_null());

  // Return Init()'s result after the transaction gets destroyed.
  trans.reset();
  fake_reader->callback().Run(OK);  // Should not crash.
}

// Tests that changes to Auth realms are treated like auth rejections.
TEST_F(HttpNetworkTransactionTest, ChangeAuthRealms) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // First transaction will request a resource and receive a Basic challenge
  // with realm="first_realm".
  MockWrite data_writes1[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "\r\n"),
  };
  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"
             "WWW-Authenticate: Basic realm=\"first_realm\"\r\n"
             "\r\n"),
  };

  // After calling trans.RestartWithAuth(), provide an Authentication header
  // for first_realm. The server will reject and provide a challenge with
  // second_realm.
  MockWrite data_writes2[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zmlyc3Q6YmF6\r\n"
          "\r\n"),
  };
  MockRead data_reads2[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"
             "WWW-Authenticate: Basic realm=\"second_realm\"\r\n"
             "\r\n"),
  };

  // This again fails, and goes back to first_realm. Make sure that the
  // entry is removed from cache.
  MockWrite data_writes3[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic c2Vjb25kOmZvdQ==\r\n"
          "\r\n"),
  };
  MockRead data_reads3[] = {
    MockRead("HTTP/1.1 401 Unauthorized\r\n"
             "WWW-Authenticate: Basic realm=\"first_realm\"\r\n"
             "\r\n"),
  };

  // Try one last time (with the correct password) and get the resource.
  MockWrite data_writes4[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "Authorization: Basic Zmlyc3Q6YmFy\r\n"
          "\r\n"),
  };
  MockRead data_reads4[] = {
    MockRead("HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html; charset=iso-8859-1\r\n"
             "Content-Length: 5\r\n"
             "\r\n"
             "hello"),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  StaticSocketDataProvider data2(data_reads2, arraysize(data_reads2),
                                 data_writes2, arraysize(data_writes2));
  StaticSocketDataProvider data3(data_reads3, arraysize(data_reads3),
                                 data_writes3, arraysize(data_writes3));
  StaticSocketDataProvider data4(data_reads4, arraysize(data_reads4),
                                 data_writes4, arraysize(data_writes4));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  session_deps_.socket_factory->AddSocketDataProvider(&data4);

  TestCompletionCallback callback1;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Issue the first request with Authorize headers. There should be a
  // password prompt for first_realm waiting to be filled in after the
  // transaction completes.
  int rv = trans.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  const AuthChallengeInfo* challenge = response->auth_challenge.get();
  ASSERT_TRUE(challenge);
  EXPECT_FALSE(challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", challenge->challenger.Serialize());
  EXPECT_EQ("first_realm", challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, challenge->scheme);

  // Issue the second request with an incorrect password. There should be a
  // password prompt for second_realm waiting to be filled in after the
  // transaction completes.
  TestCompletionCallback callback2;
  rv = trans.RestartWithAuth(AuthCredentials(kFirst, kBaz),
                             callback2.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  challenge = response->auth_challenge.get();
  ASSERT_TRUE(challenge);
  EXPECT_FALSE(challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", challenge->challenger.Serialize());
  EXPECT_EQ("second_realm", challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, challenge->scheme);

  // Issue the third request with another incorrect password. There should be
  // a password prompt for first_realm waiting to be filled in. If the password
  // prompt is not present, it indicates that the HttpAuthCacheEntry for
  // first_realm was not correctly removed.
  TestCompletionCallback callback3;
  rv = trans.RestartWithAuth(AuthCredentials(kSecond, kFou),
                             callback3.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback3.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  challenge = response->auth_challenge.get();
  ASSERT_TRUE(challenge);
  EXPECT_FALSE(challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", challenge->challenger.Serialize());
  EXPECT_EQ("first_realm", challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, challenge->scheme);

  // Issue the fourth request with the correct password and username.
  TestCompletionCallback callback4;
  rv = trans.RestartWithAuth(AuthCredentials(kFirst, kBar),
                             callback4.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback4.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
}

TEST_F(HttpNetworkTransactionTest, HonorAlternativeServiceHeader) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  url::SchemeHostPort test_server(request.url);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties->GetAlternativeServiceInfos(test_server).empty());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties->GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  AlternativeService alternative_service(kProtoHTTP2, "mail.example.org", 443);
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
}

// Regression test for https://crbug.com/615497.
TEST_F(HttpNetworkTransactionTest,
       DoNotParseAlternativeServiceHeaderOnInsecureRequest) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  url::SchemeHostPort test_server(request.url);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties->GetAlternativeServiceInfos(test_server).empty());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_TRUE(
      http_server_properties->GetAlternativeServiceInfos(test_server).empty());
}

// HTTP/2 Alternative Services should be disabled by default.
// TODO(bnc): Remove when https://crbug.com/615413 is fixed.
TEST_F(HttpNetworkTransactionTest,
       DisableHTTP2AlternativeServicesWithDifferentHost) {
  session_deps_.enable_http2_alternative_service = false;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, arraysize(data_reads), NULL,
                                       0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, "different.example.org",
                                         444);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(request.url), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  // Alternative service is not used, request fails.
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));
}

// Regression test for https://crbug.com/615497:
// Alternative Services should be disabled for http origin.
TEST_F(HttpNetworkTransactionTest,
       DisableAlternativeServicesForInsecureOrigin) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(data_reads, arraysize(data_reads), NULL,
                                       0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, "", 444);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(request.url), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  // Alternative service is not used, request fails.
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));
}

TEST_F(HttpNetworkTransactionTest, ClearAlternativeServices) {
  // Set an alternative service for origin.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  url::SchemeHostPort test_server("https", "www.example.org", 443);
  AlternativeService alternative_service(kProtoQUIC, "", 80);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetQuicAlternativeService(
      test_server, alternative_service, expiration,
      session->params().quic_supported_versions);
  EXPECT_EQ(
      1u,
      http_server_properties->GetAlternativeServiceInfos(test_server).size());

  // Send a clear header.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: clear\r\n"),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_TRUE(
      http_server_properties->GetAlternativeServiceInfos(test_server).empty());
}

TEST_F(HttpNetworkTransactionTest, HonorMultipleAlternativeServiceHeaders) {
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Alt-Svc: h2=\"www.example.com:443\","),
      MockRead("h2=\":1234\"\r\n\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  url::SchemeHostPort test_server("https", "www.example.org", 443);
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  EXPECT_TRUE(
      http_server_properties->GetAlternativeServiceInfos(test_server).empty());

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties->GetAlternativeServiceInfos(test_server);
  ASSERT_EQ(2u, alternative_service_info_vector.size());

  AlternativeService alternative_service(kProtoHTTP2, "www.example.com", 443);
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
  AlternativeService alternative_service_2(kProtoHTTP2, "www.example.org",
                                           1234);
  EXPECT_EQ(alternative_service_2,
            alternative_service_info_vector[1].alternative_service());
}

TEST_F(HttpNetworkTransactionTest, IdentifyQuicBroken) {
  url::SchemeHostPort server("https", "origin.example.org", 443);
  HostPortPair alternative("alternative.example.org", 443);
  std::string origin_url = "https://origin.example.org:443";
  std::string alternative_url = "https://alternative.example.org:443";

  // Negotiate HTTP/1.1 with alternative.example.org.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // HTTP/1.1 data for request.
  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: alternative.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 40\r\n\r\n"
               "first HTTP/1.1 response from alternative"),
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  // Set up a QUIC alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoQUIC, alternative);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetQuicAlternativeService(
      server, alternative_service, expiration,
      HttpNetworkSession::Params().quic_supported_versions);
  // Mark the QUIC alternative service as broken.
  http_server_properties->MarkAlternativeServiceBroken(alternative_service);

  HttpRequestInfo request;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  request.method = "GET";
  request.url = GURL(origin_url);
  TestCompletionCallback callback;
  NetErrorDetails details;
  EXPECT_FALSE(details.quic_broken);

  trans.Start(&request, callback.callback(), NetLogWithSource());
  trans.PopulateNetErrorDetails(&details);
  EXPECT_TRUE(details.quic_broken);
}

TEST_F(HttpNetworkTransactionTest, IdentifyQuicNotBroken) {
  url::SchemeHostPort server("https", "origin.example.org", 443);
  HostPortPair alternative1("alternative1.example.org", 443);
  HostPortPair alternative2("alternative2.example.org", 443);
  std::string origin_url = "https://origin.example.org:443";
  std::string alternative_url1 = "https://alternative1.example.org:443";
  std::string alternative_url2 = "https://alternative2.example.org:443";

  // Negotiate HTTP/1.1 with alternative1.example.org.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // HTTP/1.1 data for request.
  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: alternative1.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Type: text/html; charset=iso-8859-1\r\n"
               "Content-Length: 40\r\n\r\n"
               "first HTTP/1.1 response from alternative1"),
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();

  // Set up two QUIC alternative services for server.
  AlternativeServiceInfoVector alternative_service_info_vector;
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);

  AlternativeService alternative_service1(kProtoQUIC, alternative1);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service1, expiration,
          session->params().quic_supported_versions));
  AlternativeService alternative_service2(kProtoQUIC, alternative2);
  alternative_service_info_vector.push_back(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service2, expiration,
          session->params().quic_supported_versions));

  http_server_properties->SetAlternativeServices(
      server, alternative_service_info_vector);

  // Mark one of the QUIC alternative service as broken.
  http_server_properties->MarkAlternativeServiceBroken(alternative_service1);
  EXPECT_EQ(2u,
            http_server_properties->GetAlternativeServiceInfos(server).size());

  HttpRequestInfo request;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  request.method = "GET";
  request.url = GURL(origin_url);
  TestCompletionCallback callback;
  NetErrorDetails details;
  EXPECT_FALSE(details.quic_broken);

  trans.Start(&request, callback.callback(), NetLogWithSource());
  trans.PopulateNetErrorDetails(&details);
  EXPECT_FALSE(details.quic_broken);
}

TEST_F(HttpNetworkTransactionTest, MarkBrokenAlternateProtocolAndFallback) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const url::SchemeHostPort server(request.url);
  // Port must be < 1024, or the header will be ignored (since initial port was
  // port 80 (another restricted port).
  // Port is ignored by MockConnect anyway.
  const AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                               666);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      server, alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  const AlternativeServiceInfoVector alternative_service_info_vector =
      http_server_properties->GetAlternativeServiceInfos(server);
  ASSERT_EQ(1u, alternative_service_info_vector.size());
  EXPECT_EQ(alternative_service,
            alternative_service_info_vector[0].alternative_service());
  EXPECT_TRUE(
      http_server_properties->IsAlternativeServiceBroken(alternative_service));
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_F(HttpNetworkTransactionTest, AlternateProtocolPortRestrictedBlocked) {
  HttpRequestInfo restricted_port_request;
  restricted_port_request.method = "GET";
  restricted_port_request.url = GURL("https://www.example.org:1023/");
  restricted_port_request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnrestrictedAlternatePort = 1024;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnrestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(restricted_port_request.url), alternative_service,
      expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&restricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Invalid change to unrestricted port should fail.
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_REFUSED));
}

// Ensure that we are allowed to redirect traffic via an alternate protocol to
// an unrestricted (port >= 1024) when the original traffic was on a restricted
// port (port < 1024) if we set |enable_user_alternate_protocol_ports|.
TEST_F(HttpNetworkTransactionTest, AlternateProtocolPortRestrictedPermitted) {
  session_deps_.enable_user_alternate_protocol_ports = true;

  HttpRequestInfo restricted_port_request;
  restricted_port_request.method = "GET";
  restricted_port_request.url = GURL("https://www.example.org:1023/");
  restricted_port_request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnrestrictedAlternatePort = 1024;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnrestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(restricted_port_request.url), alternative_service,
      expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&restricted_port_request, callback.callback(),
                        NetLogWithSource()));
  // Change to unrestricted port should succeed.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_F(HttpNetworkTransactionTest, AlternateProtocolPortRestrictedAllowed) {
  HttpRequestInfo restricted_port_request;
  restricted_port_request.method = "GET";
  restricted_port_request.url = GURL("https://www.example.org:1023/");
  restricted_port_request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kRestrictedAlternatePort = 80;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kRestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(restricted_port_request.url), alternative_service,
      expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&restricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Valid change to restricted port should pass.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_F(HttpNetworkTransactionTest, AlternateProtocolPortUnrestrictedAllowed1) {
  HttpRequestInfo unrestricted_port_request;
  unrestricted_port_request.method = "GET";
  unrestricted_port_request.url = GURL("https://www.example.org:1024/");
  unrestricted_port_request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kRestrictedAlternatePort = 80;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kRestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(unrestricted_port_request.url), alternative_service,
      expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&unrestricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Valid change to restricted port should pass.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unrestricted (port >= 1024) when the original traffic was on a
// restricted port (port < 1024).  Ensure that we can redirect in all other
// cases.
TEST_F(HttpNetworkTransactionTest, AlternateProtocolPortUnrestrictedAllowed2) {
  HttpRequestInfo unrestricted_port_request;
  unrestricted_port_request.method = "GET";
  unrestricted_port_request.url = GURL("https://www.example.org:1024/");
  unrestricted_port_request.load_flags = 0;

  MockConnect mock_connect(ASYNC, ERR_CONNECTION_REFUSED);
  StaticSocketDataProvider first_data;
  first_data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&first_data);

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider second_data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnrestrictedAlternatePort = 1025;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnrestrictedAlternatePort);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(unrestricted_port_request.url), alternative_service,
      expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&unrestricted_port_request, callback.callback(),
                       NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Valid change to an unrestricted port should pass.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Ensure that we are not allowed to redirect traffic via an alternate protocol
// to an unsafe port, and that we resume the second HttpStreamFactoryImpl::Job
// once the alternate protocol request fails.
TEST_F(HttpNetworkTransactionTest, AlternateProtocolUnsafeBlocked) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  // The alternate protocol request will error out before we attempt to connect,
  // so only the standard HTTP request will try to connect.
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(ASYNC, OK),
  };
  StaticSocketDataProvider data(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  const int kUnsafePort = 7;
  AlternativeService alternative_service(kProtoHTTP2, "www.example.org",
                                         kUnsafePort);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      url::SchemeHostPort(request.url), alternative_service, expiration);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // The HTTP request should succeed.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_F(HttpNetworkTransactionTest, UseAlternateProtocolForNpnSpdy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider first_transaction(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  AddSSLSocketData();

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(data, 2), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_non_alternate_protocol_socket(
      NULL, 0, NULL, 0);
  hanging_non_alternate_protocol_socket.set_connect_data(
      never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_non_alternate_protocol_socket);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_F(HttpNetworkTransactionTest, AlternateProtocolWithSpdyLateBinding) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // First transaction receives Alt-Svc header over HTTP/1.1.
  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider http11_data(data_reads, arraysize(data_reads), NULL,
                                       0);
  session_deps_.socket_factory->AddSocketDataProvider(&http11_data);

  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  // Second transaction starts an alternative and a non-alternative Job.
  // Both sockets hang.
  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_socket1(NULL, 0, NULL, 0);
  hanging_socket1.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&hanging_socket1);

  StaticSocketDataProvider hanging_socket2(NULL, 0, NULL, 0);
  hanging_socket2.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&hanging_socket2);

  // Third transaction starts an alternative and a non-alternative job.
  // The non-alternative job hangs, but the alternative one succeeds.
  // The second transaction, still pending, binds to this socket.
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 3, LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data1(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame data2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp1, 2), CreateMockRead(data1, 3),
      CreateMockRead(resp2, 4), CreateMockRead(data2, 5),
      MockRead(ASYNC, 0, 6),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  AddSSLSocketData();

  StaticSocketDataProvider hanging_socket3(NULL, 0, NULL, 0);
  hanging_socket3.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&hanging_socket3);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  TestCompletionCallback callback2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request, callback2.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TestCompletionCallback callback3;
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, session.get());
  rv = trans3.Start(&request, callback3.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_THAT(callback3.WaitForResult(), IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  response = trans3.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans3, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_F(HttpNetworkTransactionTest, StallAlternativeServiceForNpnSpdy) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider first_transaction(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_alternate_protocol_socket(
      NULL, 0, NULL, 0);
  hanging_alternate_protocol_socket.set_connect_data(
      never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_alternate_protocol_socket);

  // 2nd request is just a copy of the first one, over HTTP/1.1 again.
  StaticSocketDataProvider second_transaction(data_reads, arraysize(data_reads),
                                              NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&second_transaction);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);
}

class CapturingProxyResolver : public ProxyResolver {
 public:
  CapturingProxyResolver() {}
  ~CapturingProxyResolver() override {}

  int GetProxyForURL(const GURL& url,
                     ProxyInfo* results,
                     const CompletionCallback& callback,
                     std::unique_ptr<Request>* request,
                     const NetLogWithSource& net_log) override {
    ProxyServer proxy_server(ProxyServer::SCHEME_HTTP,
                             HostPortPair("myproxy", 80));
    results->UseProxyServer(proxy_server);
    resolved_.push_back(url);
    return OK;
  }

  const std::vector<GURL>& resolved() const { return resolved_; }

 private:
  std::vector<GURL> resolved_;

  DISALLOW_COPY_AND_ASSIGN(CapturingProxyResolver);
};

class CapturingProxyResolverFactory : public ProxyResolverFactory {
 public:
  explicit CapturingProxyResolverFactory(CapturingProxyResolver* resolver)
      : ProxyResolverFactory(false), resolver_(resolver) {}

  int CreateProxyResolver(
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      std::unique_ptr<ProxyResolver>* resolver,
      const net::CompletionCallback& callback,
      std::unique_ptr<Request>* request) override {
    *resolver = base::MakeUnique<ForwardingProxyResolver>(resolver_);
    return OK;
  }

 private:
  ProxyResolver* resolver_;
};

// Test that proxy is resolved using the origin url,
// regardless of the alternative server.
TEST_F(HttpNetworkTransactionTest, UseOriginNotAlternativeForProxy) {
  // Configure proxy to bypass www.example.org, which is the origin URL.
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString("myproxy:70");
  proxy_config.proxy_rules().bypass_rules.AddRuleFromString("www.example.org");
  auto proxy_config_service =
      base::MakeUnique<ProxyConfigServiceFixed>(proxy_config);

  CapturingProxyResolver capturing_proxy_resolver;
  auto proxy_resolver_factory = base::MakeUnique<CapturingProxyResolverFactory>(
      &capturing_proxy_resolver);

  TestNetLog net_log;

  session_deps_.proxy_service = base::MakeUnique<ProxyService>(
      std::move(proxy_config_service), std::move(proxy_resolver_factory),
      &net_log);

  session_deps_.net_log = &net_log;

  // Configure alternative service with a hostname that is not bypassed by the
  // proxy.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  url::SchemeHostPort server("https", "www.example.org", 443);
  HostPortPair alternative("www.example.com", 443);
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      server, alternative_service, expiration);

  // Non-alternative job should hang.
  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_alternate_protocol_socket(nullptr, 0,
                                                             nullptr, 0);
  hanging_alternate_protocol_socket.set_connect_data(never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_alternate_protocol_socket);

  AddSSLSocketData();

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.load_flags = 0;

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));

  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(data, 2), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  // Origin host bypasses proxy, no resolution should have happened.
  ASSERT_TRUE(capturing_proxy_resolver.resolved().empty());
}

TEST_F(HttpNetworkTransactionTest, UseAlternativeServiceForTunneledNpnSpdy) {
  ProxyConfig proxy_config;
  proxy_config.set_auto_detect(true);
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));

  CapturingProxyResolver capturing_proxy_resolver;
  session_deps_.proxy_service = base::MakeUnique<ProxyService>(
      base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
      base::MakeUnique<CapturingProxyResolverFactory>(
          &capturing_proxy_resolver),
      nullptr);
  TestNetLog net_log;
  session_deps_.net_log = &net_log;

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider first_transaction(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  AddSSLSocketData();

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
      CreateMockWrite(req, 2),
  };

  const char kCONNECTResponse[] = "HTTP/1.1 200 Connected\r\n\r\n";

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      MockRead(ASYNC, 1, kCONNECTResponse), CreateMockRead(resp, 3),
      CreateMockRead(data, 4), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  StaticSocketDataProvider hanging_non_alternate_protocol_socket(
      NULL, 0, NULL, 0);
  hanging_non_alternate_protocol_socket.set_connect_data(
      never_finishing_connect);
  session_deps_.socket_factory->AddSocketDataProvider(
      &hanging_non_alternate_protocol_socket);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/0.9 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  ASSERT_EQ(2u, capturing_proxy_resolver.resolved().size());
  EXPECT_EQ("https://www.example.org/",
            capturing_proxy_resolver.resolved()[0].spec());
  EXPECT_EQ("https://www.example.org/",
            capturing_proxy_resolver.resolved()[1].spec());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans->GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

TEST_F(HttpNetworkTransactionTest,
       UseAlternativeServiceForNpnSpdyWithExistingSpdySession) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(ASYNC, OK),
  };

  StaticSocketDataProvider first_transaction(
      data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&first_transaction);
  SSLSocketDataProvider ssl_http11(ASYNC, OK);
  ssl_http11.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_http11);

  AddSSLSocketData();

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org/", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(data, 2), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  // Set up an initial SpdySession in the pool to reuse.
  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key(host_port_pair, ProxyServer::Direct(),
                     PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, NetLogWithSource());

  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

// GenerateAuthToken is a mighty big test.
// It tests all permutation of GenerateAuthToken behavior:
//   - Synchronous and Asynchronous completion.
//   - OK or error on completion.
//   - Direct connection, non-authenticating proxy, and authenticating proxy.
//   - HTTP or HTTPS backend (to include proxy tunneling).
//   - Non-authenticating and authenticating backend.
//
// In all, there are 44 reasonable permuations (for example, if there are
// problems generating an auth token for an authenticating proxy, we don't
// need to test all permutations of the backend server).
//
// The test proceeds by going over each of the configuration cases, and
// potentially running up to three rounds in each of the tests. The TestConfig
// specifies both the configuration for the test as well as the expectations
// for the results.
TEST_F(HttpNetworkTransactionTest, GenerateAuthToken) {
  static const char kServer[] = "http://www.example.com";
  static const char kSecureServer[] = "https://www.example.com";
  static const char kProxy[] = "myproxy:70";

  enum AuthTiming {
    AUTH_NONE,
    AUTH_SYNC,
    AUTH_ASYNC,
  };

  const MockWrite kGet(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n\r\n");
  const MockWrite kGetProxy(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n\r\n");
  const MockWrite kGetAuth(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n"
      "Authorization: auth_token\r\n\r\n");
  const MockWrite kGetProxyAuth(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Proxy-Authorization: auth_token\r\n\r\n");
  const MockWrite kGetAuthThroughProxy(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Authorization: auth_token\r\n\r\n");
  const MockWrite kGetAuthWithProxyAuth(
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Proxy-Authorization: auth_token\r\n"
      "Authorization: auth_token\r\n\r\n");
  const MockWrite kConnect(
      "CONNECT www.example.com:443 HTTP/1.1\r\n"
      "Host: www.example.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n\r\n");
  const MockWrite kConnectProxyAuth(
      "CONNECT www.example.com:443 HTTP/1.1\r\n"
      "Host: www.example.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "Proxy-Authorization: auth_token\r\n\r\n");

  const MockRead kSuccess(
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 3\r\n\r\n"
      "Yes");
  const MockRead kFailure(
      "Should not be called.");
  const MockRead kServerChallenge(
      "HTTP/1.1 401 Unauthorized\r\n"
      "WWW-Authenticate: Mock realm=server\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 14\r\n\r\n"
      "Unauthorized\r\n");
  const MockRead kProxyChallenge(
      "HTTP/1.1 407 Unauthorized\r\n"
      "Proxy-Authenticate: Mock realm=proxy\r\n"
      "Proxy-Connection: close\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 14\r\n\r\n"
      "Unauthorized\r\n");
  const MockRead kProxyConnected(
      "HTTP/1.1 200 Connection Established\r\n\r\n");

  // NOTE(cbentzel): I wanted TestReadWriteRound to be a simple struct with
  // no constructors, but the C++ compiler on Windows warns about
  // unspecified data in compound literals. So, moved to using constructors,
  // and TestRound's created with the default constructor should not be used.
  struct TestRound {
    TestRound()
        : expected_rv(ERR_UNEXPECTED),
          extra_write(NULL),
          extra_read(NULL) {
    }
    TestRound(const MockWrite& write_arg, const MockRead& read_arg,
              int expected_rv_arg)
        : write(write_arg),
          read(read_arg),
          expected_rv(expected_rv_arg),
          extra_write(NULL),
          extra_read(NULL) {
    }
    TestRound(const MockWrite& write_arg, const MockRead& read_arg,
              int expected_rv_arg, const MockWrite* extra_write_arg,
              const MockRead* extra_read_arg)
        : write(write_arg),
          read(read_arg),
          expected_rv(expected_rv_arg),
          extra_write(extra_write_arg),
          extra_read(extra_read_arg) {
    }
    MockWrite write;
    MockRead read;
    int expected_rv;
    const MockWrite* extra_write;
    const MockRead* extra_read;
  };

  static const int kNoSSL = 500;

  struct TestConfig {
    int line_number;
    const char* const proxy_url;
    AuthTiming proxy_auth_timing;
    int first_generate_proxy_token_rv;
    const char* const server_url;
    AuthTiming server_auth_timing;
    int first_generate_server_token_rv;
    int num_auth_rounds;
    int first_ssl_round;
    TestRound rounds[4];
  } test_configs[] = {
      // Non-authenticating HTTP server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       1,
       kNoSSL,
       {TestRound(kGet, kSuccess, OK)}},
      // Authenticating HTTP server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_UNSUPPORTED_AUTH_SCHEME,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_FAILED,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kFailure, ERR_FAILED)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_FAILED,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kFailure, ERR_FAILED)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_FAILED,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGet, kFailure, ERR_FAILED)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_FAILED,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGet, kFailure, ERR_FAILED)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGet, kServerChallenge, OK),
        // The second round uses a HttpAuthHandlerMock that always succeeds.
        TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      // Non-authenticating HTTP server through a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       1,
       kNoSSL,
       {TestRound(kGetProxy, kSuccess, OK)}},
      // Authenticating HTTP server through a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetAuthThroughProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetAuthThroughProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetAuthThroughProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kServerChallenge, OK),
        TestRound(kGetProxy, kSuccess, OK)}},
      // Non-authenticating HTTP server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_NONE,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      // Authenticating HTTP server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_SYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_ASYNC,
       OK,
       4,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       OK,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetAuthWithProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       4,
       kNoSSL,
       {TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxy, kProxyChallenge, OK),
        TestRound(kGetProxyAuth, kServerChallenge, OK),
        TestRound(kGetProxyAuth, kSuccess, OK)}},
      // Non-authenticating HTTPS server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       1,
       0,
       {TestRound(kGet, kSuccess, OK)}},
      // Authenticating HTTPS server with a direct connection.
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       nullptr,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kGet, kServerChallenge, OK), TestRound(kGet, kSuccess, OK)}},
      // Non-authenticating HTTPS server with a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       1,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      // Authenticating HTTPS server through a non-authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_NONE,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       2,
       0,
       {TestRound(kConnect, kProxyConnected, OK, &kGet, &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      // Non-Authenticating HTTPS server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_UNSUPPORTED_AUTH_SCHEME,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       ERR_UNEXPECTED,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, ERR_UNEXPECTED)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet, &kSuccess)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kSecureServer,
       AUTH_NONE,
       OK,
       2,
       kNoSSL,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyConnected, OK, &kGet, &kSuccess)}},
      // Authenticating HTTPS server through an authenticating proxy.
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_SYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_SYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       OK,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGetAuth, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       OK,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       3,
       1,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
      {__LINE__,
       kProxy,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       kSecureServer,
       AUTH_ASYNC,
       ERR_INVALID_AUTH_CREDENTIALS,
       4,
       2,
       {TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnect, kProxyChallenge, OK),
        TestRound(kConnectProxyAuth, kProxyConnected, OK, &kGet,
                  &kServerChallenge),
        TestRound(kGet, kSuccess, OK)}},
  };

  for (const auto& test_config : test_configs) {
    SCOPED_TRACE(::testing::Message() << "Test config at "
                                      << test_config.line_number);
    HttpAuthHandlerMock::Factory* auth_factory(
        new HttpAuthHandlerMock::Factory());
    session_deps_.http_auth_handler_factory.reset(auth_factory);
    SSLInfo empty_ssl_info;

    // Set up authentication handlers as necessary.
    if (test_config.proxy_auth_timing != AUTH_NONE) {
      for (int n = 0; n < 3; n++) {
        HttpAuthHandlerMock* auth_handler(new HttpAuthHandlerMock());
        std::string auth_challenge = "Mock realm=proxy";
        GURL origin(test_config.proxy_url);
        HttpAuthChallengeTokenizer tokenizer(auth_challenge.begin(),
                                             auth_challenge.end());
        auth_handler->InitFromChallenge(&tokenizer, HttpAuth::AUTH_PROXY,
                                        empty_ssl_info, origin,
                                        NetLogWithSource());
        auth_handler->SetGenerateExpectation(
            test_config.proxy_auth_timing == AUTH_ASYNC,
            n == 0 ? test_config.first_generate_proxy_token_rv : OK);
        auth_factory->AddMockHandler(auth_handler, HttpAuth::AUTH_PROXY);
      }
    }
    if (test_config.server_auth_timing != AUTH_NONE) {
      HttpAuthHandlerMock* auth_handler(new HttpAuthHandlerMock());
      std::string auth_challenge = "Mock realm=server";
      GURL origin(test_config.server_url);
      HttpAuthChallengeTokenizer tokenizer(auth_challenge.begin(),
                                           auth_challenge.end());
      auth_handler->InitFromChallenge(&tokenizer, HttpAuth::AUTH_SERVER,
                                      empty_ssl_info, origin,
                                      NetLogWithSource());
      auth_handler->SetGenerateExpectation(
          test_config.server_auth_timing == AUTH_ASYNC,
          test_config.first_generate_server_token_rv);
      auth_factory->AddMockHandler(auth_handler, HttpAuth::AUTH_SERVER);

      // The second handler always succeeds. It should only be used where there
      // are multiple auth sessions for server auth in the same network
      // transaction using the same auth scheme.
      std::unique_ptr<HttpAuthHandlerMock> second_handler =
          base::MakeUnique<HttpAuthHandlerMock>();
      second_handler->InitFromChallenge(&tokenizer, HttpAuth::AUTH_SERVER,
                                        empty_ssl_info, origin,
                                        NetLogWithSource());
      second_handler->SetGenerateExpectation(true, OK);
      auth_factory->AddMockHandler(second_handler.release(),
                                   HttpAuth::AUTH_SERVER);
    }
    if (test_config.proxy_url) {
      session_deps_.proxy_service =
          ProxyService::CreateFixed(test_config.proxy_url);
    } else {
      session_deps_.proxy_service = ProxyService::CreateDirect();
    }

    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL(test_config.server_url);

    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

    SSLSocketDataProvider ssl_socket_data_provider(SYNCHRONOUS, OK);

    std::vector<std::vector<MockRead>> mock_reads(1);
    std::vector<std::vector<MockWrite>> mock_writes(1);
    for (int round = 0; round < test_config.num_auth_rounds; ++round) {
      SCOPED_TRACE(round);
      const TestRound& read_write_round = test_config.rounds[round];

      // Set up expected reads and writes.
      mock_reads.back().push_back(read_write_round.read);
      mock_writes.back().push_back(read_write_round.write);

      // kProxyChallenge uses Proxy-Connection: close which means that the
      // socket is closed and a new one will be created for the next request.
      if (read_write_round.read.data == kProxyChallenge.data) {
        mock_reads.push_back(std::vector<MockRead>());
        mock_writes.push_back(std::vector<MockWrite>());
      }

      if (read_write_round.extra_read) {
        mock_reads.back().push_back(*read_write_round.extra_read);
      }
      if (read_write_round.extra_write) {
        mock_writes.back().push_back(*read_write_round.extra_write);
      }

      // Add an SSL sequence if necessary.
      if (round >= test_config.first_ssl_round)
        session_deps_.socket_factory->AddSSLSocketDataProvider(
            &ssl_socket_data_provider);
    }

    std::vector<std::unique_ptr<StaticSocketDataProvider>> data_providers;
    for (size_t i = 0; i < mock_reads.size(); ++i) {
      data_providers.push_back(base::MakeUnique<StaticSocketDataProvider>(
          mock_reads[i].data(), mock_reads[i].size(), mock_writes[i].data(),
          mock_writes[i].size()));
      session_deps_.socket_factory->AddSocketDataProvider(
          data_providers.back().get());
    }

    // Transaction must be created after DataProviders, so it's destroyed before
    // they are as well.
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    for (int round = 0; round < test_config.num_auth_rounds; ++round) {
      SCOPED_TRACE(round);
      const TestRound& read_write_round = test_config.rounds[round];
      // Start or restart the transaction.
      TestCompletionCallback callback;
      int rv;
      if (round == 0) {
        rv = trans.Start(&request, callback.callback(), NetLogWithSource());
      } else {
        rv = trans.RestartWithAuth(
            AuthCredentials(kFoo, kBar), callback.callback());
      }
      if (rv == ERR_IO_PENDING)
        rv = callback.WaitForResult();

      // Compare results with expected data.
      EXPECT_THAT(rv, IsError(read_write_round.expected_rv));
      const HttpResponseInfo* response = trans.GetResponseInfo();
      if (read_write_round.expected_rv != OK) {
        EXPECT_EQ(round + 1, test_config.num_auth_rounds);
        continue;
      }
      if (round + 1 < test_config.num_auth_rounds) {
        EXPECT_TRUE(response->auth_challenge);
      } else {
        EXPECT_FALSE(response->auth_challenge);
        EXPECT_FALSE(trans.IsReadyToRestartForAuth());
      }
    }
  }
}

TEST_F(HttpNetworkTransactionTest, MultiRoundAuth) {
  // Do multi-round authentication and make sure it works correctly.
  HttpAuthHandlerMock::Factory* auth_factory(
      new HttpAuthHandlerMock::Factory());
  session_deps_.http_auth_handler_factory.reset(auth_factory);
  session_deps_.proxy_service = ProxyService::CreateDirect();
  session_deps_.host_resolver->rules()->AddRule("www.example.com", "10.0.0.1");
  session_deps_.host_resolver->set_synchronous_mode(true);

  HttpAuthHandlerMock* auth_handler(new HttpAuthHandlerMock());
  auth_handler->set_connection_based(true);
  std::string auth_challenge = "Mock realm=server";
  GURL origin("http://www.example.com");
  HttpAuthChallengeTokenizer tokenizer(auth_challenge.begin(),
                                       auth_challenge.end());
  SSLInfo empty_ssl_info;
  auth_handler->InitFromChallenge(&tokenizer, HttpAuth::AUTH_SERVER,
                                  empty_ssl_info, origin, NetLogWithSource());
  auth_factory->AddMockHandler(auth_handler, HttpAuth::AUTH_SERVER);

  int rv = OK;
  const HttpResponseInfo* response = NULL;
  HttpRequestInfo request;
  request.method = "GET";
  request.url = origin;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Use a TCP Socket Pool with only one connection per group. This is used
  // to validate that the TCP socket is not released to the pool between
  // each round of multi-round authentication.
  HttpNetworkSessionPeer session_peer(session.get());
  TransportClientSocketPool* transport_pool = new TransportClientSocketPool(
      50,  // Max sockets for pool
      1,   // Max sockets per group
      session_deps_.host_resolver.get(), session_deps_.socket_factory.get(),
      NULL, session_deps_.net_log);
  auto mock_pool_manager = base::MakeUnique<MockClientSocketPoolManager>();
  mock_pool_manager->SetTransportSocketPool(transport_pool);
  session_peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;

  const MockWrite kGet(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n\r\n");
  const MockWrite kGetAuth(
      "GET / HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Connection: keep-alive\r\n"
      "Authorization: auth_token\r\n\r\n");

  const MockRead kServerChallenge(
      "HTTP/1.1 401 Unauthorized\r\n"
      "WWW-Authenticate: Mock realm=server\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 14\r\n\r\n"
      "Unauthorized\r\n");
  const MockRead kSuccess(
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=iso-8859-1\r\n"
      "Content-Length: 3\r\n\r\n"
      "Yes");

  MockWrite writes[] = {
    // First round
    kGet,
    // Second round
    kGetAuth,
    // Third round
    kGetAuth,
    // Fourth round
    kGetAuth,
    // Competing request
    kGet,
  };
  MockRead reads[] = {
    // First round
    kServerChallenge,
    // Second round
    kServerChallenge,
    // Third round
    kServerChallenge,
    // Fourth round
    kSuccess,
    // Competing response
    kSuccess,
  };
  StaticSocketDataProvider data_provider(reads, arraysize(reads),
                                         writes, arraysize(writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data_provider);

  const char kSocketGroup[] = "www.example.com:80";

  // First round of authentication.
  auth_handler->SetGenerateExpectation(false, OK);
  rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->auth_challenge);
  EXPECT_EQ(0, transport_pool->IdleSocketCountInGroup(kSocketGroup));
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_GENERATE_AUTH_TOKEN,
            auth_handler->state());

  // In between rounds, another request comes in for the same domain.
  // It should not be able to grab the TCP socket that trans has already
  // claimed.
  HttpNetworkTransaction trans_compete(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback_compete;
  rv = trans_compete.Start(&request, callback_compete.callback(),
                           NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // callback_compete.WaitForResult at this point would stall forever,
  // since the HttpNetworkTransaction does not release the request back to
  // the pool until after authentication completes.

  // Second round of authentication.
  auth_handler->SetGenerateExpectation(false, OK);
  rv = trans.RestartWithAuth(AuthCredentials(kFoo, kBar), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(0, transport_pool->IdleSocketCountInGroup(kSocketGroup));
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_GENERATE_AUTH_TOKEN,
            auth_handler->state());

  // Third round of authentication.
  auth_handler->SetGenerateExpectation(false, OK);
  rv = trans.RestartWithAuth(AuthCredentials(), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(0, transport_pool->IdleSocketCountInGroup(kSocketGroup));
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_GENERATE_AUTH_TOKEN,
            auth_handler->state());

  // Fourth round of authentication, which completes successfully.
  auth_handler->SetGenerateExpectation(false, OK);
  rv = trans.RestartWithAuth(AuthCredentials(), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->auth_challenge);
  EXPECT_EQ(0, transport_pool->IdleSocketCountInGroup(kSocketGroup));

  // In WAIT_FOR_CHALLENGE, although in reality the auth handler is done. A real
  // auth handler should transition to a DONE state in concert with the remote
  // server. But that's not something we can test here with a mock handler.
  EXPECT_EQ(HttpAuthHandlerMock::State::WAIT_FOR_CHALLENGE,
            auth_handler->state());

  // Read the body since the fourth round was successful. This will also
  // release the socket back to the pool.
  scoped_refptr<IOBufferWithSize> io_buf(new IOBufferWithSize(50));
  rv = trans.Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_EQ(3, rv);
  rv = trans.Read(io_buf.get(), io_buf->size(), callback.callback());
  EXPECT_EQ(0, rv);
  // There are still 0 idle sockets, since the trans_compete transaction
  // will be handed it immediately after trans releases it to the group.
  EXPECT_EQ(0, transport_pool->IdleSocketCountInGroup(kSocketGroup));

  // The competing request can now finish. Wait for the headers and then
  // read the body.
  rv = callback_compete.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  rv = trans_compete.Read(io_buf.get(), io_buf->size(), callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_EQ(3, rv);
  rv = trans_compete.Read(io_buf.get(), io_buf->size(), callback.callback());
  EXPECT_EQ(0, rv);

  // Finally, the socket is released to the group.
  EXPECT_EQ(1, transport_pool->IdleSocketCountInGroup(kSocketGroup));
}

// This tests the case that a request is issued via http instead of spdy after
// npn is negotiated.
TEST_F(HttpNetworkTransactionTest, NpnWithHttpOverSSL) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(kAlternativeServiceHttpHeader),
      MockRead("\r\n"),
      MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;

  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());

  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
}

// Simulate the SSL handshake completing with an NPN negotiation followed by an
// immediate server closing of the socket.
// Regression test for https://crbug.com/46369.
TEST_F(HttpNetworkTransactionTest, SpdyPostNPNServerHangup) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST, true));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 1)};

  MockRead spdy_reads[] = {
    MockRead(SYNCHRONOUS, 0, 0)   // Not async - return 0 immediately.
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));
}

// A subclass of HttpAuthHandlerMock that records the request URL when
// it gets it. This is needed since the auth handler may get destroyed
// before we get a chance to query it.
class UrlRecordingHttpAuthHandlerMock : public HttpAuthHandlerMock {
 public:
  explicit UrlRecordingHttpAuthHandlerMock(GURL* url) : url_(url) {}

  ~UrlRecordingHttpAuthHandlerMock() override {}

 protected:
  int GenerateAuthTokenImpl(const AuthCredentials* credentials,
                            const HttpRequestInfo* request,
                            const CompletionCallback& callback,
                            std::string* auth_token) override {
    *url_ = request->url;
    return HttpAuthHandlerMock::GenerateAuthTokenImpl(
        credentials, request, callback, auth_token);
  }

 private:
  GURL* url_;
};

// Test that if we cancel the transaction as the connection is completing, that
// everything tears down correctly.
TEST_F(HttpNetworkTransactionTest, SimpleCancel) {
  // Setup everything about the connection to complete synchronously, so that
  // after calling HttpNetworkTransaction::Start, the only thing we're waiting
  // for is the callback from the HttpStreamRequest.
  // Then cancel the transaction.
  // Verify that we don't crash.
  MockConnect mock_connect(SYNCHRONOUS, OK);
  MockRead data_reads[] = {
    MockRead(SYNCHRONOUS, "HTTP/1.0 200 OK\r\n\r\n"),
    MockRead(SYNCHRONOUS, "hello world"),
    MockRead(SYNCHRONOUS, OK),
  };

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  session_deps_.host_resolver->set_synchronous_mode(true);
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  BoundTestNetLog log;
  int rv = trans->Start(&request, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  trans.reset();  // Cancel the transaction here.

  base::RunLoop().RunUntilIdle();
}

// Test that if a transaction is cancelled after receiving the headers, the
// stream is drained properly and added back to the socket pool.  The main
// purpose of this test is to make sure that an HttpStreamParser can be read
// from after the HttpNetworkTransaction and the objects it owns have been
// deleted.
// See http://crbug.com/368418
TEST_F(HttpNetworkTransactionTest, CancelAfterHeaders) {
  MockRead data_reads[] = {
    MockRead(ASYNC, "HTTP/1.1 200 OK\r\n"),
    MockRead(ASYNC, "Content-Length: 2\r\n"),
    MockRead(ASYNC, "Connection: Keep-Alive\r\n\r\n"),
    MockRead(ASYNC, "1"),
    // 2 async reads are necessary to trigger a ReadResponseBody call after the
    // HttpNetworkTransaction has been deleted.
    MockRead(ASYNC, "2"),
    MockRead(SYNCHRONOUS, ERR_IO_PENDING),  // Should never read this.
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  {
    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");

    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
    TestCompletionCallback callback;

    int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    callback.WaitForResult();

    const HttpResponseInfo* response = trans.GetResponseInfo();
    ASSERT_TRUE(response);
    EXPECT_TRUE(response->headers);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());

    // The transaction and HttpRequestInfo are deleted.
  }

  // Let the HttpResponseBodyDrainer drain the socket.
  base::RunLoop().RunUntilIdle();

  // Socket should now be idle, waiting to be reused.
  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Test a basic GET request through a proxy.
TEST_F(HttpNetworkTransactionTest, ProxyGet) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes1[] = {
      MockWrite(
          "GET http://www.example.org/ HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Proxy-Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  BeforeHeadersSentHandler headers_handler;
  trans.SetBeforeHeadersSentCallback(
      base::Bind(&BeforeHeadersSentHandler::OnBeforeHeadersSent,
                 base::Unretained(&headers_handler)));

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(response->was_fetched_via_proxy);
  EXPECT_EQ(ProxyServer(ProxyServer::SCHEME_HTTP,
                        HostPortPair::FromString("myproxy:70")),
            response->proxy_server);
  EXPECT_TRUE(headers_handler.observed_before_headers_sent());
  EXPECT_TRUE(headers_handler.observed_before_headers_sent_with_proxy());
  EXPECT_EQ("myproxy:70", headers_handler.observed_proxy_server_uri());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_CONNECT_TIMES_ONLY);
}

// Test a basic HTTPS GET request through a proxy.
TEST_F(HttpNetworkTransactionTest, ProxyTunnelGet) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 100\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  BeforeHeadersSentHandler headers_handler;
  trans.SetBeforeHeadersSentCallback(
      base::Bind(&BeforeHeadersSentHandler::OnBeforeHeadersSent,
                 base::Unretained(&headers_handler)));

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->was_fetched_via_proxy);
  EXPECT_EQ(ProxyServer(ProxyServer::SCHEME_HTTP,
                        HostPortPair::FromString("myproxy:70")),
            response->proxy_server);
  EXPECT_TRUE(headers_handler.observed_before_headers_sent());
  EXPECT_TRUE(headers_handler.observed_before_headers_sent_with_proxy());
  EXPECT_EQ("myproxy:70", headers_handler.observed_proxy_server_uri());

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test a basic HTTPS GET request through a proxy, connecting to an IPv6
// literal host.
TEST_F(HttpNetworkTransactionTest, ProxyTunnelGetIPv6) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://[::1]:443/");

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT [::1]:443 HTTP/1.1\r\n"
                "Host: [::1]:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: [::1]\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
      MockRead("Content-Length: 100\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers->IsKeepAlive());
  EXPECT_EQ(200, response->headers->response_code());
  EXPECT_EQ(100, response->headers->GetContentLength());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(response->was_fetched_via_proxy);
  EXPECT_EQ(ProxyServer(ProxyServer::SCHEME_HTTP,
                        HostPortPair::FromString("myproxy:70")),
            response->proxy_server);

  LoadTimingInfo load_timing_info;
  EXPECT_TRUE(trans.GetLoadTimingInfo(&load_timing_info));
  TestLoadTimingNotReusedWithPac(load_timing_info,
                                 CONNECT_TIMING_HAS_SSL_TIMES);
}

// Test a basic HTTPS GET request through a proxy, but the server hangs up
// while establishing the tunnel.
TEST_F(HttpNetworkTransactionTest, ProxyTunnelGetHangup) {
  session_deps_.proxy_service = ProxyService::CreateFixed("myproxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
    MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
    MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),
    MockRead(ASYNC, 0, 0),  // EOF
  };

  StaticSocketDataProvider data1(data_reads1, arraysize(data_reads1),
                                 data_writes1, arraysize(data_writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  int rv = trans.Start(&request, callback1.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_EMPTY_RESPONSE));
  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, pos,
      NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      NetLogEventPhase::NONE);
}

// Test for crbug.com/55424.
TEST_F(HttpNetworkTransactionTest, PreconnectWithExistingSpdySession) {
  SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame data(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(data, 2), MockRead(ASYNC, 0, 3),
  };

  SequencedSocketData spdy_data(spdy_reads, arraysize(spdy_reads), spdy_writes,
                                arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Set up an initial SpdySession in the pool to reuse.
  HostPortPair host_port_pair("www.example.org", 443);
  SpdySessionKey key(host_port_pair, ProxyServer::Direct(),
                     PRIVACY_MODE_DISABLED);
  base::WeakPtr<SpdySession> spdy_session =
      CreateSpdySession(session.get(), key, NetLogWithSource());

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");

  // This is the important line that marks this as a preconnect.
  request.motivation = HttpRequestInfo::PRECONNECT_MOTIVATED;

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Given a net error, cause that error to be returned from the first Write()
// call and verify that the HttpNetworkTransaction fails with that error.
void HttpNetworkTransactionTest::CheckErrorIsPassedBack(
    int error, IoMode mode) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;

  SSLSocketDataProvider ssl_data(mode, OK);
  MockWrite data_writes[] = {
      MockWrite(mode, error),
  };
  StaticSocketDataProvider data(NULL, 0, data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  ASSERT_EQ(error, rv);
}

TEST_F(HttpNetworkTransactionTest, SSLWriteCertError) {
  // Just check a grab bag of cert errors.
  static const int kErrors[] = {
    ERR_CERT_COMMON_NAME_INVALID,
    ERR_CERT_AUTHORITY_INVALID,
    ERR_CERT_DATE_INVALID,
  };
  for (size_t i = 0; i < arraysize(kErrors); i++) {
    CheckErrorIsPassedBack(kErrors[i], ASYNC);
    CheckErrorIsPassedBack(kErrors[i], SYNCHRONOUS);
  }
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) No proxy is involved.
//  2) TLS False Start is disabled.
//  3) The initial TLS handshake requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate.
TEST_F(HttpNetworkTransactionTest, ClientAuthCertCache_Direct_NoFalseStart) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;

  scoped_refptr<SSLCertRequestInfo> cert_request(new SSLCertRequestInfo());
  cert_request->host_and_port = HostPortPair("www.example.com", 443);

  // [ssl_]data1 contains the data for the first SSL handshake. When a
  // CertificateRequest is received for the first time, the handshake will
  // be aborted to allow the caller to provide a certificate.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // [ssl_]data2 contains the data for the second SSL handshake. When TLS
  // False Start is not being used, the result of the SSL handshake will be
  // returned as part of the SSLClientSocket::Connect() call. This test
  // matches the result of a server sending a handshake_failure alert,
  // rather than a Finished message, because it requires a client
  // certificate and none was supplied.
  SSLSocketDataProvider ssl_data2(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data2.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  StaticSocketDataProvider data2(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // [ssl_]data3 contains the data for the third SSL handshake. When a
  // connection to a server fails during an SSL handshake,
  // HttpNetworkTransaction will attempt to fallback to TLSv1.1 if the previous
  // connection was attempted with TLSv1.2. This is transparent to the caller
  // of the HttpNetworkTransaction. Because this test failure is due to
  // requiring a client certificate, this fallback handshake should also
  // fail.
  SSLSocketDataProvider ssl_data3(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data3.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  // [ssl_]data4 contains the data for the fourth SSL handshake. When a
  // connection to a server fails during an SSL handshake,
  // HttpNetworkTransaction will attempt to fallback to TLSv1 if the previous
  // connection was attempted with TLSv1.1. This is transparent to the caller
  // of the HttpNetworkTransaction. Because this test failure is due to
  // requiring a client certificate, this fallback handshake should also
  // fail.
  SSLSocketDataProvider ssl_data4(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data4.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data4);
  StaticSocketDataProvider data4(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data4);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Begin the SSL handshake with the peer. This consumes ssl_data1.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Complete the SSL handshake, which should abort due to requiring a
  // client certificate.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Indicate that no certificate should be supplied. From the perspective
  // of SSLClientCertCache, NULL is just as meaningful as a real
  // certificate, so this is the same as supply a
  // legitimate-but-unacceptable certificate.
  rv = trans.RestartWithCertificate(NULL, NULL, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Ensure the certificate was added to the client auth cache before
  // allowing the connection to continue restarting.
  scoped_refptr<X509Certificate> client_cert;
  scoped_refptr<SSLPrivateKey> client_private_key;
  ASSERT_TRUE(session->ssl_client_auth_cache()->Lookup(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
  ASSERT_FALSE(client_cert);

  // Restart the handshake. This will consume ssl_data2, which fails, and
  // then consume ssl_data3 and ssl_data4, both of which should also fail.
  // The result code is checked against what ssl_data4 should return.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Ensure that the client certificate is removed from the cache on a
  // handshake failure.
  ASSERT_FALSE(session->ssl_client_auth_cache()->Lookup(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) No proxy is involved.
//  2) TLS False Start is enabled.
//  3) The initial TLS handshake requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate.
TEST_F(HttpNetworkTransactionTest, ClientAuthCertCache_Direct_FalseStart) {
  HttpRequestInfo request_info;
  request_info.url = GURL("https://www.example.com/");
  request_info.method = "GET";
  request_info.load_flags = LOAD_NORMAL;

  scoped_refptr<SSLCertRequestInfo> cert_request(new SSLCertRequestInfo());
  cert_request->host_and_port = HostPortPair("www.example.com", 443);

  // When TLS False Start is used, SSLClientSocket::Connect() calls will
  // return successfully after reading up to the peer's Certificate message.
  // This is to allow the caller to call SSLClientSocket::Write(), which can
  // enqueue application data to be sent in the same packet as the
  // ChangeCipherSpec and Finished messages.
  // The actual handshake will be finished when SSLClientSocket::Read() is
  // called, which expects to process the peer's ChangeCipherSpec and
  // Finished messages. If there was an error negotiating with the peer,
  // such as due to the peer requiring a client certificate when none was
  // supplied, the alert sent by the peer won't be processed until Read() is
  // called.

  // Like the non-False Start case, when a client certificate is requested by
  // the peer, the handshake is aborted during the Connect() call.
  // [ssl_]data1 represents the initial SSL handshake with the peer.
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // When a client certificate is supplied, Connect() will not be aborted
  // when the peer requests the certificate. Instead, the handshake will
  // artificially succeed, allowing the caller to write the HTTP request to
  // the socket. The handshake messages are not processed until Read() is
  // called, which then detects that the handshake was aborted, due to the
  // peer sending a handshake_failure because it requires a client
  // certificate.
  SSLSocketDataProvider ssl_data2(ASYNC, OK);
  ssl_data2.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  MockRead data2_reads[] = {
      MockRead(ASYNC /* async */, ERR_SSL_PROTOCOL_ERROR),
  };
  StaticSocketDataProvider data2(data2_reads, arraysize(data2_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // As described in ClientAuthCertCache_Direct_NoFalseStart, [ssl_]data3 is
  // the data for the SSL handshake once the TLSv1.1 connection falls back to
  // TLSv1. It has the same behaviour as [ssl_]data2.
  SSLSocketDataProvider ssl_data3(ASYNC, OK);
  ssl_data3.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3(data2_reads, arraysize(data2_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  // [ssl_]data4 is the data for the SSL handshake once the TLSv1 connection
  // falls back to SSLv3. It has the same behaviour as [ssl_]data2.
  SSLSocketDataProvider ssl_data4(ASYNC, OK);
  ssl_data4.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data4);
  StaticSocketDataProvider data4(data2_reads, arraysize(data2_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data4);

  // Need one more if TLSv1.2 is enabled.
  SSLSocketDataProvider ssl_data5(ASYNC, OK);
  ssl_data5.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data5);
  StaticSocketDataProvider data5(data2_reads, arraysize(data2_reads), NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data5);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  // Begin the initial SSL handshake.
  TestCompletionCallback callback;
  int rv = trans.Start(&request_info, callback.callback(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Complete the SSL handshake, which should abort due to requiring a
  // client certificate.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Indicate that no certificate should be supplied. From the perspective
  // of SSLClientCertCache, NULL is just as meaningful as a real
  // certificate, so this is the same as supply a
  // legitimate-but-unacceptable certificate.
  rv = trans.RestartWithCertificate(NULL, NULL, callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Ensure the certificate was added to the client auth cache before
  // allowing the connection to continue restarting.
  scoped_refptr<X509Certificate> client_cert;
  scoped_refptr<SSLPrivateKey> client_private_key;
  ASSERT_TRUE(session->ssl_client_auth_cache()->Lookup(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
  ASSERT_FALSE(client_cert);

  // Restart the handshake. This will consume ssl_data2, which fails, and
  // then consume ssl_data3 and ssl_data4, both of which should also fail.
  // The result code is checked against what ssl_data4 should return.
  rv = callback.WaitForResult();
  ASSERT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));

  // Ensure that the client certificate is removed from the cache on a
  // handshake failure.
  ASSERT_FALSE(session->ssl_client_auth_cache()->Lookup(
      HostPortPair("www.example.com", 443), &client_cert, &client_private_key));
}

// Ensure that a client certificate is removed from the SSL client auth
// cache when:
//  1) An HTTPS proxy is involved.
//  3) The HTTPS proxy requests a client certificate.
//  4) The client supplies an invalid/unacceptable certificate for the
//     proxy.
// The test is repeated twice, first for connecting to an HTTPS endpoint,
// then for connecting to an HTTP endpoint.
TEST_F(HttpNetworkTransactionTest, ClientAuthCertCache_Proxy_Fail) {
  session_deps_.proxy_service = ProxyService::CreateFixed("https://proxy:70");
  BoundTestNetLog log;
  session_deps_.net_log = log.bound().net_log();

  scoped_refptr<SSLCertRequestInfo> cert_request(new SSLCertRequestInfo());
  cert_request->host_and_port = HostPortPair("proxy", 70);

  // See ClientAuthCertCache_Direct_NoFalseStart for the explanation of
  // [ssl_]data[1-3]. Rather than represending the endpoint
  // (www.example.com:443), they represent failures with the HTTPS proxy
  // (proxy:70).
  SSLSocketDataProvider ssl_data1(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl_data1.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data1);
  StaticSocketDataProvider data1(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl_data2(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data2.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data2);
  StaticSocketDataProvider data2(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  // TODO(wtc): find out why this unit test doesn't need [ssl_]data3.
#if 0
  SSLSocketDataProvider ssl_data3(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl_data3.cert_request_info = cert_request.get();
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data3);
  StaticSocketDataProvider data3(NULL, 0, NULL, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
#endif

  HttpRequestInfo requests[2];
  requests[0].url = GURL("https://www.example.com/");
  requests[0].method = "GET";
  requests[0].load_flags = LOAD_NORMAL;

  requests[1].url = GURL("http://www.example.com/");
  requests[1].method = "GET";
  requests[1].load_flags = LOAD_NORMAL;

  for (size_t i = 0; i < arraysize(requests); ++i) {
    session_deps_.socket_factory->ResetNextMockIndexes();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    // Begin the SSL handshake with the proxy.
    TestCompletionCallback callback;
    int rv = trans.Start(&requests[i], callback.callback(), NetLogWithSource());
    ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

    // Complete the SSL handshake, which should abort due to requiring a
    // client certificate.
    rv = callback.WaitForResult();
    ASSERT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

    // Indicate that no certificate should be supplied. From the perspective
    // of SSLClientCertCache, NULL is just as meaningful as a real
    // certificate, so this is the same as supply a
    // legitimate-but-unacceptable certificate.
    rv = trans.RestartWithCertificate(NULL, NULL, callback.callback());
    ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

    // Ensure the certificate was added to the client auth cache before
    // allowing the connection to continue restarting.
    scoped_refptr<X509Certificate> client_cert;
    scoped_refptr<SSLPrivateKey> client_private_key;
    ASSERT_TRUE(session->ssl_client_auth_cache()->Lookup(
        HostPortPair("proxy", 70), &client_cert, &client_private_key));
    ASSERT_FALSE(client_cert);
    // Ensure the certificate was NOT cached for the endpoint. This only
    // applies to HTTPS requests, but is fine to check for HTTP requests.
    ASSERT_FALSE(session->ssl_client_auth_cache()->Lookup(
        HostPortPair("www.example.com", 443), &client_cert,
        &client_private_key));

    // Restart the handshake. This will consume ssl_data2, which fails, and
    // then consume ssl_data3, which should also fail. The result code is
    // checked against what ssl_data3 should return.
    rv = callback.WaitForResult();
    ASSERT_THAT(rv, IsError(ERR_PROXY_CONNECTION_FAILED));

    // Now that the new handshake has failed, ensure that the client
    // certificate was removed from the client auth cache.
    ASSERT_FALSE(session->ssl_client_auth_cache()->Lookup(
        HostPortPair("proxy", 70), &client_cert, &client_private_key));
    ASSERT_FALSE(session->ssl_client_auth_cache()->Lookup(
        HostPortPair("www.example.com", 443), &client_cert,
        &client_private_key));
  }
}

TEST_F(HttpNetworkTransactionTest, UseIPConnectionPooling) {
  // Set up a special HttpNetworkSession with a MockCachingHostResolver.
  session_deps_.host_resolver = base::MakeUnique<MockCachingHostResolver>();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  AddSSLSocketData();

  SpdySerializedFrame host1_req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame host2_req(
      spdy_util_.ConstructSpdyGet("https://mail.example.com", 3, LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(host1_req, 0), CreateMockWrite(host2_req, 3),
  };
  SpdySerializedFrame host1_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame host1_resp_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame host2_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame host2_resp_body(
      spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(host1_resp, 1), CreateMockRead(host1_resp_body, 2),
      CreateMockRead(host2_resp, 4), CreateMockRead(host2_resp_body, 5),
      MockRead(ASYNC, 0, 6),
  };

  IPEndPoint peer_addr(IPAddress::IPv4Localhost(), 443);
  MockConnect connect(ASYNC, OK, peer_addr);
  SequencedSocketData spdy_data(connect, spdy_reads, arraysize(spdy_reads),
                                spdy_writes, arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  // Preload mail.example.com into HostCache.
  HostPortPair host_port("mail.example.com", 443);
  HostResolver::RequestInfo resolve_info(host_port);
  AddressList ignored;
  std::unique_ptr<HostResolver::Request> request;
  rv = session_deps_.host_resolver->Resolve(resolve_info, DEFAULT_PRIORITY,
                                            &ignored, callback.callback(),
                                            &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.com/");
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_F(HttpNetworkTransactionTest, UseIPConnectionPoolingAfterResolution) {
  // Set up a special HttpNetworkSession with a MockCachingHostResolver.
  session_deps_.host_resolver = base::MakeUnique<MockCachingHostResolver>();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  AddSSLSocketData();

  SpdySerializedFrame host1_req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame host2_req(
      spdy_util_.ConstructSpdyGet("https://mail.example.com", 3, LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(host1_req, 0), CreateMockWrite(host2_req, 3),
  };
  SpdySerializedFrame host1_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame host1_resp_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame host2_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame host2_resp_body(
      spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(host1_resp, 1), CreateMockRead(host1_resp_body, 2),
      CreateMockRead(host2_resp, 4), CreateMockRead(host2_resp_body, 5),
      MockRead(ASYNC, 0, 6),
  };

  IPEndPoint peer_addr(IPAddress::IPv4Localhost(), 443);
  MockConnect connect(ASYNC, OK, peer_addr);
  SequencedSocketData spdy_data(connect, spdy_reads, arraysize(spdy_reads),
                                spdy_writes, arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.com/");
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

// Regression test for https://crbug.com/546991.
// The server might not be able to serve an IP pooled request, and might send a
// 421 Misdirected Request response status to indicate this.
// HttpNetworkTransaction should reset the request and retry without IP pooling.
TEST_F(HttpNetworkTransactionTest, RetryWithoutConnectionPooling) {
  // Two hosts resolve to the same IP address.
  const std::string ip_addr = "1.2.3.4";
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);

  session_deps_.host_resolver = base::MakeUnique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("www.example.org", ip_addr);
  session_deps_.host_resolver->rules()->AddRule("mail.example.org", ip_addr);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Two requests on the first connection.
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://mail.example.org", 3, LOWEST));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(3, ERROR_CODE_CANCEL));
  MockWrite writes1[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 3),
      CreateMockWrite(rst, 6),
  };

  // The first one succeeds, the second gets error 421 Misdirected Request.
  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdyHeaderBlock response_headers;
  response_headers[SpdyTestUtil::GetStatusKey()] = "421";
  SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyReply(3, std::move(response_headers)));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       CreateMockRead(resp2, 4), MockRead(ASYNC, 0, 5)};

  MockConnect connect1(ASYNC, OK, peer_addr);
  SequencedSocketData data1(connect1, reads1, arraysize(reads1), writes1,
                            arraysize(writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  // Retry the second request on a second connection.
  SpdyTestUtil spdy_util2;
  SpdySerializedFrame req3(
      spdy_util2.ConstructSpdyGet("https://mail.example.org", 1, LOWEST));
  MockWrite writes2[] = {
      CreateMockWrite(req3, 0),
  };

  SpdySerializedFrame resp3(spdy_util2.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body3(spdy_util2.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp3, 1), CreateMockRead(body3, 2),
                       MockRead(ASYNC, 0, 3)};

  MockConnect connect2(ASYNC, OK, peer_addr);
  SequencedSocketData data2(connect2, reads2, arraysize(reads2), writes2,
                            arraysize(writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  AddSSLSocketData();

  // Preload mail.example.org into HostCache.
  HostPortPair host_port("mail.example.org", 443);
  HostResolver::RequestInfo resolve_info(host_port);
  AddressList ignored;
  std::unique_ptr<HostResolver::Request> request;
  TestCompletionCallback callback;
  int rv = session_deps_.host_resolver->Resolve(resolve_info, DEFAULT_PRIORITY,
                                                &ignored, callback.callback(),
                                                &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  BoundTestNetLog log;
  rv = trans2.Start(&request2, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_RESTART_MISDIRECTED_REQUEST,
      NetLogEventPhase::NONE);
}

// Test that HTTP 421 responses are properly returned to the caller if received
// on the retry as well. HttpNetworkTransaction should not infinite loop or lose
// portions of the response.
TEST_F(HttpNetworkTransactionTest, ReturnHTTP421OnRetry) {
  // Two hosts resolve to the same IP address.
  const std::string ip_addr = "1.2.3.4";
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);

  session_deps_.host_resolver = base::MakeUnique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("www.example.org", ip_addr);
  session_deps_.host_resolver->rules()->AddRule("mail.example.org", ip_addr);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Two requests on the first connection.
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet("https://mail.example.org", 3, LOWEST));
  SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(3, ERROR_CODE_CANCEL));
  MockWrite writes1[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 3),
      CreateMockWrite(rst, 6),
  };

  // The first one succeeds, the second gets error 421 Misdirected Request.
  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdyHeaderBlock response_headers;
  response_headers[SpdyTestUtil::GetStatusKey()] = "421";
  SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyReply(3, response_headers.Clone()));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       CreateMockRead(resp2, 4), MockRead(ASYNC, 0, 5)};

  MockConnect connect1(ASYNC, OK, peer_addr);
  SequencedSocketData data1(connect1, reads1, arraysize(reads1), writes1,
                            arraysize(writes1));
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  // Retry the second request on a second connection. It returns 421 Misdirected
  // Retry again.
  SpdyTestUtil spdy_util2;
  SpdySerializedFrame req3(
      spdy_util2.ConstructSpdyGet("https://mail.example.org", 1, LOWEST));
  MockWrite writes2[] = {
      CreateMockWrite(req3, 0),
  };

  SpdySerializedFrame resp3(
      spdy_util2.ConstructSpdyReply(1, std::move(response_headers)));
  SpdySerializedFrame body3(spdy_util2.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp3, 1), CreateMockRead(body3, 2),
                       MockRead(ASYNC, 0, 3)};

  MockConnect connect2(ASYNC, OK, peer_addr);
  SequencedSocketData data2(connect2, reads2, arraysize(reads2), writes2,
                            arraysize(writes2));
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  AddSSLSocketData();

  // Preload mail.example.org into HostCache.
  HostPortPair host_port("mail.example.org", 443);
  HostResolver::RequestInfo resolve_info(host_port);
  AddressList ignored;
  std::unique_ptr<HostResolver::Request> request;
  TestCompletionCallback callback;
  int rv = session_deps_.host_resolver->Resolve(resolve_info, DEFAULT_PRIORITY,
                                                &ignored, callback.callback(),
                                                &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.org/");
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  BoundTestNetLog log;
  rv = trans2.Start(&request2, callback.callback(), log.bound());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  // After a retry, the 421 Misdirected Request is reported back up to the
  // caller.
  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 421", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  EXPECT_TRUE(response->ssl_info.cert);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

class OneTimeCachingHostResolver : public MockHostResolverBase {
 public:
  explicit OneTimeCachingHostResolver(const HostPortPair& host_port)
      : MockHostResolverBase(/* use_caching = */ true), host_port_(host_port) {}
  ~OneTimeCachingHostResolver() override {}

  int ResolveFromCache(const RequestInfo& info,
                       AddressList* addresses,
                       const NetLogWithSource& net_log) override {
    int rv = MockHostResolverBase::ResolveFromCache(info, addresses, net_log);
    if (rv == OK && info.host_port_pair().Equals(host_port_))
      GetHostCache()->clear();
    return rv;
  }

 private:
  const HostPortPair host_port_;
};

TEST_F(HttpNetworkTransactionTest,
       UseIPConnectionPoolingWithHostCacheExpiration) {
  // Set up a special HttpNetworkSession with a OneTimeCachingHostResolver.
  session_deps_.host_resolver = base::MakeUnique<OneTimeCachingHostResolver>(
      HostPortPair("mail.example.com", 443));
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  AddSSLSocketData();

  SpdySerializedFrame host1_req(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  spdy_util_.UpdateWithStreamDestruction(1);
  SpdySerializedFrame host2_req(
      spdy_util_.ConstructSpdyGet("https://mail.example.com", 3, LOWEST));
  MockWrite spdy_writes[] = {
      CreateMockWrite(host1_req, 0), CreateMockWrite(host2_req, 3),
  };
  SpdySerializedFrame host1_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame host1_resp_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame host2_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame host2_resp_body(
      spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead spdy_reads[] = {
      CreateMockRead(host1_resp, 1), CreateMockRead(host1_resp_body, 2),
      CreateMockRead(host2_resp, 4), CreateMockRead(host2_resp_body, 5),
      MockRead(ASYNC, 0, 6),
  };

  IPEndPoint peer_addr(IPAddress::IPv4Localhost(), 443);
  MockConnect connect(ASYNC, OK, peer_addr);
  SequencedSocketData spdy_data(connect, spdy_reads, arraysize(spdy_reads),
                                spdy_writes, arraysize(spdy_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&spdy_data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/");
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());

  int rv = trans1.Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  // Preload cache entries into HostCache.
  HostResolver::RequestInfo resolve_info(HostPortPair("mail.example.com", 443));
  AddressList ignored;
  std::unique_ptr<HostResolver::Request> request;
  rv = session_deps_.host_resolver->Resolve(resolve_info, DEFAULT_PRIORITY,
                                            &ignored, callback.callback(),
                                            &request, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://mail.example.com/");
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());

  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans2.GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(&trans2, &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
}

TEST_F(HttpNetworkTransactionTest, DoNotUseSpdySessionForHttp) {
  const std::string https_url = "https://www.example.org:8080/";
  const std::string http_url = "http://www.example.org:8080/";

  // SPDY GET for HTTPS URL
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(https_url.c_str(), 1, LOWEST));

  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
  };

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3)};

  SequencedSocketData data1(reads1, arraysize(reads1), writes1,
                            arraysize(writes1));
  MockConnect connect_data1(ASYNC, OK);
  data1.set_connect_data(connect_data1);

  // HTTP GET for the HTTP URL
  MockWrite writes2[] = {
      MockWrite(ASYNC, 0,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org:8080\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead reads2[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"),
      MockRead(ASYNC, 2, "hello"),
      MockRead(ASYNC, OK, 3),
  };

  SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                            arraysize(writes2));

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the first transaction to set up the SpdySession
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(https_url);
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(LOWEST, session.get());
  TestCompletionCallback callback1;
  EXPECT_EQ(ERR_IO_PENDING,
            trans1.Start(&request1, callback1.callback(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(trans1.GetResponseInfo()->was_fetched_via_spdy);

  // Now, start the HTTP request
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(http_url);
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            trans2.Start(&request2, callback2.callback(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(trans2.GetResponseInfo()->was_fetched_via_spdy);
}

// Alternative service requires HTTP/2 (or SPDY), but HTTP/1.1 is negotiated
// with the alternative server.  That connection should not be used.
TEST_F(HttpNetworkTransactionTest, AlternativeServiceNotOnHttp11) {
  url::SchemeHostPort server("https", "www.example.org", 443);
  HostPortPair alternative("www.example.org", 444);

  // Negotiate HTTP/1.1 with alternative.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // No data should be read from the alternative, because HTTP/1.1 is
  // negotiated.
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // This test documents that an alternate Job should not be used if HTTP/1.1 is
  // negotiated.  In order to test this, a failed connection to the server is
  // mocked.  This way the request relies on the alternate Job.
  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  // Set up alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      server, alternative_service, expiration);

  HttpRequestInfo request;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  request.method = "GET";
  request.url = GURL("https://www.example.org:443");
  TestCompletionCallback callback;

  // HTTP/2 (or SPDY) is required for alternative service, if HTTP/1.1 is
  // negotiated, the alternate Job should fail with ERR_ALPN_NEGOTIATION_FAILED.
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_ALPN_NEGOTIATION_FAILED));
}

// A request to a server with an alternative service fires two Jobs: one to the
// server, and an alternate one to the alternative server.  If the former
// succeeds, the request should succeed,  even if the latter fails because
// HTTP/1.1 is negotiated which is insufficient for alternative service.
TEST_F(HttpNetworkTransactionTest, FailedAlternativeServiceIsNotUserVisible) {
  url::SchemeHostPort server("https", "www.example.org", 443);
  HostPortPair alternative("www.example.org", 444);

  // Negotiate HTTP/1.1 with alternative.
  SSLSocketDataProvider alternative_ssl(ASYNC, OK);
  alternative_ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&alternative_ssl);

  // No data should be read from the alternative, because HTTP/1.1 is
  // negotiated.
  StaticSocketDataProvider data;
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Negotiate HTTP/1.1 with server.
  SSLSocketDataProvider origin_ssl(ASYNC, OK);
  origin_ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&origin_ssl);

  MockWrite http_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
      MockWrite("GET /second HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html\r\n"),
      MockRead("Content-Length: 6\r\n\r\n"),
      MockRead("foobar"),
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Type: text/html\r\n"),
      MockRead("Content-Length: 7\r\n\r\n"),
      MockRead("another"),
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  // Set up alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      server, alternative_service, expiration);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org:443");
  request1.load_flags = 0;
  TestCompletionCallback callback1;

  int rv = trans1.Start(&request1, callback1.callback(), NetLogWithSource());
  rv = callback1.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response1->headers->GetStatusLine());

  std::string response_data1;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data1), IsOk());
  EXPECT_EQ("foobar", response_data1);

  // Alternative should be marked as broken, because HTTP/1.1 is not sufficient
  // for alternative service.
  EXPECT_TRUE(
      http_server_properties->IsAlternativeServiceBroken(alternative_service));

  // Since |alternative_service| is broken, a second transaction to server
  // should not start an alternate Job.  It should pool to existing connection
  // to server.
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org:443/second");
  request2.load_flags = 0;
  TestCompletionCallback callback2;

  rv = trans2.Start(&request2, callback2.callback(), NetLogWithSource());
  rv = callback2.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response2->headers->GetStatusLine());

  std::string response_data2;
  ASSERT_THAT(ReadTransaction(&trans2, &response_data2), IsOk());
  EXPECT_EQ("another", response_data2);
}

// Alternative service requires HTTP/2 (or SPDY), but there is already a
// HTTP/1.1 socket open to the alternative server.  That socket should not be
// used.
TEST_F(HttpNetworkTransactionTest, AlternativeServiceShouldNotPoolToHttp11) {
  url::SchemeHostPort server("https", "origin.example.org", 443);
  HostPortPair alternative("alternative.example.org", 443);
  std::string origin_url = "https://origin.example.org:443";
  std::string alternative_url = "https://alternative.example.org:443";

  // Negotiate HTTP/1.1 with alternative.example.org.
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // HTTP/1.1 data for |request1| and |request2|.
  MockWrite http_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: alternative.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: alternative.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_reads[] = {
      MockRead(
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: text/html; charset=iso-8859-1\r\n"
          "Content-Length: 40\r\n\r\n"
          "first HTTP/1.1 response from alternative"),
      MockRead(
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: text/html; charset=iso-8859-1\r\n"
          "Content-Length: 41\r\n\r\n"
          "second HTTP/1.1 response from alternative"),
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  // This test documents that an alternate Job should not pool to an already
  // existing HTTP/1.1 connection.  In order to test this, a failed connection
  // to the server is mocked.  This way |request2| relies on the alternate Job.
  StaticSocketDataProvider data_refused;
  data_refused.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  session_deps_.socket_factory->AddSocketDataProvider(&data_refused);

  // Set up alternative service for server.
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpServerProperties* http_server_properties =
      session->http_server_properties();
  AlternativeService alternative_service(kProtoHTTP2, alternative);
  base::Time expiration = base::Time::Now() + base::TimeDelta::FromDays(1);
  http_server_properties->SetHttp2AlternativeService(
      server, alternative_service, expiration);

  // First transaction to alternative to open an HTTP/1.1 socket.
  HttpRequestInfo request1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, session.get());
  request1.method = "GET";
  request1.url = GURL(alternative_url);
  request1.load_flags = 0;
  TestCompletionCallback callback1;

  int rv = trans1.Start(&request1, callback1.callback(), NetLogWithSource());
  EXPECT_THAT(callback1.GetResult(rv), IsOk());
  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response1->headers->GetStatusLine());
  EXPECT_TRUE(response1->was_alpn_negotiated);
  EXPECT_FALSE(response1->was_fetched_via_spdy);
  std::string response_data1;
  ASSERT_THAT(ReadTransaction(&trans1, &response_data1), IsOk());
  EXPECT_EQ("first HTTP/1.1 response from alternative", response_data1);

  // Request for origin.example.org, which has an alternative service.  This
  // will start two Jobs: the alternative looks for connections to pool to,
  // finds one which is HTTP/1.1, and should ignore it, and should not try to
  // open other connections to alternative server.  The Job to server fails, so
  // this request fails.
  HttpRequestInfo request2;
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  request2.method = "GET";
  request2.url = GURL(origin_url);
  request2.load_flags = 0;
  TestCompletionCallback callback2;

  rv = trans2.Start(&request2, callback2.callback(), NetLogWithSource());
  EXPECT_THAT(callback2.GetResult(rv), IsError(ERR_CONNECTION_REFUSED));

  // Another transaction to alternative.  This is to test that the HTTP/1.1
  // socket is still open and in the pool.
  HttpRequestInfo request3;
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, session.get());
  request3.method = "GET";
  request3.url = GURL(alternative_url);
  request3.load_flags = 0;
  TestCompletionCallback callback3;

  rv = trans3.Start(&request3, callback3.callback(), NetLogWithSource());
  EXPECT_THAT(callback3.GetResult(rv), IsOk());
  const HttpResponseInfo* response3 = trans3.GetResponseInfo();
  ASSERT_TRUE(response3);
  ASSERT_TRUE(response3->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response3->headers->GetStatusLine());
  EXPECT_TRUE(response3->was_alpn_negotiated);
  EXPECT_FALSE(response3->was_fetched_via_spdy);
  std::string response_data3;
  ASSERT_THAT(ReadTransaction(&trans3, &response_data3), IsOk());
  EXPECT_EQ("second HTTP/1.1 response from alternative", response_data3);
}

TEST_F(HttpNetworkTransactionTest, DoNotUseSpdySessionForHttpOverTunnel) {
  const std::string https_url = "https://www.example.org:8080/";
  const std::string http_url = "http://www.example.org:8080/";

  // Separate SPDY util instance for naked and wrapped requests.
  SpdyTestUtil spdy_util_wrapped;

  // SPDY GET for HTTPS URL (through CONNECT tunnel)
  const HostPortPair host_port_pair("www.example.org", 8080);
  SpdySerializedFrame connect(
      spdy_util_.ConstructSpdyConnect(NULL, 0, 1, LOWEST, host_port_pair));
  SpdySerializedFrame req1(
      spdy_util_wrapped.ConstructSpdyGet(https_url.c_str(), 1, LOWEST));
  SpdySerializedFrame wrapped_req1(
      spdy_util_.ConstructWrappedSpdyFrame(req1, 1));

  // SPDY GET for HTTP URL (through the proxy, but not the tunnel).
  SpdyHeaderBlock req2_block;
  req2_block[spdy_util_.GetMethodKey()] = "GET";
  req2_block[spdy_util_.GetHostKey()] = "www.example.org:8080";
  req2_block[spdy_util_.GetSchemeKey()] = "http";
  req2_block[spdy_util_.GetPathKey()] = "/";
  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyHeaders(3, std::move(req2_block), MEDIUM, true));

  MockWrite writes1[] = {
      CreateMockWrite(connect, 0), CreateMockWrite(wrapped_req1, 2),
      CreateMockWrite(req2, 6),
  };

  SpdySerializedFrame conn_resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame resp1(
      spdy_util_wrapped.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body1(spdy_util_wrapped.ConstructSpdyDataFrame(1, true));
  SpdySerializedFrame wrapped_resp1(
      spdy_util_wrapped.ConstructWrappedSpdyFrame(resp1, 1));
  SpdySerializedFrame wrapped_body1(
      spdy_util_wrapped.ConstructWrappedSpdyFrame(body1, 1));
  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 3));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, true));
  MockRead reads1[] = {
      CreateMockRead(conn_resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_resp1, 4),
      CreateMockRead(wrapped_body1, 5),
      MockRead(ASYNC, ERR_IO_PENDING, 7),
      CreateMockRead(resp2, 8),
      CreateMockRead(body2, 9),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 10),
  };

  SequencedSocketData data1(reads1, arraysize(reads1), writes1,
                            arraysize(writes1));
  MockConnect connect_data1(ASYNC, OK);
  data1.set_connect_data(connect_data1);

  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("HTTPS proxy:70");
  TestNetLog log;
  session_deps_.net_log = &log;
  SSLSocketDataProvider ssl1(ASYNC, OK);  // to the proxy
  ssl1.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  SSLSocketDataProvider ssl2(ASYNC, OK);  // to the server
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Start the first transaction to set up the SpdySession
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(https_url);
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(LOWEST, session.get());
  TestCompletionCallback callback1;
  int rv = trans1.Start(&request1, callback1.callback(), NetLogWithSource());

  // This pause is a hack to avoid running into https://crbug.com/497228.
  data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  data1.Resume();
  EXPECT_THAT(callback1.GetResult(rv), IsOk());
  EXPECT_TRUE(trans1.GetResponseInfo()->was_fetched_via_spdy);

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans1.GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReusedWithPac(load_timing_info1,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  // Now, start the HTTP request.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(http_url);
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), NetLogWithSource());

  // This pause is a hack to avoid running into https://crbug.com/497228.
  data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  data1.Resume();
  EXPECT_THAT(callback2.GetResult(rv), IsOk());

  EXPECT_TRUE(trans2.GetResponseInfo()->was_fetched_via_spdy);

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2.GetLoadTimingInfo(&load_timing_info2));
  // The established SPDY sessions is considered reused by the HTTP request.
  TestLoadTimingReusedWithPac(load_timing_info2);
  // HTTP requests over a SPDY session should have a different connection
  // socket_log_id than requests over a tunnel.
  EXPECT_NE(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);
}

// Test that in the case where we have a SPDY session to a SPDY proxy
// that we do not pool other origins that resolve to the same IP when
// the certificate does not match the new origin.
// http://crbug.com/134690
TEST_F(HttpNetworkTransactionTest, DoNotUseSpdySessionIfCertDoesNotMatch) {
  const std::string url1 = "http://www.example.org/";
  const std::string url2 = "https://news.example.org/";
  const std::string ip_addr = "1.2.3.4";

  // Second SpdyTestUtil instance for the second socket.
  SpdyTestUtil spdy_util_secure;

  // SPDY GET for HTTP URL (through SPDY proxy)
  SpdyHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlockForProxy("http://www.example.org/"));
  SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));

  MockWrite writes1[] = {
      CreateMockWrite(req1, 0),
  };

  SpdySerializedFrame resp1(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(resp1, 2),
      CreateMockRead(body1, 3), MockRead(ASYNC, OK, 4),  // EOF
  };

  SequencedSocketData data1(reads1, arraysize(reads1), writes1,
                            arraysize(writes1));
  IPAddress ip;
  ASSERT_TRUE(ip.AssignFromIPLiteral(ip_addr));
  IPEndPoint peer_addr = IPEndPoint(ip, 443);
  MockConnect connect_data1(ASYNC, OK, peer_addr);
  data1.set_connect_data(connect_data1);

  // SPDY GET for HTTPS URL (direct)
  SpdySerializedFrame req2(
      spdy_util_secure.ConstructSpdyGet(url2.c_str(), 1, MEDIUM));

  MockWrite writes2[] = {
      CreateMockWrite(req2, 0),
  };

  SpdySerializedFrame resp2(spdy_util_secure.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body2(spdy_util_secure.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {CreateMockRead(resp2, 1), CreateMockRead(body2, 2),
                       MockRead(ASYNC, OK, 3)};

  SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                            arraysize(writes2));
  MockConnect connect_data2(ASYNC, OK);
  data2.set_connect_data(connect_data2);

  // Set up a proxy config that sends HTTP requests to a proxy, and
  // all others direct.
  ProxyConfig proxy_config;
  proxy_config.proxy_rules().ParseFromString("http=https://proxy:443");
  session_deps_.proxy_service = base::MakeUnique<ProxyService>(
      base::MakeUnique<ProxyConfigServiceFixed>(proxy_config), nullptr,
      nullptr);

  SSLSocketDataProvider ssl1(ASYNC, OK);  // to the proxy
  ssl1.next_proto = kProtoHTTP2;
  // Load a valid cert.  Note, that this does not need to
  // be valid for proxy because the MockSSLClientSocket does
  // not actually verify it.  But SpdySession will use this
  // to see if it is valid for the new origin
  ssl1.cert = ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(ssl1.cert);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl2(ASYNC, OK);  // to the server
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  session_deps_.host_resolver = base::MakeUnique<MockCachingHostResolver>();
  session_deps_.host_resolver->rules()->AddRule("news.example.org", ip_addr);
  session_deps_.host_resolver->rules()->AddRule("proxy", ip_addr);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Start the first transaction to set up the SpdySession
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(url1);
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(LOWEST, session.get());
  TestCompletionCallback callback1;
  ASSERT_EQ(ERR_IO_PENDING,
            trans1.Start(&request1, callback1.callback(), NetLogWithSource()));
  // This pause is a hack to avoid running into https://crbug.com/497228.
  data1.RunUntilPaused();
  base::RunLoop().RunUntilIdle();
  data1.Resume();

  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_TRUE(trans1.GetResponseInfo()->was_fetched_via_spdy);

  // Now, start the HTTP request
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(url2);
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            trans2.Start(&request2, callback2.callback(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();

  ASSERT_TRUE(callback2.have_result());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_TRUE(trans2.GetResponseInfo()->was_fetched_via_spdy);
}

// Test to verify that a failed socket read (due to an ERR_CONNECTION_CLOSED
// error) in SPDY session, removes the socket from pool and closes the SPDY
// session. Verify that new url's from the same HttpNetworkSession (and a new
// SpdySession) do work. http://crbug.com/224701
TEST_F(HttpNetworkTransactionTest, ErrorSocketNotConnected) {
  const std::string https_url = "https://www.example.org/";

  MockRead reads1[] = {
    MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED, 0)
  };

  SequencedSocketData data1(reads1, arraysize(reads1), NULL, 0);

  SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(https_url.c_str(), 1, MEDIUM));
  MockWrite writes2[] = {
      CreateMockWrite(req2, 0),
  };

  SpdySerializedFrame resp2(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads2[] = {
      CreateMockRead(resp2, 1), CreateMockRead(body2, 2),
      MockRead(ASYNC, OK, 3)  // EOF
  };

  SequencedSocketData data2(reads2, arraysize(reads2), writes2,
                            arraysize(writes2));

  SSLSocketDataProvider ssl1(ASYNC, OK);
  ssl1.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps_));

  // Start the first transaction to set up the SpdySession and verify that
  // connection was closed.
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL(https_url);
  request1.load_flags = 0;
  HttpNetworkTransaction trans1(MEDIUM, session.get());
  TestCompletionCallback callback1;
  EXPECT_EQ(ERR_IO_PENDING,
            trans1.Start(&request1, callback1.callback(), NetLogWithSource()));
  EXPECT_THAT(callback1.WaitForResult(), IsError(ERR_CONNECTION_CLOSED));

  // Now, start the second request and make sure it succeeds.
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL(https_url);
  request2.load_flags = 0;
  HttpNetworkTransaction trans2(MEDIUM, session.get());
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            trans2.Start(&request2, callback2.callback(), NetLogWithSource()));

  ASSERT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_TRUE(trans2.GetResponseInfo()->was_fetched_via_spdy);
}

TEST_F(HttpNetworkTransactionTest, CloseIdleSpdySessionToOpenNewOne) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Use two different hosts with different IPs so they don't get pooled.
  session_deps_.host_resolver->rules()->AddRule("www.a.com", "10.0.0.1");
  session_deps_.host_resolver->rules()->AddRule("www.b.com", "10.0.0.2");
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  SSLSocketDataProvider ssl1(ASYNC, OK);
  ssl1.next_proto = kProtoHTTP2;
  SSLSocketDataProvider ssl2(ASYNC, OK);
  ssl2.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl1);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  SpdySerializedFrame host1_req(
      spdy_util_.ConstructSpdyGet("https://www.a.com", 1, DEFAULT_PRIORITY));
  MockWrite spdy1_writes[] = {
      CreateMockWrite(host1_req, 0),
  };
  SpdySerializedFrame host1_resp(spdy_util_.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame host1_resp_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead spdy1_reads[] = {
      CreateMockRead(host1_resp, 1), CreateMockRead(host1_resp_body, 2),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),
  };

  // Use a separate test instance for the separate SpdySession that will be
  // created.
  SpdyTestUtil spdy_util_2;
  auto spdy1_data = base::MakeUnique<SequencedSocketData>(
      spdy1_reads, arraysize(spdy1_reads), spdy1_writes,
      arraysize(spdy1_writes));
  session_deps_.socket_factory->AddSocketDataProvider(spdy1_data.get());

  SpdySerializedFrame host2_req(
      spdy_util_2.ConstructSpdyGet("https://www.b.com", 1, DEFAULT_PRIORITY));
  MockWrite spdy2_writes[] = {
      CreateMockWrite(host2_req, 0),
  };
  SpdySerializedFrame host2_resp(spdy_util_2.ConstructSpdyGetReply(NULL, 0, 1));
  SpdySerializedFrame host2_resp_body(
      spdy_util_2.ConstructSpdyDataFrame(1, true));
  MockRead spdy2_reads[] = {
      CreateMockRead(host2_resp, 1), CreateMockRead(host2_resp_body, 2),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3),
  };

  auto spdy2_data = base::MakeUnique<SequencedSocketData>(
      spdy2_reads, arraysize(spdy2_reads), spdy2_writes,
      arraysize(spdy2_writes));
  session_deps_.socket_factory->AddSocketDataProvider(spdy2_data.get());

  MockWrite http_write[] = {
    MockWrite("GET / HTTP/1.1\r\n"
              "Host: www.a.com\r\n"
              "Connection: keep-alive\r\n\r\n"),
  };

  MockRead http_read[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Type: text/html; charset=iso-8859-1\r\n"),
    MockRead("Content-Length: 6\r\n\r\n"),
    MockRead("hello!"),
  };
  StaticSocketDataProvider http_data(http_read, arraysize(http_read),
                                     http_write, arraysize(http_write));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  HostPortPair host_port_pair_a("www.a.com", 443);
  SpdySessionKey spdy_session_key_a(
      host_port_pair_a, ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.a.com/");
  request1.load_flags = 0;
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);

  std::string response_data;
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  trans.reset();
  EXPECT_TRUE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));

  HostPortPair host_port_pair_b("www.b.com", 443);
  SpdySessionKey spdy_session_key_b(
      host_port_pair_b, ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_b));
  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.b.com/");
  request2.load_flags = 0;
  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));
  EXPECT_TRUE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_b));

  HostPortPair host_port_pair_a1("www.a.com", 80);
  SpdySessionKey spdy_session_key_a1(
      host_port_pair_a1, ProxyServer::Direct(), PRIVACY_MODE_DISABLED);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a1));
  HttpRequestInfo request3;
  request3.method = "GET";
  request3.url = GURL("http://www.a.com/");
  request3.load_flags = 0;
  trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans->Start(&request3, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
  EXPECT_FALSE(response->was_fetched_via_spdy);
  EXPECT_FALSE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(trans.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_a));
  EXPECT_FALSE(
      HasSpdySession(session->spdy_session_pool(), spdy_session_key_b));
}

TEST_F(HttpNetworkTransactionTest, HttpSyncConnectError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockConnect mock_connect(SYNCHRONOUS, ERR_NAME_NOT_RESOLVED);
  StaticSocketDataProvider data;
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));

  // We don't care whether this succeeds or fails, but it shouldn't crash.
  HttpRequestHeaders request_headers;
  trans.GetFullRequestHeaders(&request_headers);

  ConnectionAttempts attempts;
  trans.GetConnectionAttempts(&attempts);
  ASSERT_EQ(1u, attempts.size());
  EXPECT_THAT(attempts[0].result, IsError(ERR_NAME_NOT_RESOLVED));

  IPEndPoint endpoint;
  EXPECT_FALSE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_TRUE(endpoint.address().empty());
}

TEST_F(HttpNetworkTransactionTest, HttpAsyncConnectError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockConnect mock_connect(ASYNC, ERR_NAME_NOT_RESOLVED);
  StaticSocketDataProvider data;
  data.set_connect_data(mock_connect);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_NAME_NOT_RESOLVED));

  // We don't care whether this succeeds or fails, but it shouldn't crash.
  HttpRequestHeaders request_headers;
  trans.GetFullRequestHeaders(&request_headers);

  ConnectionAttempts attempts;
  trans.GetConnectionAttempts(&attempts);
  ASSERT_EQ(1u, attempts.size());
  EXPECT_THAT(attempts[0].result, IsError(ERR_NAME_NOT_RESOLVED));

  IPEndPoint endpoint;
  EXPECT_FALSE(trans.GetRemoteEndpoint(&endpoint));
  EXPECT_TRUE(endpoint.address().empty());
}

TEST_F(HttpNetworkTransactionTest, HttpSyncWriteError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };
  MockRead data_reads[] = {
    MockRead(SYNCHRONOUS, ERR_UNEXPECTED),  // Should not be reached.
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  HttpRequestHeaders request_headers;
  EXPECT_TRUE(trans.GetFullRequestHeaders(&request_headers));
  EXPECT_TRUE(request_headers.HasHeader("Host"));
}

TEST_F(HttpNetworkTransactionTest, HttpAsyncWriteError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
    MockWrite(ASYNC, ERR_CONNECTION_RESET),
  };
  MockRead data_reads[] = {
    MockRead(SYNCHRONOUS, ERR_UNEXPECTED),  // Should not be reached.
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  HttpRequestHeaders request_headers;
  EXPECT_TRUE(trans.GetFullRequestHeaders(&request_headers));
  EXPECT_TRUE(request_headers.HasHeader("Host"));
}

TEST_F(HttpNetworkTransactionTest, HttpSyncReadError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
    MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  HttpRequestHeaders request_headers;
  EXPECT_TRUE(trans.GetFullRequestHeaders(&request_headers));
  EXPECT_TRUE(request_headers.HasHeader("Host"));
}

TEST_F(HttpNetworkTransactionTest, HttpAsyncReadError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
    MockRead(ASYNC, ERR_CONNECTION_RESET),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  HttpRequestHeaders request_headers;
  EXPECT_TRUE(trans.GetFullRequestHeaders(&request_headers));
  EXPECT_TRUE(request_headers.HasHeader("Host"));
}

TEST_F(HttpNetworkTransactionTest, GetFullRequestHeadersIncludesExtraHeader) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.extra_headers.SetHeader("X-Foo", "bar");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n"
          "X-Foo: bar\r\n\r\n"),
  };
  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"
             "Content-Length: 5\r\n\r\n"
             "hello"),
    MockRead(ASYNC, ERR_UNEXPECTED),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads),
                                data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  HttpRequestHeaders request_headers;
  EXPECT_TRUE(trans.GetFullRequestHeaders(&request_headers));
  std::string foo;
  EXPECT_TRUE(request_headers.GetHeader("X-Foo", &foo));
  EXPECT_EQ("bar", foo);
}

namespace {

// Fake HttpStream that simply records calls to SetPriority().
class FakeStream : public HttpStream,
                   public base::SupportsWeakPtr<FakeStream> {
 public:
  explicit FakeStream(RequestPriority priority) : priority_(priority) {}
  ~FakeStream() override {}

  RequestPriority priority() const { return priority_; }

  int InitializeStream(const HttpRequestInfo* request_info,
                       RequestPriority priority,
                       const NetLogWithSource& net_log,
                       const CompletionCallback& callback) override {
    return ERR_IO_PENDING;
  }

  int SendRequest(const HttpRequestHeaders& request_headers,
                  HttpResponseInfo* response,
                  const CompletionCallback& callback) override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  int ReadResponseHeaders(const CompletionCallback& callback) override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback) override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  void Close(bool not_reusable) override {}

  bool IsResponseBodyComplete() const override {
    ADD_FAILURE();
    return false;
  }

  bool IsConnectionReused() const override {
    ADD_FAILURE();
    return false;
  }

  void SetConnectionReused() override { ADD_FAILURE(); }

  bool CanReuseConnection() const override { return false; }

  int64_t GetTotalReceivedBytes() const override {
    ADD_FAILURE();
    return 0;
  }

  int64_t GetTotalSentBytes() const override {
    ADD_FAILURE();
    return 0;
  }

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override {
    ADD_FAILURE();
    return false;
  }

  bool GetAlternativeService(
      AlternativeService* alternative_service) const override {
    ADD_FAILURE();
    return false;
  }

  void GetSSLInfo(SSLInfo* ssl_info) override { ADD_FAILURE(); }

  void GetSSLCertRequestInfo(SSLCertRequestInfo* cert_request_info) override {
    ADD_FAILURE();
  }

  bool GetRemoteEndpoint(IPEndPoint* endpoint) override { return false; }

  Error GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                 TokenBindingType tb_type,
                                 std::vector<uint8_t>* out) override {
    ADD_FAILURE();
    return ERR_NOT_IMPLEMENTED;
  }

  void Drain(HttpNetworkSession* session) override { ADD_FAILURE(); }

  void PopulateNetErrorDetails(NetErrorDetails* details) override { return; }

  void SetPriority(RequestPriority priority) override { priority_ = priority; }

  HttpStream* RenewStreamForAuth() override { return NULL; }

 private:
  RequestPriority priority_;

  DISALLOW_COPY_AND_ASSIGN(FakeStream);
};

// Fake HttpStreamRequest that simply records calls to SetPriority()
// and vends FakeStreams with its current priority.
class FakeStreamRequest : public HttpStreamRequest,
                          public base::SupportsWeakPtr<FakeStreamRequest> {
 public:
  FakeStreamRequest(RequestPriority priority,
                    HttpStreamRequest::Delegate* delegate)
      : priority_(priority),
        delegate_(delegate),
        websocket_stream_create_helper_(NULL) {}

  FakeStreamRequest(RequestPriority priority,
                    HttpStreamRequest::Delegate* delegate,
                    WebSocketHandshakeStreamBase::CreateHelper* create_helper)
      : priority_(priority),
        delegate_(delegate),
        websocket_stream_create_helper_(create_helper) {}

  ~FakeStreamRequest() override {}

  RequestPriority priority() const { return priority_; }

  const WebSocketHandshakeStreamBase::CreateHelper*
  websocket_stream_create_helper() const {
    return websocket_stream_create_helper_;
  }

  // Create a new FakeStream and pass it to the request's
  // delegate. Returns a weak pointer to the FakeStream.
  base::WeakPtr<FakeStream> FinishStreamRequest() {
    auto fake_stream = base::MakeUnique<FakeStream>(priority_);
    // Do this before calling OnStreamReady() as OnStreamReady() may
    // immediately delete |fake_stream|.
    base::WeakPtr<FakeStream> weak_stream = fake_stream->AsWeakPtr();
    delegate_->OnStreamReady(SSLConfig(), ProxyInfo(), std::move(fake_stream));
    return weak_stream;
  }

  int RestartTunnelWithProxyAuth() override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  LoadState GetLoadState() const override {
    ADD_FAILURE();
    return LoadState();
  }

  void SetPriority(RequestPriority priority) override { priority_ = priority; }

  bool was_alpn_negotiated() const override { return false; }

  NextProto negotiated_protocol() const override { return kProtoUnknown; }

  bool using_spdy() const override { return false; }

  const ConnectionAttempts& connection_attempts() const override {
    static ConnectionAttempts no_attempts;
    return no_attempts;
  }

 private:
  RequestPriority priority_;
  HttpStreamRequest::Delegate* const delegate_;
  WebSocketHandshakeStreamBase::CreateHelper* websocket_stream_create_helper_;

  DISALLOW_COPY_AND_ASSIGN(FakeStreamRequest);
};

// Fake HttpStreamFactory that vends FakeStreamRequests.
class FakeStreamFactory : public HttpStreamFactory {
 public:
  FakeStreamFactory() {}
  ~FakeStreamFactory() override {}

  // Returns a WeakPtr<> to the last HttpStreamRequest returned by
  // RequestStream() (which may be NULL if it was destroyed already).
  base::WeakPtr<FakeStreamRequest> last_stream_request() {
    return last_stream_request_;
  }

  std::unique_ptr<HttpStreamRequest> RequestStream(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      bool enable_ip_based_pooling,
      bool enable_alternative_services,
      const NetLogWithSource& net_log) override {
    auto fake_request = base::MakeUnique<FakeStreamRequest>(priority, delegate);
    last_stream_request_ = fake_request->AsWeakPtr();
    return std::move(fake_request);
  }

  std::unique_ptr<HttpStreamRequest> RequestBidirectionalStreamImpl(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      bool enable_ip_based_pooling,
      bool enable_alternative_services,
      const NetLogWithSource& net_log) override {
    NOTREACHED();
    return nullptr;
  }

  std::unique_ptr<HttpStreamRequest> RequestWebSocketHandshakeStream(
      const HttpRequestInfo& info,
      RequestPriority priority,
      const SSLConfig& server_ssl_config,
      const SSLConfig& proxy_ssl_config,
      HttpStreamRequest::Delegate* delegate,
      WebSocketHandshakeStreamBase::CreateHelper* create_helper,
      bool enable_ip_based_pooling,
      bool enable_alternative_services,
      const NetLogWithSource& net_log) override {
    auto fake_request =
        base::MakeUnique<FakeStreamRequest>(priority, delegate, create_helper);
    last_stream_request_ = fake_request->AsWeakPtr();
    return std::move(fake_request);
  }

  void PreconnectStreams(int num_streams,
                         const HttpRequestInfo& info) override {
    ADD_FAILURE();
  }

  const HostMappingRules* GetHostMappingRules() const override {
    ADD_FAILURE();
    return NULL;
  }

  void DumpMemoryStats(base::trace_event::ProcessMemoryDump* pmd,
                       const std::string& parent_absolute_name) const override {
    ADD_FAILURE();
  }

 private:
  base::WeakPtr<FakeStreamRequest> last_stream_request_;

  DISALLOW_COPY_AND_ASSIGN(FakeStreamFactory);
};

// TODO(ricea): Maybe unify this with the one in
// url_request_http_job_unittest.cc ?
class FakeWebSocketBasicHandshakeStream : public WebSocketHandshakeStreamBase {
 public:
  FakeWebSocketBasicHandshakeStream(
      std::unique_ptr<ClientSocketHandle> connection,
      bool using_proxy)
      : state_(std::move(connection), using_proxy, false) {}

  // Fake implementation of HttpStreamBase methods.
  // This ends up being quite "real" because this object has to really send data
  // on the mock socket. It might be easier to use the real implementation, but
  // the fact that the WebSocket code is not compiled on iOS makes that
  // difficult.
  int InitializeStream(const HttpRequestInfo* request_info,
                       RequestPriority priority,
                       const NetLogWithSource& net_log,
                       const CompletionCallback& callback) override {
    state_.Initialize(request_info, priority, net_log, callback);
    return OK;
  }

  int SendRequest(const HttpRequestHeaders& request_headers,
                  HttpResponseInfo* response,
                  const CompletionCallback& callback) override {
    return parser()->SendRequest(state_.GenerateRequestLine(), request_headers,
                                 response, callback);
  }

  int ReadResponseHeaders(const CompletionCallback& callback) override {
    return parser()->ReadResponseHeaders(callback);
  }

  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       const CompletionCallback& callback) override {
    NOTREACHED();
    return ERR_IO_PENDING;
  }

  void Close(bool not_reusable) override {
    if (parser())
      parser()->Close(true);
  }

  bool IsResponseBodyComplete() const override {
    NOTREACHED();
    return false;
  }

  bool IsConnectionReused() const override {
    NOTREACHED();
    return false;
  }
  void SetConnectionReused() override { NOTREACHED(); }

  bool CanReuseConnection() const override { return false; }

  int64_t GetTotalReceivedBytes() const override {
    NOTREACHED();
    return 0;
  }

  int64_t GetTotalSentBytes() const override {
    NOTREACHED();
    return 0;
  }

  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override {
    NOTREACHED();
    return false;
  }

  bool GetAlternativeService(
      AlternativeService* alternative_service) const override {
    ADD_FAILURE();
    return false;
  }

  void GetSSLInfo(SSLInfo* ssl_info) override {}

  void GetSSLCertRequestInfo(SSLCertRequestInfo* cert_request_info) override {
    NOTREACHED();
  }

  bool GetRemoteEndpoint(IPEndPoint* endpoint) override { return false; }

  Error GetTokenBindingSignature(crypto::ECPrivateKey* key,
                                 TokenBindingType tb_type,
                                 std::vector<uint8_t>* out) override {
    ADD_FAILURE();
    return ERR_NOT_IMPLEMENTED;
  }

  void Drain(HttpNetworkSession* session) override { NOTREACHED(); }

  void PopulateNetErrorDetails(NetErrorDetails* details) override { return; }

  void SetPriority(RequestPriority priority) override { NOTREACHED(); }

  HttpStream* RenewStreamForAuth() override {
    NOTREACHED();
    return nullptr;
  }

  // Fake implementation of WebSocketHandshakeStreamBase method(s)
  std::unique_ptr<WebSocketStream> Upgrade() override {
    NOTREACHED();
    return std::unique_ptr<WebSocketStream>();
  }

 private:
  HttpStreamParser* parser() const { return state_.parser(); }
  HttpBasicState state_;

  DISALLOW_COPY_AND_ASSIGN(FakeWebSocketBasicHandshakeStream);
};

// TODO(yhirano): Split this class out into a net/websockets file, if it is
// worth doing.
class FakeWebSocketStreamCreateHelper :
      public WebSocketHandshakeStreamBase::CreateHelper {
 public:
  std::unique_ptr<WebSocketHandshakeStreamBase> CreateBasicStream(
      std::unique_ptr<ClientSocketHandle> connection,
      bool using_proxy) override {
    return base::MakeUnique<FakeWebSocketBasicHandshakeStream>(
        std::move(connection), using_proxy);
  }

  ~FakeWebSocketStreamCreateHelper() override {}

  virtual std::unique_ptr<WebSocketStream> Upgrade() {
    NOTREACHED();
    return std::unique_ptr<WebSocketStream>();
  }
};

}  // namespace

// Make sure that HttpNetworkTransaction passes on its priority to its
// stream request on start.
TEST_F(HttpNetworkTransactionTest, SetStreamRequestPriorityOnStart) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkSessionPeer peer(session.get());
  FakeStreamFactory* fake_factory = new FakeStreamFactory();
  peer.SetHttpStreamFactory(std::unique_ptr<HttpStreamFactory>(fake_factory));

  HttpRequestInfo request;
  HttpNetworkTransaction trans(LOW, session.get());

  ASSERT_FALSE(fake_factory->last_stream_request());

  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));

  base::WeakPtr<FakeStreamRequest> fake_request =
      fake_factory->last_stream_request();
  ASSERT_TRUE(fake_request);
  EXPECT_EQ(LOW, fake_request->priority());
}

// Make sure that HttpNetworkTransaction passes on its priority
// updates to its stream request.
TEST_F(HttpNetworkTransactionTest, SetStreamRequestPriority) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkSessionPeer peer(session.get());
  FakeStreamFactory* fake_factory = new FakeStreamFactory();
  peer.SetHttpStreamFactory(std::unique_ptr<HttpStreamFactory>(fake_factory));

  HttpRequestInfo request;
  HttpNetworkTransaction trans(LOW, session.get());

  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));

  base::WeakPtr<FakeStreamRequest> fake_request =
      fake_factory->last_stream_request();
  ASSERT_TRUE(fake_request);
  EXPECT_EQ(LOW, fake_request->priority());

  trans.SetPriority(LOWEST);
  ASSERT_TRUE(fake_request);
  EXPECT_EQ(LOWEST, fake_request->priority());
}

// Make sure that HttpNetworkTransaction passes on its priority
// updates to its stream.
TEST_F(HttpNetworkTransactionTest, SetStreamPriority) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkSessionPeer peer(session.get());
  FakeStreamFactory* fake_factory = new FakeStreamFactory();
  peer.SetHttpStreamFactory(std::unique_ptr<HttpStreamFactory>(fake_factory));

  HttpRequestInfo request;
  HttpNetworkTransaction trans(LOW, session.get());

  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));

  base::WeakPtr<FakeStreamRequest> fake_request =
      fake_factory->last_stream_request();
  ASSERT_TRUE(fake_request);
  base::WeakPtr<FakeStream> fake_stream = fake_request->FinishStreamRequest();
  ASSERT_TRUE(fake_stream);
  EXPECT_EQ(LOW, fake_stream->priority());

  trans.SetPriority(LOWEST);
  EXPECT_EQ(LOWEST, fake_stream->priority());
}

TEST_F(HttpNetworkTransactionTest, CreateWebSocketHandshakeStream) {
  // The same logic needs to be tested for both ws: and wss: schemes, but this
  // test is already parameterised on NextProto, so it uses a loop to verify
  // that the different schemes work.
  std::string test_cases[] = {"ws://www.example.org/",
                              "wss://www.example.org/"};
  for (size_t i = 0; i < arraysize(test_cases); ++i) {
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkSessionPeer peer(session.get());
    FakeStreamFactory* fake_factory = new FakeStreamFactory();
    FakeWebSocketStreamCreateHelper websocket_stream_create_helper;
    peer.SetHttpStreamFactoryForWebSocket(
        std::unique_ptr<HttpStreamFactory>(fake_factory));

    HttpRequestInfo request;
    HttpNetworkTransaction trans(LOW, session.get());
    trans.SetWebSocketHandshakeStreamCreateHelper(
        &websocket_stream_create_helper);

    TestCompletionCallback callback;
    request.method = "GET";
    request.url = GURL(test_cases[i]);

    EXPECT_EQ(ERR_IO_PENDING,
              trans.Start(&request, callback.callback(), NetLogWithSource()));

    base::WeakPtr<FakeStreamRequest> fake_request =
        fake_factory->last_stream_request();
    ASSERT_TRUE(fake_request);
    EXPECT_EQ(&websocket_stream_create_helper,
              fake_request->websocket_stream_create_helper());
  }
}

// Tests that when a used socket is returned to the SSL socket pool, it's closed
// if the transport socket pool is stalled on the global socket limit.
TEST_F(HttpNetworkTransactionTest, CloseSSLSocketOnIdleForHttpRequest) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Set up SSL request.

  HttpRequestInfo ssl_request;
  ssl_request.method = "GET";
  ssl_request.url = GURL("https://www.example.org/");

  MockWrite ssl_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };
  MockRead ssl_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 11\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider ssl_data(ssl_reads, arraysize(ssl_reads),
                                    ssl_writes, arraysize(ssl_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Set up HTTP request.

  HttpRequestInfo http_request;
  http_request.method = "GET";
  http_request.url = GURL("http://www.example.org/");

  MockWrite http_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 7\r\n\r\n"),
    MockRead("falafel"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Start the SSL request.
  TestCompletionCallback ssl_callback;
  HttpNetworkTransaction ssl_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_trans.Start(&ssl_request, ssl_callback.callback(),
                            NetLogWithSource()));

  // Start the HTTP request.  Pool should stall.
  TestCompletionCallback http_callback;
  HttpNetworkTransaction http_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            http_trans.Start(&http_request, http_callback.callback(),
                             NetLogWithSource()));
  EXPECT_TRUE(IsTransportSocketPoolStalled(session.get()));

  // Wait for response from SSL request.
  ASSERT_THAT(ssl_callback.WaitForResult(), IsOk());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&ssl_trans, &response_data), IsOk());
  EXPECT_EQ("hello world", response_data);

  // The SSL socket should automatically be closed, so the HTTP request can
  // start.
  EXPECT_EQ(0, GetIdleSocketCountInSSLSocketPool(session.get()));
  ASSERT_FALSE(IsTransportSocketPoolStalled(session.get()));

  // The HTTP request can now complete.
  ASSERT_THAT(http_callback.WaitForResult(), IsOk());
  ASSERT_THAT(ReadTransaction(&http_trans, &response_data), IsOk());
  EXPECT_EQ("falafel", response_data);

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

// Tests that when a SSL connection is established but there's no corresponding
// request that needs it, the new socket is closed if the transport socket pool
// is stalled on the global socket limit.
TEST_F(HttpNetworkTransactionTest, CloseSSLSocketOnIdleForHttpRequest2) {
  ClientSocketPoolManager::set_max_sockets_per_group(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);
  ClientSocketPoolManager::set_max_sockets_per_pool(
      HttpNetworkSession::NORMAL_SOCKET_POOL, 1);

  // Set up an ssl request.

  HttpRequestInfo ssl_request;
  ssl_request.method = "GET";
  ssl_request.url = GURL("https://www.foopy.com/");

  // No data will be sent on the SSL socket.
  StaticSocketDataProvider ssl_data;
  session_deps_.socket_factory->AddSocketDataProvider(&ssl_data);

  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  // Set up HTTP request.

  HttpRequestInfo http_request;
  http_request.method = "GET";
  http_request.url = GURL("http://www.example.org/");

  MockWrite http_writes[] = {
      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
    MockRead("HTTP/1.1 200 OK\r\n"),
    MockRead("Content-Length: 7\r\n\r\n"),
    MockRead("falafel"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider http_data(http_reads, arraysize(http_reads),
                                     http_writes, arraysize(http_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Preconnect an SSL socket.  A preconnect is needed because connect jobs are
  // cancelled when a normal transaction is cancelled.
  HttpStreamFactory* http_stream_factory = session->http_stream_factory();
  http_stream_factory->PreconnectStreams(1, ssl_request);
  EXPECT_EQ(0, GetIdleSocketCountInSSLSocketPool(session.get()));

  // Start the HTTP request.  Pool should stall.
  TestCompletionCallback http_callback;
  HttpNetworkTransaction http_trans(DEFAULT_PRIORITY, session.get());
  ASSERT_EQ(ERR_IO_PENDING,
            http_trans.Start(&http_request, http_callback.callback(),
                             NetLogWithSource()));
  EXPECT_TRUE(IsTransportSocketPoolStalled(session.get()));

  // The SSL connection will automatically be closed once the connection is
  // established, to let the HTTP request start.
  ASSERT_THAT(http_callback.WaitForResult(), IsOk());
  std::string response_data;
  ASSERT_THAT(ReadTransaction(&http_trans, &response_data), IsOk());
  EXPECT_EQ("falafel", response_data);

  EXPECT_EQ(1, GetIdleSocketCountInTransportSocketPool(session.get()));
}

TEST_F(HttpNetworkTransactionTest, PostReadsErrorResponseAfterReset) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This test makes sure the retry logic doesn't trigger when reading an error
// response from a server that rejected a POST with a CONNECTION_RESET.
TEST_F(HttpNetworkTransactionTest,
       PostReadsErrorResponseAfterResetOnReusedSocket) {
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  MockWrite data_writes[] = {
    MockWrite("GET / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n\r\n"),
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.1 200 Peachy\r\n"
             "Content-Length: 14\r\n\r\n"),
    MockRead("first response"),
    MockRead("HTTP/1.1 400 Not OK\r\n"
             "Content-Length: 15\r\n\r\n"),
    MockRead("second response"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("http://www.foo.com/");
  request1.load_flags = 0;

  auto trans1 =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  int rv = trans1->Start(&request1, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);

  EXPECT_TRUE(response1->headers);
  EXPECT_EQ("HTTP/1.1 200 Peachy", response1->headers->GetStatusLine());

  std::string response_data1;
  rv = ReadTransaction(trans1.get(), &response_data1);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("first response", response_data1);
  // Delete the transaction to release the socket back into the socket pool.
  trans1.reset();

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request2;
  request2.method = "POST";
  request2.url = GURL("http://www.foo.com/");
  request2.upload_data_stream = &upload_data_stream;
  request2.load_flags = 0;

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, session.get());
  rv = trans2.Start(&request2, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);

  EXPECT_TRUE(response2->headers);
  EXPECT_EQ("HTTP/1.1 400 Not OK", response2->headers->GetStatusLine());

  std::string response_data2;
  rv = ReadTransaction(&trans2, &response_data2);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("second response", response_data2);
}

TEST_F(HttpNetworkTransactionTest,
       PostReadsErrorResponseAfterResetPartialBodySent) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"
              "fo"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

// This tests the more common case than the previous test, where headers and
// body are not merged into a single request.
TEST_F(HttpNetworkTransactionTest, ChunkedPostReadsErrorResponseAfterReset) {
  ChunkedUploadDataStream upload_data_stream(0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Transfer-Encoding: chunked\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Make sure the headers are sent before adding a chunk.  This ensures that
  // they can't be merged with the body in a single send.  Not currently
  // necessary since a chunked body is never merged with headers, but this makes
  // the test more future proof.
  base::RunLoop().RunUntilIdle();

  upload_data_stream.AppendData("last chunk", 10, true);

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_F(HttpNetworkTransactionTest, PostReadsErrorResponseAfterResetAnd100) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
    MockRead("HTTP/1.0 400 Not OK\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans.GetResponseInfo();
  ASSERT_TRUE(response);

  EXPECT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.0 400 Not OK", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello world", response_data);
}

TEST_F(HttpNetworkTransactionTest, PostIgnoresNonErrorResponseAfterReset) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 200 Just Dandy\r\n\r\n"),
    MockRead("hello world"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_F(HttpNetworkTransactionTest,
       PostIgnoresNonErrorResponseAfterResetAnd100) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 100 Continue\r\n\r\n"),
    MockRead("HTTP/1.0 302 Redirect\r\n"),
    MockRead("Location: http://somewhere-else.com/\r\n"),
    MockRead("Content-Length: 0\r\n\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_F(HttpNetworkTransactionTest, PostIgnoresHttp09ResponseAfterReset) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP 0.9 rocks!"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

TEST_F(HttpNetworkTransactionTest, PostIgnoresPartial400HeadersAfterReset) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
    MockWrite("POST / HTTP/1.1\r\n"
              "Host: www.foo.com\r\n"
              "Connection: keep-alive\r\n"
              "Content-Length: 3\r\n\r\n"),
    MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET),
  };

  MockRead data_reads[] = {
    MockRead("HTTP/1.0 400 Not a Full Response\r\n"),
    MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

// Verify that proxy headers are not sent to the destination server when
// establishing a tunnel for a secure WebSocket connection.
TEST_F(HttpNetworkTransactionTest, ProxyHeadersNotSentOverWssTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("wss://www.example.org/");
  AddWebSocketHeaders(&request.extra_headers);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since a proxy is configured, try to establish a tunnel.
  MockWrite data_writes[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),

      // After calling trans->RestartWithAuth(), this is the request we should
      // be issuing -- the final header line contains the credentials.
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead("Content-Length: 0\r\n"),
      MockRead("Proxy-Connection: keep-alive\r\n\r\n"),

      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 101 Switching Protocols\r\n"),
      MockRead("Upgrade: websocket\r\n"),
      MockRead("Connection: Upgrade\r\n"),
      MockRead("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  FakeWebSocketStreamCreateHelper websocket_stream_create_helper;
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  {
    TestCompletionCallback callback;

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());
  }

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());

  {
    TestCompletionCallback callback;

    int rv = trans->RestartWithAuth(AuthCredentials(kFoo, kBar),
                                    callback.callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    rv = callback.WaitForResult();
    EXPECT_THAT(rv, IsOk());
  }

  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);

  EXPECT_EQ(101, response->headers->response_code());

  trans.reset();
  session->CloseAllConnections();
}

// Verify that proxy headers are not sent to the destination server when
// establishing a tunnel for an insecure WebSocket connection.
// This requires the authentication info to be injected into the auth cache
// due to crbug.com/395064
// TODO(ricea): Change to use a 407 response once issue 395064 is fixed.
TEST_F(HttpNetworkTransactionTest, ProxyHeadersNotSentOverWsTunnel) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("ws://www.example.org/");
  AddWebSocketHeaders(&request.extra_headers);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("PROXY myproxy:70");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  MockWrite data_writes[] = {
      // Try to establish a tunnel for the WebSocket connection, with
      // credentials. Because WebSockets have a separate set of socket pools,
      // they cannot and will not use the same TCP/IP connection as the
      // preflight HTTP request.
      MockWrite(
          "CONNECT www.example.org:80 HTTP/1.1\r\n"
          "Host: www.example.org:80\r\n"
          "Proxy-Connection: keep-alive\r\n"
          "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),

      MockWrite(
          "GET / HTTP/1.1\r\n"
          "Host: www.example.org\r\n"
          "Connection: Upgrade\r\n"
          "Upgrade: websocket\r\n"
          "Origin: http://www.example.org\r\n"
          "Sec-WebSocket-Version: 13\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"),
  };

  MockRead data_reads[] = {
      // HTTP CONNECT with credentials.
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      // WebSocket connection established inside tunnel.
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"),
      MockRead("Upgrade: websocket\r\n"),
      MockRead("Connection: Upgrade\r\n"),
      MockRead("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"),
  };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  session->http_auth_cache()->Add(
      GURL("http://myproxy:70/"), "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC,
      "Basic realm=MyRealm1", AuthCredentials(kFoo, kBar), "/");

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());
  FakeWebSocketStreamCreateHelper websocket_stream_create_helper;
  trans->SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback;

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);

  EXPECT_EQ(101, response->headers->response_code());

  trans.reset();
  session->CloseAllConnections();
}

TEST_F(HttpNetworkTransactionTest, TotalNetworkBytesPost) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite("foo"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

  EXPECT_EQ(CountWriteBytes(data_writes, arraysize(data_writes)),
            trans.GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(data_reads, arraysize(data_reads)),
            trans.GetTotalReceivedBytes());
}

TEST_F(HttpNetworkTransactionTest, TotalNetworkBytesPost100Continue) {
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(
      base::MakeUnique<UploadBytesElementReader>("foo", 3));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Content-Length: 3\r\n\r\n"),
      MockWrite("foo"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 100 Continue\r\n\r\n"),
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

  EXPECT_EQ(CountWriteBytes(data_writes, arraysize(data_writes)),
            trans.GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(data_reads, arraysize(data_reads)),
            trans.GetTotalReceivedBytes());
}

TEST_F(HttpNetworkTransactionTest, TotalNetworkBytesChunkedPost) {
  ChunkedUploadDataStream upload_data_stream(0);

  HttpRequestInfo request;
  request.method = "POST";
  request.url = GURL("http://www.foo.com/");
  request.upload_data_stream = &upload_data_stream;

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("POST / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Transfer-Encoding: chunked\r\n\r\n"),
      MockWrite("1\r\nf\r\n"), MockWrite("2\r\noo\r\n"), MockWrite("0\r\n\r\n"),
  };

  MockRead data_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));

  base::RunLoop().RunUntilIdle();
  upload_data_stream.AppendData("f", 1, false);

  base::RunLoop().RunUntilIdle();
  upload_data_stream.AppendData("oo", 2, true);

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  std::string response_data;
  EXPECT_THAT(ReadTransaction(&trans, &response_data), IsOk());

  EXPECT_EQ(CountWriteBytes(data_writes, arraysize(data_writes)),
            trans.GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(data_reads, arraysize(data_reads)),
            trans.GetTotalReceivedBytes());
}

// Confirm that transactions whose throttle is created in (and stays in)
// the unthrottled state are not blocked.
TEST_F(HttpNetworkTransactionTest, ThrottlingUnthrottled) {
  TestNetworkStreamThrottler* throttler(nullptr);
  std::unique_ptr<HttpNetworkSession> session(
      CreateSessionWithThrottler(&session_deps_, &throttler));

  // Send a simple request and make sure it goes through.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider reads(data_reads, arraysize(data_reads), data_writes,
                                 arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  TestCompletionCallback callback;
  trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_EQ(OK, callback.WaitForResult());
}

// Confirm requests can be blocked by a throttler, and are resumed
// when the throttle is unblocked.
TEST_F(HttpNetworkTransactionTest, ThrottlingBasic) {
  TestNetworkStreamThrottler* throttler(nullptr);
  std::unique_ptr<HttpNetworkSession> session(
      CreateSessionWithThrottler(&session_deps_, &throttler));

  // Send a simple request and make sure it goes through.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider reads(data_reads, arraysize(data_reads), data_writes,
                                 arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  // Start a request that will be throttled at start; confirm it
  // doesn't complete.
  throttler->set_throttle_new_requests(true);
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_THROTTLED, trans->GetLoadState());
  EXPECT_FALSE(callback.have_result());

  // Confirm the request goes on to complete when unthrottled.
  throttler->UnthrottleAllRequests();
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback.have_result());
  EXPECT_EQ(OK, callback.WaitForResult());
}

// Destroy a request while it's throttled.
TEST_F(HttpNetworkTransactionTest, ThrottlingDestruction) {
  TestNetworkStreamThrottler* throttler(nullptr);
  std::unique_ptr<HttpNetworkSession> session(
      CreateSessionWithThrottler(&session_deps_, &throttler));

  // Send a simple request and make sure it goes through.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider reads(data_reads, arraysize(data_reads), data_writes,
                                 arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  // Start a request that will be throttled at start; confirm it
  // doesn't complete.
  throttler->set_throttle_new_requests(true);
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_THROTTLED, trans->GetLoadState());
  EXPECT_FALSE(callback.have_result());

  EXPECT_EQ(1u, throttler->num_outstanding_requests());
  trans.reset();
  EXPECT_EQ(0u, throttler->num_outstanding_requests());
}

// Confirm the throttler receives SetPriority calls.
TEST_F(HttpNetworkTransactionTest, ThrottlingPrioritySet) {
  TestNetworkStreamThrottler* throttler(nullptr);
  std::unique_ptr<HttpNetworkSession> session(
      CreateSessionWithThrottler(&session_deps_, &throttler));

  // Send a simple request and make sure it goes through.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider reads(data_reads, arraysize(data_reads), data_writes,
                                 arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  throttler->set_throttle_new_requests(true);
  auto trans = base::MakeUnique<HttpNetworkTransaction>(IDLE, session.get());
  // Start the transaction to associate a throttle with it.
  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  EXPECT_EQ(0, throttler->num_set_priority_calls());
  trans->SetPriority(LOW);
  EXPECT_EQ(1, throttler->num_set_priority_calls());
  EXPECT_EQ(LOW, throttler->last_priority_set());

  throttler->UnthrottleAllRequests();
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback.have_result());
  EXPECT_EQ(OK, callback.WaitForResult());
}

// Confirm that unthrottling from a SetPriority call by the
// throttler works properly.
TEST_F(HttpNetworkTransactionTest, ThrottlingPrioritySetUnthrottle) {
  TestNetworkStreamThrottler* throttler(nullptr);
  std::unique_ptr<HttpNetworkSession> session(
      CreateSessionWithThrottler(&session_deps_, &throttler));

  // Send a simple request and make sure it goes through.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider reads(data_reads, arraysize(data_reads), data_writes,
                                 arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  StaticSocketDataProvider reads1(data_reads, arraysize(data_reads),
                                  data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads1);

  // Start a request that will be throttled at start; confirm it
  // doesn't complete.
  throttler->set_throttle_new_requests(true);
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_THROTTLED, trans->GetLoadState());
  EXPECT_FALSE(callback.have_result());

  // Create a new request, call SetPriority on it to unthrottle,
  // and make sure that allows the original request to complete.
  auto trans1 = base::MakeUnique<HttpNetworkTransaction>(LOW, session.get());
  throttler->set_priority_change_closure(
      base::Bind(&TestNetworkStreamThrottler::UnthrottleAllRequests,
                 base::Unretained(throttler)));

  // Start the transaction to associate a throttle with it.
  TestCompletionCallback callback1;
  rv = trans1->Start(&request, callback1.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  trans1->SetPriority(IDLE);

  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(callback.have_result());
  EXPECT_EQ(OK, callback.WaitForResult());
  ASSERT_TRUE(callback1.have_result());
  EXPECT_EQ(OK, callback1.WaitForResult());
}

// Transaction will be destroyed when the unique_ptr goes out of scope.
void DestroyTransaction(std::unique_ptr<HttpNetworkTransaction> transaction) {}

// Confirm that destroying a transaction from a SetPriority call by the
// throttler works properly.
TEST_F(HttpNetworkTransactionTest, ThrottlingPrioritySetDestroy) {
  TestNetworkStreamThrottler* throttler(nullptr);
  std::unique_ptr<HttpNetworkSession> session(
      CreateSessionWithThrottler(&session_deps_, &throttler));

  // Send a simple request and make sure it goes through.
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead data_reads[] = {
      MockRead("HTTP/1.0 200 OK\r\n\r\n"), MockRead("hello world"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider reads(data_reads, arraysize(data_reads), data_writes,
                                 arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads);

  StaticSocketDataProvider reads1(data_reads, arraysize(data_reads),
                                  data_writes, arraysize(data_writes));
  session_deps_.socket_factory->AddSocketDataProvider(&reads1);

  // Start a request that will be throttled at start; confirm it
  // doesn't complete.
  throttler->set_throttle_new_requests(true);
  auto trans =
      base::MakeUnique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_THROTTLED, trans->GetLoadState());
  EXPECT_FALSE(callback.have_result());

  // Arrange for the set priority call on the above transaction to delete
  // the transaction.
  HttpNetworkTransaction* trans_ptr(trans.get());
  throttler->set_priority_change_closure(
      base::Bind(&DestroyTransaction, base::Passed(&trans)));

  // Call it and check results (partially a "doesn't crash" test).
  trans_ptr->SetPriority(IDLE);
  trans_ptr = nullptr;  // No longer a valid pointer.

  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(callback.have_result());
}

#if !defined(OS_IOS)
TEST_F(HttpNetworkTransactionTest, TokenBindingSpdy) {
  const std::string https_url = "https://www.example.com";
  HttpRequestInfo request;
  request.url = GURL(https_url);
  request.method = "GET";

  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.token_binding_negotiated = true;
  ssl.token_binding_key_param = TB_PARAM_ECDSAP256;
  ssl.next_proto = kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {CreateMockRead(resp), CreateMockRead(body),
                      MockRead(ASYNC, ERR_IO_PENDING)};
  StaticSocketDataProvider data(reads, arraysize(reads), nullptr, 0);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.channel_id_service =
      base::MakeUnique<ChannelIDService>(new DefaultChannelIDStore(nullptr));
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans.Start(&request, callback.callback(), NetLogWithSource()));

  NetTestSuite::GetScopedTaskEnvironment()->RunUntilIdle();

  EXPECT_TRUE(trans.GetResponseInfo()->was_fetched_via_spdy);
  HttpRequestHeaders headers;
  ASSERT_TRUE(trans.GetFullRequestHeaders(&headers));
  EXPECT_TRUE(headers.HasHeader(HttpRequestHeaders::kTokenBinding));
}
#endif  // !defined(OS_IOS)

void CheckContentEncodingMatching(SpdySessionDependencies* session_deps,
                                  const std::string& accept_encoding,
                                  const std::string& content_encoding,
                                  const std::string& location,
                                  bool should_match) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.foo.com/");
  request.extra_headers.SetHeader(HttpRequestHeaders::kAcceptEncoding,
                                  accept_encoding);

  std::unique_ptr<HttpNetworkSession> session(CreateSession(session_deps));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  // Send headers successfully, but get an error while sending the body.
  MockWrite data_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.foo.com\r\n"
                "Connection: keep-alive\r\n"
                "Accept-Encoding: "),
      MockWrite(accept_encoding.data()), MockWrite("\r\n\r\n"),
  };

  std::string response_code = "200 OK";
  std::string extra;
  if (!location.empty()) {
    response_code = "301 Redirect\r\nLocation: ";
    response_code.append(location);
  }

  MockRead data_reads[] = {
      MockRead("HTTP/1.0 "),
      MockRead(response_code.data()),
      MockRead("\r\nContent-Encoding: "),
      MockRead(content_encoding.data()),
      MockRead("\r\n\r\n"),
      MockRead(SYNCHRONOUS, OK),
  };
  StaticSocketDataProvider data(data_reads, arraysize(data_reads), data_writes,
                                arraysize(data_writes));
  session_deps->socket_factory->AddSocketDataProvider(&data);

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback.WaitForResult();
  if (should_match) {
    EXPECT_THAT(rv, IsOk());
  } else {
    EXPECT_THAT(rv, IsError(ERR_CONTENT_DECODING_FAILED));
  }
}

TEST_F(HttpNetworkTransactionTest, MatchContentEncoding1) {
  CheckContentEncodingMatching(&session_deps_, "gzip,sdch", "br", "", false);
}

TEST_F(HttpNetworkTransactionTest, MatchContentEncoding2) {
  CheckContentEncodingMatching(&session_deps_, "identity;q=1, *;q=0", "", "",
                               true);
}

TEST_F(HttpNetworkTransactionTest, MatchContentEncoding3) {
  CheckContentEncodingMatching(&session_deps_, "identity;q=1, *;q=0", "gzip",
                               "", false);
}

TEST_F(HttpNetworkTransactionTest, MatchContentEncoding4) {
  CheckContentEncodingMatching(&session_deps_, "identity;q=1, *;q=0", "gzip",
                               "www.foo.com/other", true);
}

TEST_F(HttpNetworkTransactionTest, ProxyResolutionFailsSync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  MockAsyncProxyResolver resolver;
  session_deps_.proxy_service.reset(new ProxyService(
      base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
      base::WrapUnique(new FailingProxyResolverFactory), nullptr));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;

  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(),
              IsError(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
}

TEST_F(HttpNetworkTransactionTest, ProxyResolutionFailsAsync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  MockAsyncProxyResolverFactory* proxy_resolver_factory =
      new MockAsyncProxyResolverFactory(false);
  MockAsyncProxyResolver resolver;
  session_deps_.proxy_service.reset(
      new ProxyService(base::MakeUnique<ProxyConfigServiceFixed>(proxy_config),
                       base::WrapUnique(proxy_resolver_factory), nullptr));
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  proxy_resolver_factory->pending_requests()[0]->CompleteNowWithForwarder(
      ERR_FAILED, &resolver);
  EXPECT_THAT(callback.WaitForResult(),
              IsError(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED));
}

TEST_F(HttpNetworkTransactionTest, NoSupportedProxies) {
  session_deps_.proxy_service =
      ProxyService::CreateFixedFromPacResult("QUIC myproxy.org:443");
  session_deps_.enable_quic = false;
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");

  TestCompletionCallback callback;
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());
  int rv = trans.Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_NO_SUPPORTED_PROXIES));
}

}  // namespace net
