// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <ostream>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_task_scheduler.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/ip_address.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/proxy_service.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_simple_server.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using base::StringPiece;

namespace net {

using test::IsOk;

namespace test {

namespace {

const char kResponseBody[] = "some arbitrary response body";

// Factory for creating HttpTransactions, used by TestTransactionConsumer.
class TestTransactionFactory : public HttpTransactionFactory {
 public:
  explicit TestTransactionFactory(const HttpNetworkSession::Params& params)
      : session_(new HttpNetworkSession(params)) {}

  ~TestTransactionFactory() override {}

  // HttpTransactionFactory methods
  int CreateTransaction(RequestPriority priority,
                        std::unique_ptr<HttpTransaction>* trans) override {
    trans->reset(new HttpNetworkTransaction(priority, session_.get()));
    return OK;
  }

  HttpCache* GetCache() override { return nullptr; }

  HttpNetworkSession* GetSession() override { return session_.get(); };

 private:
  std::unique_ptr<HttpNetworkSession> session_;
};

struct TestParams {
  explicit TestParams(bool use_stateless_rejects)
      : use_stateless_rejects(use_stateless_rejects) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ use_stateless_rejects: " << p.use_stateless_rejects << " }";
    return os;
  }
  bool use_stateless_rejects;
};

std::vector<TestParams> GetTestParams() {
  return std::vector<TestParams>{TestParams(true), TestParams(false)};
}

}  // namespace

class QuicEndToEndTest : public ::testing::TestWithParam<TestParams> {
 protected:
  QuicEndToEndTest()
      : host_resolver_impl_(CreateResolverImpl()),
        host_resolver_(std::move(host_resolver_impl_)),
        cert_transparency_verifier_(new MultiLogCTVerifier()),
        ssl_config_service_(new SSLConfigServiceDefaults),
        proxy_service_(ProxyService::CreateDirect()),
        auth_handler_factory_(
            HttpAuthHandlerFactory::CreateDefault(&host_resolver_)),
        strike_register_no_startup_period_(false) {
    request_.method = "GET";
    request_.url = GURL("https://test.example.com/");
    request_.load_flags = 0;

    params_.enable_quic = true;
    params_.quic_clock = nullptr;
    params_.quic_random = nullptr;
    if (GetParam().use_stateless_rejects) {
      params_.quic_connection_options.push_back(kSREJ);
    }
    params_.host_resolver = &host_resolver_;
    params_.cert_verifier = &cert_verifier_;
    params_.transport_security_state = &transport_security_state_;
    params_.cert_transparency_verifier = cert_transparency_verifier_.get();
    params_.ct_policy_enforcer = &ct_policy_enforcer_;
    params_.proxy_service = proxy_service_.get();
    params_.ssl_config_service = ssl_config_service_.get();
    params_.http_auth_handler_factory = auth_handler_factory_.get();
    params_.http_server_properties = &http_server_properties_;
    channel_id_service_.reset(
        new ChannelIDService(new DefaultChannelIDStore(nullptr)));
    params_.channel_id_service = channel_id_service_.get();

    CertVerifyResult verify_result;
    verify_result.verified_cert = ImportCertFromFile(
        GetTestCertsDirectory(), "quic_test.example.com.crt");
    cert_verifier_.AddResultForCertAndHost(verify_result.verified_cert.get(),
                                           "test.example.com", verify_result,
                                           OK);
    verify_result.verified_cert = ImportCertFromFile(
        GetTestCertsDirectory(), "quic_test_ecc.example.com.crt");
    cert_verifier_.AddResultForCertAndHost(verify_result.verified_cert.get(),
                                           "test.example.com", verify_result,
                                           OK);
  }

  // Creates a mock host resolver in which test.example.com
  // resolves to localhost.
  static MockHostResolver* CreateResolverImpl() {
    MockHostResolver* resolver = new MockHostResolver();
    resolver->rules()->AddRule("test.example.com", "127.0.0.1");
    return resolver;
  }

  void SetUp() override {
    StartServer();

    // Use a mapped host resolver so that request for test.example.com (port 80)
    // reach the server running on localhost.
    std::string map_rule = "MAP test.example.com test.example.com:" +
                           base::IntToString(server_->server_address().port());
    EXPECT_TRUE(host_resolver_.AddRuleFromString(map_rule));

    // To simplify the test, and avoid the race with the HTTP request, we force
    // QUIC for these requests.
    params_.origins_to_force_quic_on.insert(
        HostPortPair::FromString("test.example.com:443"));

    transaction_factory_.reset(new TestTransactionFactory(params_));
  }

  void TearDown() override {}

  // Starts the QUIC server listening on a random port.
  void StartServer() {
    server_address_ = IPEndPoint(IPAddress(127, 0, 0, 1), 0);
    server_config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    server_config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    server_config_options_.token_binding_params = QuicTagVector{kTB10, kP256};
    server_.reset(new QuicSimpleServer(
        crypto_test_utils::ProofSourceForTesting(), server_config_,
        server_config_options_, AllSupportedVersions(), &response_cache_));
    server_->Listen(server_address_);
    server_address_ = server_->server_address();
    server_->StartReading();
    server_started_ = true;
  }

  // Adds an entry to the cache used by the QUIC server to serve
  // responses.
  void AddToCache(StringPiece path,
                  int response_code,
                  StringPiece response_detail,
                  StringPiece body) {
    response_cache_.AddSimpleResponse("test.example.com", path, response_code,
                                      body);
  }

  // Populates |request_body_| with |length_| ASCII bytes.
  void GenerateBody(size_t length) {
    request_body_.clear();
    request_body_.reserve(length);
    for (size_t i = 0; i < length; ++i) {
      request_body_.append(1, static_cast<char>(32 + i % (126 - 32)));
    }
  }

  // Initializes |request_| for a post of |length| bytes.
  void InitializePostRequest(size_t length) {
    GenerateBody(length);
    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(base::MakeUnique<UploadBytesElementReader>(
        request_body_.data(), request_body_.length()));
    upload_data_stream_.reset(
        new ElementsUploadDataStream(std::move(element_readers), 0));
    request_.method = "POST";
    request_.url = GURL("https://test.example.com/");
    request_.upload_data_stream = upload_data_stream_.get();
    ASSERT_THAT(request_.upload_data_stream->Init(CompletionCallback(),
                                                  NetLogWithSource()),
                IsOk());
  }

  // Checks that |consumer| completed and received |status_line| and |body|.
  void CheckResponse(const TestTransactionConsumer& consumer,
                     const std::string& status_line,
                     const std::string& body) {
    ASSERT_TRUE(consumer.is_done());
    ASSERT_THAT(consumer.error(), IsOk());
    EXPECT_EQ(status_line, consumer.response_info()->headers->GetStatusLine());
    EXPECT_EQ(body, consumer.content());
  }

  std::unique_ptr<MockHostResolver> host_resolver_impl_;
  MappedHostResolver host_resolver_;
  MockCertVerifier cert_verifier_;
  std::unique_ptr<ChannelIDService> channel_id_service_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<CTVerifier> cert_transparency_verifier_;
  CTPolicyEnforcer ct_policy_enforcer_;
  scoped_refptr<SSLConfigServiceDefaults> ssl_config_service_;
  std::unique_ptr<ProxyService> proxy_service_;
  std::unique_ptr<HttpAuthHandlerFactory> auth_handler_factory_;
  HttpServerPropertiesImpl http_server_properties_;
  HttpNetworkSession::Params params_;
  std::unique_ptr<TestTransactionFactory> transaction_factory_;
  HttpRequestInfo request_;
  std::string request_body_;
  std::unique_ptr<UploadDataStream> upload_data_stream_;
  std::unique_ptr<QuicSimpleServer> server_;
  QuicHttpResponseCache response_cache_;
  IPEndPoint server_address_;
  std::string server_hostname_;
  QuicConfig server_config_;
  QuicCryptoServerConfig::ConfigOptions server_config_options_;
  bool server_started_;
  bool strike_register_no_startup_period_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicEndToEndTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicEndToEndTest, LargeGetWithNoPacketLoss) {
  std::string response(10 * 1024, 'x');

  AddToCache(request_.url.PathForRequest(), 200, "OK", response);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  // Will terminate when the last consumer completes.
  base::RunLoop().Run();

  CheckResponse(consumer, "HTTP/1.1 200", response);
}

TEST_P(QuicEndToEndTest, TokenBinding) {
  // Required by ChannelIDService.
  base::test::ScopedTaskScheduler scoped_task_scheduler(
      base::MessageLoop::current());

  // Enable token binding and re-initialize the TestTransactionFactory.
  params_.enable_token_binding = true;
  transaction_factory_.reset(new TestTransactionFactory(params_));

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  // Will terminate when the last consumer completes.
  base::RunLoop().Run();

  CheckResponse(consumer, "HTTP/1.1 200", kResponseBody);
  HttpRequestHeaders headers;
  ASSERT_TRUE(consumer.transaction()->GetFullRequestHeaders(&headers));
  EXPECT_TRUE(headers.HasHeader(HttpRequestHeaders::kTokenBinding));
}

// crbug.com/559173
#if defined(THREAD_SANITIZER)
TEST_P(QuicEndToEndTest, DISABLED_LargePostWithNoPacketLoss) {
#else
TEST_P(QuicEndToEndTest, LargePostWithNoPacketLoss) {
#endif
  InitializePostRequest(1024 * 1024);

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  // Will terminate when the last consumer completes.
  base::RunLoop().Run();

  CheckResponse(consumer, "HTTP/1.1 200", kResponseBody);
}

// crbug.com/559173
#if defined(THREAD_SANITIZER)
TEST_P(QuicEndToEndTest, DISABLED_LargePostWithPacketLoss) {
#else
TEST_P(QuicEndToEndTest, LargePostWithPacketLoss) {
#endif
  // FLAGS_fake_packet_loss_percentage = 30;
  InitializePostRequest(1024 * 1024);

  const char kResponseBody[] = "some really big response body";
  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  // Will terminate when the last consumer completes.
  base::RunLoop().Run();

  CheckResponse(consumer, "HTTP/1.1 200", kResponseBody);
}

// crbug.com/536845
#if defined(THREAD_SANITIZER)
TEST_P(QuicEndToEndTest, DISABLED_UberTest) {
#else
TEST_P(QuicEndToEndTest, UberTest) {
#endif
  // FLAGS_fake_packet_loss_percentage = 30;

  const char kResponseBody[] = "some really big response body";
  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  std::vector<std::unique_ptr<TestTransactionConsumer>> consumers;
  for (size_t i = 0; i < 100; ++i) {
    TestTransactionConsumer* consumer = new TestTransactionConsumer(
        DEFAULT_PRIORITY, transaction_factory_.get());
    consumers.push_back(base::WrapUnique(consumer));
    consumer->Start(&request_, NetLogWithSource());
  }

  // Will terminate when the last consumer completes.
  base::RunLoop().Run();

  for (const auto& consumer : consumers)
    CheckResponse(*consumer.get(), "HTTP/1.1 200", kResponseBody);
}

}  // namespace test
}  // namespace net
