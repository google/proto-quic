// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "net/base/request_priority.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_handler_mock.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_request_info.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/transport_security_state.h"
#include "net/proxy/proxy_service.h"
#include "net/socket/socket_test_util.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

namespace net {

namespace {

class TLS10SSLConfigService : public SSLConfigService {
 public:
  TLS10SSLConfigService() {
    ssl_config_.version_min = SSL_PROTOCOL_VERSION_TLS1;
    ssl_config_.version_max = SSL_PROTOCOL_VERSION_TLS1;
  }

  void GetSSLConfig(SSLConfig* config) override { *config = ssl_config_; }

 private:
  ~TLS10SSLConfigService() override {}

  SSLConfig ssl_config_;
};

class TLS12SSLConfigService : public SSLConfigService {
 public:
  TLS12SSLConfigService() {
    ssl_config_.version_min = SSL_PROTOCOL_VERSION_TLS1;
    ssl_config_.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  }

  void GetSSLConfig(SSLConfig* config) override { *config = ssl_config_; }

 private:
  ~TLS12SSLConfigService() override {}

  SSLConfig ssl_config_;
};

class TokenBindingSSLConfigService : public SSLConfigService {
 public:
  TokenBindingSSLConfigService() {
    ssl_config_.token_binding_params.push_back(TB_PARAM_ECDSAP256);
  }

  void GetSSLConfig(SSLConfig* config) override { *config = ssl_config_; }

 private:
  ~TokenBindingSSLConfigService() override {}

  SSLConfig ssl_config_;
};

}  // namespace

class HttpNetworkTransactionSSLTest : public testing::Test {
 protected:
  void SetUp() override {
    ssl_config_service_ = new TLS10SSLConfigService;
    session_params_.ssl_config_service = ssl_config_service_.get();

    auth_handler_factory_.reset(new HttpAuthHandlerMock::Factory());
    session_params_.http_auth_handler_factory = auth_handler_factory_.get();

    proxy_service_ = ProxyService::CreateDirect();
    session_params_.proxy_service = proxy_service_.get();

    session_params_.client_socket_factory = &mock_socket_factory_;
    session_params_.host_resolver = &mock_resolver_;
    session_params_.http_server_properties = &http_server_properties_;
    session_params_.cert_verifier = &cert_verifier_;
    session_params_.transport_security_state = &transport_security_state_;
    session_params_.cert_transparency_verifier = &ct_verifier_;
    session_params_.ct_policy_enforcer = &ct_policy_enforcer_;
  }

  HttpRequestInfo* GetRequestInfo(const std::string& url) {
    HttpRequestInfo* request_info = new HttpRequestInfo;
    request_info->url = GURL(url);
    request_info->method = "GET";
    request_info_vector_.push_back(base::WrapUnique(request_info));
    return request_info;
  }

  SSLConfig& GetServerSSLConfig(HttpNetworkTransaction* trans) {
    return trans->server_ssl_config_;
  }

  scoped_refptr<SSLConfigService> ssl_config_service_;
  std::unique_ptr<HttpAuthHandlerMock::Factory> auth_handler_factory_;
  std::unique_ptr<ProxyService> proxy_service_;

  MockClientSocketFactory mock_socket_factory_;
  MockHostResolver mock_resolver_;
  HttpServerPropertiesImpl http_server_properties_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  MultiLogCTVerifier ct_verifier_;
  CTPolicyEnforcer ct_policy_enforcer_;
  HttpNetworkSession::Params session_params_;
  std::vector<std::unique_ptr<HttpRequestInfo>> request_info_vector_;
};

#if !defined(OS_IOS)
TEST_F(HttpNetworkTransactionSSLTest, TokenBinding) {
  ssl_config_service_ = new TokenBindingSSLConfigService;
  session_params_.ssl_config_service = ssl_config_service_.get();
  ChannelIDService channel_id_service(new DefaultChannelIDStore(NULL),
                                      base::ThreadTaskRunnerHandle::Get());
  session_params_.channel_id_service = &channel_id_service;

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.token_binding_negotiated = true;
  ssl_data.token_binding_key_param = TB_PARAM_ECDSAP256;
  mock_socket_factory_.AddSSLSocketDataProvider(&ssl_data);
  MockRead mock_reads[] = {MockRead("HTTP/1.1 200 OK\r\n\r\n"),
                           MockRead(SYNCHRONOUS, OK)};
  StaticSocketDataProvider data(mock_reads, arraysize(mock_reads), NULL, 0);
  mock_socket_factory_.AddSocketDataProvider(&data);

  HttpNetworkSession session(session_params_);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, &session);

  TestCompletionCallback callback;
  int rv = callback.GetResult(
      trans1.Start(GetRequestInfo("https://www.example.com/"),
                   callback.callback(), BoundNetLog()));
  EXPECT_THAT(rv, IsOk());

  HttpRequestHeaders headers1;
  ASSERT_TRUE(trans1.GetFullRequestHeaders(&headers1));
  std::string token_binding_header1;
  EXPECT_TRUE(headers1.GetHeader(HttpRequestHeaders::kTokenBinding,
                                 &token_binding_header1));

  // Send a second request and verify that the token binding header is the same
  // as in the first request.
  mock_socket_factory_.AddSSLSocketDataProvider(&ssl_data);
  StaticSocketDataProvider data2(mock_reads, arraysize(mock_reads), NULL, 0);
  mock_socket_factory_.AddSocketDataProvider(&data2);
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, &session);

  rv = callback.GetResult(
      trans2.Start(GetRequestInfo("https://www.example.com/"),
                   callback.callback(), BoundNetLog()));
  EXPECT_THAT(rv, IsOk());

  HttpRequestHeaders headers2;
  ASSERT_TRUE(trans2.GetFullRequestHeaders(&headers2));
  std::string token_binding_header2;
  EXPECT_TRUE(headers2.GetHeader(HttpRequestHeaders::kTokenBinding,
                                 &token_binding_header2));

  EXPECT_EQ(token_binding_header1, token_binding_header2);
}

TEST_F(HttpNetworkTransactionSSLTest, NoTokenBindingOverHttp) {
  ssl_config_service_ = new TokenBindingSSLConfigService;
  session_params_.ssl_config_service = ssl_config_service_.get();
  ChannelIDService channel_id_service(new DefaultChannelIDStore(NULL),
                                      base::ThreadTaskRunnerHandle::Get());
  session_params_.channel_id_service = &channel_id_service;

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.token_binding_negotiated = true;
  ssl_data.token_binding_key_param = TB_PARAM_ECDSAP256;
  mock_socket_factory_.AddSSLSocketDataProvider(&ssl_data);
  MockRead mock_reads[] = {MockRead("HTTP/1.1 200 OK\r\n\r\n"),
                           MockRead(SYNCHRONOUS, OK)};
  StaticSocketDataProvider data(mock_reads, arraysize(mock_reads), NULL, 0);
  mock_socket_factory_.AddSocketDataProvider(&data);

  HttpNetworkSession session(session_params_);
  HttpNetworkTransaction trans(DEFAULT_PRIORITY, &session);

  TestCompletionCallback callback;
  int rv =
      callback.GetResult(trans.Start(GetRequestInfo("http://www.example.com/"),
                                     callback.callback(), BoundNetLog()));
  EXPECT_THAT(rv, IsOk());

  HttpRequestHeaders headers;
  ASSERT_TRUE(trans.GetFullRequestHeaders(&headers));
  std::string token_binding_header;
  EXPECT_FALSE(headers.GetHeader(HttpRequestHeaders::kTokenBinding,
                                 &token_binding_header));
}
#endif  // !defined(OS_IOS)

}  // namespace net
