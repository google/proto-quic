// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context_storage.h"

#include <utility>

#include "base/logging.h"
#include "net/base/network_delegate.h"
#include "net/base/proxy_delegate.h"
#include "net/base/sdch_manager.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_verifier.h"
#include "net/cookies/cookie_store.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_transaction_factory.h"
#include "net/log/net_log.h"
#include "net/proxy/proxy_service.h"
#include "net/ssl/channel_id_service.h"
#include "net/url_request/http_user_agent_settings.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_throttler_manager.h"

namespace net {

URLRequestContextStorage::URLRequestContextStorage(URLRequestContext* context)
    : context_(context) {
  DCHECK(context);
}

URLRequestContextStorage::~URLRequestContextStorage() {}

void URLRequestContextStorage::set_net_log(std::unique_ptr<NetLog> net_log) {
  context_->set_net_log(net_log.get());
  net_log_ = std::move(net_log);
}

void URLRequestContextStorage::set_host_resolver(
    std::unique_ptr<HostResolver> host_resolver) {
  context_->set_host_resolver(host_resolver.get());
  host_resolver_ = std::move(host_resolver);
}

void URLRequestContextStorage::set_cert_verifier(
    std::unique_ptr<CertVerifier> cert_verifier) {
  context_->set_cert_verifier(cert_verifier.get());
  cert_verifier_ = std::move(cert_verifier);
}

void URLRequestContextStorage::set_channel_id_service(
    std::unique_ptr<ChannelIDService> channel_id_service) {
  context_->set_channel_id_service(channel_id_service.get());
  channel_id_service_ = std::move(channel_id_service);
}

void URLRequestContextStorage::set_http_auth_handler_factory(
    std::unique_ptr<HttpAuthHandlerFactory> http_auth_handler_factory) {
  context_->set_http_auth_handler_factory(http_auth_handler_factory.get());
  http_auth_handler_factory_ = std::move(http_auth_handler_factory);
}

void URLRequestContextStorage::set_proxy_service(
    std::unique_ptr<ProxyService> proxy_service) {
  context_->set_proxy_service(proxy_service.get());
  proxy_service_ = std::move(proxy_service);
}

void URLRequestContextStorage::set_ssl_config_service(
    SSLConfigService* ssl_config_service) {
  context_->set_ssl_config_service(ssl_config_service);
  ssl_config_service_ = ssl_config_service;
}

void URLRequestContextStorage::set_network_delegate(
    std::unique_ptr<NetworkDelegate> network_delegate) {
  context_->set_network_delegate(network_delegate.get());
  network_delegate_ = std::move(network_delegate);
}

void URLRequestContextStorage::set_proxy_delegate(
    std::unique_ptr<ProxyDelegate> proxy_delegate) {
  proxy_delegate_ = std::move(proxy_delegate);
}

void URLRequestContextStorage::set_http_server_properties(
    std::unique_ptr<HttpServerProperties> http_server_properties) {
  context_->set_http_server_properties(http_server_properties.get());
  http_server_properties_ = std::move(http_server_properties);
}

void URLRequestContextStorage::set_cookie_store(
    std::unique_ptr<CookieStore> cookie_store) {
  context_->set_cookie_store(cookie_store.get());
  cookie_store_ = std::move(cookie_store);
}

void URLRequestContextStorage::set_transport_security_state(
    std::unique_ptr<TransportSecurityState> transport_security_state) {
  context_->set_transport_security_state(transport_security_state.get());
  transport_security_state_ = std::move(transport_security_state);
}

void URLRequestContextStorage::set_cert_transparency_verifier(
    std::unique_ptr<CTVerifier> cert_transparency_verifier) {
  context_->set_cert_transparency_verifier(cert_transparency_verifier.get());
  cert_transparency_verifier_ = std::move(cert_transparency_verifier);
}

void URLRequestContextStorage::set_ct_policy_enforcer(
    std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer) {
  context_->set_ct_policy_enforcer(ct_policy_enforcer.get());
  ct_policy_enforcer_ = std::move(ct_policy_enforcer);
}

void URLRequestContextStorage::set_http_network_session(
    std::unique_ptr<HttpNetworkSession> http_network_session) {
  http_network_session_ = std::move(http_network_session);
}

void URLRequestContextStorage::set_http_transaction_factory(
    std::unique_ptr<HttpTransactionFactory> http_transaction_factory) {
  context_->set_http_transaction_factory(http_transaction_factory.get());
  http_transaction_factory_ = std::move(http_transaction_factory);
}

void URLRequestContextStorage::set_job_factory(
    std::unique_ptr<URLRequestJobFactory> job_factory) {
  context_->set_job_factory(job_factory.get());
  job_factory_ = std::move(job_factory);
}

void URLRequestContextStorage::set_throttler_manager(
    std::unique_ptr<URLRequestThrottlerManager> throttler_manager) {
  context_->set_throttler_manager(throttler_manager.get());
  throttler_manager_ = std::move(throttler_manager);
}

void URLRequestContextStorage::set_http_user_agent_settings(
    std::unique_ptr<HttpUserAgentSettings> http_user_agent_settings) {
  context_->set_http_user_agent_settings(http_user_agent_settings.get());
  http_user_agent_settings_ = std::move(http_user_agent_settings);
}

void URLRequestContextStorage::set_sdch_manager(
    std::unique_ptr<SdchManager> sdch_manager) {
  context_->set_sdch_manager(sdch_manager.get());
  sdch_manager_ = std::move(sdch_manager);
}

}  // namespace net
