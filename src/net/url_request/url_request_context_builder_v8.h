// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_V8_H_
#define NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_V8_H_

#include <memory>

#include "base/macros.h"
#include "net/proxy/dhcp_proxy_script_fetcher_factory.h"
#include "net/proxy/proxy_service.h"
#include "net/url_request/url_request_context_builder.h"

namespace net {

class HostResolver;
class NetLog;
class NetworkDelegate;
class MojoProxyResolverFactory;
class URLRequestContext;

// Specialization of URLRequestContextBuilder that can create a ProxyService
// that uses a V8 ProxyResolver. PAC scripts are run by V8 in process, by
// default, but a Mojo factory can be passed in for out-of-process resolution.
// PAC scripts will be fetched using the request context itself. If a
// PoxyService is set directly via the URLRequestContextBuilder API, it will be
// used instead of the one this class normally creates.
class URLRequestContextBuilderV8 : public URLRequestContextBuilder {
 public:
  URLRequestContextBuilderV8();
  ~URLRequestContextBuilderV8() override;

  // If set to false, the URLrequestContextBuilder will create a ProxyService,
  // which won't use V8. Defaults to true.
  void set_use_v8(bool use_v8) { use_v8_ = use_v8; }

  // Sets whether quick PAC checks are enabled. Defaults to true. Ignored if
  // use_v8 is false.
  void set_quick_check_enabled(bool quick_check_enabled) {
    quick_check_enabled_ = quick_check_enabled;
  }

  // Sets policy for sanitizing URLs before passing them a PAC. Defaults to
  // ProxyService::SanitizeUrlPolicy::SAFE. Ignored if use_v8 is false.
  void set_pac_sanitize_url_policy(
      net::ProxyService::SanitizeUrlPolicy sanitize_url_policy) {
    sanitize_url_policy_ = sanitize_url_policy;
  }

  // Overrides default DhcpProxyScriptFetcherFactory. Ignored if use_v8 is
  // false.
  void set_dhcp_fetcher_factory(
      std::unique_ptr<DhcpProxyScriptFetcherFactory> dhcp_fetcher_factory) {
    dhcp_fetcher_factory = std::move(dhcp_fetcher_factory_);
  }

#ifdef ENABLE_NET_MOJO
  // Sets Mojo factory used to create ProxyResolvers. If not set, V8 will be
  // used in process instead of Mojo. Ignored if use_v8 is false. The passed in
  // factory must outlive the URLRequestContext the builder creates.
  void set_mojo_proxy_resolver_factory(
      MojoProxyResolverFactory* mojo_proxy_resolver_factory) {
    mojo_proxy_resolver_factory_ = mojo_proxy_resolver_factory;
  }
#endif  // ENABLE_NET_MOJO

 private:
  std::unique_ptr<ProxyService> CreateProxyService(
      std::unique_ptr<ProxyConfigService> proxy_config_service,
      URLRequestContext* url_request_context,
      HostResolver* host_resolver,
      NetworkDelegate* network_delegate,
      NetLog* net_log) override;

  bool use_v8_ = true;
  bool quick_check_enabled_ = true;
  net::ProxyService::SanitizeUrlPolicy sanitize_url_policy_ =
      net::ProxyService::SanitizeUrlPolicy::SAFE;

  std::unique_ptr<DhcpProxyScriptFetcherFactory> dhcp_fetcher_factory_;

#ifdef ENABLE_NET_MOJO
  MojoProxyResolverFactory* mojo_proxy_resolver_factory_ = nullptr;
#endif

  DISALLOW_COPY_AND_ASSIGN(URLRequestContextBuilderV8);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_V8_H_
