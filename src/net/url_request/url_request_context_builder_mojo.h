// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_MOJO_H_
#define NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_MOJO_H_

#include <memory>

#include "base/macros.h"
#include "build/build_config.h"
#include "net/proxy/dhcp_proxy_script_fetcher_factory.h"
#include "net/url_request/url_request_context_builder.h"

namespace net {

class HostResolver;
class NetLog;
class NetworkDelegate;
class MojoProxyResolverFactory;
class ProxyService;
class URLRequestContext;

// Specialization of URLRequestContextBuilder that can create a ProxyService
// that uses a Mojo ProxyResolver. The consumer is responsible for providing
// the MojoProxyResolverFactory.  If a PoxyService is set directly via the
// URLRequestContextBuilder API, it will be used instead.
class URLRequestContextBuilderMojo : public URLRequestContextBuilder {
 public:
  URLRequestContextBuilderMojo();
  ~URLRequestContextBuilderMojo() override;

  // Overrides default DhcpProxyScriptFetcherFactory. Ignored if no
  // MojoProxyResolverFactory is provided.
  void set_dhcp_fetcher_factory(
      std::unique_ptr<DhcpProxyScriptFetcherFactory> dhcp_fetcher_factory) {
    dhcp_fetcher_factory_ = std::move(dhcp_fetcher_factory);
  }

  // Sets Mojo factory used to create ProxyResolvers. If not set, falls back to
  // URLRequestContext's default behavior. The passed in factory must outlive
  // the URLRequestContext the builder creates.
  void set_mojo_proxy_resolver_factory(
      MojoProxyResolverFactory* mojo_proxy_resolver_factory) {
    mojo_proxy_resolver_factory_ = mojo_proxy_resolver_factory;
  }

 private:
  std::unique_ptr<ProxyService> CreateProxyService(
      std::unique_ptr<ProxyConfigService> proxy_config_service,
      URLRequestContext* url_request_context,
      HostResolver* host_resolver,
      NetworkDelegate* network_delegate,
      NetLog* net_log) override;

  std::unique_ptr<DhcpProxyScriptFetcherFactory> dhcp_fetcher_factory_;

  MojoProxyResolverFactory* mojo_proxy_resolver_factory_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(URLRequestContextBuilderMojo);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_CONTEXT_BUILDER_MOJO_H_
