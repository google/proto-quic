// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context_builder_mojo.h"

#include "base/logging.h"
#include "build/build_config.h"
#include "net/proxy/proxy_config_service.h"
#include "net/proxy/proxy_script_fetcher_impl.h"
#include "net/proxy/proxy_service_mojo.h"

namespace net {

URLRequestContextBuilderMojo::URLRequestContextBuilderMojo()
    : dhcp_fetcher_factory_(new DhcpProxyScriptFetcherFactory()) {}

URLRequestContextBuilderMojo::~URLRequestContextBuilderMojo() = default;

std::unique_ptr<ProxyService> URLRequestContextBuilderMojo::CreateProxyService(
    std::unique_ptr<ProxyConfigService> proxy_config_service,
    URLRequestContext* url_request_context,
    HostResolver* host_resolver,
    NetworkDelegate* network_delegate,
    NetLog* net_log) {
  DCHECK(url_request_context);
  DCHECK(host_resolver);

  if (!mojo_proxy_resolver_factory_) {
    return URLRequestContextBuilder::CreateProxyService(
        std::move(proxy_config_service), url_request_context, host_resolver,
        network_delegate, net_log);
  }

  std::unique_ptr<net::DhcpProxyScriptFetcher> dhcp_proxy_script_fetcher =
      dhcp_fetcher_factory_->Create(url_request_context);
  std::unique_ptr<net::ProxyScriptFetcher> proxy_script_fetcher =
      base::MakeUnique<ProxyScriptFetcherImpl>(url_request_context);
  return CreateProxyServiceUsingMojoFactory(
      mojo_proxy_resolver_factory_, std::move(proxy_config_service),
      proxy_script_fetcher.release(), std::move(dhcp_proxy_script_fetcher),
      host_resolver, net_log, network_delegate);
}

}  // namespace net
