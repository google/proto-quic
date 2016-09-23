// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_PROXY_SERVICE_MOJO_H_
#define NET_PROXY_PROXY_SERVICE_MOJO_H_

#include <memory>

#include "net/proxy/dhcp_proxy_script_fetcher.h"

namespace net {
namespace interfaces {
class ProxyResolverFactory;
}

class HostResolver;
class MojoProxyResolverFactory;
class NetLog;
class NetworkDelegate;
class ProxyConfigService;
class ProxyScriptFetcher;
class ProxyService;

// Creates a proxy service that uses |mojo_proxy_factory| to create and connect
// to a Mojo proxy resolver service. This proxy service polls
// |proxy_config_service| to notice when the proxy settings change.
//
// |proxy_script_fetcher| specifies the dependency to use for downloading
// any PAC scripts. The resulting ProxyService will take ownership of it.
//
// |dhcp_proxy_script_fetcher| specifies the dependency to use for attempting
// to retrieve the most appropriate PAC script configured in DHCP.
//
// |host_resolver| points to the host resolving dependency the PAC script
// should use for any DNS queries. It must remain valid throughout the
// lifetime of the ProxyService.
std::unique_ptr<ProxyService> CreateProxyServiceUsingMojoFactory(
    MojoProxyResolverFactory* mojo_proxy_factory,
    std::unique_ptr<ProxyConfigService> proxy_config_service,
    ProxyScriptFetcher* proxy_script_fetcher,
    std::unique_ptr<DhcpProxyScriptFetcher> dhcp_proxy_script_fetcher,
    HostResolver* host_resolver,
    NetLog* net_log,
    NetworkDelegate* network_delegate);

// Creates a proxy service that connects to an in-process Mojo proxy resolver
// service. See above for information about other arguments.
//
// ##########################################################################
// # See the warnings in net/proxy/proxy_resolver_v8.h describing the
// # multi-threading model. In order for this to be safe to use, *ALL* the
// # other V8's running in the process must use v8::Locker.
// ##########################################################################
std::unique_ptr<ProxyService> CreateProxyServiceUsingMojoInProcess(
    std::unique_ptr<ProxyConfigService> proxy_config_service,
    ProxyScriptFetcher* proxy_script_fetcher,
    std::unique_ptr<DhcpProxyScriptFetcher> dhcp_proxy_script_fetcher,
    HostResolver* host_resolver,
    NetLog* net_log,
    NetworkDelegate* network_delegate);

}  // namespace net

#endif  // NET_PROXY_PROXY_SERVICE_MOJO_H_
