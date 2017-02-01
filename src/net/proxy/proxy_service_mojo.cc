// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_service_mojo.h"

#include <memory>
#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/dns/mojo_host_resolver_impl.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"
#include "net/proxy/mojo_proxy_resolver_factory.h"
#include "net/proxy/network_delegate_error_observer.h"
#include "net/proxy/proxy_resolver_factory.h"
#include "net/proxy/proxy_resolver_factory_mojo.h"
#include "net/proxy/proxy_service.h"

namespace net {

std::unique_ptr<ProxyService> CreateProxyServiceUsingMojoFactory(
    MojoProxyResolverFactory* mojo_proxy_factory,
    std::unique_ptr<ProxyConfigService> proxy_config_service,
    ProxyScriptFetcher* proxy_script_fetcher,
    std::unique_ptr<DhcpProxyScriptFetcher> dhcp_proxy_script_fetcher,
    HostResolver* host_resolver,
    NetLog* net_log,
    NetworkDelegate* network_delegate) {
  DCHECK(proxy_config_service);
  DCHECK(proxy_script_fetcher);
  DCHECK(dhcp_proxy_script_fetcher);
  DCHECK(host_resolver);

  std::unique_ptr<ProxyService> proxy_service(new ProxyService(
      std::move(proxy_config_service),
      base::MakeUnique<ProxyResolverFactoryMojo>(
          mojo_proxy_factory, host_resolver,
          base::Bind(&NetworkDelegateErrorObserver::Create, network_delegate,
                     base::ThreadTaskRunnerHandle::Get()),
          net_log),
      net_log));

  // Configure fetchers to use for PAC script downloads and auto-detect.
  proxy_service->SetProxyScriptFetchers(proxy_script_fetcher,
                                        std::move(dhcp_proxy_script_fetcher));

  return proxy_service;
}

}  // namespace net
