// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_MOJO_PROXY_RESOLVER_FACTORY_IMPL_H_
#define NET_PROXY_MOJO_PROXY_RESOLVER_FACTORY_IMPL_H_

#include <map>

#include "base/callback.h"
#include "base/macros.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"

namespace net {
class ProxyResolverV8TracingFactory;

class MojoProxyResolverFactoryImpl : public interfaces::ProxyResolverFactory {
 public:
  MojoProxyResolverFactoryImpl();
  explicit MojoProxyResolverFactoryImpl(
      std::unique_ptr<ProxyResolverV8TracingFactory> proxy_resolver_factory);

  ~MojoProxyResolverFactoryImpl() override;

 private:
  class Job;

  // interfaces::ProxyResolverFactory override.
  void CreateResolver(
      const std::string& pac_script,
      interfaces::ProxyResolverRequest request,
      interfaces::ProxyResolverFactoryRequestClientPtr client) override;

  void RemoveJob(Job* job);

  const std::unique_ptr<ProxyResolverV8TracingFactory>
      proxy_resolver_impl_factory_;

  std::map<Job*, std::unique_ptr<Job>> jobs_;

  DISALLOW_COPY_AND_ASSIGN(MojoProxyResolverFactoryImpl);
};

}  // namespace net

#endif  // NET_PROXY_MOJO_PROXY_RESOLVER_FACTORY_IMPL_H_
