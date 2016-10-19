// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/in_process_mojo_proxy_resolver_factory.h"

#include <utility>

#include "base/memory/singleton.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/proxy/mojo_proxy_resolver_factory_impl.h"

namespace net {

// static
InProcessMojoProxyResolverFactory*
InProcessMojoProxyResolverFactory::GetInstance() {
  return base::Singleton<InProcessMojoProxyResolverFactory>::get();
}

InProcessMojoProxyResolverFactory::InProcessMojoProxyResolverFactory() {
  mojo::MakeStrongBinding(base::MakeUnique<MojoProxyResolverFactoryImpl>(),
                          mojo::GetProxy(&factory_));
}

InProcessMojoProxyResolverFactory::~InProcessMojoProxyResolverFactory() =
    default;

std::unique_ptr<base::ScopedClosureRunner>
InProcessMojoProxyResolverFactory::CreateResolver(
    const std::string& pac_script,
    mojo::InterfaceRequest<interfaces::ProxyResolver> req,
    interfaces::ProxyResolverFactoryRequestClientPtr client) {
  factory_->CreateResolver(pac_script, std::move(req), std::move(client));
  return nullptr;
}

}  // namespace net
