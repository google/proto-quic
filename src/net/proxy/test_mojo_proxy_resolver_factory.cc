// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/test_mojo_proxy_resolver_factory.h"

#include "base/memory/ptr_util.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/proxy/mojo_proxy_resolver_factory_impl.h"

namespace net {

TestMojoProxyResolverFactory* TestMojoProxyResolverFactory::GetInstance() {
  return base::Singleton<TestMojoProxyResolverFactory>::get();
}

std::unique_ptr<base::ScopedClosureRunner>
TestMojoProxyResolverFactory::CreateResolver(
    const std::string& pac_script,
    mojo::InterfaceRequest<interfaces::ProxyResolver> req,
    interfaces::ProxyResolverFactoryRequestClientPtr client) {
  resolver_created_ = true;
  factory_->CreateResolver(pac_script, std::move(req), std::move(client));
  return nullptr;
}

TestMojoProxyResolverFactory::TestMojoProxyResolverFactory() {
  mojo::MakeStrongBinding(base::MakeUnique<MojoProxyResolverFactoryImpl>(),
                          mojo::MakeRequest(&factory_));
}

TestMojoProxyResolverFactory::~TestMojoProxyResolverFactory() = default;

}  // namespace net
