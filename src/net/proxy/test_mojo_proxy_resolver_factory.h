// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_TEST_MOJO_PROXY_RESOLVER_FACTORY_H_
#define NET_PROXY_TEST_MOJO_PROXY_RESOLVER_FACTORY_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/singleton.h"
#include "net/proxy/mojo_proxy_resolver_factory.h"

namespace net {

// MojoProxyResolverFactory that runs PAC scripts in-process, for tests.
class TestMojoProxyResolverFactory : public MojoProxyResolverFactory {
 public:
  static TestMojoProxyResolverFactory* GetInstance();

  // Returns true if CreateResolver was called.
  bool resolver_created() { return resolver_created_; }

  // Sets the value returned by resolver_created. Since this is a singleton,
  // Serves to avoid with test fixture reuse.
  void set_resolver_created(bool resolver_created) {
    resolver_created_ = resolver_created;
  }

  // Overridden from MojoProxyResolverFactory:
  std::unique_ptr<base::ScopedClosureRunner> CreateResolver(
      const std::string& pac_script,
      mojo::InterfaceRequest<interfaces::ProxyResolver> req,
      interfaces::ProxyResolverFactoryRequestClientPtr client) override;

 private:
  TestMojoProxyResolverFactory();
  ~TestMojoProxyResolverFactory() override;

  friend struct base::DefaultSingletonTraits<TestMojoProxyResolverFactory>;

  interfaces::ProxyResolverFactoryPtr factory_;

  bool resolver_created_ = false;

  DISALLOW_COPY_AND_ASSIGN(TestMojoProxyResolverFactory);
};

}  // namespace net

#endif  // NET_PROXY_TEST_MOJO_PROXY_RESOLVER_FACTORY_H_
