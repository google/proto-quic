// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_MOJO_PROXY_RESOLVER_FACTORY_H_
#define NET_PROXY_MOJO_PROXY_RESOLVER_FACTORY_H_

#include <memory>

#include "base/callback_helpers.h"
#include "mojo/public/cpp/bindings/interface_request.h"
#include "net/interfaces/host_resolver_service.mojom.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"

namespace net {

// Factory for connecting to Mojo ProxyResolver services.
class MojoProxyResolverFactory {
 public:
  // Connect to a new ProxyResolver service using request |req|, using
  // |host_resolver| as the DNS resolver. The return value should be released
  // when the connection to |req| is no longer needed.
  // Note: The connection request |req| may be resolved asynchronously.
  virtual std::unique_ptr<base::ScopedClosureRunner> CreateResolver(
      const mojo::String& pac_script,
      mojo::InterfaceRequest<interfaces::ProxyResolver> req,
      interfaces::ProxyResolverFactoryRequestClientPtr client) = 0;

 protected:
  virtual ~MojoProxyResolverFactory() = default;
};

}  // namespace net

#endif  // NET_PROXY_MOJO_PROXY_RESOLVER_FACTORY_H_
