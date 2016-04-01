// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_PROXY_RESOLVER_MAC_H_
#define NET_PROXY_PROXY_RESOLVER_MAC_H_

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/proxy/proxy_resolver_factory.h"
#include "url/gurl.h"

namespace net {

// Implementation of ProxyResolverFactory that uses the Mac CFProxySupport to
// implement proxies.
class NET_EXPORT ProxyResolverFactoryMac : public ProxyResolverFactory {
 public:
  ProxyResolverFactoryMac();

  int CreateProxyResolver(
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      scoped_ptr<ProxyResolver>* resolver,
      const CompletionCallback& callback,
      scoped_ptr<Request>* request) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(ProxyResolverFactoryMac);
};

}  // namespace net

#endif  // NET_PROXY_PROXY_RESOLVER_MAC_H_
