// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_PROXY_MOJO_PROXY_RESOLVER_V8_TRACING_BINDINGS_H_
#define NET_PROXY_MOJO_PROXY_RESOLVER_V8_TRACING_BINDINGS_H_

#include <utility>

#include "base/threading/thread_checker.h"
#include "mojo/common/common_type_converters.h"
#include "net/dns/host_resolver_mojo.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"
#include "net/proxy/proxy_resolver_v8_tracing.h"

namespace net {

// An implementation of ProxyResolverV8Tracing::Bindings that forwards requests
// onto a Client mojo interface. Alert() and OnError() may be called from any
// thread; when they are called from another thread, the calls are proxied to
// the origin task runner. GetHostResolver() and GetBoundNetLog() may only be
// called from the origin task runner.
template <typename Client>
class MojoProxyResolverV8TracingBindings
    : public ProxyResolverV8Tracing::Bindings,
      public HostResolverMojo::Impl {
 public:
  explicit MojoProxyResolverV8TracingBindings(Client* client)
      : client_(client), host_resolver_(this) {
    DCHECK(client_);
  }

  // ProxyResolverV8Tracing::Bindings overrides.
  void Alert(const base::string16& message) override {
    DCHECK(thread_checker_.CalledOnValidThread());
    client_->Alert(mojo::String::From(message));
  }

  void OnError(int line_number, const base::string16& message) override {
    DCHECK(thread_checker_.CalledOnValidThread());
    client_->OnError(line_number, mojo::String::From(message));
  }

  HostResolver* GetHostResolver() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    return &host_resolver_;
  }

  BoundNetLog GetBoundNetLog() override {
    DCHECK(thread_checker_.CalledOnValidThread());
    return BoundNetLog();
  }

 private:
  // HostResolverMojo::Impl override.
  void ResolveDns(interfaces::HostResolverRequestInfoPtr request_info,
                  interfaces::HostResolverRequestClientPtr client) {
    DCHECK(thread_checker_.CalledOnValidThread());
    client_->ResolveDns(std::move(request_info), std::move(client));
  }

  base::ThreadChecker thread_checker_;
  Client* client_;
  HostResolverMojo host_resolver_;
};

}  // namespace net

#endif  // NET_PROXY_MOJO_PROXY_RESOLVER_V8_TRACING_BINDINGS_H_
