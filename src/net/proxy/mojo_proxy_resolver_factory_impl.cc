// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_resolver_factory_impl.h"

#include <string>
#include <utility>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "net/base/net_errors.h"
#include "net/proxy/mojo_proxy_resolver_impl.h"
#include "net/proxy/mojo_proxy_resolver_v8_tracing_bindings.h"
#include "net/proxy/proxy_resolver_factory.h"
#include "net/proxy/proxy_resolver_v8_tracing.h"

namespace net {

class MojoProxyResolverFactoryImpl::Job {
 public:
  Job(MojoProxyResolverFactoryImpl* parent,
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      ProxyResolverV8TracingFactory* proxy_resolver_factory,
      mojo::InterfaceRequest<interfaces::ProxyResolver> request,
      interfaces::ProxyResolverFactoryRequestClientPtr client);
  ~Job();

 private:
  // Mojo error handler.
  void OnConnectionError();

  void OnProxyResolverCreated(int error);

  MojoProxyResolverFactoryImpl* const parent_;
  std::unique_ptr<ProxyResolverV8Tracing> proxy_resolver_impl_;
  mojo::InterfaceRequest<interfaces::ProxyResolver> proxy_request_;
  ProxyResolverV8TracingFactory* factory_;
  std::unique_ptr<net::ProxyResolverFactory::Request> request_;
  interfaces::ProxyResolverFactoryRequestClientPtr client_ptr_;

  DISALLOW_COPY_AND_ASSIGN(Job);
};

MojoProxyResolverFactoryImpl::Job::Job(
    MojoProxyResolverFactoryImpl* factory,
    const scoped_refptr<ProxyResolverScriptData>& pac_script,
    ProxyResolverV8TracingFactory* proxy_resolver_factory,
    mojo::InterfaceRequest<interfaces::ProxyResolver> request,
    interfaces::ProxyResolverFactoryRequestClientPtr client)
    : parent_(factory),
      proxy_request_(std::move(request)),
      factory_(proxy_resolver_factory),
      client_ptr_(std::move(client)) {
  client_ptr_.set_connection_error_handler(
      base::Bind(&MojoProxyResolverFactoryImpl::Job::OnConnectionError,
                 base::Unretained(this)));
  factory_->CreateProxyResolverV8Tracing(
      pac_script,
      base::MakeUnique<MojoProxyResolverV8TracingBindings<
          interfaces::ProxyResolverFactoryRequestClient>>(client_ptr_.get()),
      &proxy_resolver_impl_,
      base::Bind(&MojoProxyResolverFactoryImpl::Job::OnProxyResolverCreated,
                 base::Unretained(this)),
      &request_);
}

MojoProxyResolverFactoryImpl::Job::~Job() = default;

void MojoProxyResolverFactoryImpl::Job::OnConnectionError() {
  client_ptr_->ReportResult(ERR_PAC_SCRIPT_TERMINATED);
  parent_->RemoveJob(this);
}

void MojoProxyResolverFactoryImpl::Job::OnProxyResolverCreated(int error) {
  if (error == OK) {
    mojo::MakeStrongBinding(base::MakeUnique<MojoProxyResolverImpl>(
                                std::move(proxy_resolver_impl_)),
                            std::move(proxy_request_));
  }
  client_ptr_->ReportResult(error);
  parent_->RemoveJob(this);
}

MojoProxyResolverFactoryImpl::MojoProxyResolverFactoryImpl(
    std::unique_ptr<ProxyResolverV8TracingFactory> proxy_resolver_factory)
    : proxy_resolver_impl_factory_(std::move(proxy_resolver_factory)) {}

MojoProxyResolverFactoryImpl::MojoProxyResolverFactoryImpl()
    : MojoProxyResolverFactoryImpl(ProxyResolverV8TracingFactory::Create()) {}

MojoProxyResolverFactoryImpl::~MojoProxyResolverFactoryImpl() {
}

void MojoProxyResolverFactoryImpl::CreateResolver(
    const std::string& pac_script,
    mojo::InterfaceRequest<interfaces::ProxyResolver> request,
    interfaces::ProxyResolverFactoryRequestClientPtr client) {
  // The Job will call RemoveJob on |this| when either the create request
  // finishes or |request| or |client| encounters a connection error.
  std::unique_ptr<Job> job =
      base::MakeUnique<Job>(this, ProxyResolverScriptData::FromUTF8(pac_script),
                            proxy_resolver_impl_factory_.get(),
                            std::move(request), std::move(client));
  Job* job_ptr = job.get();
  jobs_[job_ptr] = std::move(job);
}

void MojoProxyResolverFactoryImpl::RemoveJob(Job* job) {
  auto it = jobs_.find(job);
  DCHECK(it != jobs_.end());
  jobs_.erase(it);
}

}  // namespace net
