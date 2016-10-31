// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_resolver_impl.h"

#include <utility>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "net/base/net_errors.h"
#include "net/proxy/mojo_proxy_resolver_v8_tracing_bindings.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver_script_data.h"
#include "net/proxy/proxy_resolver_v8_tracing.h"

namespace net {

class MojoProxyResolverImpl::Job {
 public:
  Job(interfaces::ProxyResolverRequestClientPtr client,
      MojoProxyResolverImpl* resolver,
      const GURL& url);
  ~Job();

  void Start();

 private:
  // Mojo error handler. This is invoked in response to the client
  // disconnecting, indicating cancellation.
  void OnConnectionError();

  void GetProxyDone(int error);

  MojoProxyResolverImpl* resolver_;

  interfaces::ProxyResolverRequestClientPtr client_;
  ProxyInfo result_;
  GURL url_;
  std::unique_ptr<net::ProxyResolver::Request> request_;
  bool done_;

  DISALLOW_COPY_AND_ASSIGN(Job);
};

MojoProxyResolverImpl::MojoProxyResolverImpl(
    std::unique_ptr<ProxyResolverV8Tracing> resolver)
    : resolver_(std::move(resolver)) {}

MojoProxyResolverImpl::~MojoProxyResolverImpl() {
}

void MojoProxyResolverImpl::GetProxyForUrl(
    const GURL& url,
    interfaces::ProxyResolverRequestClientPtr client) {
  DVLOG(1) << "GetProxyForUrl(" << url << ")";
  std::unique_ptr<Job> job =
      base::MakeUnique<Job>(std::move(client), this, url);
  Job* job_ptr = job.get();
  resolve_jobs_[job_ptr] = std::move(job);
  job_ptr->Start();
}

void MojoProxyResolverImpl::DeleteJob(Job* job) {
  auto it = resolve_jobs_.find(job);
  DCHECK(it != resolve_jobs_.end());
  resolve_jobs_.erase(it);
}

MojoProxyResolverImpl::Job::Job(
    interfaces::ProxyResolverRequestClientPtr client,
    MojoProxyResolverImpl* resolver,
    const GURL& url)
    : resolver_(resolver),
      client_(std::move(client)),
      url_(url),
      done_(false) {}

MojoProxyResolverImpl::Job::~Job() {}

void MojoProxyResolverImpl::Job::Start() {
  resolver_->resolver_->GetProxyForURL(
      url_, &result_, base::Bind(&Job::GetProxyDone, base::Unretained(this)),
      &request_, base::MakeUnique<MojoProxyResolverV8TracingBindings<
                     interfaces::ProxyResolverRequestClient>>(client_.get()));
  client_.set_connection_error_handler(base::Bind(
      &MojoProxyResolverImpl::Job::OnConnectionError, base::Unretained(this)));
}

void MojoProxyResolverImpl::Job::GetProxyDone(int error) {
  done_ = true;
  DVLOG(1) << "GetProxyForUrl(" << url_ << ") finished with error " << error
           << ". " << result_.proxy_list().size() << " Proxies returned:";
  for (const auto& proxy : result_.proxy_list().GetAll()) {
    DVLOG(1) << proxy.ToURI();
  }
  if (error == OK)
    client_->ReportResult(error, result_);
  else
    client_->ReportResult(error, ProxyInfo());

  resolver_->DeleteJob(this);
}

void MojoProxyResolverImpl::Job::OnConnectionError() {
  resolver_->DeleteJob(this);
}

}  // namespace net
