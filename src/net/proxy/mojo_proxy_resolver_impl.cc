// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_resolver_impl.h"

#include <utility>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/stl_util.h"
#include "net/base/net_errors.h"
#include "net/log/net_log.h"
#include "net/proxy/mojo_proxy_resolver_v8_tracing_bindings.h"
#include "net/proxy/mojo_proxy_type_converters.h"
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
  net::ProxyResolver::RequestHandle request_handle_;
  bool done_;

  DISALLOW_COPY_AND_ASSIGN(Job);
};

MojoProxyResolverImpl::MojoProxyResolverImpl(
    std::unique_ptr<ProxyResolverV8Tracing> resolver)
    : resolver_(std::move(resolver)) {}

MojoProxyResolverImpl::~MojoProxyResolverImpl() {
  base::STLDeleteElements(&resolve_jobs_);
}

void MojoProxyResolverImpl::GetProxyForUrl(
    const GURL& url,
    interfaces::ProxyResolverRequestClientPtr client) {
  DVLOG(1) << "GetProxyForUrl(" << url << ")";
  Job* job = new Job(std::move(client), this, url);
  bool inserted = resolve_jobs_.insert(job).second;
  DCHECK(inserted);
  job->Start();
}

void MojoProxyResolverImpl::DeleteJob(Job* job) {
  size_t num_erased = resolve_jobs_.erase(job);
  DCHECK(num_erased);
  delete job;
}

MojoProxyResolverImpl::Job::Job(
    interfaces::ProxyResolverRequestClientPtr client,
    MojoProxyResolverImpl* resolver,
    const GURL& url)
    : resolver_(resolver),
      client_(std::move(client)),
      url_(url),
      request_handle_(nullptr),
      done_(false) {}

MojoProxyResolverImpl::Job::~Job() {
  if (request_handle_ && !done_)
    resolver_->resolver_->CancelRequest(request_handle_);
}

void MojoProxyResolverImpl::Job::Start() {
  resolver_->resolver_->GetProxyForURL(
      url_, &result_, base::Bind(&Job::GetProxyDone, base::Unretained(this)),
      &request_handle_,
      base::MakeUnique<MojoProxyResolverV8TracingBindings<
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
  mojo::Array<interfaces::ProxyServerPtr> result;
  if (error == OK) {
    result = mojo::Array<interfaces::ProxyServerPtr>::From(
        result_.proxy_list().GetAll());
  }
  client_->ReportResult(error, std::move(result));
  resolver_->DeleteJob(this);
}

void MojoProxyResolverImpl::Job::OnConnectionError() {
  resolver_->DeleteJob(this);
}

}  // namespace net
