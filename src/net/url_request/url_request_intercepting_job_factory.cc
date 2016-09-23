// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_intercepting_job_factory.h"

#include <utility>

#include "base/logging.h"
#include "net/url_request/url_request_interceptor.h"

namespace net {

URLRequestInterceptingJobFactory::URLRequestInterceptingJobFactory(
    std::unique_ptr<URLRequestJobFactory> job_factory,
    std::unique_ptr<URLRequestInterceptor> interceptor)
    : job_factory_(std::move(job_factory)),
      interceptor_(std::move(interceptor)) {}

URLRequestInterceptingJobFactory::~URLRequestInterceptingJobFactory() {}

URLRequestJob* URLRequestInterceptingJobFactory::
MaybeCreateJobWithProtocolHandler(
    const std::string& scheme,
    URLRequest* request,
    NetworkDelegate* network_delegate) const {
  DCHECK(CalledOnValidThread());
  URLRequestJob* job = interceptor_->MaybeInterceptRequest(request,
                                                           network_delegate);
  if (job)
    return job;
  return job_factory_->MaybeCreateJobWithProtocolHandler(
      scheme, request, network_delegate);
}

URLRequestJob* URLRequestInterceptingJobFactory::MaybeInterceptRedirect(
    URLRequest* request,
    NetworkDelegate* network_delegate,
    const GURL& location) const {
  DCHECK(CalledOnValidThread());
  URLRequestJob* job = interceptor_->MaybeInterceptRedirect(request,
                                                            network_delegate,
                                                            location);
  if (job)
    return job;
  return job_factory_->MaybeInterceptRedirect(request,
                                              network_delegate,
                                              location);
}

URLRequestJob* URLRequestInterceptingJobFactory::MaybeInterceptResponse(
    URLRequest* request,
    NetworkDelegate* network_delegate) const {
  DCHECK(CalledOnValidThread());
  URLRequestJob* job = interceptor_->MaybeInterceptResponse(request,
                                                            network_delegate);
  if (job)
    return job;
  return job_factory_->MaybeInterceptResponse(request,
                                              network_delegate);
}

bool URLRequestInterceptingJobFactory::IsHandledProtocol(
    const std::string& scheme) const {
  return job_factory_->IsHandledProtocol(scheme);
}

bool URLRequestInterceptingJobFactory::IsHandledURL(const GURL& url) const {
  return job_factory_->IsHandledURL(url);
}

bool URLRequestInterceptingJobFactory::IsSafeRedirectTarget(
    const GURL& location) const {
  return job_factory_->IsSafeRedirectTarget(location);
}

}  // namespace net
