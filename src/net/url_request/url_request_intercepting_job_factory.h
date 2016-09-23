// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_URL_REQUEST_URL_REQUEST_INTERCEPTING_JOB_FACTORY_H_
#define NET_URL_REQUEST_URL_REQUEST_INTERCEPTING_JOB_FACTORY_H_

#include <memory>
#include <string>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/url_request/url_request_job_factory.h"

class GURL;

namespace net {

class URLRequest;
class URLRequestJob;
class URLRequestInterceptor;

// This class acts as a wrapper for URLRequestJobFactory.  The
// URLRequestInteceptor is given the option of creating a URLRequestJob for each
// URLRequest. If the interceptor does not create a job, the URLRequest is
// forwarded to the wrapped URLRequestJobFactory instead.
//
// This class is only intended for use in intercepting requests before they
// are passed on to their default ProtocolHandler.  Each supported scheme should
// have its own ProtocolHandler.
class NET_EXPORT URLRequestInterceptingJobFactory
    : public URLRequestJobFactory {
 public:
  URLRequestInterceptingJobFactory(
      std::unique_ptr<URLRequestJobFactory> job_factory,
      std::unique_ptr<URLRequestInterceptor> interceptor);
  ~URLRequestInterceptingJobFactory() override;

  // URLRequestJobFactory implementation
  URLRequestJob* MaybeCreateJobWithProtocolHandler(
      const std::string& scheme,
      URLRequest* request,
      NetworkDelegate* network_delegate) const override;

  URLRequestJob* MaybeInterceptRedirect(
      URLRequest* request,
      NetworkDelegate* network_delegate,
      const GURL& location) const override;

  URLRequestJob* MaybeInterceptResponse(
      URLRequest* request,
      NetworkDelegate* network_delegate) const override;

  bool IsHandledProtocol(const std::string& scheme) const override;
  bool IsHandledURL(const GURL& url) const override;
  bool IsSafeRedirectTarget(const GURL& location) const override;

 private:
  std::unique_ptr<URLRequestJobFactory> job_factory_;
  std::unique_ptr<URLRequestInterceptor> interceptor_;

  DISALLOW_COPY_AND_ASSIGN(URLRequestInterceptingJobFactory);
};

}  // namespace net

#endif  // NET_URL_REQUEST_URL_REQUEST_INTERCEPTING_JOB_FACTORY_H_
