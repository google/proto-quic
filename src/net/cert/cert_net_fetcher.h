// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CERT_NET_FETCHER_H_
#define NET_CERT_CERT_NET_FETCHER_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/callback.h"
#include "base/macros.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"

class GURL;

namespace net {

class URLRequestContext;

// CertNetFetcher is an asynchronous interface for fetching AIA URLs and CRL
// URLs.
//
// -------------------------
// Cancellation of requests
// -------------------------
//
//  * Network requests started by the CertNetFetcher can be cancelled by
//    deleting the Request object. Cancellation means the request's callback
//    will no longer be invoked.
//
//  * If the CertNetFetcher is deleted then any outstanding
//    requests are automatically cancelled.
//
//  * Cancelling a request within the execution of a callback is allowed.
//
//  * Deleting the CertNetFetcher from within the execution of a callback is
//    allowed.
//
// -------------------------
// Threading
// -------------------------
//
// The CertNetFetcher is expected to be operated from a single thread, which has
// an IO message loop. The URLRequestContext will be accessed from this same
// thread, and callbacks will be posted to this message loop.
//
// For more details see the design document:
//   https://docs.google.com/a/chromium.org/document/d/1CdS9YOnPdAyVZBJqHY7ZJ6tUlU71OCvX8kHnaVhf144/edit
class NET_EXPORT CertNetFetcher {
 public:
  class Request {
   public:
    virtual ~Request() {}
  };

  // Callback invoked on request completion. If the Error is OK, then the
  // vector contains the response bytes.
  using FetchCallback =
      base::Callback<void(Error, const std::vector<uint8_t>&)>;

  // This value can be used in place of timeout or max size limits.
  enum { DEFAULT = -1 };

  CertNetFetcher() {}

  // Deletion implicitly cancels any outstanding requests.
  virtual ~CertNetFetcher() {}

  // The Fetch*() methods start an asynchronous request which can be cancelled
  // by deleting the returned Request. Here is the meaning of the common
  // parameters:
  //
  //   * url -- The http:// URL to fetch.
  //   * timeout_seconds -- The maximum allowed duration for the fetch job. If
  //         this delay is exceeded then the request will fail. To use a default
  //         timeout pass DEFAULT.
  //   * max_response_bytes -- The maximum size of the response body. If this
  //     size is exceeded then the request will fail. To use a default timeout
  //     pass DEFAULT.
  //   * callback -- The callback that will be invoked on completion of the job.

  virtual WARN_UNUSED_RESULT std::unique_ptr<Request> FetchCaIssuers(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes,
      const FetchCallback& callback) = 0;

  virtual WARN_UNUSED_RESULT std::unique_ptr<Request> FetchCrl(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes,
      const FetchCallback& callback) = 0;

  virtual WARN_UNUSED_RESULT std::unique_ptr<Request> FetchOcsp(
      const GURL& url,
      int timeout_milliseconds,
      int max_response_bytes,
      const FetchCallback& callback) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(CertNetFetcher);
};

}  // namespace net

#endif  // NET_CERT_NET_CERT_NET_FETCHER_H_
