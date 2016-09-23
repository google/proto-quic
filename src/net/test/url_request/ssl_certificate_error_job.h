// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TEST_URL_REQUEST_SSL_CERTIFICATE_ERROR_JOB_H_
#define NET_TEST_URL_REQUEST_SSL_CERTIFICATE_ERROR_JOB_H_

#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "net/url_request/url_request_job.h"
#include "url/gurl.h"

namespace net {

class NetworkDelegate;
class URLRequest;

// SSLCertificateErrorJob simulates a ERR_CERT_DATE_INVALID error.
class SSLCertificateErrorJob : public URLRequestJob {
 public:
  SSLCertificateErrorJob(URLRequest* request,
                         NetworkDelegate* network_delegate);

  // URLRequestJob implementation:
  void Start() override;

  // Adds the testing URLs to the URLRequestFilter.
  static void AddUrlHandler();

  static GURL GetMockUrl();

 private:
  ~SSLCertificateErrorJob() override;

  void NotifyError();

  base::WeakPtrFactory<SSLCertificateErrorJob> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(SSLCertificateErrorJob);
};

}  // namespace net

#endif  // NET_TEST_URL_REQUEST_SSL_CERTIFICATE_ERROR_JOB_H_
