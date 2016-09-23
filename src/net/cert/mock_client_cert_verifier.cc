// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/mock_client_cert_verifier.h"

#include <memory>

#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"

namespace net {

struct MockClientCertVerifier::Rule {
  Rule(X509Certificate* cert, int rv) : cert(cert), rv(rv) { DCHECK(cert); }

  scoped_refptr<X509Certificate> cert;
  int rv;
};

MockClientCertVerifier::MockClientCertVerifier()
    : default_result_(ERR_CERT_INVALID) {}

MockClientCertVerifier::~MockClientCertVerifier() {}

int MockClientCertVerifier::Verify(X509Certificate* cert,
                                   const CompletionCallback& callback,
                                   std::unique_ptr<Request>* out_req) {
  for (const Rule& rule : rules_) {
    // Check just the server cert. Intermediates will be ignored.
    if (rule.cert->Equals(cert))
      return rule.rv;
  }
  return default_result_;
}

void MockClientCertVerifier::AddResultForCert(X509Certificate* cert, int rv) {
  Rule rule(cert, rv);
  rules_.push_back(rule);
}

}  // namespace net
