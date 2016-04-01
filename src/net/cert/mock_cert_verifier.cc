// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/mock_cert_verifier.h"

#include "base/memory/ref_counted.h"
#include "base/strings/pattern.h"
#include "base/strings/string_util.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"

namespace net {

struct MockCertVerifier::Rule {
  Rule(X509Certificate* cert,
       const std::string& hostname,
       const CertVerifyResult& result,
       int rv)
      : cert(cert),
        hostname(hostname),
        result(result),
        rv(rv) {
    DCHECK(cert);
    DCHECK(result.verified_cert.get());
  }

  scoped_refptr<X509Certificate> cert;
  std::string hostname;
  CertVerifyResult result;
  int rv;
};

MockCertVerifier::MockCertVerifier() : default_result_(ERR_CERT_INVALID) {}

MockCertVerifier::~MockCertVerifier() {}

int MockCertVerifier::Verify(X509Certificate* cert,
                             const std::string& hostname,
                             const std::string& ocsp_response,
                             int flags,
                             CRLSet* crl_set,
                             CertVerifyResult* verify_result,
                             const CompletionCallback& callback,
                             scoped_ptr<Request>* out_req,
                             const BoundNetLog& net_log) {
  RuleList::const_iterator it;
  for (it = rules_.begin(); it != rules_.end(); ++it) {
    // Check just the server cert. Intermediates will be ignored.
    if (!it->cert->Equals(cert))
      continue;
    if (!base::MatchPattern(hostname, it->hostname))
      continue;
    *verify_result = it->result;
    return it->rv;
  }

  // Fall through to the default.
  verify_result->verified_cert = cert;
  verify_result->cert_status = MapNetErrorToCertStatus(default_result_);
  return default_result_;
}

void MockCertVerifier::AddResultForCert(X509Certificate* cert,
                                        const CertVerifyResult& verify_result,
                                        int rv) {
  AddResultForCertAndHost(cert, "*", verify_result, rv);
}

void MockCertVerifier::AddResultForCertAndHost(
    X509Certificate* cert,
    const std::string& host_pattern,
    const CertVerifyResult& verify_result,
    int rv) {
  Rule rule(cert, host_pattern, verify_result, rv);
  rules_.push_back(rule);
}

}  // namespace net
