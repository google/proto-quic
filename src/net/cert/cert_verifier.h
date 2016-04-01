// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CERT_VERIFIER_H_
#define NET_CERT_CERT_VERIFIER_H_

#include <string>

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"

namespace net {

class BoundNetLog;
class CertVerifyResult;
class CRLSet;
class X509Certificate;

// CertVerifier represents a service for verifying certificates.
//
// CertVerifiers can handle multiple requests at a time.
class NET_EXPORT CertVerifier {
 public:
  class Request {
   public:
    Request() {}

    // Destruction of the Request cancels it.
    virtual ~Request() {}

   private:
    DISALLOW_COPY_AND_ASSIGN(Request);
  };

  enum VerifyFlags {
    // If set, enables online revocation checking via CRLs and OCSP for the
    // certificate chain.
    VERIFY_REV_CHECKING_ENABLED = 1 << 0,

    // If set, and the certificate being verified may be an EV certificate,
    // attempt to verify the certificate according to the EV processing
    // guidelines. In order to successfully verify a certificate as EV,
    // either an online or offline revocation check must be successfully
    // completed. To ensure it's possible to complete a revocation check,
    // callers should also specify either VERIFY_REV_CHECKING_ENABLED or
    // VERIFY_REV_CHECKING_ENABLED_EV_ONLY (to enable online checks), and
    // VERIFY_CERT_IO_ENABLED (to enable network fetches for online checks).
    VERIFY_EV_CERT = 1 << 1,

    // If set, permits NSS to use the network when verifying certificates,
    // such as to fetch missing intermediates or to check OCSP or CRLs.
    // TODO(rsleevi): http://crbug.com/143300 - Define this flag for all
    // verification engines with well-defined semantics, rather than being
    // NSS only.
    VERIFY_CERT_IO_ENABLED = 1 << 2,

    // If set, enables online revocation checking via CRLs or OCSP when the
    // chain is not covered by a fresh CRLSet, but only for certificates which
    // may be EV, and only when VERIFY_EV_CERT is also set.
    VERIFY_REV_CHECKING_ENABLED_EV_ONLY = 1 << 3,

    // If set, this is equivalent to VERIFY_REV_CHECKING_ENABLED, in that it
    // enables online revocation checking via CRLs or OCSP, but only
    // for certificates issued by non-public trust anchors. Failure to check
    // revocation is treated as a hard failure.
    // Note: If VERIFY_CERT_IO_ENABLE is not also supplied, certificates
    // that chain to local trust anchors will likely fail - for example, due to
    // lacking fresh cached revocation issue (Windows) or because OCSP stapling
    // can only provide information for the leaf, and not for any
    // intermediates.
    VERIFY_REV_CHECKING_REQUIRED_LOCAL_ANCHORS = 1 << 4,
  };

  // When the verifier is destroyed, all certificate verification requests are
  // canceled, and their completion callbacks will not be called.
  virtual ~CertVerifier() {}

  // Verifies the given certificate against the given hostname as an SSL server.
  // Returns OK if successful or an error code upon failure.
  //
  // The |*verify_result| structure, including the |verify_result->cert_status|
  // bitmask, is always filled out regardless of the return value.  If the
  // certificate has multiple errors, the corresponding status flags are set in
  // |verify_result->cert_status|, and the error code for the most serious
  // error is returned.
  //
  // |ocsp_response|, if non-empty, is a stapled OCSP response to use.
  //
  // |flags| is bitwise OR'd of VerifyFlags.
  // If VERIFY_REV_CHECKING_ENABLED is set in |flags|, certificate revocation
  // checking is performed.
  //
  // If VERIFY_EV_CERT is set in |flags| too, EV certificate verification is
  // performed.  If |flags| is VERIFY_EV_CERT (that is,
  // VERIFY_REV_CHECKING_ENABLED is not set), EV certificate verification will
  // not be performed.
  //
  // |crl_set| points to an optional CRLSet structure which can be used to
  // avoid revocation checks over the network.
  //
  // |callback| must not be null.  ERR_IO_PENDING is returned if the operation
  // could not be completed synchronously, in which case the result code will
  // be passed to the callback when available.
  //
  // On asynchronous completion (when Verify returns ERR_IO_PENDING) |out_req|
  // will be reset with a pointer to the request. Freeing this pointer before
  // the request has completed will cancel it.
  //
  // If Verify() completes synchronously then |out_req| *may* be reset to
  // nullptr. However it is not guaranteed that all implementations will reset
  // it in this case.
  //
  // TODO(rsleevi): Move CRLSet* out of the CertVerifier signature.
  virtual int Verify(X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     int flags,
                     CRLSet* crl_set,
                     CertVerifyResult* verify_result,
                     const CompletionCallback& callback,
                     scoped_ptr<Request>* out_req,
                     const BoundNetLog& net_log) = 0;

  // Returns true if this CertVerifier supports stapled OCSP responses.
  virtual bool SupportsOCSPStapling();

  // Creates a CertVerifier implementation that verifies certificates using
  // the preferred underlying cryptographic libraries.
  static scoped_ptr<CertVerifier> CreateDefault();
};

}  // namespace net

#endif  // NET_CERT_CERT_VERIFIER_H_
