// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_VERIFIER_H_
#define NET_CERT_CT_VERIFIER_H_

#include <string>

#include "net/base/net_export.h"

namespace net {

namespace ct {
struct CTVerifyResult;
struct SignedCertificateTimestamp;
}  // namespace ct

class BoundNetLog;
class CTLogVerifier;
class X509Certificate;

// Interface for verifying Signed Certificate Timestamps over a certificate.
// The only known (non-test) implementation currently is MultiLogCTVerifier.
class NET_EXPORT CTVerifier {
 public:
  class NET_EXPORT Observer {
   public:
    // Called for each Signed Certificate Timestamp from a known log that vas
    // verified successfully (i.e. the signature verifies). |sct| is the
    // Signed Certificate Timestamp, |cert| is the certificate it applies to.
    // The certificate is needed to calculate the hash of the log entry,
    // necessary for checking inclusion in the log.
    // Note: The observer (whose implementation is expected to exist outside
    // net/) may store the observed |cert| and |sct|.
    virtual void OnSCTVerified(X509Certificate* cert,
                               const ct::SignedCertificateTimestamp* sct) = 0;
  };

  virtual ~CTVerifier() {}

  // Verifies SCTs embedded in the certificate itself, SCTs embedded in a
  // stapled OCSP response, and SCTs obtained via the
  // signed_certificate_timestamp TLS extension on the given |cert|.
  // A certificate is permitted but not required to use multiple sources for
  // SCTs. It is expected that most certificates will use only one source
  // (embedding, TLS extension or OCSP stapling). If no stapled OCSP response
  // is available, |stapled_ocsp_response| should be an empty string. If no SCT
  // TLS extension was negotiated, |sct_list_from_tls_extension| should be an
  // empty string. |result| will be filled with the SCTs present, divided into
  // categories based on the verification result.
  virtual int Verify(X509Certificate* cert,
                     const std::string& stapled_ocsp_response,
                     const std::string& sct_list_from_tls_extension,
                     ct::CTVerifyResult* result,
                     const BoundNetLog& net_log) = 0;

  // Registers |observer| to receive notifications of validated SCTs. Does not
  // take ownership of the observer as the observer may be performing
  // URLRequests which have to be cancelled before this object is destroyed.
  // Setting |observer| to nullptr has the effect of stopping all notifications.
  virtual void SetObserver(Observer* observer) = 0;
};

}  // namespace net

#endif  // NET_CERT_CT_VERIFIER_H_
