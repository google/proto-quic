// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_NSS_H_
#define NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_NSS_H_

#include "net/base/net_export.h"
#include "net/cert/internal/cert_issuer_source.h"

namespace net {

// Returns issuers from NSS. Always returns results synchronously.
// This will return any matches from NSS, possibly including trust anchors,
// blacklisted/distrusted certs, and temporary/cached certs. In the current
// implementation, trust is checked in a separate stage of path building, so
// including trusted certs here doesn't cause any issues. In particular, a trust
// anchor being returned here indicates the path ending in that trust anchor
// must already have been tested and failed to verify, and now the pathbuilder
// is trying to find a different path through that certificate. Including
// distrusted certs is desirable so that those paths can be built (and then fail
// to verify), leading to a better error message.
class NET_EXPORT CertIssuerSourceNSS : public CertIssuerSource {
 public:
  CertIssuerSourceNSS();
  ~CertIssuerSourceNSS() override;

  // CertIssuerSource implementation:
  void SyncGetIssuersOf(const ParsedCertificate* cert,
                        ParsedCertificateList* issuers) override;
  void AsyncGetIssuersOf(const ParsedCertificate* cert,
                         std::unique_ptr<Request>* out_req) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(CertIssuerSourceNSS);
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_NSS_H_
