// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_issuer_source_static.h"

namespace net {

CertIssuerSourceStatic::CertIssuerSourceStatic() = default;
CertIssuerSourceStatic::~CertIssuerSourceStatic() = default;

void CertIssuerSourceStatic::AddCert(scoped_refptr<ParsedCertificate> cert) {
  intermediates_.insert(std::make_pair(
      cert->normalized_subject().AsStringPiece(), std::move(cert)));
}

void CertIssuerSourceStatic::SyncGetIssuersOf(const ParsedCertificate* cert,
                                              ParsedCertificateList* issuers) {
  auto range =
      intermediates_.equal_range(cert->normalized_issuer().AsStringPiece());
  for (auto it = range.first; it != range.second; ++it)
    issuers->push_back(it->second);
}

void CertIssuerSourceStatic::AsyncGetIssuersOf(
    const ParsedCertificate* cert,
    const IssuerCallback& issuers_callback,
    std::unique_ptr<Request>* out_req) {
  // CertIssuerSourceStatic never returns asynchronous results.
  out_req->reset();
}

}  // namespace net
