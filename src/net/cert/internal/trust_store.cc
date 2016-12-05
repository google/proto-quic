// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store.h"

namespace net {

scoped_refptr<TrustAnchor> TrustAnchor::CreateFromCertificateNoConstraints(
    scoped_refptr<ParsedCertificate> cert) {
  return scoped_refptr<TrustAnchor>(new TrustAnchor(std::move(cert), false));
}

scoped_refptr<TrustAnchor> TrustAnchor::CreateFromCertificateWithConstraints(
    scoped_refptr<ParsedCertificate> cert) {
  return scoped_refptr<TrustAnchor>(new TrustAnchor(std::move(cert), true));
}

der::Input TrustAnchor::spki() const {
  return cert_->tbs().spki_tlv;
}

der::Input TrustAnchor::normalized_subject() const {
  return cert_->normalized_subject();
}

const scoped_refptr<ParsedCertificate>& TrustAnchor::cert() const {
  return cert_;
}

TrustAnchor::TrustAnchor(scoped_refptr<ParsedCertificate> cert,
                         bool enforces_constraints)
    : cert_(std::move(cert)), enforces_constraints_(enforces_constraints) {
  DCHECK(cert_);
}

TrustAnchor::~TrustAnchor() = default;

TrustStore::TrustStore() = default;
TrustStore::~TrustStore() = default;

}  // namespace net
