// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/test_root_certs.h"

#include <cert.h>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "crypto/nss_util.h"
#include "net/cert/x509_certificate.h"

namespace net {


TestRootCerts::TrustEntry::TrustEntry(CERTCertificate* certificate,
                                      const CERTCertTrust& trust)
    : certificate_(CERT_DupCertificate(certificate)),
      trust_(trust) {
}

TestRootCerts::TrustEntry::~TrustEntry() {
  CERT_DestroyCertificate(certificate_);
}

bool TestRootCerts::Add(X509Certificate* certificate) {
  CERTCertificate* cert_handle = certificate->os_cert_handle();
  // Preserve the original trust bits so that they can be restored when
  // the certificate is removed.
  CERTCertTrust original_trust;
  SECStatus rv = CERT_GetCertTrust(cert_handle, &original_trust);
  if (rv != SECSuccess) {
    // CERT_GetCertTrust will fail if the certificate does not have any
    // particular trust settings associated with it, and attempts to use
    // |original_trust| later to restore the original trust settings will not
    // cause the trust settings to be revoked. If the certificate has no
    // particular trust settings associated with it, mark the certificate as
    // a valid CA certificate with no specific trust.
    rv = CERT_DecodeTrustString(&original_trust, "c,c,c");
  }

  // Change the trust bits to unconditionally trust this certificate.
  CERTCertTrust new_trust;
  rv = CERT_DecodeTrustString(&new_trust, "TCPu,Cu,Tu");
  if (rv != SECSuccess) {
    LOG(ERROR) << "Cannot decode certificate trust string.";
    return false;
  }

  rv = CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), cert_handle, &new_trust);
  if (rv != SECSuccess) {
    LOG(ERROR) << "Cannot change certificate trust.";
    return false;
  }

  trust_cache_.push_back(
      base::MakeUnique<TrustEntry>(cert_handle, original_trust));
  return true;
}

void TestRootCerts::Clear() {
  // Restore the certificate trusts to what they were originally, before
  // Add() was called. Work from the rear first, since if a certificate was
  // added twice, the second entry's original trust status will be that of
  // the first entry, while the first entry contains the desired resultant
  // status.
  for (auto it = trust_cache_.rbegin(); it != trust_cache_.rend(); ++it) {
    CERTCertTrust original_trust = (*it)->trust();
    SECStatus rv = CERT_ChangeCertTrust(CERT_GetDefaultCertDB(),
                                        (*it)->certificate(),
                                        &original_trust);
    // DCHECK(), rather than LOG(), as a failure to restore the original
    // trust can cause flake or hard-to-trace errors in any unit tests that
    // occur after Clear() has been called.
    DCHECK_EQ(SECSuccess, rv) << "Cannot restore certificate trust.";
  }
  trust_cache_.clear();
}

bool TestRootCerts::IsEmpty() const {
  return trust_cache_.empty();
}

bool TestRootCerts::Contains(CERTCertificate* cert) const {
  for (const auto& item : trust_cache_)
    if (X509Certificate::IsSameOSCert(cert, item->certificate()))
      return true;

  return false;
}

TestRootCerts::~TestRootCerts() {
  Clear();
}

void TestRootCerts::Init() {
  crypto::EnsureNSSInit();
}

}  // namespace net
