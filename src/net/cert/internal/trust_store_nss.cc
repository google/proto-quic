// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_nss.h"

#include <cert.h>
#include <certdb.h>

#include "base/memory/ptr_util.h"
#include "crypto/nss_util.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/x509_util.h"

// TODO(mattm): structure so that supporting ChromeOS multi-profile stuff is
// doable (Have a TrustStoreChromeOS which uses net::NSSProfileFilterChromeOS,
// similar to CertVerifyProcChromeOS.)

namespace net {

TrustStoreNSS::TrustStoreNSS(SECTrustType trust_type)
    : trust_type_(trust_type) {}

TrustStoreNSS::~TrustStoreNSS() = default;

void TrustStoreNSS::FindTrustAnchorsForCert(
    const scoped_refptr<ParsedCertificate>& cert,
    TrustAnchors* out_anchors) const {
  crypto::EnsureNSSInit();

  SECItem name;
  // Use the original issuer value instead of the normalized version. NSS does a
  // less extensive normalization in its Name comparisons, so our normalized
  // version may not match the unnormalized version.
  name.len = cert->tbs().issuer_tlv.Length();
  name.data = const_cast<uint8_t*>(cert->tbs().issuer_tlv.UnsafeData());
  // |validOnly| in CERT_CreateSubjectCertList controls whether to return only
  // certs that are valid at |sorttime|. Expiration isn't meaningful for trust
  // anchors, so request all the matches.
  CERTCertList* found_certs = CERT_CreateSubjectCertList(
      nullptr /* certList */, CERT_GetDefaultCertDB(), &name,
      PR_Now() /* sorttime */, PR_FALSE /* validOnly */);
  if (!found_certs)
    return;

  for (CERTCertListNode* node = CERT_LIST_HEAD(found_certs);
       !CERT_LIST_END(node, found_certs); node = CERT_LIST_NEXT(node)) {
    CERTCertTrust trust;
    if (CERT_GetCertTrust(node->cert, &trust) != SECSuccess)
      continue;

    // TODO(mattm): handle explicit distrust (blacklisting)?
    const int ca_trust = CERTDB_TRUSTED_CA;
    if ((SEC_GET_TRUST_FLAGS(&trust, trust_type_) & ca_trust) != ca_trust)
      continue;

    CertErrors errors;
    scoped_refptr<ParsedCertificate> anchor_cert = ParsedCertificate::Create(
        x509_util::CreateCryptoBuffer(node->cert->derCert.data,
                                      node->cert->derCert.len),
        {}, &errors);
    if (!anchor_cert) {
      // TODO(crbug.com/634443): return errors better.
      LOG(ERROR) << "Error parsing issuer certificate:\n"
                 << errors.ToDebugString();
      continue;
    }

    out_anchors->push_back(TrustAnchor::CreateFromCertificateNoConstraints(
        std::move(anchor_cert)));
  }
  CERT_DestroyCertList(found_certs);
}

}  // namespace net
