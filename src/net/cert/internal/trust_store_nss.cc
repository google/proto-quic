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
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_util.h"

// TODO(mattm): structure so that supporting ChromeOS multi-profile stuff is
// doable (Have a TrustStoreChromeOS which uses net::NSSProfileFilterChromeOS,
// similar to CertVerifyProcChromeOS.)

namespace net {

TrustStoreNSS::TrustStoreNSS(SECTrustType trust_type)
    : trust_type_(trust_type) {}

TrustStoreNSS::~TrustStoreNSS() = default;

void TrustStoreNSS::SyncGetIssuersOf(const ParsedCertificate* cert,
                                     ParsedCertificateList* issuers) {
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
    CertErrors parse_errors;
    scoped_refptr<ParsedCertificate> cur_cert = ParsedCertificate::Create(
        x509_util::CreateCryptoBuffer(node->cert->derCert.data,
                                      node->cert->derCert.len),
        {}, &parse_errors);

    if (!cur_cert) {
      // TODO(crbug.com/634443): return errors better.
      LOG(ERROR) << "Error parsing issuer certificate:\n"
                 << parse_errors.ToDebugString();
      continue;
    }

    issuers->push_back(std::move(cur_cert));
  }
  CERT_DestroyCertList(found_certs);
}

void TrustStoreNSS::GetTrust(const scoped_refptr<ParsedCertificate>& cert,
                             CertificateTrust* out_trust) const {
  crypto::EnsureNSSInit();

  // TODO(eroman): Inefficient -- path building will convert between
  // CERTCertificate and ParsedCertificate representations multiple times
  // (when getting the issuers, and again here).

  // Lookup the certificate by Issuer + Serial number. Note that
  // CERT_FindCertByDERCert() doesn't check for equal DER, just matching issuer
  // + serial number.
  SECItem der_cert;
  der_cert.data = const_cast<uint8_t*>(cert->der_cert().UnsafeData());
  der_cert.len = cert->der_cert().Length();
  der_cert.type = siDERCertBuffer;
  ScopedCERTCertificate nss_matched_cert(
      CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &der_cert));
  if (!nss_matched_cert) {
    *out_trust = CertificateTrust::ForUnspecified();
    return;
  }

  // Determine the trustedness of the matched certificate.
  CERTCertTrust trust;
  if (CERT_GetCertTrust(nss_matched_cert.get(), &trust) != SECSuccess) {
    *out_trust = CertificateTrust::ForUnspecified();
    return;
  }

  // TODO(eroman): Determine if |nss_matched_cert| is distrusted.

  // Determine if the certificate is a trust anchor.
  const int ca_trust = CERTDB_TRUSTED_CA;
  bool is_trusted =
      (SEC_GET_TRUST_FLAGS(&trust, trust_type_) & ca_trust) == ca_trust;

  // To consider |cert| trusted, need to additionally check that
  // |cert| is the same as |nss_matched_cert|. This is because the lookup in NSS
  // was only by issuer + serial number, so could be for a different
  // SPKI.
  if (is_trusted &&
      (cert->der_cert() == der::Input(nss_matched_cert->derCert.data,
                                      nss_matched_cert->derCert.len))) {
    *out_trust = CertificateTrust::ForTrustAnchor();
    return;
  }

  *out_trust = CertificateTrust::ForUnspecified();
  return;
}

}  // namespace net
