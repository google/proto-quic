// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_issuer_source_nss.h"

#include <cert.h>
#include <certdb.h>

#include "crypto/nss_util.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/x509_util.h"

namespace net {

CertIssuerSourceNSS::CertIssuerSourceNSS() = default;
CertIssuerSourceNSS::~CertIssuerSourceNSS() = default;

void CertIssuerSourceNSS::SyncGetIssuersOf(const ParsedCertificate* cert,
                                           ParsedCertificateList* issuers) {
  crypto::EnsureNSSInit();

  SECItem name;
  // Use the original issuer value instead of the normalized version. NSS does a
  // less extensive normalization in its Name comparisons, so our normalized
  // version may not match the unnormalized version.
  name.len = cert->tbs().issuer_tlv.Length();
  name.data = const_cast<uint8_t*>(cert->tbs().issuer_tlv.UnsafeData());
  // |validOnly| in CERT_CreateSubjectCertList controls whether to return only
  // certs that are valid at |sorttime|. Including expired certs could lead to
  // more useful error messages in the case where a valid path can't be found,
  // so request all matches.
  CERTCertList* found_certs = CERT_CreateSubjectCertList(
      nullptr /* certList */, CERT_GetDefaultCertDB(), &name,
      PR_Now() /* sorttime */, PR_FALSE /* validOnly */);
  if (!found_certs)
    return;

  for (CERTCertListNode* node = CERT_LIST_HEAD(found_certs);
       !CERT_LIST_END(node, found_certs); node = CERT_LIST_NEXT(node)) {
    CertErrors errors;
    scoped_refptr<ParsedCertificate> issuer_cert = ParsedCertificate::Create(
        x509_util::CreateCryptoBuffer(node->cert->derCert.data,
                                      node->cert->derCert.len),
        {}, &errors);
    if (!issuer_cert) {
      // TODO(crbug.com/634443): return errors better.
      LOG(ERROR) << "Error parsing issuer certificate:\n"
                 << errors.ToDebugString();
      continue;
    }

    issuers->push_back(std::move(issuer_cert));
  }
  CERT_DestroyCertList(found_certs);
}

void CertIssuerSourceNSS::AsyncGetIssuersOf(const ParsedCertificate* cert,
                                            std::unique_ptr<Request>* out_req) {
  // CertIssuerSourceNSS never returns asynchronous results.
  out_req->reset();
}

}  // namespace net
