// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/cert_issuer_source_nss.h"

#include <cert.h>
#include <certdb.h>

#include "base/strings/string_number_conversions.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/cert/internal/cert_issuer_source_sync_unittest.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class CertIssuerSourceNSSTestDelegate {
 public:
  void AddCert(scoped_refptr<ParsedCertificate> cert) {
    ASSERT_TRUE(test_nssdb_.is_open());
    std::string nickname = GetUniqueNickname();
    ScopedCERTCertificate nss_cert(
        X509Certificate::CreateOSCertHandleFromBytesWithNickname(
            cert->der_cert().AsStringPiece().data(), cert->der_cert().Length(),
            nickname.c_str()));
    ASSERT_TRUE(nss_cert);
    SECStatus srv =
        PK11_ImportCert(test_nssdb_.slot(), nss_cert.get(), CK_INVALID_HANDLE,
                        nickname.c_str(), PR_FALSE /* includeTrust (unused) */);
    ASSERT_EQ(SECSuccess, srv);
  }

  CertIssuerSource& source() { return cert_issuer_source_nss_; }

 protected:
  std::string GetUniqueNickname() {
    return "cert_issuer_source_nss_unittest" +
           base::UintToString(nickname_counter_++);
  }

  crypto::ScopedTestNSSDB test_nssdb_;
  CertIssuerSourceNSS cert_issuer_source_nss_;
  unsigned int nickname_counter_ = 0;
};

INSTANTIATE_TYPED_TEST_CASE_P(CertIssuerSourceNSSTest,
                              CertIssuerSourceSyncTest,
                              CertIssuerSourceNSSTestDelegate);

// NSS doesn't normalize UTF8String values, so use the not-normalized version of
// those tests.
INSTANTIATE_TYPED_TEST_CASE_P(CertIssuerSourceNSSNotNormalizedTest,
                              CertIssuerSourceSyncNotNormalizedTest,
                              CertIssuerSourceNSSTestDelegate);

}  // namespace

}  // namespace net
