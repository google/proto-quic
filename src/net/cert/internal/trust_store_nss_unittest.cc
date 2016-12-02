// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_nss.h"

#include <cert.h>
#include <certdb.h>

#include "base/memory/ptr_util.h"
#include "base/strings/string_number_conversions.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class TrustStoreNSSTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(test_nssdb_.is_open());

    ParsedCertificateList chain;
    bool unused_verify_result;
    der::GeneralizedTime unused_time;
    std::string unused_errors;

    ReadVerifyCertChainTestFromFile(
        "net/data/verify_certificate_chain_unittest/key-rollover-oldchain.pem",
        &chain, &oldroot_, &unused_time, &unused_verify_result, &unused_errors);
    ASSERT_EQ(2U, chain.size());
    target_ = chain[0];
    oldintermediate_ = chain[1];
    ASSERT_TRUE(target_);
    ASSERT_TRUE(oldintermediate_);
    ASSERT_TRUE(oldroot_);

    scoped_refptr<TrustAnchor> unused_root;
    ReadVerifyCertChainTestFromFile(
        "net/data/verify_certificate_chain_unittest/"
        "key-rollover-longrolloverchain.pem",
        &chain, &unused_root, &unused_time, &unused_verify_result,
        &unused_errors);
    ASSERT_EQ(4U, chain.size());
    newintermediate_ = chain[1];
    newroot_ = TrustAnchor::CreateFromCertificateNoConstraints(chain[2]);
    newrootrollover_ = chain[3];
    ASSERT_TRUE(newintermediate_);
    ASSERT_TRUE(newroot_);
    ASSERT_TRUE(newrootrollover_);

    trust_store_nss_.reset(new TrustStoreNSS(trustSSL));
  }

  std::string GetUniqueNickname() {
    return "trust_store_nss_unittest" + base::UintToString(nickname_counter_++);
  }

  void AddCertToNSS(const ParsedCertificate* cert) {
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

  void AddCertsToNSS() {
    AddCertToNSS(target_.get());
    AddCertToNSS(oldintermediate_.get());
    AddCertToNSS(newintermediate_.get());
    AddCertToNSS(oldroot_->cert().get());
    AddCertToNSS(newroot_->cert().get());
    AddCertToNSS(newrootrollover_.get());
  }

  // Trusts |cert|. Assumes the cert was already imported into NSS.
  void TrustCert(const TrustAnchor* anchor) { TrustCert(anchor->cert().get()); }
  void TrustCert(const ParsedCertificate* cert) {
    SECItem der_cert;
    der_cert.data = const_cast<uint8_t*>(cert->der_cert().UnsafeData());
    der_cert.len = base::checked_cast<unsigned>(cert->der_cert().Length());
    der_cert.type = siDERCertBuffer;

    ScopedCERTCertificate nss_cert(
        CERT_FindCertByDERCert(CERT_GetDefaultCertDB(), &der_cert));
    ASSERT_TRUE(nss_cert);

    CERTCertTrust trust = {0};
    trust.sslFlags =
        CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA | CERTDB_VALID_CA;
    SECStatus srv =
        CERT_ChangeCertTrust(CERT_GetDefaultCertDB(), nss_cert.get(), &trust);
    ASSERT_EQ(SECSuccess, srv);
  }

 protected:
  bool TrustStoreContains(scoped_refptr<ParsedCertificate> cert,
                          TrustAnchors expected_matches) {
    TrustAnchors matches;
    trust_store_nss_->FindTrustAnchorsForCert(cert, &matches);

    std::vector<der::Input> der_result_matches;
    for (const auto& it : matches)
      der_result_matches.push_back(it->cert()->der_cert());
    std::sort(der_result_matches.begin(), der_result_matches.end());

    std::vector<der::Input> der_expected_matches;
    for (const auto& it : expected_matches)
      der_expected_matches.push_back(it->cert()->der_cert());
    std::sort(der_expected_matches.begin(), der_expected_matches.end());

    if (der_expected_matches == der_result_matches)
      return true;

    // Print some extra information for debugging.
    EXPECT_EQ(der_expected_matches, der_result_matches);
    return false;
  }

  scoped_refptr<TrustAnchor> oldroot_;
  scoped_refptr<TrustAnchor> newroot_;

  scoped_refptr<ParsedCertificate> target_;
  scoped_refptr<ParsedCertificate> oldintermediate_;
  scoped_refptr<ParsedCertificate> newintermediate_;
  scoped_refptr<ParsedCertificate> newrootrollover_;
  crypto::ScopedTestNSSDB test_nssdb_;
  std::unique_ptr<TrustStoreNSS> trust_store_nss_;
  unsigned nickname_counter_ = 0;
};

// Without adding any certs to the NSS DB, should get no anchor results for any
// of the test certs.
TEST_F(TrustStoreNSSTest, CertsNotPresent) {
  EXPECT_TRUE(TrustStoreContains(target_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newintermediate_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newroot_->cert(), TrustAnchors()));
}

// If certs are present in NSS DB but aren't marked as trusted, should get no
// anchor results for any of the test certs.
TEST_F(TrustStoreNSSTest, CertsPresentButNotTrusted) {
  AddCertsToNSS();
  EXPECT_TRUE(TrustStoreContains(newintermediate_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(target_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newintermediate_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newroot_->cert(), TrustAnchors()));
}

// A self-signed CA certificate is trusted. FindTrustAnchorsForCert should
// return the cert on any intermediates with a matching issuer, and on any
// matching self-signed/self-issued CA certs.
TEST_F(TrustStoreNSSTest, TrustedCA) {
  AddCertsToNSS();
  TrustCert(newroot_.get());
  EXPECT_TRUE(TrustStoreContains(target_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newintermediate_, {newroot_}));
  EXPECT_TRUE(TrustStoreContains(oldintermediate_, {newroot_}));
  EXPECT_TRUE(TrustStoreContains(newrootrollover_, {newroot_}));
  EXPECT_TRUE(TrustStoreContains(oldroot_->cert(), {newroot_}));
  EXPECT_TRUE(TrustStoreContains(newroot_->cert(), {newroot_}));
}

// When an intermediate certificate is trusted, FindTrustAnchorsForCert should
// return that cert on any certs issued by the intermediate, but not for the
// intermediate itself (or the CAs).
TEST_F(TrustStoreNSSTest, TrustedIntermediate) {
  AddCertsToNSS();
  TrustCert(newintermediate_.get());
  EXPECT_TRUE(TrustStoreContains(
      target_,
      {TrustAnchor::CreateFromCertificateNoConstraints(newintermediate_)}));
  EXPECT_TRUE(TrustStoreContains(newintermediate_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(oldintermediate_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newrootrollover_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(oldroot_->cert(), TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newroot_->cert(), TrustAnchors()));
}

// Multiple self-signed CA certificates with the same name are trusted.
// FindTrustAnchorsForCert should return all these certs on any intermediates
// with a matching issuer, and on any matching self-signed/self-issued CA certs.
TEST_F(TrustStoreNSSTest, MultipleTrustedCAWithSameSubject) {
  AddCertsToNSS();
  TrustCert(oldroot_.get());
  TrustCert(newroot_.get());
  EXPECT_TRUE(TrustStoreContains(target_, TrustAnchors()));
  EXPECT_TRUE(TrustStoreContains(newintermediate_, {newroot_, oldroot_}));
  EXPECT_TRUE(TrustStoreContains(oldintermediate_, {newroot_, oldroot_}));
  EXPECT_TRUE(TrustStoreContains(oldroot_->cert(), {newroot_, oldroot_}));
}

}  // namespace

}  // namespace net
