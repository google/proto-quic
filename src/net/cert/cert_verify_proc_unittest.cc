// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc.h"

#include <vector>

#include "base/callback_helpers.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"
#include "build/build_config.h"
#include "crypto/sha2.h"
#include "net/base/net_errors.h"
#include "net/cert/asn1_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/crl_set.h"
#include "net/cert/crl_set_storage.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_certificate.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_ANDROID)
#include "base/android/build_info.h"
#endif

using net::test::IsError;
using net::test::IsOk;

using base::HexEncode;

namespace net {

namespace {

// Mock CertVerifyProc that sets the CertVerifyResult to a given value for
// all certificates that are Verify()'d
class MockCertVerifyProc : public CertVerifyProc {
 public:
  explicit MockCertVerifyProc(const CertVerifyResult& result)
      : result_(result) {}
  // CertVerifyProc implementation:
  bool SupportsAdditionalTrustAnchors() const override { return false; }
  bool SupportsOCSPStapling() const override { return false; }

 protected:
  ~MockCertVerifyProc() override {}

 private:
  int VerifyInternal(X509Certificate* cert,
                     const std::string& hostname,
                     const std::string& ocsp_response,
                     int flags,
                     CRLSet* crl_set,
                     const CertificateList& additional_trust_anchors,
                     CertVerifyResult* verify_result) override;

  const CertVerifyResult result_;

  DISALLOW_COPY_AND_ASSIGN(MockCertVerifyProc);
};

int MockCertVerifyProc::VerifyInternal(
    X509Certificate* cert,
    const std::string& hostname,
    const std::string& ocsp_response,
    int flags,
    CRLSet* crl_set,
    const CertificateList& additional_trust_anchors,
    CertVerifyResult* verify_result) {
  *verify_result = result_;
  verify_result->verified_cert = cert;
  return OK;
}

bool SupportsReturningVerifiedChain() {
#if defined(OS_ANDROID)
  // Before API level 17, Android does not expose the APIs necessary to get at
  // the verified certificate chain.
  if (base::android::BuildInfo::GetInstance()->sdk_int() < 17)
    return false;
#endif
  return true;
}

bool SupportsDetectingKnownRoots() {
#if defined(OS_ANDROID)
  // Before API level 17, Android does not expose the APIs necessary to get at
  // the verified certificate chain and detect known roots.
  if (base::android::BuildInfo::GetInstance()->sdk_int() < 17)
    return false;
#elif defined(OS_IOS)
  // iOS does not expose the APIs necessary to get the known system roots.
  return false;
#endif
  return true;
}

// Template helper to load a series of certificate files into a CertificateList.
// Like CertTestUtil's CreateCertificateListFromFile, except it can load a
// series of individual certificates (to make the tests clearer).
template <size_t N>
void LoadCertificateFiles(const char* const (&cert_files)[N],
                          CertificateList* certs) {
  certs->clear();
  for (size_t i = 0; i < N; ++i) {
    SCOPED_TRACE(cert_files[i]);
    scoped_refptr<X509Certificate> cert = CreateCertificateChainFromFile(
        GetTestCertsDirectory(), cert_files[i], X509Certificate::FORMAT_AUTO);
    ASSERT_TRUE(cert);
    certs->push_back(cert);
  }
}

}  // namespace

class CertVerifyProcTest : public testing::Test {
 public:
  CertVerifyProcTest()
      : verify_proc_(CertVerifyProc::CreateDefault()) {
  }
  ~CertVerifyProcTest() override {}

 protected:
  bool SupportsAdditionalTrustAnchors() {
    return verify_proc_->SupportsAdditionalTrustAnchors();
  }

  // Returns true if the underlying CertVerifyProc supports integrating CRLSets
  // into path building logic, such as allowing the selection of alternatively
  // valid paths when one or more are revoked. As the goal is to integrate this
  // into all platforms, this is a temporary, test-only flag to centralize the
  // conditionals in tests.
  bool SupportsCRLSetsInPathBuilding() {
#if defined(OS_WIN) || defined(USE_NSS_CERTS)
    return true;
#else
    return false;
#endif
  }

  int Verify(X509Certificate* cert,
             const std::string& hostname,
             int flags,
             CRLSet* crl_set,
             const CertificateList& additional_trust_anchors,
             CertVerifyResult* verify_result) {
    return verify_proc_->Verify(cert, hostname, std::string(), flags, crl_set,
                                additional_trust_anchors, verify_result);
  }

  const CertificateList empty_cert_list_;
  scoped_refptr<CertVerifyProc> verify_proc_;
};

#if defined(OS_ANDROID) || defined(USE_OPENSSL_CERTS)
// TODO(jnd): http://crbug.com/117478 - EV verification is not yet supported.
#define MAYBE_EVVerification DISABLED_EVVerification
#else
// TODO(rsleevi): Reenable this test once comodo.chaim.pem is no longer
// expired, http://crbug.com/502818
#define MAYBE_EVVerification DISABLED_EVVerification
#endif
TEST_F(CertVerifyProcTest, MAYBE_EVVerification) {
  CertificateList certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(),
      "comodo.chain.pem",
      X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  ASSERT_EQ(3U, certs.size());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(certs[1]->os_cert_handle());
  intermediates.push_back(certs[2]->os_cert_handle());

  scoped_refptr<X509Certificate> comodo_chain =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);

  scoped_refptr<CRLSet> crl_set(CRLSet::ForTesting(false, NULL, ""));
  CertVerifyResult verify_result;
  int flags = CertVerifier::VERIFY_EV_CERT;
  int error = Verify(comodo_chain.get(),
                     "comodo.com",
                     flags,
                     crl_set.get(),
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_IS_EV);
}

// TODO(crbug.com/605457): the test expectation was incorrect on some
// configurations, so disable the test until it is fixed (better to have
// a bug to track a failing test than a false sense of security due to
// false positive).
TEST_F(CertVerifyProcTest, DISABLED_PaypalNullCertParsing) {
  // A certificate for www.paypal.com with a NULL byte in the common name.
  // From http://www.gossamer-threads.com/lists/fulldisc/full-disclosure/70363
  SHA256HashValue paypal_null_fingerprint = {{0x00}};

  scoped_refptr<X509Certificate> paypal_null_cert(
      X509Certificate::CreateFromBytes(
          reinterpret_cast<const char*>(paypal_null_der),
          sizeof(paypal_null_der)));

  ASSERT_NE(static_cast<X509Certificate*>(NULL), paypal_null_cert.get());

  EXPECT_EQ(paypal_null_fingerprint, X509Certificate::CalculateFingerprint256(
                                         paypal_null_cert->os_cert_handle()));

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(paypal_null_cert.get(),
                     "www.paypal.com",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
#if defined(USE_NSS_CERTS) || defined(OS_ANDROID)
  EXPECT_THAT(error, IsError(ERR_CERT_COMMON_NAME_INVALID));
#elif defined(OS_IOS) && TARGET_IPHONE_SIMULATOR
  // iOS returns a ERR_CERT_INVALID error on the simulator, while returning
  // ERR_CERT_AUTHORITY_INVALID on the real device.
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
#else
  // TOOD(bulach): investigate why macosx and win aren't returning
  // ERR_CERT_INVALID or ERR_CERT_COMMON_NAME_INVALID.
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
#endif
  // Either the system crypto library should correctly report a certificate
  // name mismatch, or our certificate blacklist should cause us to report an
  // invalid certificate.
#if defined(USE_NSS_CERTS) || defined(OS_WIN)
  EXPECT_TRUE(verify_result.cert_status &
              (CERT_STATUS_COMMON_NAME_INVALID | CERT_STATUS_INVALID));
#endif
}

// A regression test for http://crbug.com/31497.
#if defined(OS_ANDROID)
// Disabled on Android, as the Android verification libraries require an
// explicit policy to be specified, even when anyPolicy is permitted.
#define MAYBE_IntermediateCARequireExplicitPolicy \
    DISABLED_IntermediateCARequireExplicitPolicy
#else
#define MAYBE_IntermediateCARequireExplicitPolicy \
    IntermediateCARequireExplicitPolicy
#endif
TEST_F(CertVerifyProcTest, MAYBE_IntermediateCARequireExplicitPolicy) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "explicit-policy-chain.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(certs[1]->os_cert_handle());

  scoped_refptr<X509Certificate> cert =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);
  ASSERT_TRUE(cert.get());

  ScopedTestRoot scoped_root(certs[2].get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(),
                     "policy_test.example",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0u, verify_result.cert_status);
}

TEST_F(CertVerifyProcTest, RejectExpiredCert) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  // Load root_ca_cert.pem into the test root store.
  ScopedTestRoot test_root(
      ImportCertFromFile(certs_dir, "root_ca_cert.pem").get());

  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "expired_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, certs.size());

  X509Certificate::OSCertHandles intermediates;
  scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromHandle(
      certs[0]->os_cert_handle(), intermediates);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, NULL, empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_DATE_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_DATE_INVALID);
}

// Currently, only RSA and DSA keys are checked for weakness, and our example
// weak size is 768. These could change in the future.
//
// Note that this means there may be false negatives: keys for other
// algorithms and which are weak will pass this test.
static bool IsWeakKeyType(const std::string& key_type) {
  size_t pos = key_type.find("-");
  std::string size = key_type.substr(0, pos);
  std::string type = key_type.substr(pos + 1);

  if (type == "rsa" || type == "dsa")
    return size == "768";

  return false;
}

TEST_F(CertVerifyProcTest, RejectWeakKeys) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  typedef std::vector<std::string> Strings;
  Strings key_types;

  // generate-weak-test-chains.sh currently has:
  //     key_types="768-rsa 1024-rsa 2048-rsa prime256v1-ecdsa"
  // We must use the same key types here. The filenames generated look like:
  //     2048-rsa-ee-by-768-rsa-intermediate.pem
  key_types.push_back("768-rsa");
  key_types.push_back("1024-rsa");
  key_types.push_back("2048-rsa");
  key_types.push_back("prime256v1-ecdsa");

  // Add the root that signed the intermediates for this test.
  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(certs_dir, "2048-rsa-root.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), root_cert.get());
  ScopedTestRoot scoped_root(root_cert.get());

  // Now test each chain.
  for (Strings::const_iterator ee_type = key_types.begin();
       ee_type != key_types.end(); ++ee_type) {
    for (Strings::const_iterator signer_type = key_types.begin();
         signer_type != key_types.end(); ++signer_type) {
      std::string basename = *ee_type + "-ee-by-" + *signer_type +
          "-intermediate.pem";
      SCOPED_TRACE(basename);
      scoped_refptr<X509Certificate> ee_cert =
          ImportCertFromFile(certs_dir, basename);
      ASSERT_NE(static_cast<X509Certificate*>(NULL), ee_cert.get());

      basename = *signer_type + "-intermediate.pem";
      scoped_refptr<X509Certificate> intermediate =
          ImportCertFromFile(certs_dir, basename);
      ASSERT_NE(static_cast<X509Certificate*>(NULL), intermediate.get());

      X509Certificate::OSCertHandles intermediates;
      intermediates.push_back(intermediate->os_cert_handle());
      scoped_refptr<X509Certificate> cert_chain =
          X509Certificate::CreateFromHandle(ee_cert->os_cert_handle(),
                                            intermediates);

      CertVerifyResult verify_result;
      int error = Verify(cert_chain.get(),
                         "127.0.0.1",
                         0,
                         NULL,
                         empty_cert_list_,
                         &verify_result);

      if (IsWeakKeyType(*ee_type) || IsWeakKeyType(*signer_type)) {
        EXPECT_NE(OK, error);
        EXPECT_EQ(CERT_STATUS_WEAK_KEY,
                  verify_result.cert_status & CERT_STATUS_WEAK_KEY);
        EXPECT_NE(CERT_STATUS_INVALID,
                  verify_result.cert_status & CERT_STATUS_INVALID);
      } else {
        EXPECT_THAT(error, IsOk());
        EXPECT_EQ(0U, verify_result.cert_status & CERT_STATUS_WEAK_KEY);
      }
    }
  }
}

// Regression test for http://crbug.com/108514.
#if defined(OS_MACOSX) && !defined(OS_IOS)
// Disabled on OS X - Security.framework doesn't ignore superflous certificates
// provided by servers. See CertVerifyProcTest.CybertrustGTERoot for further
// details.
#define MAYBE_ExtraneousMD5RootCert DISABLED_ExtraneousMD5RootCert
#else
#define MAYBE_ExtraneousMD5RootCert ExtraneousMD5RootCert
#endif
TEST_F(CertVerifyProcTest, MAYBE_ExtraneousMD5RootCert) {
  if (!SupportsReturningVerifiedChain()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> server_cert =
      ImportCertFromFile(certs_dir, "cross-signed-leaf.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), server_cert.get());

  scoped_refptr<X509Certificate> extra_cert =
      ImportCertFromFile(certs_dir, "cross-signed-root-md5.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), extra_cert.get());

  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(certs_dir, "cross-signed-root-sha256.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), root_cert.get());

  ScopedTestRoot scoped_root(root_cert.get());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(extra_cert->os_cert_handle());
  scoped_refptr<X509Certificate> cert_chain =
      X509Certificate::CreateFromHandle(server_cert->os_cert_handle(),
                                        intermediates);

  CertVerifyResult verify_result;
  int flags = 0;
  int error = Verify(cert_chain.get(),
                     "127.0.0.1",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());

  // The extra MD5 root should be discarded
  ASSERT_TRUE(verify_result.verified_cert.get());
  ASSERT_EQ(1u,
            verify_result.verified_cert->GetIntermediateCertificates().size());
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
        verify_result.verified_cert->GetIntermediateCertificates().front(),
        root_cert->os_cert_handle()));

  EXPECT_FALSE(verify_result.has_md5);
}

// Test for bug 94673.
TEST_F(CertVerifyProcTest, GoogleDigiNotarTest) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> server_cert =
      ImportCertFromFile(certs_dir, "google_diginotar.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), server_cert.get());

  scoped_refptr<X509Certificate> intermediate_cert =
      ImportCertFromFile(certs_dir, "diginotar_public_ca_2025.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), intermediate_cert.get());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(intermediate_cert->os_cert_handle());
  scoped_refptr<X509Certificate> cert_chain =
      X509Certificate::CreateFromHandle(server_cert->os_cert_handle(),
                                        intermediates);

  CertVerifyResult verify_result;
  int flags = CertVerifier::VERIFY_REV_CHECKING_ENABLED;
  int error = Verify(cert_chain.get(),
                     "mail.google.com",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_NE(OK, error);

  // Now turn off revocation checking.  Certificate verification should still
  // fail.
  flags = 0;
  error = Verify(cert_chain.get(),
                 "mail.google.com",
                 flags,
                 NULL,
                 empty_cert_list_,
                 &verify_result);
  EXPECT_NE(OK, error);
}

// Ensures the CertVerifyProc blacklist remains in sorted order, so that it
// can be binary-searched.
TEST_F(CertVerifyProcTest, BlacklistIsSorted) {
// Defines kBlacklistedSPKIs.
#include "net/cert/cert_verify_proc_blacklist.inc"
  for (size_t i = 0; i < arraysize(kBlacklistedSPKIs) - 1; ++i) {
    EXPECT_GT(0, memcmp(kBlacklistedSPKIs[i], kBlacklistedSPKIs[i + 1],
                        crypto::kSHA256Length))
        << " at index " << i;
  }
}

TEST_F(CertVerifyProcTest, DigiNotarCerts) {
  static const char* const kDigiNotarFilenames[] = {
    "diginotar_root_ca.pem",
    "diginotar_cyber_ca.pem",
    "diginotar_services_1024_ca.pem",
    "diginotar_pkioverheid.pem",
    "diginotar_pkioverheid_g2.pem",
    NULL,
  };

  base::FilePath certs_dir = GetTestCertsDirectory();

  for (size_t i = 0; kDigiNotarFilenames[i]; i++) {
    scoped_refptr<X509Certificate> diginotar_cert =
        ImportCertFromFile(certs_dir, kDigiNotarFilenames[i]);
    std::string der_bytes;
    ASSERT_TRUE(X509Certificate::GetDEREncoded(
        diginotar_cert->os_cert_handle(), &der_bytes));

    base::StringPiece spki;
    ASSERT_TRUE(asn1::ExtractSPKIFromDERCert(der_bytes, &spki));

    std::string spki_sha256 = crypto::SHA256HashString(spki.as_string());

    HashValueVector public_keys;
    HashValue hash(HASH_VALUE_SHA256);
    ASSERT_EQ(hash.size(), spki_sha256.size());
    memcpy(hash.data(), spki_sha256.data(), spki_sha256.size());
    public_keys.push_back(hash);

    EXPECT_TRUE(CertVerifyProc::IsPublicKeyBlacklisted(public_keys)) <<
        "Public key not blocked for " << kDigiNotarFilenames[i];
  }
}

TEST_F(CertVerifyProcTest, NameConstraintsOk) {
  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0].get());

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "name_constraint_good.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());

  X509Certificate::OSCertHandles intermediates;
  scoped_refptr<X509Certificate> leaf =
      X509Certificate::CreateFromHandle(cert_list[0]->os_cert_handle(),
                                        intermediates);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf.get(),
                     "test.example.com",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  error = Verify(leaf.get(), "foo.test2.example.com", flags, NULL,
                 empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
}

TEST_F(CertVerifyProcTest, NameConstraintsFailure) {
  if (!SupportsReturningVerifiedChain()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0].get());

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "name_constraint_bad.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());

  X509Certificate::OSCertHandles intermediates;
  scoped_refptr<X509Certificate> leaf =
      X509Certificate::CreateFromHandle(cert_list[0]->os_cert_handle(),
                                        intermediates);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf.get(),
                     "test.example.com",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_NAME_CONSTRAINT_VIOLATION));
  EXPECT_EQ(CERT_STATUS_NAME_CONSTRAINT_VIOLATION,
            verify_result.cert_status & CERT_STATUS_NAME_CONSTRAINT_VIOLATION);
}

TEST_F(CertVerifyProcTest, TestHasTooLongValidity) {
  struct {
    const char* const file;
    bool is_valid_too_long;
  } tests[] = {
      {"twitter-chain.pem", false},
      {"start_after_expiry.pem", true},
      {"pre_br_validity_ok.pem", false},
      {"pre_br_validity_bad_121.pem", true},
      {"pre_br_validity_bad_2020.pem", true},
      {"10_year_validity.pem", false},
      {"11_year_validity.pem", true},
      {"39_months_after_2015_04.pem", false},
      {"40_months_after_2015_04.pem", true},
      {"60_months_after_2012_07.pem", false},
      {"61_months_after_2012_07.pem", true},
  };

  base::FilePath certs_dir = GetTestCertsDirectory();

  for (size_t i = 0; i < arraysize(tests); ++i) {
    scoped_refptr<X509Certificate> certificate =
        ImportCertFromFile(certs_dir, tests[i].file);
    SCOPED_TRACE(tests[i].file);
    ASSERT_TRUE(certificate);
    EXPECT_EQ(tests[i].is_valid_too_long,
              CertVerifyProc::HasTooLongValidity(*certificate));
  }
}

// TODO(crbug.com/610546): Fix and re-enable this test.
TEST_F(CertVerifyProcTest, DISABLED_TestKnownRoot) {
  if (!SupportsDetectingKnownRoots()) {
    LOG(INFO) << "Skipping this test on this platform.";
    return;
  }

  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "twitter-chain.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(certs[1]->os_cert_handle());

  scoped_refptr<X509Certificate> cert_chain =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);

  int flags = 0;
  CertVerifyResult verify_result;
  // This will blow up, May 9th, 2016. Sorry! Please disable and file a bug
  // against agl. See also PublicKeyHashes.
  int error = Verify(cert_chain.get(), "twitter.com", flags, NULL,
                     empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.is_issued_by_known_root);
}

// TODO(crbug.com/610546): Fix and re-enable this test.
TEST_F(CertVerifyProcTest, DISABLED_PublicKeyHashes) {
  if (!SupportsReturningVerifiedChain()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "twitter-chain.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(certs[1]->os_cert_handle());

  scoped_refptr<X509Certificate> cert_chain =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);
  int flags = 0;
  CertVerifyResult verify_result;

  // This will blow up, May 9th, 2016. Sorry! Please disable and file a bug
  // against agl. See also TestKnownRoot.
  int error = Verify(cert_chain.get(), "twitter.com", flags, NULL,
                     empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_LE(3U, verify_result.public_key_hashes.size());

  HashValueVector sha1_hashes;
  for (size_t i = 0; i < verify_result.public_key_hashes.size(); ++i) {
    if (verify_result.public_key_hashes[i].tag != HASH_VALUE_SHA1)
      continue;
    sha1_hashes.push_back(verify_result.public_key_hashes[i]);
  }
  ASSERT_LE(3u, sha1_hashes.size());

  for (size_t i = 0; i < 3; ++i) {
    EXPECT_EQ(HexEncode(kTwitterSPKIs[i], base::kSHA1Length),
              HexEncode(sha1_hashes[i].data(), base::kSHA1Length));
  }

  HashValueVector sha256_hashes;
  for (size_t i = 0; i < verify_result.public_key_hashes.size(); ++i) {
    if (verify_result.public_key_hashes[i].tag != HASH_VALUE_SHA256)
      continue;
    sha256_hashes.push_back(verify_result.public_key_hashes[i]);
  }
  ASSERT_LE(3u, sha256_hashes.size());

  for (size_t i = 0; i < 3; ++i) {
    EXPECT_EQ(HexEncode(kTwitterSPKIsSHA256[i], crypto::kSHA256Length),
              HexEncode(sha256_hashes[i].data(), crypto::kSHA256Length));
  }
}

// A regression test for http://crbug.com/70293.
// The Key Usage extension in this RSA SSL server certificate does not have
// the keyEncipherment bit.
TEST_F(CertVerifyProcTest, InvalidKeyUsage) {
  base::FilePath certs_dir = GetTestCertsDirectory();

  scoped_refptr<X509Certificate> server_cert =
      ImportCertFromFile(certs_dir, "invalid_key_usage_cert.der");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), server_cert.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(server_cert.get(),
                     "jira.aquameta.com",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
#if defined(USE_OPENSSL_CERTS) && !defined(OS_ANDROID)
  // This certificate has two errors: "invalid key usage" and "untrusted CA".
  // However, OpenSSL returns only one (the latter), and we can't detect
  // the other errors.
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
#else
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_INVALID);
#endif
  // TODO(wtc): fix http://crbug.com/75520 to get all the certificate errors
  // from NSS.
#if !defined(USE_NSS_CERTS) && !defined(OS_IOS) && !defined(OS_ANDROID)
  // The certificate is issued by an unknown CA.
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_AUTHORITY_INVALID);
#endif
}

// Basic test for returning the chain in CertVerifyResult. Note that the
// returned chain may just be a reflection of the originally supplied chain;
// that is, if any errors occur, the default chain returned is an exact copy
// of the certificate to be verified. The remaining VerifyReturn* tests are
// used to ensure that the actual, verified chain is being returned by
// Verify().
TEST_F(CertVerifyProcTest, VerifyReturnChainBasic) {
  if (!SupportsReturningVerifiedChain()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(certs[1]->os_cert_handle());
  intermediates.push_back(certs[2]->os_cert_handle());

  ScopedTestRoot scoped_root(certs[2].get());

  scoped_refptr<X509Certificate> google_full_chain =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);
  ASSERT_NE(static_cast<X509Certificate*>(NULL), google_full_chain.get());
  ASSERT_EQ(2U, google_full_chain->GetIntermediateCertificates().size());

  CertVerifyResult verify_result;
  EXPECT_EQ(static_cast<X509Certificate*>(NULL),
            verify_result.verified_cert.get());
  int error = Verify(google_full_chain.get(),
                     "127.0.0.1",
                     0,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_NE(static_cast<X509Certificate*>(NULL),
            verify_result.verified_cert.get());

  EXPECT_NE(google_full_chain, verify_result.verified_cert);
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      google_full_chain->os_cert_handle(),
      verify_result.verified_cert->os_cert_handle()));
  const X509Certificate::OSCertHandles& return_intermediates =
      verify_result.verified_cert->GetIntermediateCertificates();
  ASSERT_EQ(2U, return_intermediates.size());
  EXPECT_TRUE(X509Certificate::IsSameOSCert(return_intermediates[0],
                                            certs[1]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(return_intermediates[1],
                                            certs[2]->os_cert_handle()));
}

// Test that certificates issued for 'intranet' names (that is, containing no
// known public registry controlled domain information) issued by well-known
// CAs are flagged appropriately, while certificates that are issued by
// internal CAs are not flagged.
TEST_F(CertVerifyProcTest, IntranetHostsRejected) {
  if (!SupportsDetectingKnownRoots()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "reject_intranet_hosts.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  CertVerifyResult verify_result;
  int error = 0;

  // Intranet names for public CAs should be flagged:
  CertVerifyResult dummy_result;
  dummy_result.is_issued_by_known_root = true;
  verify_proc_ = new MockCertVerifyProc(dummy_result);
  error =
      Verify(cert.get(), "intranet", 0, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_NON_UNIQUE_NAME);

  // However, if the CA is not well known, these should not be flagged:
  dummy_result.Reset();
  dummy_result.is_issued_by_known_root = false;
  verify_proc_ = new MockCertVerifyProc(dummy_result);
  error =
      Verify(cert.get(), "intranet", 0, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_NON_UNIQUE_NAME);
}

// Test that a SHA-1 certificate from a publicly trusted CA issued after
// 1 January 2016 is rejected, but those issued before that date, or with
// SHA-1 in the intermediate, is not rejected.
TEST_F(CertVerifyProcTest, VerifyRejectsSHA1AfterDeprecation) {
  CertVerifyResult dummy_result;
  CertVerifyResult verify_result;
  int error = 0;
  scoped_refptr<X509Certificate> cert;

  // Publicly trusted SHA-1 leaf certificates issued before 1 January 2016
  // are accepted.
  verify_result.Reset();
  dummy_result.Reset();
  dummy_result.is_issued_by_known_root = true;
  dummy_result.has_sha1 = true;
  dummy_result.has_sha1_leaf = true;
  verify_proc_ = new MockCertVerifyProc(dummy_result);
  cert = CreateCertificateChainFromFile(GetTestCertsDirectory(),
                                        "sha1_dec_2015.pem",
                                        X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  error = Verify(cert.get(), "127.0.0.1", 0, NULL, empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_SHA1_SIGNATURE_PRESENT);

  // Publicly trusted SHA-1 leaf certificates issued on/after 1 January 2016
  // are rejected.
  verify_result.Reset();
  dummy_result.Reset();
  dummy_result.is_issued_by_known_root = true;
  dummy_result.has_sha1 = true;
  dummy_result.has_sha1_leaf = true;
  verify_proc_ = new MockCertVerifyProc(dummy_result);
  cert = CreateCertificateChainFromFile(GetTestCertsDirectory(),
                                        "sha1_jan_2016.pem",
                                        X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  error = Verify(cert.get(), "127.0.0.1", 0, NULL, empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_WEAK_SIGNATURE_ALGORITHM);

  // Enterprise issued SHA-1 leaf certificates issued on/after 1 January 2016
  // remain accepted until SHA-1 is disabled.
  verify_result.Reset();
  dummy_result.Reset();
  dummy_result.is_issued_by_known_root = false;
  dummy_result.has_sha1 = true;
  dummy_result.has_sha1_leaf = true;
  verify_proc_ = new MockCertVerifyProc(dummy_result);
  cert = CreateCertificateChainFromFile(GetTestCertsDirectory(),
                                        "sha1_jan_2016.pem",
                                        X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  error = Verify(cert.get(), "127.0.0.1", 0, NULL, empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_SHA1_SIGNATURE_PRESENT);

  // Publicly trusted SHA-1 intermediates issued on/after 1 January 2016 are,
  // unfortunately, accepted. This can arise due to OS path building quirks.
  verify_result.Reset();
  dummy_result.Reset();
  dummy_result.is_issued_by_known_root = true;
  dummy_result.has_sha1 = true;
  dummy_result.has_sha1_leaf = false;
  verify_proc_ = new MockCertVerifyProc(dummy_result);
  cert = CreateCertificateChainFromFile(GetTestCertsDirectory(),
                                        "sha1_jan_2016.pem",
                                        X509Certificate::FORMAT_AUTO);
  ASSERT_TRUE(cert);
  error = Verify(cert.get(), "127.0.0.1", 0, NULL, empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_SHA1_SIGNATURE_PRESENT);
}

// Test that the certificate returned in CertVerifyResult is able to reorder
// certificates that are not ordered from end-entity to root. While this is
// a protocol violation if sent during a TLS handshake, if multiple sources
// of intermediate certificates are combined, it's possible that order may
// not be maintained.
TEST_F(CertVerifyProcTest, VerifyReturnChainProperlyOrdered) {
  if (!SupportsReturningVerifiedChain()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  // Construct the chain out of order.
  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(certs[2]->os_cert_handle());
  intermediates.push_back(certs[1]->os_cert_handle());

  ScopedTestRoot scoped_root(certs[2].get());

  scoped_refptr<X509Certificate> google_full_chain =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);
  ASSERT_NE(static_cast<X509Certificate*>(NULL), google_full_chain.get());
  ASSERT_EQ(2U, google_full_chain->GetIntermediateCertificates().size());

  CertVerifyResult verify_result;
  EXPECT_EQ(static_cast<X509Certificate*>(NULL),
            verify_result.verified_cert.get());
  int error = Verify(google_full_chain.get(),
                     "127.0.0.1",
                     0,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_NE(static_cast<X509Certificate*>(NULL),
            verify_result.verified_cert.get());

  EXPECT_NE(google_full_chain, verify_result.verified_cert);
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      google_full_chain->os_cert_handle(),
      verify_result.verified_cert->os_cert_handle()));
  const X509Certificate::OSCertHandles& return_intermediates =
      verify_result.verified_cert->GetIntermediateCertificates();
  ASSERT_EQ(2U, return_intermediates.size());
  EXPECT_TRUE(X509Certificate::IsSameOSCert(return_intermediates[0],
                                            certs[1]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(return_intermediates[1],
                                            certs[2]->os_cert_handle()));
}

// Test that Verify() filters out certificates which are not related to
// or part of the certificate chain being verified.
TEST_F(CertVerifyProcTest, VerifyReturnChainFiltersUnrelatedCerts) {
  if (!SupportsReturningVerifiedChain()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  base::FilePath certs_dir = GetTestCertsDirectory();
  CertificateList certs = CreateCertificateListFromFile(
      certs_dir, "x509_verify_results.chain.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());
  ScopedTestRoot scoped_root(certs[2].get());

  scoped_refptr<X509Certificate> unrelated_certificate =
      ImportCertFromFile(certs_dir, "duplicate_cn_1.pem");
  scoped_refptr<X509Certificate> unrelated_certificate2 =
      ImportCertFromFile(certs_dir, "aia-cert.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), unrelated_certificate.get());
  ASSERT_NE(static_cast<X509Certificate*>(NULL), unrelated_certificate2.get());

  // Interject unrelated certificates into the list of intermediates.
  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(unrelated_certificate->os_cert_handle());
  intermediates.push_back(certs[1]->os_cert_handle());
  intermediates.push_back(unrelated_certificate2->os_cert_handle());
  intermediates.push_back(certs[2]->os_cert_handle());

  scoped_refptr<X509Certificate> google_full_chain =
      X509Certificate::CreateFromHandle(certs[0]->os_cert_handle(),
                                        intermediates);
  ASSERT_NE(static_cast<X509Certificate*>(NULL), google_full_chain.get());
  ASSERT_EQ(4U, google_full_chain->GetIntermediateCertificates().size());

  CertVerifyResult verify_result;
  EXPECT_EQ(static_cast<X509Certificate*>(NULL),
            verify_result.verified_cert.get());
  int error = Verify(google_full_chain.get(),
                     "127.0.0.1",
                     0,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  ASSERT_NE(static_cast<X509Certificate*>(NULL),
            verify_result.verified_cert.get());

  EXPECT_NE(google_full_chain, verify_result.verified_cert);
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      google_full_chain->os_cert_handle(),
      verify_result.verified_cert->os_cert_handle()));
  const X509Certificate::OSCertHandles& return_intermediates =
      verify_result.verified_cert->GetIntermediateCertificates();
  ASSERT_EQ(2U, return_intermediates.size());
  EXPECT_TRUE(X509Certificate::IsSameOSCert(return_intermediates[0],
                                            certs[1]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(return_intermediates[1],
                                            certs[2]->os_cert_handle()));
}

TEST_F(CertVerifyProcTest, AdditionalTrustAnchors) {
  if (!SupportsAdditionalTrustAnchors()) {
    LOG(INFO) << "Skipping this test in this platform.";
    return;
  }

  // |ca_cert| is the issuer of |cert|.
  CertificateList ca_cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "root_ca_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  scoped_refptr<X509Certificate> ca_cert(ca_cert_list[0]);

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  // Verification of |cert| fails when |ca_cert| is not in the trust anchors
  // list.
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(
      cert.get(), "127.0.0.1", flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);

  // Now add the |ca_cert| to the |trust_anchors|, and verification should pass.
  CertificateList trust_anchors;
  trust_anchors.push_back(ca_cert);
  error = Verify(
      cert.get(), "127.0.0.1", flags, NULL, trust_anchors, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
  EXPECT_TRUE(verify_result.is_issued_by_additional_trust_anchor);

  // Clearing the |trust_anchors| makes verification fail again (the cache
  // should be skipped).
  error = Verify(
      cert.get(), "127.0.0.1", flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_AUTHORITY_INVALID));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, verify_result.cert_status);
  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);
}

// Tests that certificates issued by user-supplied roots are not flagged as
// issued by a known root. This should pass whether or not the platform supports
// detecting known roots.
TEST_F(CertVerifyProcTest, IsIssuedByKnownRootIgnoresTestRoots) {
  // Load root_ca_cert.pem into the test root store.
  ScopedTestRoot test_root(
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem").get());

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem"));

  // Verification should pass.
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(
      cert.get(), "127.0.0.1", flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);
  // But should not be marked as a known root.
  EXPECT_FALSE(verify_result.is_issued_by_known_root);
}

#if defined(USE_NSS_CERTS) || defined(OS_WIN) || \
    (defined(OS_MACOSX) && !defined(OS_IOS))
// Test that CRLSets are effective in making a certificate appear to be
// revoked.
TEST_F(CertVerifyProcTest, CRLSet) {
  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "root_ca_cert.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0].get());

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "ok_cert.pem", X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(
      cert.get(), "127.0.0.1", flags, NULL, empty_cert_list_, &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(0U, verify_result.cert_status);

  scoped_refptr<CRLSet> crl_set;
  std::string crl_set_bytes;

  // First test blocking by SPKI.
  EXPECT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_leaf_spki.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSetStorage::Parse(crl_set_bytes, &crl_set));

  error = Verify(cert.get(),
                 "127.0.0.1",
                 flags,
                 crl_set.get(),
                 empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));

  // Second, test revocation by serial number of a cert directly under the
  // root.
  crl_set_bytes.clear();
  EXPECT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_root_serial.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSetStorage::Parse(crl_set_bytes, &crl_set));

  error = Verify(cert.get(),
                 "127.0.0.1",
                 flags,
                 crl_set.get(),
                 empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
}

TEST_F(CertVerifyProcTest, CRLSetLeafSerial) {
  CertificateList ca_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "quic_root.crt",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, ca_cert_list.size());
  ScopedTestRoot test_root(ca_cert_list[0].get());

  CertificateList intermediate_cert_list =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "quic_intermediate.crt",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, intermediate_cert_list.size());
  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(intermediate_cert_list[0]->os_cert_handle());

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "quic_test.example.com.crt",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());

  scoped_refptr<X509Certificate> leaf =
      X509Certificate::CreateFromHandle(cert_list[0]->os_cert_handle(),
                                        intermediates);

  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(leaf.get(),
                     "test.example.com",
                     flags,
                     NULL,
                     empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsOk());
  EXPECT_EQ(CERT_STATUS_SHA1_SIGNATURE_PRESENT, verify_result.cert_status);

  // Test revocation by serial number of a certificate not under the root.
  scoped_refptr<CRLSet> crl_set;
  std::string crl_set_bytes;
  ASSERT_TRUE(base::ReadFileToString(
      GetTestCertsDirectory().AppendASCII("crlset_by_intermediate_serial.raw"),
      &crl_set_bytes));
  ASSERT_TRUE(CRLSetStorage::Parse(crl_set_bytes, &crl_set));

  error = Verify(leaf.get(),
                 "test.example.com",
                 flags,
                 crl_set.get(),
                 empty_cert_list_,
                 &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_REVOKED));
}

// Tests that CRLSets participate in path building functions, and that as
// long as a valid path exists within the verification graph, verification
// succeeds.
//
// In this test, there are two roots (D and E), and three possible paths
// to validate a leaf (A):
// 1. A(B) -> B(C) -> C(D) -> D(D)
// 2. A(B) -> B(C) -> C(E) -> E(E)
// 3. A(B) -> B(F) -> F(E) -> E(E)
//
// Each permutation of revocation is tried:
// 1. Revoking E by SPKI, so that only Path 1 is valid (as E is in Paths 2 & 3)
// 2. Revoking C(D) and F(E) by serial, so that only Path 2 is valid.
// 3. Revoking C by SPKI, so that only Path 3 is valid (as C is in Paths 1 & 2)
TEST_F(CertVerifyProcTest, CRLSetDuringPathBuilding) {
  if (!SupportsCRLSetsInPathBuilding()) {
    LOG(INFO) << "Skipping this test on this platform.";
    return;
  }

  const char* const kPath1Files[] = {
      "multi-root-A-by-B.pem", "multi-root-B-by-C.pem", "multi-root-C-by-D.pem",
      "multi-root-D-by-D.pem"};
  const char* const kPath2Files[] = {
      "multi-root-A-by-B.pem", "multi-root-B-by-C.pem", "multi-root-C-by-E.pem",
      "multi-root-E-by-E.pem"};
  const char* const kPath3Files[] = {
      "multi-root-A-by-B.pem", "multi-root-B-by-F.pem", "multi-root-F-by-E.pem",
      "multi-root-E-by-E.pem"};

  CertificateList path_1_certs;
  ASSERT_NO_FATAL_FAILURE(LoadCertificateFiles(kPath1Files, &path_1_certs));

  CertificateList path_2_certs;
  ASSERT_NO_FATAL_FAILURE(LoadCertificateFiles(kPath2Files, &path_2_certs));

  CertificateList path_3_certs;
  ASSERT_NO_FATAL_FAILURE(LoadCertificateFiles(kPath3Files, &path_3_certs));

  // Add D and E as trust anchors.
  ScopedTestRoot test_root_D(path_1_certs[3].get());  // D-by-D
  ScopedTestRoot test_root_E(path_2_certs[3].get());  // E-by-E

  // Create a chain that contains all the certificate paths possible.
  // CertVerifyProcTest.VerifyReturnChainFiltersUnrelatedCerts already
  // ensures that it's safe to send additional certificates as inputs, and
  // that they're ignored if not necessary.
  // This is to avoid relying on AIA or internal object caches when
  // interacting with the underlying library.
  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(path_1_certs[1]->os_cert_handle());  // B-by-C
  intermediates.push_back(path_1_certs[2]->os_cert_handle());  // C-by-D
  intermediates.push_back(path_2_certs[2]->os_cert_handle());  // C-by-E
  intermediates.push_back(path_3_certs[1]->os_cert_handle());  // B-by-F
  intermediates.push_back(path_3_certs[2]->os_cert_handle());  // F-by-E
  scoped_refptr<X509Certificate> cert = X509Certificate::CreateFromHandle(
      path_1_certs[0]->os_cert_handle(), intermediates);
  ASSERT_TRUE(cert);

  struct TestPermutations {
    const char* crlset;
    bool expect_valid;
    scoped_refptr<X509Certificate> expected_intermediate;
  } kTests[] = {
      {"multi-root-crlset-D-and-E.raw", false, nullptr},
      {"multi-root-crlset-E.raw", true, path_1_certs[2].get()},
      {"multi-root-crlset-CD-and-FE.raw", true, path_2_certs[2].get()},
      {"multi-root-crlset-C.raw", true, path_3_certs[2].get()},
      {"multi-root-crlset-unrelated.raw", true, nullptr}};

  for (const auto& testcase : kTests) {
    SCOPED_TRACE(testcase.crlset);
    scoped_refptr<CRLSet> crl_set;
    std::string crl_set_bytes;
    EXPECT_TRUE(base::ReadFileToString(
        GetTestCertsDirectory().AppendASCII(testcase.crlset), &crl_set_bytes));
    ASSERT_TRUE(CRLSetStorage::Parse(crl_set_bytes, &crl_set));

    int flags = 0;
    CertVerifyResult verify_result;
    int error = Verify(cert.get(), "127.0.0.1", flags, crl_set.get(),
                       empty_cert_list_, &verify_result);

    if (!testcase.expect_valid) {
      EXPECT_NE(OK, error);
      EXPECT_NE(0U, verify_result.cert_status);
      continue;
    }

    ASSERT_THAT(error, IsOk());
    ASSERT_EQ(0U, verify_result.cert_status);
    ASSERT_TRUE(verify_result.verified_cert.get());

    if (!testcase.expected_intermediate)
      continue;

    const X509Certificate::OSCertHandles& verified_intermediates =
        verify_result.verified_cert->GetIntermediateCertificates();
    ASSERT_EQ(3U, verified_intermediates.size());

    scoped_refptr<X509Certificate> intermediate =
        X509Certificate::CreateFromHandle(verified_intermediates[1],
                                          X509Certificate::OSCertHandles());
    ASSERT_TRUE(intermediate);

    EXPECT_TRUE(testcase.expected_intermediate->Equals(intermediate.get()))
        << "Expected: " << testcase.expected_intermediate->subject().common_name
        << " issued by " << testcase.expected_intermediate->issuer().common_name
        << "; Got: " << intermediate->subject().common_name << " issued by "
        << intermediate->issuer().common_name;
  }
}

#endif

enum ExpectedAlgorithms {
  EXPECT_MD2 = 1 << 0,
  EXPECT_MD4 = 1 << 1,
  EXPECT_MD5 = 1 << 2,
  EXPECT_SHA1 = 1 << 3,
  EXPECT_SHA1_LEAF = 1 << 4,
};

struct WeakDigestTestData {
  const char* root_cert_filename;
  const char* intermediate_cert_filename;
  const char* ee_cert_filename;
  int expected_algorithms;
};

// GTest 'magic' pretty-printer, so that if/when a test fails, it knows how
// to output the parameter that was passed. Without this, it will simply
// attempt to print out the first twenty bytes of the object, which depending
// on platform and alignment, may result in an invalid read.
void PrintTo(const WeakDigestTestData& data, std::ostream* os) {
  *os << "root: "
      << (data.root_cert_filename ? data.root_cert_filename : "none")
      << "; intermediate: " << data.intermediate_cert_filename
      << "; end-entity: " << data.ee_cert_filename;
}

class CertVerifyProcWeakDigestTest
    : public CertVerifyProcTest,
      public testing::WithParamInterface<WeakDigestTestData> {
 public:
  CertVerifyProcWeakDigestTest() {}
  virtual ~CertVerifyProcWeakDigestTest() {}
};

TEST_P(CertVerifyProcWeakDigestTest, Verify) {
  WeakDigestTestData data = GetParam();
  base::FilePath certs_dir = GetTestCertsDirectory();

  ScopedTestRoot test_root;
  if (data.root_cert_filename) {
     scoped_refptr<X509Certificate> root_cert =
         ImportCertFromFile(certs_dir, data.root_cert_filename);
     ASSERT_NE(static_cast<X509Certificate*>(NULL), root_cert.get());
     test_root.Reset(root_cert.get());
  }

  scoped_refptr<X509Certificate> intermediate_cert =
      ImportCertFromFile(certs_dir, data.intermediate_cert_filename);
  ASSERT_NE(static_cast<X509Certificate*>(NULL), intermediate_cert.get());
  scoped_refptr<X509Certificate> ee_cert =
      ImportCertFromFile(certs_dir, data.ee_cert_filename);
  ASSERT_NE(static_cast<X509Certificate*>(NULL), ee_cert.get());

  X509Certificate::OSCertHandles intermediates;
  intermediates.push_back(intermediate_cert->os_cert_handle());

  scoped_refptr<X509Certificate> ee_chain =
      X509Certificate::CreateFromHandle(ee_cert->os_cert_handle(),
                                        intermediates);
  ASSERT_NE(static_cast<X509Certificate*>(NULL), ee_chain.get());

  int flags = 0;
  CertVerifyResult verify_result;
  int rv = Verify(ee_chain.get(),
                  "127.0.0.1",
                  flags,
                  NULL,
                  empty_cert_list_,
                  &verify_result);
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_MD2), verify_result.has_md2);
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_MD4), verify_result.has_md4);
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_MD5), verify_result.has_md5);
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_SHA1), verify_result.has_sha1);
  EXPECT_EQ(!!(data.expected_algorithms & EXPECT_SHA1_LEAF),
            verify_result.has_sha1_leaf);

  EXPECT_FALSE(verify_result.is_issued_by_additional_trust_anchor);

  // Ensure that MD4 and MD2 are tagged as invalid.
  if (data.expected_algorithms & (EXPECT_MD2 | EXPECT_MD4)) {
    EXPECT_EQ(CERT_STATUS_INVALID,
              verify_result.cert_status & CERT_STATUS_INVALID);
  }

  // Ensure that MD5 is flagged as weak.
  if (data.expected_algorithms & EXPECT_MD5) {
    EXPECT_EQ(
        CERT_STATUS_WEAK_SIGNATURE_ALGORITHM,
        verify_result.cert_status & CERT_STATUS_WEAK_SIGNATURE_ALGORITHM);
  }

  // If a root cert is present, then check that the chain was rejected if any
  // weak algorithms are present. This is only checked when a root cert is
  // present because the error reported for incomplete chains with weak
  // algorithms depends on which implementation was used to validate (NSS,
  // OpenSSL, CryptoAPI, Security.framework) and upon which weak algorithm
  // present (MD2, MD4, MD5).
  if (data.root_cert_filename) {
    if (data.expected_algorithms & (EXPECT_MD2 | EXPECT_MD4)) {
      EXPECT_THAT(rv, IsError(ERR_CERT_INVALID));
    } else if (data.expected_algorithms & EXPECT_MD5) {
      EXPECT_THAT(rv, IsError(ERR_CERT_WEAK_SIGNATURE_ALGORITHM));
    } else {
      EXPECT_THAT(rv, IsOk());
    }
  }
}

// Unlike TEST/TEST_F, which are macros that expand to further macros,
// INSTANTIATE_TEST_CASE_P is a macro that expands directly to code that
// stringizes the arguments. As a result, macros passed as parameters (such as
// prefix or test_case_name) will not be expanded by the preprocessor. To work
// around this, indirect the macro for INSTANTIATE_TEST_CASE_P, so that the
// pre-processor will expand macros such as MAYBE_test_name before
// instantiating the test.
#define WRAPPED_INSTANTIATE_TEST_CASE_P(prefix, test_case_name, generator) \
    INSTANTIATE_TEST_CASE_P(prefix, test_case_name, generator)

// The signature algorithm of the root CA should not matter.
const WeakDigestTestData kVerifyRootCATestData[] = {
    {"weak_digest_md5_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_SHA1 | EXPECT_SHA1_LEAF},
#if defined(USE_OPENSSL_CERTS) || defined(OS_WIN)
    // MD4 is not supported by OS X / NSS
    {"weak_digest_md4_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_SHA1 | EXPECT_SHA1_LEAF},
#endif
    {"weak_digest_md2_root.pem", "weak_digest_sha1_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_SHA1 | EXPECT_SHA1_LEAF},
};
#if defined(OS_ANDROID)
#define MAYBE_VerifyRoot DISABLED_VerifyRoot
#else
#define MAYBE_VerifyRoot VerifyRoot
#endif
INSTANTIATE_TEST_CASE_P(MAYBE_VerifyRoot,
                        CertVerifyProcWeakDigestTest,
                        testing::ValuesIn(kVerifyRootCATestData));

// The signature algorithm of intermediates should be properly detected.
const WeakDigestTestData kVerifyIntermediateCATestData[] = {
    {"weak_digest_sha1_root.pem", "weak_digest_md5_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_MD5 | EXPECT_SHA1 | EXPECT_SHA1_LEAF},
#if defined(USE_OPENSSL_CERTS) || defined(OS_WIN)
    // MD4 is not supported by OS X / NSS
    {"weak_digest_sha1_root.pem", "weak_digest_md4_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_MD4 | EXPECT_SHA1 | EXPECT_SHA1_LEAF},
#endif
    {"weak_digest_sha1_root.pem", "weak_digest_md2_intermediate.pem",
     "weak_digest_sha1_ee.pem", EXPECT_MD2 | EXPECT_SHA1 | EXPECT_SHA1_LEAF},
};
// Disabled on NSS - MD4 is not supported, and MD2 and MD5 are disabled.
#if defined(USE_NSS_CERTS) || defined(OS_IOS) || defined(OS_ANDROID)
#define MAYBE_VerifyIntermediate DISABLED_VerifyIntermediate
#else
#define MAYBE_VerifyIntermediate VerifyIntermediate
#endif
WRAPPED_INSTANTIATE_TEST_CASE_P(
    MAYBE_VerifyIntermediate,
    CertVerifyProcWeakDigestTest,
    testing::ValuesIn(kVerifyIntermediateCATestData));

// The signature algorithm of end-entity should be properly detected.
const WeakDigestTestData kVerifyEndEntityTestData[] = {
  { "weak_digest_sha1_root.pem", "weak_digest_sha1_intermediate.pem",
    "weak_digest_md5_ee.pem", EXPECT_MD5 | EXPECT_SHA1 },
#if defined(USE_OPENSSL_CERTS) || defined(OS_WIN)
  // MD4 is not supported by OS X / NSS
  { "weak_digest_sha1_root.pem", "weak_digest_sha1_intermediate.pem",
    "weak_digest_md4_ee.pem", EXPECT_MD4 | EXPECT_SHA1 },
#endif
  { "weak_digest_sha1_root.pem", "weak_digest_sha1_intermediate.pem",
    "weak_digest_md2_ee.pem", EXPECT_MD2 | EXPECT_SHA1 },
};
// Disabled on NSS - NSS caches chains/signatures in such a way that cannot
// be cleared until NSS is cleanly shutdown, which is not presently supported
// in Chromium.
#if defined(USE_NSS_CERTS) || defined(OS_IOS) || defined(OS_ANDROID)
#define MAYBE_VerifyEndEntity DISABLED_VerifyEndEntity
#else
#define MAYBE_VerifyEndEntity VerifyEndEntity
#endif
WRAPPED_INSTANTIATE_TEST_CASE_P(MAYBE_VerifyEndEntity,
                                CertVerifyProcWeakDigestTest,
                                testing::ValuesIn(kVerifyEndEntityTestData));

// Incomplete chains should still report the status of the intermediate.
const WeakDigestTestData kVerifyIncompleteIntermediateTestData[] = {
    {NULL, "weak_digest_md5_intermediate.pem", "weak_digest_sha1_ee.pem",
     EXPECT_MD5 | EXPECT_SHA1 | EXPECT_SHA1_LEAF},
#if defined(USE_OPENSSL_CERTS) || defined(OS_WIN)
    // MD4 is not supported by OS X / NSS
    {NULL, "weak_digest_md4_intermediate.pem", "weak_digest_sha1_ee.pem",
     EXPECT_MD4 | EXPECT_SHA1 | EXPECT_SHA1_LEAF},
#endif
    {NULL, "weak_digest_md2_intermediate.pem", "weak_digest_sha1_ee.pem",
     EXPECT_MD2 | EXPECT_SHA1 | EXPECT_SHA1_LEAF},
};
// Disabled on NSS - libpkix does not return constructed chains on error,
// preventing us from detecting/inspecting the verified chain.
#if defined(USE_NSS_CERTS) || defined(OS_IOS) || defined(OS_ANDROID)
#define MAYBE_VerifyIncompleteIntermediate \
    DISABLED_VerifyIncompleteIntermediate
#else
#define MAYBE_VerifyIncompleteIntermediate VerifyIncompleteIntermediate
#endif
WRAPPED_INSTANTIATE_TEST_CASE_P(
    MAYBE_VerifyIncompleteIntermediate,
    CertVerifyProcWeakDigestTest,
    testing::ValuesIn(kVerifyIncompleteIntermediateTestData));

// Incomplete chains should still report the status of the end-entity.
const WeakDigestTestData kVerifyIncompleteEETestData[] = {
  { NULL, "weak_digest_sha1_intermediate.pem", "weak_digest_md5_ee.pem",
    EXPECT_MD5 | EXPECT_SHA1 },
#if defined(USE_OPENSSL_CERTS) || defined(OS_WIN)
  // MD4 is not supported by OS X / NSS
  { NULL, "weak_digest_sha1_intermediate.pem", "weak_digest_md4_ee.pem",
    EXPECT_MD4 | EXPECT_SHA1 },
#endif
  { NULL, "weak_digest_sha1_intermediate.pem", "weak_digest_md2_ee.pem",
    EXPECT_MD2 | EXPECT_SHA1 },
};
// Disabled on NSS - libpkix does not return constructed chains on error,
// preventing us from detecting/inspecting the verified chain.
#if defined(USE_NSS_CERTS) || defined(OS_IOS) || defined(OS_ANDROID)
#define MAYBE_VerifyIncompleteEndEntity DISABLED_VerifyIncompleteEndEntity
#else
#define MAYBE_VerifyIncompleteEndEntity VerifyIncompleteEndEntity
#endif
WRAPPED_INSTANTIATE_TEST_CASE_P(
    MAYBE_VerifyIncompleteEndEntity,
    CertVerifyProcWeakDigestTest,
    testing::ValuesIn(kVerifyIncompleteEETestData));

// Differing algorithms between the intermediate and the EE should still be
// reported.
const WeakDigestTestData kVerifyMixedTestData[] = {
  { "weak_digest_sha1_root.pem", "weak_digest_md5_intermediate.pem",
    "weak_digest_md2_ee.pem", EXPECT_MD2 | EXPECT_MD5 },
  { "weak_digest_sha1_root.pem", "weak_digest_md2_intermediate.pem",
    "weak_digest_md5_ee.pem", EXPECT_MD2 | EXPECT_MD5 },
#if defined(USE_OPENSSL_CERTS) || defined(OS_WIN)
  // MD4 is not supported by OS X / NSS
  { "weak_digest_sha1_root.pem", "weak_digest_md4_intermediate.pem",
    "weak_digest_md2_ee.pem", EXPECT_MD2 | EXPECT_MD4 },
#endif
};
// NSS does not support MD4 and does not enable MD2 by default, making all
// permutations invalid.
#if defined(USE_NSS_CERTS) || defined(OS_IOS) || defined(OS_ANDROID)
#define MAYBE_VerifyMixed DISABLED_VerifyMixed
#else
#define MAYBE_VerifyMixed VerifyMixed
#endif
WRAPPED_INSTANTIATE_TEST_CASE_P(
    MAYBE_VerifyMixed,
    CertVerifyProcWeakDigestTest,
    testing::ValuesIn(kVerifyMixedTestData));

// For the list of valid hostnames, see
// net/cert/data/ssl/certificates/subjectAltName_sanity_check.pem
static const struct CertVerifyProcNameData {
  const char* hostname;
  bool valid;  // Whether or not |hostname| matches a subjectAltName.
} kVerifyNameData[] = {
  { "127.0.0.1", false },  // Don't match the common name
  { "127.0.0.2", true },  // Matches the iPAddress SAN (IPv4)
  { "FE80:0:0:0:0:0:0:1", true },  // Matches the iPAddress SAN (IPv6)
  { "[FE80:0:0:0:0:0:0:1]", false },  // Should not match the iPAddress SAN
  { "FE80::1", true },  // Compressed form matches the iPAddress SAN (IPv6)
  { "::127.0.0.2", false },  // IPv6 mapped form should NOT match iPAddress SAN
  { "test.example", true },  // Matches the dNSName SAN
  { "test.example.", true },  // Matches the dNSName SAN (trailing . ignored)
  { "www.test.example", false },  // Should not match the dNSName SAN
  { "test..example", false },  // Should not match the dNSName SAN
  { "test.example..", false },  // Should not match the dNSName SAN
  { ".test.example.", false },  // Should not match the dNSName SAN
  { ".test.example", false },  // Should not match the dNSName SAN
};

// GTest 'magic' pretty-printer, so that if/when a test fails, it knows how
// to output the parameter that was passed. Without this, it will simply
// attempt to print out the first twenty bytes of the object, which depending
// on platform and alignment, may result in an invalid read.
void PrintTo(const CertVerifyProcNameData& data, std::ostream* os) {
  *os << "Hostname: " << data.hostname << "; valid=" << data.valid;
}

class CertVerifyProcNameTest
    : public CertVerifyProcTest,
      public testing::WithParamInterface<CertVerifyProcNameData> {
 public:
  CertVerifyProcNameTest() {}
  virtual ~CertVerifyProcNameTest() {}
};

TEST_P(CertVerifyProcNameTest, VerifyCertName) {
  CertVerifyProcNameData data = GetParam();

  CertificateList cert_list = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "subjectAltName_sanity_check.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(1U, cert_list.size());
  scoped_refptr<X509Certificate> cert(cert_list[0]);

  ScopedTestRoot scoped_root(cert.get());

  CertVerifyResult verify_result;
  int error = Verify(cert.get(), data.hostname, 0, NULL, empty_cert_list_,
                     &verify_result);
  if (data.valid) {
    EXPECT_THAT(error, IsOk());
    EXPECT_FALSE(verify_result.cert_status & CERT_STATUS_COMMON_NAME_INVALID);
  } else {
    EXPECT_THAT(error, IsError(ERR_CERT_COMMON_NAME_INVALID));
    EXPECT_TRUE(verify_result.cert_status & CERT_STATUS_COMMON_NAME_INVALID);
  }
}

WRAPPED_INSTANTIATE_TEST_CASE_P(
    VerifyName,
    CertVerifyProcNameTest,
    testing::ValuesIn(kVerifyNameData));

#if defined(OS_MACOSX) && !defined(OS_IOS)
// Test that CertVerifyProcMac reacts appropriately when Apple's certificate
// verifier rejects a certificate with a fatal error. This is a regression
// test for https://crbug.com/472291.
TEST_F(CertVerifyProcTest, LargeKey) {
  // Load root_ca_cert.pem into the test root store.
  ScopedTestRoot test_root(
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem").get());

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "large_key.pem"));

  // Apple's verifier rejects this certificate as invalid because the
  // RSA key is too large. If a future version of OS X changes this,
  // large_key.pem may need to be regenerated with a larger key.
  int flags = 0;
  CertVerifyResult verify_result;
  int error = Verify(cert.get(), "127.0.0.1", flags, NULL, empty_cert_list_,
                     &verify_result);
  EXPECT_THAT(error, IsError(ERR_CERT_INVALID));
  EXPECT_EQ(CERT_STATUS_INVALID, verify_result.cert_status);
}
#endif  // defined(OS_MACOSX) && !defined(OS_IOS)

}  // namespace net
