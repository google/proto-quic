// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/crypto/proof_verifier_chromium.h"

#include "base/memory/ref_counted.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/core/crypto/proof_verifier.h"
#include "net/test/cert_test_util.h"
#include "net/test/ct_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Return;

namespace net {
namespace test {

namespace {

// CertVerifier that will fail the test if it is ever called.
class FailsTestCertVerifier : public CertVerifier {
 public:
  FailsTestCertVerifier() {}
  ~FailsTestCertVerifier() override {}

  // CertVerifier implementation
  int Verify(const RequestParams& params,
             CRLSet* crl_set,
             CertVerifyResult* verify_result,
             const CompletionCallback& callback,
             std::unique_ptr<Request>* out_req,
             const NetLogWithSource& net_log) override {
    ADD_FAILURE() << "CertVerifier::Verify() should not be called";
    return ERR_FAILED;
  }
};

// CTPolicyEnforcer that will fail the test if it is ever called.
class FailsTestCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  FailsTestCTPolicyEnforcer() {}
  ~FailsTestCTPolicyEnforcer() override {}

  ct::EVPolicyCompliance DoesConformToCTEVPolicy(
      X509Certificate* cert,
      const ct::EVCertsWhitelist* ev_whitelist,
      const ct::SCTList& verified_scts,
      const NetLogWithSource& net_log) override {
    ADD_FAILURE() << "CTPolicyEnforcer::DoesConformToCTEVPolicy() should "
                  << "not be called";
    return ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY;
  }
};

// A mock CTPolicyEnforcer that returns a custom verification result.
class MockCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  MOCK_METHOD3(DoesConformToCertPolicy,
               ct::CertPolicyCompliance(X509Certificate* cert,
                                        const ct::SCTList&,
                                        const NetLogWithSource&));
  MOCK_METHOD4(DoesConformToCTEVPolicy,
               ct::EVPolicyCompliance(X509Certificate* cert,
                                      const ct::EVCertsWhitelist*,
                                      const ct::SCTList&,
                                      const NetLogWithSource&));
};

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD1(IsCTRequiredForHost,
               CTRequirementLevel(const std::string& host));
};

class DummyProofVerifierCallback : public ProofVerifierCallback {
 public:
  DummyProofVerifierCallback() {}
  ~DummyProofVerifierCallback() override {}

  void Run(bool ok,
           const std::string& error_details,
           std::unique_ptr<ProofVerifyDetails>* details) override {
    // Do nothing
  }
};

const char kTestHostname[] = "test.example.com";
const uint16_t kTestPort = 8443;
const char kTestConfig[] = "server config bytes";
const char kLogDescription[] = "somelog";

}  // namespace

class ProofVerifierChromiumTest : public ::testing::Test {
 public:
  ProofVerifierChromiumTest()
      : verify_context_(new ProofVerifyContextChromium(0 /*cert_verify_flags*/,
                                                       NetLogWithSource())) {}

  void SetUp() override {
    EXPECT_CALL(ct_policy_enforcer_, DoesConformToCertPolicy(_, _, _))
        .WillRepeatedly(
            Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));
    EXPECT_CALL(ct_policy_enforcer_, DoesConformToCTEVPolicy(_, _, _, _))
        .WillRepeatedly(
            Return(ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY));

    scoped_refptr<const CTLogVerifier> log(
        CTLogVerifier::Create(ct::GetTestPublicKey(), kLogDescription,
                              "https://test.example.com", "dns.example.com"));
    ASSERT_TRUE(log);
    log_verifiers_.push_back(log);

    ct_verifier_.reset(new MultiLogCTVerifier());
    ct_verifier_->AddLogs(log_verifiers_);

    ASSERT_NO_FATAL_FAILURE(GetTestCertificates(&certs_));
  }

  scoped_refptr<X509Certificate> GetTestServerCertificate() {
    static const char kTestCert[] = "quic_test.example.com.crt";
    return ImportCertFromFile(GetTestCertsDirectory(), kTestCert);
  }

  void GetTestCertificates(std::vector<std::string>* certs) {
    scoped_refptr<X509Certificate> cert = GetTestServerCertificate();
    ASSERT_TRUE(cert);

    std::string der_bytes;
    ASSERT_TRUE(
        X509Certificate::GetDEREncoded(cert->os_cert_handle(), &der_bytes));

    certs->clear();
    certs->push_back(der_bytes);
  }

  std::string GetTestSignature() {
    // Sample known answer test from ProofTest.VerifyRSAKnownAnswerTest.
    // Generated by dumping the bytes of the |signature| output of
    // ProofSource::GetProof().
    static const unsigned char kTestSignature[] = {
        0x31, 0xd5, 0xfb, 0x40, 0x30, 0x75, 0xd2, 0x7d, 0x61, 0xf9, 0xd7, 0x54,
        0x30, 0x06, 0xaf, 0x54, 0x0d, 0xb0, 0x0a, 0xda, 0x63, 0xca, 0x7e, 0x9e,
        0xce, 0xba, 0x10, 0x05, 0x1b, 0xa6, 0x7f, 0xef, 0x2b, 0xa3, 0xff, 0x3c,
        0xbb, 0x9a, 0xe4, 0xbf, 0xb8, 0x0c, 0xc1, 0xbd, 0xed, 0xc2, 0x90, 0x68,
        0xeb, 0x45, 0x48, 0xea, 0x3c, 0x95, 0xf8, 0xa2, 0xb9, 0xe7, 0x62, 0x29,
        0x00, 0xc3, 0x18, 0xb4, 0x16, 0x6f, 0x5e, 0xb0, 0xc1, 0x26, 0xc0, 0x4b,
        0x84, 0xf5, 0x97, 0xfc, 0x17, 0xf9, 0x1c, 0x43, 0xb8, 0xf2, 0x3f, 0x38,
        0x32, 0xad, 0x36, 0x52, 0x2c, 0x26, 0x92, 0x7a, 0xea, 0x2c, 0xa2, 0xf4,
        0x28, 0x2f, 0x19, 0x4d, 0x1f, 0x11, 0x46, 0x82, 0xd0, 0xc4, 0x86, 0x56,
        0x5c, 0x97, 0x9e, 0xc6, 0x37, 0x8e, 0xaf, 0x9d, 0x69, 0xe9, 0x4f, 0x5a,
        0x6d, 0x70, 0x75, 0xc7, 0x41, 0x95, 0x68, 0x53, 0x94, 0xca, 0x31, 0x63,
        0x61, 0x9f, 0xb8, 0x8c, 0x3b, 0x75, 0x36, 0x8b, 0x69, 0xa2, 0x35, 0xc0,
        0x4b, 0x77, 0x55, 0x08, 0xc2, 0xb4, 0x56, 0xd2, 0x81, 0xce, 0x9e, 0x25,
        0xdb, 0x50, 0x74, 0xb3, 0x8a, 0xd9, 0x20, 0x42, 0x3f, 0x85, 0x2d, 0xaa,
        0xfd, 0x66, 0xfa, 0xd6, 0x95, 0x55, 0x6b, 0x63, 0x63, 0x04, 0xf8, 0x6c,
        0x3e, 0x08, 0x22, 0x39, 0xb9, 0x9a, 0xe0, 0xd7, 0x01, 0xff, 0xeb, 0x8a,
        0xb9, 0xe2, 0x34, 0xa5, 0xa0, 0x51, 0xe9, 0xbe, 0x15, 0x12, 0xbf, 0xbe,
        0x64, 0x3d, 0x3f, 0x98, 0xce, 0xc1, 0xa6, 0x33, 0x32, 0xd3, 0x5c, 0xa8,
        0x39, 0x93, 0xdc, 0x1c, 0xb9, 0xab, 0x3c, 0x80, 0x62, 0xb3, 0x76, 0x21,
        0xdf, 0x47, 0x1e, 0xa9, 0x0e, 0x5e, 0x8a, 0xbe, 0x66, 0x5b, 0x7c, 0x21,
        0xfa, 0x78, 0x2d, 0xd1, 0x1d, 0x5c, 0x35, 0x8a, 0x34, 0xb2, 0x1a, 0xc2,
        0xc4, 0x4b, 0x53, 0x54,
    };
    return std::string(reinterpret_cast<const char*>(kTestSignature),
                       sizeof(kTestSignature));
  }

  void GetSCTTestCertificates(std::vector<std::string>* certs) {
    std::string der_test_cert(ct::GetDerEncodedX509Cert());
    scoped_refptr<X509Certificate> test_cert = X509Certificate::CreateFromBytes(
        der_test_cert.data(), der_test_cert.length());
    ASSERT_TRUE(test_cert.get());

    std::string der_bytes;
    ASSERT_TRUE(X509Certificate::GetDEREncoded(test_cert->os_cert_handle(),
                                               &der_bytes));

    certs->clear();
    certs->push_back(der_bytes);
  }

  void CheckSCT(bool sct_expected_ok) {
    ProofVerifyDetailsChromium* proof_details =
        reinterpret_cast<ProofVerifyDetailsChromium*>(details_.get());
    const ct::CTVerifyResult& ct_verify_result =
        proof_details->ct_verify_result;
    if (sct_expected_ok) {
      ASSERT_TRUE(ct::CheckForSingleVerifiedSCTInResult(ct_verify_result.scts,
                                                        kLogDescription));
      ASSERT_TRUE(ct::CheckForSCTOrigin(
          ct_verify_result.scts,
          ct::SignedCertificateTimestamp::SCT_FROM_TLS_EXTENSION));
    } else {
      EXPECT_EQ(1U, ct_verify_result.scts.size());
      EXPECT_EQ(ct::SCT_STATUS_LOG_UNKNOWN, ct_verify_result.scts[0].status);
    }
  }

 protected:
  TransportSecurityState transport_security_state_;
  MockCTPolicyEnforcer ct_policy_enforcer_;

  std::unique_ptr<MultiLogCTVerifier> ct_verifier_;
  std::vector<scoped_refptr<const CTLogVerifier>> log_verifiers_;
  std::unique_ptr<ProofVerifyContext> verify_context_;
  std::unique_ptr<ProofVerifyDetails> details_;
  std::string error_details_;
  std::vector<std::string> certs_;
};

// Tests that the ProofVerifier fails verification if certificate
// verification fails.
TEST_F(ProofVerifierChromiumTest, DISABLED_FailsIfCertFails) {
  MockCertVerifier dummy_verifier;
  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
}

// Valid SCT, but invalid signature.
TEST_F(ProofVerifierChromiumTest, DISABLED_ValidSCTList) {
  // Use different certificates for SCT tests.
  ASSERT_NO_FATAL_FAILURE(GetSCTTestCertificates(&certs_));

  MockCertVerifier cert_verifier;
  ProofVerifierChromium proof_verifier(&cert_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_,
      ct::GetSCTListForTesting(), "", verify_context_.get(), &error_details_,
      &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
  CheckSCT(/*sct_expected_ok=*/true);
}

// Invalid SCT and signature.
TEST_F(ProofVerifierChromiumTest, DISABLED_InvalidSCTList) {
  // Use different certificates for SCT tests.
  ASSERT_NO_FATAL_FAILURE(GetSCTTestCertificates(&certs_));

  MockCertVerifier cert_verifier;
  ProofVerifierChromium proof_verifier(&cert_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_,
      ct::GetSCTListWithInvalidSCT(), "", verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
  CheckSCT(/*sct_expected_ok=*/false);
}

// Tests that the ProofVerifier doesn't verify certificates if the config
// signature fails.
TEST_F(ProofVerifierChromiumTest, DISABLED_FailsIfSignatureFails) {
  FailsTestCertVerifier cert_verifier;
  ProofVerifierChromium proof_verifier(&cert_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      kTestConfig, verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
}

// Tests that the certificate policy enforcer is consulted for EV
// and the certificate is allowed to be EV.
TEST_F(ProofVerifierChromiumTest, DISABLED_PreservesEVIfAllowed) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.cert_status = CERT_STATUS_IS_EV;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  EXPECT_CALL(ct_policy_enforcer_, DoesConformToCTEVPolicy(_, _, _, _))
      .WillRepeatedly(
          Return(ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS));

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result.cert_status,
            verify_details->cert_verify_result.cert_status);
}

// Tests that the certificate policy enforcer is consulted for EV
// and the certificate is not allowed to be EV.
TEST_F(ProofVerifierChromiumTest, DISABLED_StripsEVIfNotAllowed) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.cert_status = CERT_STATUS_IS_EV;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  EXPECT_CALL(ct_policy_enforcer_, DoesConformToCTEVPolicy(_, _, _, _))
      .WillRepeatedly(
          Return(ct::EVPolicyCompliance::EV_POLICY_NOT_ENOUGH_SCTS));

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(CERT_STATUS_CT_COMPLIANCE_FAILED,
            verify_details->cert_verify_result.cert_status &
                (CERT_STATUS_CT_COMPLIANCE_FAILED | CERT_STATUS_IS_EV));
}

// Tests that the certificate policy enforcer is not consulted if
// the certificate is not EV.
TEST_F(ProofVerifierChromiumTest, DISABLED_IgnoresPolicyEnforcerIfNotEV) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.cert_status = 0;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  FailsTestCTPolicyEnforcer policy_enforcer;

  ProofVerifierChromium proof_verifier(&dummy_verifier, &policy_enforcer,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(0u, verify_details->cert_verify_result.cert_status);
}

HashValueVector MakeHashValueVector(uint8_t tag) {
  HashValue hash(HASH_VALUE_SHA256);
  memset(hash.data(), tag, hash.size());
  HashValueVector hashes;
  hashes.push_back(hash);
  return hashes;
}

// Test that PKP is enforced for certificates that chain up to known roots.
TEST_F(ProofVerifierChromiumTest, DISABLED_PKPEnforced) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.is_issued_by_known_root = true;
  dummy_result.public_key_hashes = MakeHashValueVector(0x01);
  dummy_result.cert_status = 0;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  HashValueVector pin_hashes = MakeHashValueVector(0x02);
  transport_security_state_.AddHPKP(
      kTestHostname, base::Time::Now() + base::TimeDelta::FromSeconds(10000),
      true, pin_hashes, GURL());

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_FALSE(verify_details->pkp_bypassed);
  EXPECT_NE("", verify_details->pinning_failure_log);
}

// Test |pkp_bypassed| is set when PKP is bypassed due to a local
// trust anchor
TEST_F(ProofVerifierChromiumTest, DISABLED_PKPBypassFlagSet) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.is_issued_by_known_root = false;
  dummy_result.public_key_hashes = MakeHashValueVector(0x01);
  dummy_result.cert_status = 0;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  HashValueVector expected_hashes = MakeHashValueVector(0x02);
  transport_security_state_.AddHPKP(
      kTestHostname, base::Time::Now() + base::TimeDelta::FromSeconds(10000),
      true, expected_hashes, GURL());

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->pkp_bypassed);
}

// Test that when CT is required (in this case, by the delegate), the
// absence of CT information is a socket error.
TEST_F(ProofVerifierChromiumTest, DISABLED_CTIsRequired) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.is_issued_by_known_root = true;
  dummy_result.public_key_hashes = MakeHashValueVector(0x01);
  dummy_result.cert_status = 0;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  // Set up CT.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_.SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(kTestHostname))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));
  EXPECT_CALL(ct_policy_enforcer_, DoesConformToCertPolicy(_, _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
}

// Test that CT is considered even when HPKP fails.
TEST_F(ProofVerifierChromiumTest, DISABLED_PKPAndCTBothTested) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.is_issued_by_known_root = true;
  dummy_result.public_key_hashes = MakeHashValueVector(0x01);
  dummy_result.cert_status = 0;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  // Set up HPKP.
  HashValueVector pin_hashes = MakeHashValueVector(0x02);
  transport_security_state_.AddHPKP(
      kTestHostname, base::Time::Now() + base::TimeDelta::FromSeconds(10000),
      true, pin_hashes, GURL());

  // Set up CT.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_.SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(kTestHostname))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));
  EXPECT_CALL(ct_policy_enforcer_, DoesConformToCertPolicy(_, _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, "", certs_, "",
      GetTestSignature(), verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
}

// Tests that the VerifyCertChain verifies certificates.
TEST_F(ProofVerifierChromiumTest, VerifyCertChain) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.cert_status = 0;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyCertChain(
      kTestHostname, certs_, verify_context_.get(), &error_details_, &details_,
      std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(0u, verify_details->cert_verify_result.cert_status);
}

}  // namespace test
}  // namespace net
