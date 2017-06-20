// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/crypto/proof_verifier_chromium.h"

#include "base/memory/ptr_util.h"
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
#include "net/quic/chromium/crypto/proof_source_chromium.h"
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

// A mock CTPolicyEnforcer that returns a custom verification result.
class MockCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  MOCK_METHOD3(DoesConformToCertPolicy,
               ct::CertPolicyCompliance(X509Certificate* cert,
                                        const ct::SCTList&,
                                        const NetLogWithSource&));
};

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD1(IsCTRequiredForHost,
               CTRequirementLevel(const std::string& host));
};

// Proof source callback which saves the signature into |signature|.
class SignatureSaver : public ProofSource::Callback {
 public:
  explicit SignatureSaver(std::string* signature) : signature_(signature) {}
  ~SignatureSaver() override {}

  void Run(bool /*ok*/,
           const QuicReferenceCountedPointer<ProofSource::Chain>& /*chain*/,
           const QuicCryptoProof& proof,
           std::unique_ptr<ProofSource::Details> /*details*/) override {
    *signature_ = proof.signature;
  }

  std::string* signature_;
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
const char kTestChloHash[] = "CHLO hash";
const char kTestEmptySCT[] = "";
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
    ProofSourceChromium source;
    source.Initialize(
        GetTestCertsDirectory().AppendASCII("quic_test.example.com.crt"),
        GetTestCertsDirectory().AppendASCII("quic_test.example.com.key.pkcs8"),
        GetTestCertsDirectory().AppendASCII("quic_test.example.com.key.sct"));
    std::string signature;
    source.GetProof(QuicSocketAddress(), kTestHostname, kTestConfig,
                    QUIC_VERSION_35, kTestChloHash, QuicTagVector(),
                    base::MakeUnique<SignatureSaver>(&signature));
    return signature;
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
TEST_F(ProofVerifierChromiumTest, FailsIfCertFails) {
  MockCertVerifier dummy_verifier;
  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
}

// Valid SCT, but invalid signature.
TEST_F(ProofVerifierChromiumTest, ValidSCTList) {
  // Use different certificates for SCT tests.
  ASSERT_NO_FATAL_FAILURE(GetSCTTestCertificates(&certs_));

  MockCertVerifier cert_verifier;

  ProofVerifierChromium proof_verifier(&cert_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, ct::GetSCTListForTesting(), kTestEmptySCT, verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
  CheckSCT(/*sct_expected_ok=*/true);
}

// Invalid SCT and signature.
TEST_F(ProofVerifierChromiumTest, InvalidSCTList) {
  // Use different certificates for SCT tests.
  ASSERT_NO_FATAL_FAILURE(GetSCTTestCertificates(&certs_));

  MockCertVerifier cert_verifier;
  ProofVerifierChromium proof_verifier(&cert_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, ct::GetSCTListWithInvalidSCT(), kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
  CheckSCT(/*sct_expected_ok=*/false);
}

// Tests that the ProofVerifier doesn't verify certificates if the config
// signature fails.
TEST_F(ProofVerifierChromiumTest, FailsIfSignatureFails) {
  FailsTestCertVerifier cert_verifier;
  ProofVerifierChromium proof_verifier(&cert_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, kTestConfig, verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);
}

// Tests that the certificate policy enforcer is consulted for EV
// and the certificate is allowed to be EV.
TEST_F(ProofVerifierChromiumTest, PreservesEVIfAllowed) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.cert_status = CERT_STATUS_IS_EV;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  EXPECT_CALL(ct_policy_enforcer_, DoesConformToCertPolicy(_, _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS));

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result.cert_status,
            verify_details->cert_verify_result.cert_status);
}

// Tests that the certificate policy enforcer is consulted for EV
// and the certificate is not allowed to be EV.
TEST_F(ProofVerifierChromiumTest, StripsEVIfNotAllowed) {
  scoped_refptr<X509Certificate> test_cert = GetTestServerCertificate();
  ASSERT_TRUE(test_cert);

  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert;
  dummy_result.cert_status = CERT_STATUS_IS_EV;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert.get(), dummy_result, OK);

  EXPECT_CALL(ct_policy_enforcer_, DoesConformToCertPolicy(_, _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));

  ProofVerifierChromium proof_verifier(&dummy_verifier, &ct_policy_enforcer_,
                                       &transport_security_state_,
                                       ct_verifier_.get());

  std::unique_ptr<DummyProofVerifierCallback> callback(
      new DummyProofVerifierCallback);
  QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(CERT_STATUS_CT_COMPLIANCE_FAILED,
            verify_details->cert_verify_result.cert_status &
                (CERT_STATUS_CT_COMPLIANCE_FAILED | CERT_STATUS_IS_EV));
}

HashValueVector MakeHashValueVector(uint8_t tag) {
  HashValue hash(HASH_VALUE_SHA256);
  memset(hash.data(), tag, hash.size());
  HashValueVector hashes;
  hashes.push_back(hash);
  return hashes;
}

// Test that PKP is enforced for certificates that chain up to known roots.
TEST_F(ProofVerifierChromiumTest, PKPEnforced) {
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
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
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
TEST_F(ProofVerifierChromiumTest, PKPBypassFlagSet) {
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
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->pkp_bypassed);
}

// Test that when CT is required (in this case, by the delegate), the
// absence of CT information is a socket error.
TEST_F(ProofVerifierChromiumTest, CTIsRequired) {
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
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
  ASSERT_EQ(QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
}

// Test that CT is considered even when HPKP fails.
TEST_F(ProofVerifierChromiumTest, PKPAndCTBothTested) {
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
      kTestHostname, kTestPort, kTestConfig, QUIC_VERSION_35, kTestChloHash,
      certs_, kTestEmptySCT, GetTestSignature(), verify_context_.get(),
      &error_details_, &details_, std::move(callback));
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
