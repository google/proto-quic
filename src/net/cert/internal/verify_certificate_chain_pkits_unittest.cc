// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_certificate_chain.h"

#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store.h"
#include "net/der/input.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

// Disable tests that require DSA signatures (DSA signatures are intentionally
// unsupported). Custom versions of the DSA tests are defined below which expect
// verification to fail.
#define Section1ValidDSASignaturesTest4 DISABLED_Section1ValidDSASignaturesTest4
#define Section1ValidDSAParameterInheritanceTest5 \
  DISABLED_Section1ValidDSAParameterInheritanceTest5

// Disable tests that require name constraints with name types that are
// intentionally unsupported. Custom versions of the tests are defined below
// which expect verification to fail.
#define Section13ValidRFC822nameConstraintsTest21 \
  DISABLED_Section13ValidRFC822nameConstraintsTest21
#define Section13ValidRFC822nameConstraintsTest23 \
  DISABLED_Section13ValidRFC822nameConstraintsTest23
#define Section13ValidRFC822nameConstraintsTest25 \
  DISABLED_Section13ValidRFC822nameConstraintsTest25
#define Section13ValidDNandRFC822nameConstraintsTest27 \
  DISABLED_Section13ValidDNandRFC822nameConstraintsTest27
#define Section13ValidURInameConstraintsTest34 \
  DISABLED_Section13ValidURInameConstraintsTest34
#define Section13ValidURInameConstraintsTest36 \
  DISABLED_Section13ValidURInameConstraintsTest36

// TODO(mattm): these require CRL support:
#define Section7InvalidkeyUsageCriticalcRLSignFalseTest4 \
  DISABLED_Section7InvalidkeyUsageCriticalcRLSignFalseTest4
#define Section7InvalidkeyUsageNotCriticalcRLSignFalseTest5 \
  DISABLED_Section7InvalidkeyUsageNotCriticalcRLSignFalseTest5

#include "net/cert/internal/nist_pkits_unittest.h"

namespace net {

namespace {

class VerifyCertificateChainPkitsTestDelegate {
 public:
  static void RunTest(std::vector<std::string> cert_ders,
                      std::vector<std::string> crl_ders,
                      const PkitsTestInfo& info) {
    ASSERT_FALSE(cert_ders.empty());

    // PKITS lists chains from trust anchor to target, whereas
    // VerifyCertificateChain takes them starting with the target and ending
    // with the trust anchor.
    std::vector<scoped_refptr<net::ParsedCertificate>> input_chain;
    CertErrors parsing_errors;
    for (auto i = cert_ders.rbegin(); i != cert_ders.rend(); ++i) {
      ASSERT_TRUE(net::ParsedCertificate::CreateAndAddToVector(
          bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(
              reinterpret_cast<const uint8_t*>(i->data()), i->size(), nullptr)),
          {}, &input_chain, &parsing_errors))
          << parsing_errors.ToDebugString();
    }

    SimpleSignaturePolicy signature_policy(1024);

    std::set<der::Input> user_constrained_policy_set;

    CertPathErrors path_errors;
    VerifyCertificateChain(
        input_chain, CertificateTrust::ForTrustAnchor(), &signature_policy,
        info.time, KeyPurpose::ANY_EKU, info.initial_explicit_policy,
        info.initial_policy_set, info.initial_policy_mapping_inhibit,
        info.initial_inhibit_any_policy, &user_constrained_policy_set,
        &path_errors);
    bool did_succeed = !path_errors.ContainsHighSeverityErrors();

    EXPECT_EQ(info.user_constrained_policy_set, user_constrained_policy_set);

    //  TODO(crbug.com/634443): Test errors on failure?
    if (info.should_validate != did_succeed) {
      ASSERT_EQ(info.should_validate, did_succeed)
          << path_errors.ToDebugString(input_chain);
    }
  }
};

}  // namespace

class PkitsTest01SignatureVerificationCustom
    : public PkitsTest<VerifyCertificateChainPkitsTestDelegate> {};

// Modified version of 4.1.4 Valid DSA Signatures Test4
TEST_F(PkitsTest01SignatureVerificationCustom,
       Section1ValidDSASignaturesTest4Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate", "DSACACert",
                               "ValidDSASignaturesTest4EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "DSACACRL"};
  // DSA signatures are intentionally unsupported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

// Modified version of 4.1.5 Valid DSA Parameter Inheritance Test5
TEST_F(PkitsTest01SignatureVerificationCustom,
       Section1ValidDSAParameterInheritanceTest5Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate", "DSACACert",
                               "DSAParametersInheritedCACert",
                               "ValidDSAParameterInheritanceTest5EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "DSACACRL",
                              "DSAParametersInheritedCACRL"};
  // DSA signatures are intentionally unsupported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

class PkitsTest13SignatureVerificationCustom
    : public PkitsTest<VerifyCertificateChainPkitsTestDelegate> {};

// Modified version of 4.13.21 Valid RFC822 nameConstraints Test21
TEST_F(PkitsTest13SignatureVerificationCustom,
       Section13ValidRFC822nameConstraintsTest21Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsRFC822CA1Cert",
                               "ValidRFC822nameConstraintsTest21EE"};
  const char* const crls[] = {"TrustAnchorRootCRL",
                              "nameConstraintsRFC822CA1CRL"};
  // Name constraints on rfc822Names are not supported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

// Modified version of 4.13.23 Valid RFC822 nameConstraints Test23
TEST_F(PkitsTest13SignatureVerificationCustom,
       Section13ValidRFC822nameConstraintsTest23Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsRFC822CA2Cert",
                               "ValidRFC822nameConstraintsTest23EE"};
  const char* const crls[] = {"TrustAnchorRootCRL",
                              "nameConstraintsRFC822CA2CRL"};
  // Name constraints on rfc822Names are not supported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

// Modified version of 4.13.25 Valid RFC822 nameConstraints Test25
TEST_F(PkitsTest13SignatureVerificationCustom,
       Section13ValidRFC822nameConstraintsTest25Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsRFC822CA3Cert",
                               "ValidRFC822nameConstraintsTest25EE"};
  const char* const crls[] = {"TrustAnchorRootCRL",
                              "nameConstraintsRFC822CA3CRL"};
  // Name constraints on rfc822Names are not supported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

// Modified version of 4.13.27 Valid DN and RFC822 nameConstraints Test27
TEST_F(PkitsTest13SignatureVerificationCustom,
       Section13ValidDNandRFC822nameConstraintsTest27Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsDN1CACert",
                               "nameConstraintsDN1subCA3Cert",
                               "ValidDNandRFC822nameConstraintsTest27EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "nameConstraintsDN1CACRL",
                              "nameConstraintsDN1subCA3CRL"};
  // Name constraints on rfc822Names are not supported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

// Modified version of 4.13.34 Valid URI nameConstraints Test34
TEST_F(PkitsTest13SignatureVerificationCustom,
       Section13ValidURInameConstraintsTest34Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsURI1CACert",
                               "ValidURInameConstraintsTest34EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "nameConstraintsURI1CACRL"};
  // Name constraints on uniformResourceIdentifiers are not supported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

// Modified version of 4.13.36 Valid URI nameConstraints Test36
TEST_F(PkitsTest13SignatureVerificationCustom,
       Section13ValidURInameConstraintsTest36Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsURI2CACert",
                               "ValidURInameConstraintsTest36EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "nameConstraintsURI2CACRL"};
  // Name constraints on uniformResourceIdentifiers are not supported.
  PkitsTestInfo info;
  info.should_validate = false;

  this->RunTest(certs, crls, info);
}

INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest01SignatureVerification,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest02ValidityPeriods,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest03VerifyingNameChaining,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest06VerifyingBasicConstraints,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest07KeyUsage,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest08CertificatePolicies,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest09RequireExplicitPolicy,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest10PolicyMappings,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest11InhibitPolicyMapping,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest12InhibitAnyPolicy,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest13NameConstraints,
                              VerifyCertificateChainPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              PkitsTest16PrivateCertificateExtensions,
                              VerifyCertificateChainPkitsTestDelegate);

// TODO(mattm): CRL support: PkitsTest04BasicCertificateRevocationTests,
// PkitsTest05VerifyingPathswithSelfIssuedCertificates,
// PkitsTest14DistributionPoints, PkitsTest15DeltaCRLs

}  // namespace net
