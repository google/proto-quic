// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/path_builder.h"

#include "net/base/net_errors.h"
#include "net/cert/internal/cert_issuer_source_static.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store_in_memory.h"
#include "net/cert/internal/verify_certificate_chain.h"
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

class PathBuilderPkitsTestDelegate {
 public:
  static bool Verify(std::vector<std::string> cert_ders,
                     std::vector<std::string> crl_ders) {
    if (cert_ders.empty()) {
      ADD_FAILURE() << "cert_ders is empty";
      return false;
    }
    ParsedCertificateList certs;
    for (const std::string& der : cert_ders) {
      CertErrors errors;
      if (!ParsedCertificate::CreateAndAddToVector(
              bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(
                  reinterpret_cast<const uint8_t*>(der.data()), der.size(),
                  nullptr)),
              {}, &certs, &errors)) {
        ADD_FAILURE() << "ParseCertificate::CreateAndAddToVector() failed:\n"
                      << errors.ToDebugString();
        return false;
      }
    }
    // First entry in the PKITS chain is the trust anchor.
    // TODO(mattm): test with all possible trust anchors in the trust store?
    TrustStoreInMemory trust_store;

    scoped_refptr<TrustAnchor> trust_anchor =
        TrustAnchor::CreateFromCertificateNoConstraints(certs[0]);
    trust_store.AddTrustAnchor(std::move(trust_anchor));

    // TODO(mattm): test with other irrelevant certs in cert_issuer_sources?
    CertIssuerSourceStatic cert_issuer_source;
    for (size_t i = 1; i < cert_ders.size() - 1; ++i)
      cert_issuer_source.AddCert(certs[i]);

    scoped_refptr<ParsedCertificate> target_cert(certs.back());

    SimpleSignaturePolicy signature_policy(1024);

    // Run all tests at the time the PKITS was published.
    der::GeneralizedTime time = {2011, 4, 15, 0, 0, 0};

    CertPathBuilder::Result result;
    CertPathBuilder path_builder(std::move(target_cert), &trust_store,
                                 &signature_policy, time, &result);
    path_builder.AddCertIssuerSource(&cert_issuer_source);

    path_builder.Run();

    return result.HasValidPath();
  }
};

}  // namespace

class PkitsTest01SignatureVerificationCustomPathBuilderFoo
    : public PkitsTest<PathBuilderPkitsTestDelegate> {};

// Modified version of 4.1.4 Valid DSA Signatures Test4
TEST_F(PkitsTest01SignatureVerificationCustomPathBuilderFoo,
       Section1ValidDSASignaturesTest4Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate", "DSACACert",
                               "ValidDSASignaturesTest4EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "DSACACRL"};
  // DSA signatures are intentionally unsupported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

// Modified version of 4.1.5 Valid DSA Parameter Inheritance Test5
TEST_F(PkitsTest01SignatureVerificationCustomPathBuilderFoo,
       Section1ValidDSAParameterInheritanceTest5Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate", "DSACACert",
                               "DSAParametersInheritedCACert",
                               "ValidDSAParameterInheritanceTest5EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "DSACACRL",
                              "DSAParametersInheritedCACRL"};
  // DSA signatures are intentionally unsupported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

class PkitsTest13SignatureVerificationCustomPathBuilderFoo
    : public PkitsTest<PathBuilderPkitsTestDelegate> {};

// Modified version of 4.13.21 Valid RFC822 nameConstraints Test21
TEST_F(PkitsTest13SignatureVerificationCustomPathBuilderFoo,
       Section13ValidRFC822nameConstraintsTest21Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsRFC822CA1Cert",
                               "ValidRFC822nameConstraintsTest21EE"};
  const char* const crls[] = {"TrustAnchorRootCRL",
                              "nameConstraintsRFC822CA1CRL"};
  // Name constraints on rfc822Names are not supported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

// Modified version of 4.13.23 Valid RFC822 nameConstraints Test23
TEST_F(PkitsTest13SignatureVerificationCustomPathBuilderFoo,
       Section13ValidRFC822nameConstraintsTest23Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsRFC822CA2Cert",
                               "ValidRFC822nameConstraintsTest23EE"};
  const char* const crls[] = {"TrustAnchorRootCRL",
                              "nameConstraintsRFC822CA2CRL"};
  // Name constraints on rfc822Names are not supported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

// Modified version of 4.13.25 Valid RFC822 nameConstraints Test25
TEST_F(PkitsTest13SignatureVerificationCustomPathBuilderFoo,
       Section13ValidRFC822nameConstraintsTest25Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsRFC822CA3Cert",
                               "ValidRFC822nameConstraintsTest25EE"};
  const char* const crls[] = {"TrustAnchorRootCRL",
                              "nameConstraintsRFC822CA3CRL"};
  // Name constraints on rfc822Names are not supported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

// Modified version of 4.13.27 Valid DN and RFC822 nameConstraints Test27
TEST_F(PkitsTest13SignatureVerificationCustomPathBuilderFoo,
       Section13ValidDNandRFC822nameConstraintsTest27Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsDN1CACert",
                               "nameConstraintsDN1subCA3Cert",
                               "ValidDNandRFC822nameConstraintsTest27EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "nameConstraintsDN1CACRL",
                              "nameConstraintsDN1subCA3CRL"};
  // Name constraints on rfc822Names are not supported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

// Modified version of 4.13.34 Valid URI nameConstraints Test34
TEST_F(PkitsTest13SignatureVerificationCustomPathBuilderFoo,
       Section13ValidURInameConstraintsTest34Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsURI1CACert",
                               "ValidURInameConstraintsTest34EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "nameConstraintsURI1CACRL"};
  // Name constraints on uniformResourceIdentifiers are not supported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

// Modified version of 4.13.36 Valid URI nameConstraints Test36
TEST_F(PkitsTest13SignatureVerificationCustomPathBuilderFoo,
       Section13ValidURInameConstraintsTest36Custom) {
  const char* const certs[] = {"TrustAnchorRootCertificate",
                               "nameConstraintsURI2CACert",
                               "ValidURInameConstraintsTest36EE"};
  const char* const crls[] = {"TrustAnchorRootCRL", "nameConstraintsURI2CACRL"};
  // Name constraints on uniformResourceIdentifiers are not supported.
  ASSERT_FALSE(this->Verify(certs, crls));
}

INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest01SignatureVerification,
                              PathBuilderPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest02ValidityPeriods,
                              PathBuilderPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest03VerifyingNameChaining,
                              PathBuilderPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest06VerifyingBasicConstraints,
                              PathBuilderPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest07KeyUsage,
                              PathBuilderPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest13NameConstraints,
                              PathBuilderPkitsTestDelegate);
INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              PkitsTest16PrivateCertificateExtensions,
                              PathBuilderPkitsTestDelegate);

// TODO(mattm): CRL support: PkitsTest04BasicCertificateRevocationTests,
// PkitsTest05VerifyingPathswithSelfIssuedCertificates,
// PkitsTest14DistributionPoints, PkitsTest15DeltaCRLs

// TODO(mattm): Certificate Policies support: PkitsTest08CertificatePolicies,
// PkitsTest09RequireExplicitPolicy PkitsTest10PolicyMappings,
// PkitsTest11InhibitPolicyMapping, PkitsTest12InhibitAnyPolicy

}  // namespace net
