// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_TYPED_UNITTEST_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_TYPED_UNITTEST_H_

#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/pem_tokenizer.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

template <typename TestDelegate>
class VerifyCertificateChainTest : public ::testing::Test {
 public:
  void RunTest(const char* file_name) {
    ParsedCertificateList chain;
    scoped_refptr<TrustAnchor> trust_anchor;
    der::GeneralizedTime time;
    bool expected_result;
    std::string expected_errors;

    std::string path =
        std::string("net/data/verify_certificate_chain_unittest/") + file_name;

    ReadVerifyCertChainTestFromFile(path, &chain, &trust_anchor, &time,
                                    &expected_result, &expected_errors);

    TestDelegate::Verify(chain, trust_anchor, time, expected_result,
                         expected_errors, path);
  }
};

// Tests that have only one root. These can be tested without requiring any
// path-building ability.
template <typename TestDelegate>
class VerifyCertificateChainSingleRootTest
    : public VerifyCertificateChainTest<TestDelegate> {};

TYPED_TEST_CASE_P(VerifyCertificateChainSingleRootTest);

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetAndIntermediate) {
  this->RunTest("target-and-intermediate.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IntermediateLacksBasicConstraints) {
  this->RunTest("intermediate-lacks-basic-constraints.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IntermediateBasicConstraintsCaFalse) {
  this->RunTest("intermediate-basic-constraints-ca-false.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IntermediateBasicConstraintsNotCritical) {
  this->RunTest("intermediate-basic-constraints-not-critical.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IntermediateLacksSigningKeyUsage) {
  this->RunTest("intermediate-lacks-signing-key-usage.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IntermediateUnknownCriticalExtension) {
  this->RunTest("intermediate-unknown-critical-extension.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IntermediateUnknownNonCriticalExtension) {
  this->RunTest("intermediate-unknown-non-critical-extension.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             ViolatesBasicConstraintsPathlen0) {
  this->RunTest("violates-basic-constraints-pathlen-0.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             BasicConstraintsPathlen0SelfIssued) {
  this->RunTest("basic-constraints-pathlen-0-self-issued.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedWithMd5) {
  this->RunTest("target-signed-with-md5.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, IntermediateSignedWithMd5) {
  this->RunTest("intermediate-signed-with-md5.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetWrongSignature) {
  this->RunTest("target-wrong-signature.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedBy512bitRsa) {
  this->RunTest("target-signed-by-512bit-rsa.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedUsingEcdsa) {
  this->RunTest("target-signed-using-ecdsa.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExpiredIntermediate) {
  this->RunTest("expired-intermediate.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExpiredTarget) {
  this->RunTest("expired-target.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExpiredTargetNotBefore) {
  this->RunTest("expired-target-notBefore.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExpiredUnconstrainedRoot) {
  this->RunTest("expired-unconstrained-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExpiredConstrainedRoot) {
  this->RunTest("expired-constrained-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetNotEndEntity) {
  this->RunTest("target-not-end-entity.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             TargetHasKeyCertSignButNotCa) {
  this->RunTest("target-has-keycertsign-but-not-ca.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetHasPathlenButNotCa) {
  this->RunTest("target-has-pathlen-but-not-ca.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             TargetUnknownCriticalExtension) {
  this->RunTest("target-unknown-critical-extension.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IssuerAndSubjectNotByteForByteEqual) {
  this->RunTest("issuer-and-subject-not-byte-for-byte-equal.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IssuerAndSubjectNotByteForByteEqualAnchor) {
  this->RunTest("issuer-and-subject-not-byte-for-byte-equal-anchor.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             ViolatesPathlen1UnconstrainedRoot) {
  this->RunTest("violates-pathlen-1-unconstrained-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             ViolatesPathlen1ConstrainedRoot) {
  this->RunTest("violates-pathlen-1-constrained-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, NonSelfSignedRoot) {
  this->RunTest("non-self-signed-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyRolloverOldChain) {
  this->RunTest("key-rollover-oldchain.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyRolloverRolloverChain) {
  this->RunTest("key-rollover-rolloverchain.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             KeyRolloverLongRolloverChain) {
  this->RunTest("key-rollover-longrolloverchain.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyRolloverNewChain) {
  this->RunTest("key-rollover-newchain.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, IncorrectTrustAnchor) {
  this->RunTest("incorrect-trust-anchor.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             UnconstrainedRootLacksBasicConstraints) {
  this->RunTest("unconstrained-root-lacks-basic-constraints.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             ConstrainedRootLacksBasicConstraints) {
  this->RunTest("constrained-root-lacks-basic-constraints.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             UnconstrainedRootBasicConstraintsCaFalse) {
  this->RunTest("unconstrained-root-basic-constraints-ca-false.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             ConstrainedRootBasicConstraintsCaFalse) {
  this->RunTest("constrained-root-basic-constraints-ca-false.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             UnconstrainedNonSelfSignedRoot) {
  this->RunTest("unconstrained-non-self-signed-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             ConstrainedNonSelfSignedRoot) {
  this->RunTest("constrained-non-self-signed-root.pem");
}

// TODO(eroman): Add test that invalid validity dates where the day or month
// ordinal not in range, like "March 39, 2016" are rejected.

REGISTER_TYPED_TEST_CASE_P(VerifyCertificateChainSingleRootTest,
                           TargetAndIntermediate,
                           IntermediateLacksBasicConstraints,
                           IntermediateBasicConstraintsCaFalse,
                           IntermediateBasicConstraintsNotCritical,
                           IntermediateLacksSigningKeyUsage,
                           IntermediateUnknownCriticalExtension,
                           IntermediateUnknownNonCriticalExtension,
                           ViolatesBasicConstraintsPathlen0,
                           BasicConstraintsPathlen0SelfIssued,
                           TargetSignedWithMd5,
                           IntermediateSignedWithMd5,
                           TargetWrongSignature,
                           TargetSignedBy512bitRsa,
                           TargetSignedUsingEcdsa,
                           ExpiredIntermediate,
                           ExpiredTarget,
                           ExpiredTargetNotBefore,
                           ExpiredUnconstrainedRoot,
                           ExpiredConstrainedRoot,
                           TargetNotEndEntity,
                           TargetHasKeyCertSignButNotCa,
                           TargetHasPathlenButNotCa,
                           TargetUnknownCriticalExtension,
                           IssuerAndSubjectNotByteForByteEqual,
                           IssuerAndSubjectNotByteForByteEqualAnchor,
                           ViolatesPathlen1UnconstrainedRoot,
                           ViolatesPathlen1ConstrainedRoot,
                           NonSelfSignedRoot,
                           KeyRolloverOldChain,
                           KeyRolloverRolloverChain,
                           KeyRolloverLongRolloverChain,
                           KeyRolloverNewChain,
                           IncorrectTrustAnchor,
                           UnconstrainedRootLacksBasicConstraints,
                           ConstrainedRootLacksBasicConstraints,
                           UnconstrainedRootBasicConstraintsCaFalse,
                           ConstrainedRootBasicConstraintsCaFalse,
                           UnconstrainedNonSelfSignedRoot,
                           ConstrainedNonSelfSignedRoot);

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_TYPED_UNITTEST_H_
