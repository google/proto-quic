// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_TYPED_UNITTEST_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_TYPED_UNITTEST_H_

#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_certificate_chain.h"
#include "net/cert/pem_tokenizer.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

template <typename TestDelegate>
class VerifyCertificateChainTest : public ::testing::Test {
 public:
  void RunTest(const char* file_name) {
    VerifyCertChainTest test;

    std::string path =
        std::string("net/data/verify_certificate_chain_unittest/") + file_name;

    SCOPED_TRACE("Test file: " + path);

    ReadVerifyCertChainTestFromFile(path, &test);

    TestDelegate::Verify(test, path);
  }
};

// Tests that have only one root. These can be tested without requiring any
// path-building ability.
template <typename TestDelegate>
class VerifyCertificateChainSingleRootTest
    : public VerifyCertificateChainTest<TestDelegate> {};

TYPED_TEST_CASE_P(VerifyCertificateChainSingleRootTest);

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, Simple) {
  this->RunTest("target-and-intermediate.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, BasicConstraintsCa) {
  this->RunTest("intermediate-lacks-basic-constraints.pem");
  this->RunTest("intermediate-basic-constraints-ca-false.pem");
  this->RunTest("intermediate-basic-constraints-not-critical.pem");
  this->RunTest("unconstrained-root-lacks-basic-constraints.pem");
  this->RunTest("constrained-root-lacks-basic-constraints.pem");
  this->RunTest("unconstrained-root-basic-constraints-ca-false.pem");
  this->RunTest("constrained-root-basic-constraints-ca-false.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, BasicConstraintsPathlen) {
  this->RunTest("violates-basic-constraints-pathlen-0.pem");
  this->RunTest("basic-constraints-pathlen-0-self-issued.pem");
  this->RunTest("target-has-pathlen-but-not-ca.pem");
  this->RunTest("violates-pathlen-1-constrained-root.pem");
  this->RunTest("violates-pathlen-1-unconstrained-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, UnknownExtension) {
  this->RunTest("intermediate-unknown-critical-extension.pem");
  this->RunTest("intermediate-unknown-non-critical-extension.pem");
  this->RunTest("target-unknown-critical-extension.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, Md5) {
  this->RunTest("target-signed-with-md5.pem");
  this->RunTest("intermediate-signed-with-md5.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, WrongSignature) {
  this->RunTest("target-wrong-signature.pem");
  this->RunTest("incorrect-trust-anchor.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedBy512bitRsa) {
  this->RunTest("target-signed-by-512bit-rsa.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedUsingEcdsa) {
  this->RunTest("target-signed-using-ecdsa.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, Expired) {
  this->RunTest("expired-target.pem");
  this->RunTest("expired-intermediate.pem");
  this->RunTest("expired-target-notBefore.pem");
  this->RunTest("expired-unconstrained-root.pem");
  this->RunTest("expired-constrained-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetNotEndEntity) {
  this->RunTest("target-not-end-entity.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyUsage) {
  this->RunTest("intermediate-lacks-signing-key-usage.pem");
  this->RunTest("target-has-keycertsign-but-not-ca.pem");

  this->RunTest("serverauth-ec-ku-decipheronly.pem");
  this->RunTest("serverauth-ec-ku-digitalsignature.pem");
  this->RunTest("serverauth-ec-ku-keyagreement.pem");
  this->RunTest("serverauth-ec-ku-keyencipherment.pem");

  this->RunTest("serverauth-rsa-ku-decipheronly.pem");
  this->RunTest("serverauth-rsa-ku-digitalsignature.pem");
  this->RunTest("serverauth-rsa-ku-keyagreement.pem");
  this->RunTest("serverauth-rsa-ku-keyencipherment.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExtendedKeyUsage) {
  this->RunTest("target-lacks-eku.pem");
  this->RunTest("target-restricts-eku-fail.pem");
  this->RunTest("intermediate-restricts-eku-fail.pem");
  this->RunTest("intermediate-restricts-eku-ok.pem");
  this->RunTest("intermediate-sets-eku-any.pem");
  this->RunTest("target-sets-eku-any.pem");
  this->RunTest("constrained-root-bad-eku.pem");
  this->RunTest("unconstrained-root-bad-eku.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IssuerAndSubjectNotByteForByteEqual) {
  this->RunTest("issuer-and-subject-not-byte-for-byte-equal.pem");
  this->RunTest("issuer-and-subject-not-byte-for-byte-equal-anchor.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TrustAnchorNotSelfSigned) {
  this->RunTest("non-self-signed-root.pem");
  this->RunTest("unconstrained-non-self-signed-root.pem");
  this->RunTest("constrained-non-self-signed-root.pem");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyRollover) {
  this->RunTest("key-rollover-oldchain.pem");
  this->RunTest("key-rollover-rolloverchain.pem");
  this->RunTest("key-rollover-longrolloverchain.pem");
  this->RunTest("key-rollover-newchain.pem");
}

// TODO(eroman): Add test that invalid validity dates where the day or month
// ordinal not in range, like "March 39, 2016" are rejected.

REGISTER_TYPED_TEST_CASE_P(VerifyCertificateChainSingleRootTest,
                           Simple,
                           BasicConstraintsCa,
                           BasicConstraintsPathlen,
                           UnknownExtension,
                           Md5,
                           WrongSignature,
                           TargetSignedBy512bitRsa,
                           TargetSignedUsingEcdsa,
                           Expired,
                           TargetNotEndEntity,
                           KeyUsage,
                           ExtendedKeyUsage,
                           IssuerAndSubjectNotByteForByteEqual,
                           TrustAnchorNotSelfSigned,
                           KeyRollover);

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_TYPED_UNITTEST_H_
