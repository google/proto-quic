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

    if (!ReadVerifyCertChainTestFromFile(path, &test)) {
      ADD_FAILURE() << "Couldn't load test case: " << path;
      return;
    }

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
  this->RunTest("target-and-intermediate/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, BasicConstraintsCa) {
  this->RunTest("intermediate-lacks-basic-constraints/main.test");
  this->RunTest("intermediate-basic-constraints-ca-false/main.test");
  this->RunTest("intermediate-basic-constraints-not-critical/main.test");
  this->RunTest("root-lacks-basic-constraints/main.test");
  this->RunTest("root-lacks-basic-constraints/ta-with-constraints.test");
  this->RunTest("root-basic-constraints-ca-false/main.test");
  this->RunTest("root-basic-constraints-ca-false/ta-with-constraints.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, BasicConstraintsPathlen) {
  this->RunTest("violates-basic-constraints-pathlen-0/main.test");
  this->RunTest("basic-constraints-pathlen-0-self-issued/main.test");
  this->RunTest("target-has-pathlen-but-not-ca/main.test");
  this->RunTest("violates-pathlen-1-from-root/main.test");
  this->RunTest("violates-pathlen-1-from-root/ta-with-constraints.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, UnknownExtension) {
  this->RunTest("intermediate-unknown-critical-extension/main.test");
  this->RunTest("intermediate-unknown-non-critical-extension/main.test");
  this->RunTest("target-unknown-critical-extension/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, Md5) {
  this->RunTest("target-signed-with-md5/main.test");
  this->RunTest("intermediate-signed-with-md5/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, WrongSignature) {
  this->RunTest("target-wrong-signature/main.test");
  this->RunTest("incorrect-trust-anchor/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, LastCertificateNotTrusted) {
  this->RunTest("target-and-intermediate/distrusted-root.test");
  this->RunTest("target-and-intermediate/unspecified-trust-root.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedBy512bitRsa) {
  this->RunTest("target-signed-by-512bit-rsa/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetSignedUsingEcdsa) {
  this->RunTest("target-signed-using-ecdsa/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, Expired) {
  this->RunTest("expired-target/not-before.test");
  this->RunTest("expired-target/not-after.test");
  this->RunTest("expired-intermediate/not-before.test");
  this->RunTest("expired-intermediate/not-after.test");
  this->RunTest("expired-root/not-before.test");
  this->RunTest("expired-root/not-after.test");
  this->RunTest("expired-root/not-after-ta-with-constraints.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TargetNotEndEntity) {
  this->RunTest("target-not-end-entity/main.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyUsage) {
  this->RunTest("intermediate-lacks-signing-key-usage/main.test");
  this->RunTest("target-has-keycertsign-but-not-ca/main.test");

  this->RunTest("target-serverauth-various-keyusages/rsa-decipherOnly.test");
  this->RunTest(
      "target-serverauth-various-keyusages/rsa-digitalSignature.test");
  this->RunTest("target-serverauth-various-keyusages/rsa-keyAgreement.test");
  this->RunTest("target-serverauth-various-keyusages/rsa-keyEncipherment.test");

  this->RunTest("target-serverauth-various-keyusages/ec-decipherOnly.test");
  this->RunTest("target-serverauth-various-keyusages/ec-digitalSignature.test");
  this->RunTest("target-serverauth-various-keyusages/ec-keyAgreement.test");
  this->RunTest("target-serverauth-various-keyusages/ec-keyEncipherment.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, ExtendedKeyUsage) {
  this->RunTest("target-lacks-eku/main.test");
  this->RunTest("target-restricts-eku-fail/main.test");
  this->RunTest("intermediate-restricts-eku-fail/main.test");
  this->RunTest("intermediate-restricts-eku-ok/main.test");
  this->RunTest("intermediate-sets-eku-any/main.test");
  this->RunTest("target-sets-eku-any/main.test");
  this->RunTest("root-bad-eku/main.test");
  this->RunTest("root-bad-eku/ta-with-constraints.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest,
             IssuerAndSubjectNotByteForByteEqual) {
  this->RunTest("issuer-and-subject-not-byte-for-byte-equal/target.test");
  this->RunTest("issuer-and-subject-not-byte-for-byte-equal/anchor.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, TrustAnchorNotSelfSigned) {
  this->RunTest("non-self-signed-root/main.test");
  this->RunTest("non-self-signed-root/ta-with-constraints.test");
}

TYPED_TEST_P(VerifyCertificateChainSingleRootTest, KeyRollover) {
  this->RunTest("key-rollover/oldchain.test");
  this->RunTest("key-rollover/rolloverchain.test");
  this->RunTest("key-rollover/longrolloverchain.test");
  this->RunTest("key-rollover/newchain.test");
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
                           LastCertificateNotTrusted,
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
