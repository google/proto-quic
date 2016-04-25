// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_certificate_chain.h"

#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/pem_tokenizer.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Reads a data file from the unit-test data.
std::string ReadTestFileToString(const std::string& file_name) {
  // Compute the full path, relative to the src/ directory.
  base::FilePath src_root;
  PathService::Get(base::DIR_SOURCE_ROOT, &src_root);
  base::FilePath filepath = src_root.AppendASCII(
      std::string("net/data/verify_certificate_chain_unittest/") + file_name);

  // Read the full contents of the file.
  std::string file_data;
  if (!base::ReadFileToString(filepath, &file_data)) {
    ADD_FAILURE() << "Couldn't read file: " << filepath.value();
    return std::string();
  }

  return file_data;
}

// Reads a test case from |file_name|. Test cases are comprised of a
// certificate chain, trust store, a timestamp to validate at, and the
// expected result of verification.
void ReadTestFromFile(const std::string& file_name,
                      std::vector<std::string>* chain,
                      TrustStore* trust_store,
                      der::GeneralizedTime* time,
                      bool* verify_result) {
  chain->clear();
  trust_store->Clear();

  std::string file_data = ReadTestFileToString(file_name);

  std::vector<std::string> pem_headers;

  const char kCertificateHeader[] = "CERTIFICATE";
  const char kTrustedCertificateHeader[] = "TRUSTED_CERTIFICATE";
  const char kTimeHeader[] = "TIME";
  const char kResultHeader[] = "VERIFY_RESULT";

  pem_headers.push_back(kCertificateHeader);
  pem_headers.push_back(kTrustedCertificateHeader);
  pem_headers.push_back(kTimeHeader);
  pem_headers.push_back(kResultHeader);

  bool has_time = false;
  bool has_result = false;

  PEMTokenizer pem_tokenizer(file_data, pem_headers);
  while (pem_tokenizer.GetNext()) {
    const std::string& block_type = pem_tokenizer.block_type();
    const std::string& block_data = pem_tokenizer.data();

    if (block_type == kCertificateHeader) {
      chain->push_back(block_data);
    } else if (block_type == kTrustedCertificateHeader) {
      ASSERT_TRUE(trust_store->AddTrustedCertificate(block_data));
    } else if (block_type == kTimeHeader) {
      ASSERT_FALSE(has_time) << "Duplicate " << kTimeHeader;
      has_time = true;
      ASSERT_TRUE(der::ParseUTCTime(der::Input(&block_data), time));
    } else if (block_type == kResultHeader) {
      ASSERT_FALSE(has_result) << "Duplicate " << kResultHeader;
      ASSERT_TRUE(block_data == "SUCCESS" || block_data == "FAIL")
          << "Unrecognized result: " << block_data;
      has_result = true;
      *verify_result = block_data == "SUCCESS";
    }
  }

  ASSERT_TRUE(has_time);
  ASSERT_TRUE(has_result);
}

void RunTest(const char* file_name) {
  std::vector<std::string> chain;
  TrustStore trust_store;
  der::GeneralizedTime time;
  bool expected_result;

  ReadTestFromFile(file_name, &chain, &trust_store, &time, &expected_result);

  std::vector<der::Input> input_chain;
  for (const auto& cert_str : chain)
    input_chain.push_back(der::Input(&cert_str));

  SimpleSignaturePolicy signature_policy(1024);

  bool result =
      VerifyCertificateChain(input_chain, trust_store, &signature_policy, time);

  ASSERT_EQ(expected_result, result);
}

TEST(VerifyCertificateChainTest, TargetAndIntermediary) {
  RunTest("target-and-intermediary.pem");
}

TEST(VerifyCertificateChainTest, UnknownRoot) {
  RunTest("unknown-root.pem");
}

TEST(VerifyCertificateChainTest, IntermediaryLacksBasicConstraints) {
  RunTest("intermediary-lacks-basic-constraints.pem");
}

TEST(VerifyCertificateChainTest, IntermediaryBasicConstraintsCaFalse) {
  RunTest("intermediary-basic-constraints-ca-false.pem");
}

TEST(VerifyCertificateChainTest, IntermediaryBasicConstraintsNotCritical) {
  RunTest("intermediary-basic-constraints-not-critical.pem");
}

TEST(VerifyCertificateChainTest, IntermediaryLacksSigningKeyUsage) {
  RunTest("intermediary-lacks-signing-key-usage.pem");
}

TEST(VerifyCertificateChainTest, IntermediaryUnknownCriticalExtension) {
  RunTest("intermediary-unknown-critical-extension.pem");
}

TEST(VerifyCertificateChainTest, IntermediaryUnknownNonCriticalExtension) {
  RunTest("intermediary-unknown-non-critical-extension.pem");
}

TEST(VerifyCertificateChainTest, ViolatesBasicConstraintsPathlen0) {
  RunTest("violates-basic-constraints-pathlen-0.pem");
}

TEST(VerifyCertificateChainTest, BasicConstraintsPathlen0SelfIssued) {
  RunTest("basic-constraints-pathlen-0-self-issued.pem");
}

TEST(VerifyCertificateChainTest, TargetSignedWithMd5) {
  RunTest("target-signed-with-md5.pem");
}

TEST(VerifyCertificateChainTest, IntermediarySignedWithMd5) {
  RunTest("intermediary-signed-with-md5.pem");
}

TEST(VerifyCertificateChainTest, TargetWrongSignature) {
  RunTest("target-wrong-signature.pem");
}

TEST(VerifyCertificateChainTest, TargetSignedBy512bitRsa) {
  RunTest("target-signed-by-512bit-rsa.pem");
}

TEST(VerifyCertificateChainTest, TargetSignedUsingEcdsa) {
  RunTest("target-signed-using-ecdsa.pem");
}

TEST(VerifyCertificateChainTest, ExpiredIntermediary) {
  RunTest("expired-intermediary.pem");
}

TEST(VerifyCertificateChainTest, ExpiredTarget) {
  RunTest("expired-target.pem");
}

TEST(VerifyCertificateChainTest, ExpiredTargetNotBefore) {
  RunTest("expired-target-notBefore.pem");
}

TEST(VerifyCertificateChainTest, ExpiredRoot) {
  RunTest("expired-root.pem");
}

TEST(VerifyCertificateChainTest, TargetNotEndEntity) {
  RunTest("target-not-end-entity.pem");
}

TEST(VerifyCertificateChainTest, TargetHasKeyCertSignButNotCa) {
  RunTest("target-has-keycertsign-but-not-ca.pem");
}

TEST(VerifyCertificateChainTest, TargetHasPathlenButNotCa) {
  RunTest("target-has-pathlen-but-not-ca.pem");
}

TEST(VerifyCertificateChainTest, TargetUnknownCriticalExtension) {
  RunTest("target-unknown-critical-extension.pem");
}

TEST(VerifyCertificateChainTest, IssuerAndSubjectNotByteForByteEqual) {
  RunTest("issuer-and-subject-not-byte-for-byte-equal.pem");
}

TEST(VerifyCertificateChainTest, IssuerAndSubjectNotByteForByteEqualAnchor) {
  RunTest("issuer-and-subject-not-byte-for-byte-equal-anchor.pem");
}

TEST(VerifyCertificateChainTest, ViolatesPathlen1Root) {
  RunTest("violates-pathlen-1-root.pem");
}

TEST(VerifyCertificateChainTest, NonSelfSignedRoot) {
  RunTest("non-self-signed-root.pem");
}

// Tests that verifying a chain with no certificates fails.
TEST(VerifyCertificateChainTest, EmptyChainIsInvalid) {
  TrustStore trust_store;
  der::GeneralizedTime time;
  std::vector<der::Input> chain;
  SimpleSignaturePolicy signature_policy(2048);

  ASSERT_FALSE(
      VerifyCertificateChain(chain, trust_store, &signature_policy, time));
}

// TODO(eroman): Add test that invalidate validity dates where the day or month
// ordinal not in range, like "March 39, 2016" are rejected.

}  // namespace

}  // namespace net
