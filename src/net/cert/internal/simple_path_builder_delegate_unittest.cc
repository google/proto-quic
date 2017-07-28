// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "net/cert/internal/simple_path_builder_delegate.h"

#include <memory>
#include <set>

#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/internal/verify_signed_data.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/nid.h"

namespace net {

namespace {

// Reads the public key and algorithm from the test data at |file_name|.
void ReadTestCase(const char* file_name,
                  std::unique_ptr<SignatureAlgorithm>* signature_algorithm,
                  bssl::UniquePtr<EVP_PKEY>* public_key) {
  std::string path =
      std::string("net/data/verify_signed_data_unittest/") + file_name;

  std::string public_key_str;
  std::string algorithm_str;

  const PemBlockMapping mappings[] = {
      {"PUBLIC KEY", &public_key_str}, {"ALGORITHM", &algorithm_str},
  };

  ASSERT_TRUE(ReadTestDataFromPemFile(path, mappings));

  CertErrors algorithm_errors;
  *signature_algorithm =
      SignatureAlgorithm::Create(der::Input(&algorithm_str), &algorithm_errors);
  ASSERT_TRUE(*signature_algorithm) << algorithm_errors.ToDebugString();

  ASSERT_TRUE(ParsePublicKey(der::Input(&public_key_str), public_key));
}

class SimplePathBuilderDelegate1024SuccessTest
    : public ::testing::TestWithParam<const char*> {};

const char* kSuccess1024Filenames[] = {
    "rsa-pkcs1-sha1.pem",
    "rsa-pkcs1-sha256.pem",
    "rsa2048-pkcs1-sha512.pem",
    "ecdsa-secp384r1-sha256.pem",
    "ecdsa-prime256v1-sha512.pem",
    "rsa-pss-sha1-salt20.pem",
    "rsa-pss-sha256-mgf1-sha512-salt33.pem",
    "rsa-pss-sha256-salt10.pem",
    "ecdsa-secp384r1-sha256.pem",
    "ecdsa-prime256v1-sha512.pem",
};

INSTANTIATE_TEST_CASE_P(,
                        SimplePathBuilderDelegate1024SuccessTest,
                        ::testing::ValuesIn(kSuccess1024Filenames));

TEST_P(SimplePathBuilderDelegate1024SuccessTest, IsAcceptableSignatureAndKey) {
  std::unique_ptr<SignatureAlgorithm> signature_algorithm;
  bssl::UniquePtr<EVP_PKEY> public_key;
  ReadTestCase(GetParam(), &signature_algorithm, &public_key);
  ASSERT_TRUE(signature_algorithm);
  ASSERT_TRUE(public_key);

  CertErrors errors;
  SimplePathBuilderDelegate delegate(1024);

  EXPECT_TRUE(
      delegate.IsSignatureAlgorithmAcceptable(*signature_algorithm, &errors));

  EXPECT_TRUE(delegate.IsPublicKeyAcceptable(public_key.get(), &errors));
}

class SimplePathBuilderDelegate2048FailTest
    : public ::testing::TestWithParam<const char*> {};

const char* kFail2048Filenames[] = {"rsa-pkcs1-sha1.pem",
                                    "rsa-pkcs1-sha256.pem"};

INSTANTIATE_TEST_CASE_P(,
                        SimplePathBuilderDelegate2048FailTest,
                        ::testing::ValuesIn(kFail2048Filenames));

TEST_P(SimplePathBuilderDelegate2048FailTest, RsaKeySmallerThan2048) {
  std::unique_ptr<SignatureAlgorithm> signature_algorithm;
  bssl::UniquePtr<EVP_PKEY> public_key;
  ReadTestCase(GetParam(), &signature_algorithm, &public_key);
  ASSERT_TRUE(signature_algorithm);
  ASSERT_TRUE(public_key);

  CertErrors errors;
  SimplePathBuilderDelegate delegate(2048);

  EXPECT_TRUE(
      delegate.IsSignatureAlgorithmAcceptable(*signature_algorithm, &errors));

  EXPECT_FALSE(delegate.IsPublicKeyAcceptable(public_key.get(), &errors));
}

}  // namespace

}  // namespace net
