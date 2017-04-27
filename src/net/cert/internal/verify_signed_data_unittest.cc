// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_signed_data.h"

#include <memory>
#include <set>

#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/test_helpers.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/nid.h"

namespace net {

namespace {

enum VerifyResult {
  SUCCESS,
  FAILURE,
};

// Reads test data from |file_name| and runs VerifySignedData() over its
// inputs, using |policy|.
//
// If expected_result was SUCCESS then the test will only succeed if
// VerifySignedData() returns true.
//
// If expected_result was FAILURE then the test will only succeed if
// VerifySignedData() returns false.
void RunTestCaseUsingPolicy(VerifyResult expected_result,
                            const char* file_name,
                            const SignaturePolicy* policy) {
  std::string path =
      std::string("net/data/verify_signed_data_unittest/") + file_name;

  std::string public_key;
  std::string algorithm;
  std::string signed_data;
  std::string signature_value;

  const PemBlockMapping mappings[] = {
      {"PUBLIC KEY", &public_key},
      {"ALGORITHM", &algorithm},
      {"DATA", &signed_data},
      {"SIGNATURE", &signature_value},
  };

  ASSERT_TRUE(ReadTestDataFromPemFile(path, mappings));

  CertErrors algorithm_errors;
  std::unique_ptr<SignatureAlgorithm> signature_algorithm =
      SignatureAlgorithm::Create(der::Input(&algorithm), &algorithm_errors);
  ASSERT_TRUE(signature_algorithm) << algorithm_errors.ToDebugString();

  der::BitString signature_value_bit_string;
  der::Parser signature_value_parser((der::Input(&signature_value)));
  ASSERT_TRUE(signature_value_parser.ReadBitString(&signature_value_bit_string))
      << "The signature value is not a valid BIT STRING";

  bool expected_result_bool = expected_result == SUCCESS;

  CertErrors verify_errors;
  bool result =
      VerifySignedData(*signature_algorithm, der::Input(&signed_data),
                       signature_value_bit_string, der::Input(&public_key),
                       policy, &verify_errors);
  EXPECT_EQ(expected_result_bool, result);
  // TODO(crbug.com/634443): Verify the returned errors.
  // if (!result)
  //   EXPECT_FALSE(verify_errors.empty());
}

// RunTestCase() is the same as RunTestCaseUsingPolicy(), only it uses a
// default policy. This policy will accept a basic profile of signature
// algorithms (including ANY sized RSA key >= 1024).
void RunTestCase(VerifyResult expected_result, const char* file_name) {
  SimpleSignaturePolicy policy(1024);
  return RunTestCaseUsingPolicy(expected_result, file_name, &policy);
}

// Read the descriptions in the test files themselves for details on what is
// being tested.

TEST(VerifySignedDataTest, RsaPkcs1Sha1) {
  RunTestCase(SUCCESS, "rsa-pkcs1-sha1.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha256) {
  RunTestCase(SUCCESS, "rsa-pkcs1-sha256.pem");
}

TEST(VerifySignedDataTest, Rsa2048Pkcs1Sha512) {
  RunTestCase(SUCCESS, "rsa2048-pkcs1-sha512.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha256KeyEncodedBer) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha256-key-encoded-ber.pem");
}

TEST(VerifySignedDataTest, EcdsaSecp384r1Sha256) {
  RunTestCase(SUCCESS, "ecdsa-secp384r1-sha256.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512) {
  RunTestCase(SUCCESS, "ecdsa-prime256v1-sha512.pem");
}

TEST(VerifySignedDataTest, RsaPssSha1) {
  RunTestCase(SUCCESS, "rsa-pss-sha1-salt20.pem");
}

TEST(VerifySignedDataTest, RsaPssSha256Mgf1Sha512Salt33) {
  RunTestCase(SUCCESS, "rsa-pss-sha256-mgf1-sha512-salt33.pem");
}

TEST(VerifySignedDataTest, RsaPssSha256) {
  RunTestCase(SUCCESS, "rsa-pss-sha256-salt10.pem");
}

TEST(VerifySignedDataTest, RsaPssSha1WrongSalt) {
  RunTestCase(FAILURE, "rsa-pss-sha1-wrong-salt.pem");
}

TEST(VerifySignedDataTest, EcdsaSecp384r1Sha256CorruptedData) {
  RunTestCase(FAILURE, "ecdsa-secp384r1-sha256-corrupted-data.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha1WrongAlgorithm) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha1-wrong-algorithm.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512WrongSignatureFormat) {
  RunTestCase(FAILURE, "ecdsa-prime256v1-sha512-wrong-signature-format.pem");
}

TEST(VerifySignedDataTest, EcdsaUsingRsaKey) {
  RunTestCase(FAILURE, "ecdsa-using-rsa-key.pem");
}

TEST(VerifySignedDataTest, RsaUsingEcKey) {
  RunTestCase(FAILURE, "rsa-using-ec-key.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha1BadKeyDerNull) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha1-bad-key-der-null.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha1BadKeyDerLength) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha1-bad-key-der-length.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha256UsingEcdsaAlgorithm) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha256-using-ecdsa-algorithm.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512UsingRsaAlgorithm) {
  RunTestCase(FAILURE, "ecdsa-prime256v1-sha512-using-rsa-algorithm.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512UsingEcdhKey) {
  RunTestCase(FAILURE, "ecdsa-prime256v1-sha512-using-ecdh-key.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512UsingEcmqvKey) {
  RunTestCase(FAILURE, "ecdsa-prime256v1-sha512-using-ecmqv-key.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha1KeyParamsAbsent) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha1-key-params-absent.pem");
}

TEST(VerifySignedDataTest, RsaPssSha1Salt20UsingPssKeyNoParams) {
  // TODO(eroman): This should pass! (rsaPss not currently supported in key
  // algorithm). See https://crbug.com/522232
  RunTestCase(FAILURE, "rsa-pss-sha1-salt20-using-pss-key-no-params.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha1UsingPssKeyNoParams) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha1-using-pss-key-no-params.pem");
}

TEST(VerifySignedDataTest, RsaPssSha256Salt10UsingPssKeyWithParams) {
  // TODO(eroman): This should pass! (rsaPss not currently supported in key
  // algorithm). See https://crbug.com/522232
  RunTestCase(FAILURE, "rsa-pss-sha256-salt10-using-pss-key-with-params.pem");
}

TEST(VerifySignedDataTest, RsaPssSha256Salt10UsingPssKeyWithWrongParams) {
  RunTestCase(FAILURE,
              "rsa-pss-sha256-salt10-using-pss-key-with-wrong-params.pem");
}

TEST(VerifySignedDataTest, RsaPssSha256Salt12UsingPssKeyWithNullParams) {
  RunTestCase(FAILURE,
              "rsa-pss-sha1-salt20-using-pss-key-with-null-params.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512SpkiParamsNull) {
  RunTestCase(FAILURE, "ecdsa-prime256v1-sha512-spki-params-null.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha256UsingIdEaRsa) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha256-using-id-ea-rsa.pem");
}

TEST(VerifySignedDataTest, RsaPkcs1Sha256SpkiNonNullParams) {
  RunTestCase(FAILURE, "rsa-pkcs1-sha256-spki-non-null-params.pem");
}

TEST(VerifySignedDataTest, EcdsaPrime256v1Sha512UnusedBitsSignature) {
  RunTestCase(FAILURE, "ecdsa-prime256v1-sha512-unused-bits-signature.pem");
}

// This policy rejects specifically secp384r1 curves.
class RejectSecp384r1Policy : public SignaturePolicy {
 public:
  bool IsAcceptableCurveForEcdsa(int curve_nid,
                                 CertErrors* errors) const override {
    if (curve_nid == NID_secp384r1)
      return false;
    return true;
  }
};

TEST(VerifySignedDataTest, PolicyIsAcceptableCurveForEcdsa) {
  // Using the regular policy both secp384r1 and secp256r1 should be accepted.
  RunTestCase(SUCCESS, "ecdsa-secp384r1-sha256.pem");
  RunTestCase(SUCCESS, "ecdsa-prime256v1-sha512.pem");

  // However when using a policy that specifically rejects secp384r1, only
  // prime256v1 should be accepted.
  RejectSecp384r1Policy policy;
  RunTestCaseUsingPolicy(FAILURE, "ecdsa-secp384r1-sha256.pem", &policy);
  RunTestCaseUsingPolicy(SUCCESS, "ecdsa-prime256v1-sha512.pem", &policy);
}

TEST(VerifySignedDataTest, PolicyIsAcceptableModulusLengthForRsa) {
  // Using the regular policy both 1024-bit and 2048-bit RSA keys should be
  // accepted.
  SimpleSignaturePolicy policy_1024(1024);
  RunTestCaseUsingPolicy(SUCCESS, "rsa-pkcs1-sha256.pem", &policy_1024);
  RunTestCaseUsingPolicy(SUCCESS, "rsa2048-pkcs1-sha512.pem", &policy_1024);

  // However when using a policy that rejects any keys less than 2048-bits, only
  // one of the tests will pass.
  SimpleSignaturePolicy policy_2048(2048);
  RunTestCaseUsingPolicy(FAILURE, "rsa-pkcs1-sha256.pem", &policy_2048);
  RunTestCaseUsingPolicy(SUCCESS, "rsa2048-pkcs1-sha512.pem", &policy_2048);
}

// This policy rejects the use of SHA-512.
class RejectSha512 : public SignaturePolicy {
 public:
  RejectSha512() : SignaturePolicy() {}

  bool IsAcceptableSignatureAlgorithm(const SignatureAlgorithm& algorithm,
                                      CertErrors* errors) const override {
    if (algorithm.algorithm() == SignatureAlgorithmId::RsaPss &&
        algorithm.ParamsForRsaPss()->mgf1_hash() == DigestAlgorithm::Sha512) {
      return false;
    }

    return algorithm.digest() != DigestAlgorithm::Sha512;
  }

  bool IsAcceptableModulusLengthForRsa(size_t modulus_length_bits,
                                       CertErrors* errors) const override {
    return true;
  }
};

TEST(VerifySignedDataTest, PolicyIsAcceptableDigestAlgorithm) {
  // Using the regular policy use of either SHA256 or SHA512 should work
  // (whether as the main digest, or the MGF1 for RSASSA-PSS)
  RunTestCase(SUCCESS, "rsa2048-pkcs1-sha512.pem");
  RunTestCase(SUCCESS, "ecdsa-prime256v1-sha512.pem");
  RunTestCase(SUCCESS, "ecdsa-secp384r1-sha256.pem");
  RunTestCase(SUCCESS, "rsa-pkcs1-sha256.pem");
  RunTestCase(SUCCESS, "rsa-pss-sha256-salt10.pem");
  // This one uses both SHA256 and SHA512
  RunTestCase(SUCCESS, "rsa-pss-sha256-mgf1-sha512-salt33.pem");

  // The tests using SHA512 should fail when using a policy that rejects SHA512.
  // Everything else should pass.
  RejectSha512 policy;
  RunTestCaseUsingPolicy(FAILURE, "rsa2048-pkcs1-sha512.pem", &policy);
  RunTestCaseUsingPolicy(FAILURE, "ecdsa-prime256v1-sha512.pem", &policy);
  RunTestCaseUsingPolicy(SUCCESS, "ecdsa-secp384r1-sha256.pem", &policy);
  RunTestCaseUsingPolicy(SUCCESS, "rsa-pkcs1-sha256.pem", &policy);
  RunTestCaseUsingPolicy(SUCCESS, "rsa-pss-sha256-salt10.pem", &policy);
  RunTestCaseUsingPolicy(FAILURE, "rsa-pss-sha256-mgf1-sha512-salt33.pem",
                         &policy);
}

}  // namespace

}  // namespace net
