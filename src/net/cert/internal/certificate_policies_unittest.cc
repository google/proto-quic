// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/certificate_policies.h"

#include "net/cert/internal/test_helpers.h"
#include "net/der/input.h"
#include "net/der/parser.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

::testing::AssertionResult LoadTestData(const std::string& name,
                                        std::string* result) {
  std::string path = "net/data/certificate_policies_unittest/" + name;

  const PemBlockMapping mappings[] = {
      {"CERTIFICATE POLICIES", result},
  };

  return ReadTestDataFromPemFile(path, mappings);
}

const uint8_t policy_1_2_3_der[] = {0x2A, 0x03};
const uint8_t policy_1_2_4_der[] = {0x2A, 0x04};

}  // namespace

TEST(ParseCertificatePoliciesTest, InvalidEmpty) {
  std::string der;
  ASSERT_TRUE(LoadTestData("invalid-empty.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest, InvalidIdentifierNotOid) {
  std::string der;
  ASSERT_TRUE(LoadTestData("invalid-policy_identifier_not_oid.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest, AnyPolicy) {
  std::string der;
  ASSERT_TRUE(LoadTestData("anypolicy.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(1U, policies.size());
  EXPECT_EQ(AnyPolicy(), policies[0]);
}

TEST(ParseCertificatePoliciesTest, AnyPolicyWithQualifier) {
  std::string der;
  ASSERT_TRUE(LoadTestData("anypolicy_with_qualifier.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(1U, policies.size());
  EXPECT_EQ(AnyPolicy(), policies[0]);
}

TEST(ParseCertificatePoliciesTest, InvalidAnyPolicyWithCustomQualifier) {
  std::string der;
  ASSERT_TRUE(
      LoadTestData("invalid-anypolicy_with_custom_qualifier.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest, OnePolicy) {
  std::string der;
  ASSERT_TRUE(LoadTestData("policy_1_2_3.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(1U, policies.size());
  EXPECT_EQ(der::Input(policy_1_2_3_der), policies[0]);
}

TEST(ParseCertificatePoliciesTest, OnePolicyWithQualifier) {
  std::string der;
  ASSERT_TRUE(LoadTestData("policy_1_2_3_with_qualifier.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(1U, policies.size());
  EXPECT_EQ(der::Input(policy_1_2_3_der), policies[0]);
}

TEST(ParseCertificatePoliciesTest, OnePolicyWithCustomQualifier) {
  std::string der;
  ASSERT_TRUE(LoadTestData("policy_1_2_3_with_custom_qualifier.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(1U, policies.size());
  EXPECT_EQ(der::Input(policy_1_2_3_der), policies[0]);
}

TEST(ParseCertificatePoliciesTest, InvalidPolicyWithDuplicatePolicyOid) {
  std::string der;
  ASSERT_TRUE(LoadTestData("invalid-policy_1_2_3_dupe.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest, InvalidPolicyWithEmptyQualifiersSequence) {
  std::string der;
  ASSERT_TRUE(LoadTestData(
      "invalid-policy_1_2_3_with_empty_qualifiers_sequence.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest, InvalidPolicyInformationHasUnconsumedData) {
  std::string der;
  ASSERT_TRUE(LoadTestData(
      "invalid-policy_1_2_3_policyinformation_unconsumed_data.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest,
     InvalidPolicyQualifierInfoHasUnconsumedData) {
  std::string der;
  ASSERT_TRUE(LoadTestData(
      "invalid-policy_1_2_3_policyqualifierinfo_unconsumed_data.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_FALSE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
}

TEST(ParseCertificatePoliciesTest, TwoPolicies) {
  std::string der;
  ASSERT_TRUE(LoadTestData("policy_1_2_3_and_1_2_4.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(2U, policies.size());
  EXPECT_EQ(der::Input(policy_1_2_3_der), policies[0]);
  EXPECT_EQ(der::Input(policy_1_2_4_der), policies[1]);
}

TEST(ParseCertificatePoliciesTest, TwoPoliciesWithQualifiers) {
  std::string der;
  ASSERT_TRUE(LoadTestData("policy_1_2_3_and_1_2_4_with_qualifiers.pem", &der));
  std::vector<der::Input> policies;
  EXPECT_TRUE(ParseCertificatePoliciesExtension(der::Input(&der), &policies));
  ASSERT_EQ(2U, policies.size());
  EXPECT_EQ(der::Input(policy_1_2_3_der), policies[0]);
  EXPECT_EQ(der::Input(policy_1_2_4_der), policies[1]);
}

}  // namespace net
