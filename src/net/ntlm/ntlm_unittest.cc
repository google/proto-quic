// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tests on exact results from cryptographic operations are based on test data
// provided in [MS-NLMP] Version 28.0 [1] Section 4.2.
//
// Additional sanity checks on the low level hashing operations test for
// properties of the outputs, such as whether the hashes change, whether they
// should be zeroed out, or whether they should be the same or different.
//
// [1] https://msdn.microsoft.com/en-us/library/cc236621.aspx

#include "net/ntlm/ntlm.h"

#include <string>

#include "base/strings/string16.h"
#include "base/strings/utf_string_conversions.h"
#include "net/ntlm/ntlm_test_data.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace ntlm {

TEST(NtlmTest, GenerateNtlmHashV1PasswordSpecTests) {
  uint8_t hash[kNtlmHashLen];
  GenerateNtlmHashV1(test::kPassword, hash);
  ASSERT_EQ(0, memcmp(hash, test::kExpectedNtlmHashV1, kNtlmHashLen));
}

TEST(NtlmTest, GenerateNtlmHashV1PasswordChangesHash) {
  base::string16 password1 = base::UTF8ToUTF16("pwd01");
  base::string16 password2 = base::UTF8ToUTF16("pwd02");
  uint8_t hash1[kNtlmHashLen];
  uint8_t hash2[kNtlmHashLen];

  GenerateNtlmHashV1(password1, hash1);
  GenerateNtlmHashV1(password2, hash2);

  // Verify that the hash is different with a different password.
  ASSERT_NE(0, memcmp(hash1, hash2, kNtlmHashLen));
}

TEST(NtlmTest, GenerateResponsesV1SpecTests) {
  uint8_t lm_response[kResponseLenV1];
  uint8_t ntlm_response[kResponseLenV1];
  GenerateResponsesV1(test::kPassword, test::kServerChallenge, lm_response,
                      ntlm_response);

  ASSERT_EQ(
      0, memcmp(test::kExpectedNtlmResponseV1, ntlm_response, kResponseLenV1));

  // This implementation never sends an LMv1 response (spec equivalent of the
  // client variable NoLMResponseNTLMv1 being false) so the LM response is
  // equal to the NTLM response when
  // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is not negotiated. See
  // [MS-NLMP] Section 3.3.1.
  ASSERT_EQ(0,
            memcmp(test::kExpectedNtlmResponseV1, lm_response, kResponseLenV1));
}

TEST(NtlmTest, GenerateResponsesV1WithSessionSecuritySpecTests) {
  uint8_t lm_response[kResponseLenV1];
  uint8_t ntlm_response[kResponseLenV1];
  GenerateResponsesV1WithSessionSecurity(
      test::kPassword, test::kServerChallenge, test::kClientChallenge,
      lm_response, ntlm_response);

  ASSERT_EQ(0, memcmp(test::kExpectedLmResponseWithV1SS, lm_response,
                      kResponseLenV1));
  ASSERT_EQ(0, memcmp(test::kExpectedNtlmResponseWithV1SS, ntlm_response,
                      kResponseLenV1));
}

TEST(NtlmTest, GenerateResponsesV1WithSessionSecurityClientChallengeUsed) {
  uint8_t lm_response1[kResponseLenV1];
  uint8_t lm_response2[kResponseLenV1];
  uint8_t ntlm_response1[kResponseLenV1];
  uint8_t ntlm_response2[kResponseLenV1];
  uint8_t client_challenge1[kChallengeLen];
  uint8_t client_challenge2[kChallengeLen];

  memset(client_challenge1, 0x01, kChallengeLen);
  memset(client_challenge2, 0x02, kChallengeLen);

  GenerateResponsesV1WithSessionSecurity(
      test::kPassword, test::kServerChallenge, client_challenge1, lm_response1,
      ntlm_response1);
  GenerateResponsesV1WithSessionSecurity(
      test::kPassword, test::kServerChallenge, client_challenge2, lm_response2,
      ntlm_response2);

  // The point of session security is that the client can introduce some
  // randomness, so verify different client_challenge gives a different result.
  ASSERT_NE(0, memcmp(lm_response1, lm_response2, kResponseLenV1));
  ASSERT_NE(0, memcmp(ntlm_response1, ntlm_response2, kResponseLenV1));

  // With session security the lm and ntlm hash should be different.
  ASSERT_NE(0, memcmp(lm_response1, ntlm_response1, kResponseLenV1));
  ASSERT_NE(0, memcmp(lm_response2, ntlm_response2, kResponseLenV1));
}

TEST(NtlmTest, GenerateResponsesV1WithSessionSecurityVerifySSUsed) {
  uint8_t lm_response1[kResponseLenV1];
  uint8_t lm_response2[kResponseLenV1];
  uint8_t ntlm_response1[kResponseLenV1];
  uint8_t ntlm_response2[kResponseLenV1];

  GenerateResponsesV1WithSessionSecurity(
      test::kPassword, test::kServerChallenge, test::kClientChallenge,
      lm_response1, ntlm_response1);
  GenerateResponsesV1(test::kPassword, test::kServerChallenge, lm_response2,
                      ntlm_response2);

  // Verify that the responses with session security are not the
  // same as without it.
  ASSERT_NE(0, memcmp(lm_response1, lm_response2, kResponseLenV1));
  ASSERT_NE(0, memcmp(ntlm_response1, ntlm_response2, kResponseLenV1));
}

}  // namespace ntlm
}  // namespace net
