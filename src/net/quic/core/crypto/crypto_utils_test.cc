// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/crypto/crypto_utils.h"

#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {
namespace {

TEST(CryptoUtilsTest, IsValidSNI) {
  // IP as SNI.
  EXPECT_FALSE(CryptoUtils::IsValidSNI("192.168.0.1"));
  // SNI without any dot.
  EXPECT_FALSE(CryptoUtils::IsValidSNI("somedomain"));
  // Invalid by RFC2396 but unfortunately domains of this form exist.
  EXPECT_TRUE(CryptoUtils::IsValidSNI("some_domain.com"));
  // An empty string must be invalid otherwise the QUIC client will try sending
  // it.
  EXPECT_FALSE(CryptoUtils::IsValidSNI(""));

  // Valid SNI
  EXPECT_TRUE(CryptoUtils::IsValidSNI("test.google.com"));
}

TEST(CryptoUtilsTest, NormalizeHostname) {
  struct {
    const char *input, *expected;
  } tests[] = {
      {
          "www.google.com", "www.google.com",
      },
      {
          "WWW.GOOGLE.COM", "www.google.com",
      },
      {
          "www.google.com.", "www.google.com",
      },
      {
          "www.google.COM.", "www.google.com",
      },
      {
          "www.google.com..", "www.google.com",
      },
      {
          "www.google.com........", "www.google.com",
      },
  };

  for (size_t i = 0; i < arraysize(tests); ++i) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", tests[i].input);
    EXPECT_EQ(string(tests[i].expected), CryptoUtils::NormalizeHostname(buf));
  }
}

TEST(CryptoUtilsTest, TestExportKeyingMaterial) {
  const struct TestVector {
    // Input (strings of hexadecimal digits):
    const char* subkey_secret;
    const char* label;
    const char* context;
    size_t result_len;

    // Expected output (string of hexadecimal digits):
    const char* expected;  // Null if it should fail.
  } test_vector[] = {
      // Try a typical input
      {"4823c1189ecc40fce888fbb4cf9ae6254f19ba12e6d9af54788f195a6f509ca3",
       "e934f78d7a71dd85420fceeb8cea0317",
       "b8d766b5d3c8aba0009c7ed3de553eba53b4de1030ea91383dcdf724cd8b7217", 32,
       "a9979da0d5f1c1387d7cbe68f5c4163ddb445a03c4ad6ee72cb49d56726d679e"},
      // Don't let the label contain nulls
      {"14fe51e082ffee7d1b4d8d4ab41f8c55", "3132333435363700",
       "58585858585858585858585858585858", 16, nullptr},
      // Make sure nulls in the context are fine
      {"d862c2e36b0a42f7827c67ebc8d44df7", "7a5b95e4e8378123",
       "4142434445464700", 16, "12d418c6d0738a2e4d85b2d0170f76e1"},
      // ... and give a different result than without
      {"d862c2e36b0a42f7827c67ebc8d44df7", "7a5b95e4e8378123", "41424344454647",
       16, "abfa1c479a6e3ffb98a11dee7d196408"},
      // Try weird lengths
      {"d0ec8a34f6cc9a8c96", "49711798cc6251",
       "933d4a2f30d22f089cfba842791116adc121e0", 23,
       "c9a46ed0757bd1812f1f21b4d41e62125fec8364a21db7"},
  };

  for (size_t i = 0; i < arraysize(test_vector); i++) {
    // Decode the test vector.
    string subkey_secret =
        QuicTextUtils::HexDecode(test_vector[i].subkey_secret);
    string label = QuicTextUtils::HexDecode(test_vector[i].label);
    string context = QuicTextUtils::HexDecode(test_vector[i].context);
    size_t result_len = test_vector[i].result_len;
    bool expect_ok = test_vector[i].expected != nullptr;
    string expected;
    if (expect_ok) {
      expected = QuicTextUtils::HexDecode(test_vector[i].expected);
    }

    string result;
    bool ok = CryptoUtils::ExportKeyingMaterial(subkey_secret, label, context,
                                                result_len, &result);
    EXPECT_EQ(expect_ok, ok);
    if (expect_ok) {
      EXPECT_EQ(result_len, result.length());
      test::CompareCharArraysWithHexError("HKDF output", result.data(),
                                          result.length(), expected.data(),
                                          expected.length());
    }
  }
}

TEST(CryptoUtilsTest, HandshakeFailureReasonToString) {
  EXPECT_STREQ("HANDSHAKE_OK",
               CryptoUtils::HandshakeFailureReasonToString(HANDSHAKE_OK));
  EXPECT_STREQ("CLIENT_NONCE_UNKNOWN_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_UNKNOWN_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_ORBIT_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_ORBIT_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_DECRYPTION_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_REQUIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_REQUIRED_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_INCHOATE_HELLO_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_INCHOATE_HELLO_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_INVALID_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_PARSE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_PARSE_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE));
  EXPECT_STREQ("INVALID_EXPECTED_LEAF_CERTIFICATE",
               CryptoUtils::HandshakeFailureReasonToString(
                   INVALID_EXPECTED_LEAF_CERTIFICATE));
  EXPECT_STREQ("MAX_FAILURE_REASON",
               CryptoUtils::HandshakeFailureReasonToString(MAX_FAILURE_REASON));
  EXPECT_STREQ(
      "INVALID_HANDSHAKE_FAILURE_REASON",
      CryptoUtils::HandshakeFailureReasonToString(
          static_cast<HandshakeFailureReason>(MAX_FAILURE_REASON + 1)));
}

}  // namespace
}  // namespace test
}  // namespace net
