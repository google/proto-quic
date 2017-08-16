// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ntlm/ntlm_client.h"

#include <string>

#include "build/build_config.h"
#include "net/ntlm/ntlm.h"
#include "net/ntlm/ntlm_buffer_reader.h"
#include "net/ntlm/ntlm_buffer_writer.h"
#include "net/ntlm/ntlm_test_data.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace ntlm {

namespace {

Buffer GenerateAuthMsg(const NtlmClient& client, const Buffer& challenge_msg) {
  return client.GenerateAuthenticateMessage(
      test::kNtlmDomain, test::kUser, test::kPassword, test::kHostnameAscii,
      test::kClientChallenge, challenge_msg);
}

Buffer GenerateAuthMsg(const NtlmClient& client,
                       const uint8_t* challenge_msg,
                       size_t challenge_msg_len) {
  return GenerateAuthMsg(client, Buffer(challenge_msg, challenge_msg_len));
}

Buffer GenerateAuthMsg(const NtlmClient& client,
                       const NtlmBufferWriter& challenge_writer) {
  return GenerateAuthMsg(client, challenge_writer.GetBuffer());
}

bool GetAuthMsgResult(const NtlmClient& client,
                      const NtlmBufferWriter& challenge_writer) {
  return !GenerateAuthMsg(client, challenge_writer).empty();
}

bool ReadBytesPayload(NtlmBufferReader* reader, uint8_t* buffer, size_t len) {
  SecurityBuffer sec_buf;
  return reader->ReadSecurityBuffer(&sec_buf) && (sec_buf.length == len) &&
         reader->ReadBytesFrom(sec_buf, buffer);
}

// Reads bytes from a payload and assigns them to a string. This makes
// no assumptions about the underlying encoding.
bool ReadStringPayload(NtlmBufferReader* reader, std::string* str) {
  SecurityBuffer sec_buf;
  if (!reader->ReadSecurityBuffer(&sec_buf))
    return false;

  std::unique_ptr<uint8_t[]> raw(new uint8_t[sec_buf.length]);
  if (!reader->ReadBytesFrom(sec_buf, raw.get()))
    return false;

  str->assign(reinterpret_cast<const char*>(raw.get()), sec_buf.length);
  return true;
}

// Reads bytes from a payload and assigns them to a string16. This makes
// no assumptions about the underlying encoding. This will fail if there
// are an odd number of bytes in the payload.
bool ReadString16Payload(NtlmBufferReader* reader, base::string16* str) {
  SecurityBuffer sec_buf;
  if (!reader->ReadSecurityBuffer(&sec_buf) || (sec_buf.length % 2 != 0))
    return false;

  std::unique_ptr<uint8_t[]> raw(new uint8_t[sec_buf.length]);
  if (!reader->ReadBytesFrom(sec_buf, raw.get()))
    return false;

#if defined(ARCH_CPU_BIG_ENDIAN)
  for (size_t i = 0; i < sec_buf.length; i += 2) {
    std::swap(raw.get()[i], raw.get()[i + 1]);
  }
#endif

  str->assign(reinterpret_cast<const base::char16*>(raw.get()),
              sec_buf.length / 2);
  return true;
}

}  // namespace

TEST(NtlmClientTest, VerifyNegotiateMessageV1) {
  NtlmClient client;

  Buffer result = client.GetNegotiateMessage();

  ASSERT_EQ(kNegotiateMessageLen, result.size());
  ASSERT_EQ(0, memcmp(test::kExpectedNegotiateMsg, result.data(),
                      kNegotiateMessageLen));
}

TEST(NtlmClientTest, MinimalStructurallyValidChallenge) {
  NtlmClient client;

  NtlmBufferWriter writer(kMinChallengeHeaderLen);
  ASSERT_TRUE(
      writer.WriteBytes(test::kMinChallengeMessage, kMinChallengeHeaderLen));

  ASSERT_TRUE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, MinimalStructurallyValidChallengeZeroOffset) {
  NtlmClient client;

  // The spec (2.2.1.2) states that the length SHOULD be 0 and the offset
  // SHOULD be where the payload would be if it was present. This is the
  // expected response from a compliant server when no target name is sent.
  // In reality the offset should always be ignored if the length is zero.
  // Also implementations often just write zeros.
  uint8_t raw[kMinChallengeHeaderLen];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Modify the default valid message to overwrite the offset to zero.
  ASSERT_NE(0x00, raw[16]);
  raw[16] = 0x00;

  NtlmBufferWriter writer(kMinChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));

  ASSERT_TRUE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, ChallengeMsgTooShort) {
  NtlmClient client;

  // Fail because the minimum size valid message is 32 bytes.
  NtlmBufferWriter writer(kMinChallengeHeaderLen - 1);
  ASSERT_TRUE(writer.WriteBytes(test::kMinChallengeMessage,
                                kMinChallengeHeaderLen - 1));
  ASSERT_FALSE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, ChallengeMsgNoSig) {
  NtlmClient client;

  // Fail because the first 8 bytes don't match "NTLMSSP\0"
  uint8_t raw[kMinChallengeHeaderLen];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Modify the default valid message to overwrite the last byte of the
  // signature.
  ASSERT_NE(0xff, raw[7]);
  raw[7] = 0xff;
  NtlmBufferWriter writer(kMinChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));
  ASSERT_FALSE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, ChallengeMsgWrongMessageType) {
  NtlmClient client;

  // Fail because the message type should be MessageType::kChallenge
  // (0x00000002)
  uint8_t raw[kMinChallengeHeaderLen];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Modify the message type.
  ASSERT_NE(0x03, raw[8]);
  raw[8] = 0x03;

  NtlmBufferWriter writer(kMinChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));

  ASSERT_FALSE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, ChallengeWithNoTargetName) {
  NtlmClient client;

  // The spec (2.2.1.2) states that the length SHOULD be 0 and the offset
  // SHOULD be where the payload would be if it was present. This is the
  // expected response from a compliant server when no target name is sent.
  // In reality the offset should always be ignored if the length is zero.
  // Also implementations often just write zeros.
  uint8_t raw[kMinChallengeHeaderLen];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Modify the default valid message to overwrite the offset to zero.
  ASSERT_NE(0x00, raw[16]);
  raw[16] = 0x00;

  NtlmBufferWriter writer(kMinChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));

  ASSERT_TRUE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, Type2MessageWithTargetName) {
  NtlmClient client;

  // One extra byte is provided for target name.
  uint8_t raw[kMinChallengeHeaderLen + 1];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Put something in the target name.
  raw[kMinChallengeHeaderLen] = 'Z';

  // Modify the default valid message to indicate 1 byte is present in the
  // target name payload.
  ASSERT_NE(0x01, raw[12]);
  ASSERT_EQ(0x00, raw[13]);
  ASSERT_NE(0x01, raw[14]);
  ASSERT_EQ(0x00, raw[15]);
  raw[12] = 0x01;
  raw[14] = 0x01;

  NtlmBufferWriter writer(kChallengeHeaderLen + 1);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));

  ASSERT_TRUE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, NoTargetNameOverflowFromOffset) {
  NtlmClient client;

  uint8_t raw[kMinChallengeHeaderLen];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Modify the default valid message to claim that the target name field is 1
  // byte long overrunning the end of the message message.
  ASSERT_NE(0x01, raw[12]);
  ASSERT_EQ(0x00, raw[13]);
  ASSERT_NE(0x01, raw[14]);
  ASSERT_EQ(0x00, raw[15]);
  raw[12] = 0x01;
  raw[14] = 0x01;

  NtlmBufferWriter writer(kMinChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));

  // The above malformed message could cause an implementation to read outside
  // the message buffer because the offset is past the end of the message.
  // Verify it gets rejected.
  ASSERT_FALSE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, NoTargetNameOverflowFromLength) {
  NtlmClient client;

  // Message has 1 extra byte of space after the header for the target name.
  // One extra byte is provided for target name.
  uint8_t raw[kMinChallengeHeaderLen + 1];
  memcpy(raw, test::kMinChallengeMessage, kMinChallengeHeaderLen);
  // Put something in the target name.
  raw[kMinChallengeHeaderLen] = 'Z';

  // Modify the default valid message to indicate 2 bytes are present in the
  // target name payload (however there is only space for 1).
  ASSERT_NE(0x02, raw[12]);
  ASSERT_EQ(0x00, raw[13]);
  ASSERT_NE(0x02, raw[14]);
  ASSERT_EQ(0x00, raw[15]);
  raw[12] = 0x02;
  raw[14] = 0x02;

  NtlmBufferWriter writer(kMinChallengeHeaderLen + 1);
  ASSERT_TRUE(writer.WriteBytes(raw, arraysize(raw)));

  // The above malformed message could cause an implementation
  // to read outside the message buffer because the length is
  // longer than available space. Verify it gets rejected.
  ASSERT_FALSE(GetAuthMsgResult(client, writer));
}

TEST(NtlmClientTest, Type3UnicodeWithSessionSecuritySpecTest) {
  NtlmClient client;

  Buffer result = GenerateAuthMsg(client, test::kChallengeMsgV1,
                                  arraysize(test::kChallengeMsgV1));

  ASSERT_FALSE(result.empty());
  ASSERT_EQ(arraysize(test::kExpectedAuthenticateMsgV1), result.size());
  ASSERT_EQ(0, memcmp(test::kExpectedAuthenticateMsgV1, result.data(),
                      result.size()));
}

TEST(NtlmClientTest, Type3WithoutUnicode) {
  NtlmClient client;

  Buffer result = GenerateAuthMsg(client, test::kMinChallengeMessageNoUnicode,
                                  kMinChallengeHeaderLen);
  ASSERT_FALSE(result.empty());

  NtlmBufferReader reader(result);
  ASSERT_TRUE(reader.MatchMessageHeader(MessageType::kAuthenticate));

  // Read the LM and NTLM Response Payloads.
  uint8_t actual_lm_response[kResponseLenV1];
  uint8_t actual_ntlm_response[kResponseLenV1];

  ASSERT_TRUE(ReadBytesPayload(&reader, actual_lm_response, kResponseLenV1));
  ASSERT_TRUE(ReadBytesPayload(&reader, actual_ntlm_response, kResponseLenV1));

  ASSERT_EQ(0, memcmp(test::kExpectedLmResponseWithV1SS, actual_lm_response,
                      kResponseLenV1));
  ASSERT_EQ(0, memcmp(test::kExpectedNtlmResponseWithV1SS, actual_ntlm_response,
                      kResponseLenV1));

  std::string domain;
  std::string username;
  std::string hostname;
  ASSERT_TRUE(ReadStringPayload(&reader, &domain));
  ASSERT_EQ(test::kNtlmDomainAscii, domain);
  ASSERT_TRUE(ReadStringPayload(&reader, &username));
  ASSERT_EQ(test::kUserAscii, username);
  ASSERT_TRUE(ReadStringPayload(&reader, &hostname));
  ASSERT_EQ(test::kHostnameAscii, hostname);

  // The session key is not used in HTTP. Since NTLMSSP_NEGOTIATE_KEY_EXCH
  // was not sent this is empty.
  ASSERT_TRUE(reader.MatchEmptySecurityBuffer());

  // Verify the unicode flag is not set and OEM flag is.
  NegotiateFlags flags;
  ASSERT_TRUE(reader.ReadFlags(&flags));
  ASSERT_EQ(NegotiateFlags::kNone, flags & NegotiateFlags::kUnicode);
  ASSERT_EQ(NegotiateFlags::kOem, flags & NegotiateFlags::kOem);
}

TEST(NtlmClientTest, ClientDoesNotDowngradeSessionSecurity) {
  NtlmClient client;

  Buffer result = GenerateAuthMsg(client, test::kMinChallengeMessageNoSS,
                                  kMinChallengeHeaderLen);
  ASSERT_FALSE(result.empty());

  NtlmBufferReader reader(result);
  ASSERT_TRUE(reader.MatchMessageHeader(MessageType::kAuthenticate));

  // Read the LM and NTLM Response Payloads.
  uint8_t actual_lm_response[kResponseLenV1];
  uint8_t actual_ntlm_response[kResponseLenV1];

  ASSERT_TRUE(ReadBytesPayload(&reader, actual_lm_response, kResponseLenV1));
  ASSERT_TRUE(ReadBytesPayload(&reader, actual_ntlm_response, kResponseLenV1));

  // The important part of this test is that even though the
  // server told the client to drop session security. The client
  // DID NOT drop it.
  ASSERT_EQ(0, memcmp(test::kExpectedLmResponseWithV1SS, actual_lm_response,
                      kResponseLenV1));
  ASSERT_EQ(0, memcmp(test::kExpectedNtlmResponseWithV1SS, actual_ntlm_response,
                      kResponseLenV1));

  base::string16 domain;
  base::string16 username;
  base::string16 hostname;
  ASSERT_TRUE(ReadString16Payload(&reader, &domain));
  ASSERT_EQ(test::kNtlmDomain, domain);
  ASSERT_TRUE(ReadString16Payload(&reader, &username));
  ASSERT_EQ(test::kUser, username);
  ASSERT_TRUE(ReadString16Payload(&reader, &hostname));
  ASSERT_EQ(test::kHostname, hostname);

  // The session key is not used in HTTP. Since NTLMSSP_NEGOTIATE_KEY_EXCH
  // was not sent this is empty.
  ASSERT_TRUE(reader.MatchEmptySecurityBuffer());

  // Verify the unicode and session security flag is set.
  NegotiateFlags flags;
  ASSERT_TRUE(reader.ReadFlags(&flags));
  ASSERT_EQ(NegotiateFlags::kUnicode, flags & NegotiateFlags::kUnicode);
  ASSERT_EQ(NegotiateFlags::kExtendedSessionSecurity,
            flags & NegotiateFlags::kExtendedSessionSecurity);
}

}  // namespace ntlm
}  // namespace net
