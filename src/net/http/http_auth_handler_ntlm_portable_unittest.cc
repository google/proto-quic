// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/base64.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_handler_ntlm.h"
#include "net/http/http_request_info.h"
#include "net/http/mock_allow_http_auth_preferences.h"
#include "net/log/net_log_with_source.h"
#include "net/ntlm/ntlm.h"
#include "net/ntlm/ntlm_buffer_reader.h"
#include "net/ntlm/ntlm_buffer_writer.h"
#include "net/ntlm/ntlm_test_data.h"
#include "net/ssl/ssl_info.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace net {

class HttpAuthHandlerNtlmPortableTest : public PlatformTest {
 public:
  // Test input value defined in [MS-NLMP] Section 4.2.1.
  HttpAuthHandlerNtlmPortableTest() {
    http_auth_preferences_.reset(new MockAllowHttpAuthPreferences());
    factory_.reset(new HttpAuthHandlerNTLM::Factory());
    factory_->set_http_auth_preferences(http_auth_preferences_.get());
    creds_ = AuthCredentials(
        ntlm::test::kNtlmDomain + base::ASCIIToUTF16("\\") + ntlm::test::kUser,
        ntlm::test::kPassword);
  }

  int CreateHandler() {
    GURL gurl("https://foo.com");
    SSLInfo null_ssl_info;

    return factory_->CreateAuthHandlerFromString(
        "NTLM", HttpAuth::AUTH_SERVER, null_ssl_info, gurl, NetLogWithSource(),
        &auth_handler_);
  }

  std::string CreateNtlmAuthHeader(ntlm::Buffer message) {
    std::string output;
    base::Base64Encode(
        base::StringPiece(reinterpret_cast<const char*>(message.data()),
                          message.size()),
        &output);

    return "NTLM " + output;
  }

  std::string CreateNtlmAuthHeader(const uint8_t* buffer, size_t length) {
    return CreateNtlmAuthHeader(ntlm::Buffer(buffer, length));
  }

  HttpAuth::AuthorizationResult HandleAnotherChallenge(
      const std::string& challenge) {
    HttpAuthChallengeTokenizer tokenizer(challenge.begin(), challenge.end());
    return GetAuthHandler()->HandleAnotherChallenge(&tokenizer);
  }

  bool DecodeChallenge(const std::string& challenge, std::string* decoded) {
    HttpAuthChallengeTokenizer tokenizer(challenge.begin(), challenge.end());
    return base::Base64Decode(tokenizer.base64_param(), decoded);
  }

  int GenerateAuthToken(std::string* token) {
    TestCompletionCallback callback;
    HttpRequestInfo request_info;
    return callback.GetResult(GetAuthHandler()->GenerateAuthToken(
        GetCreds(), &request_info, callback.callback(), token));
  }

  bool ReadBytesPayload(ntlm::NtlmBufferReader* reader,
                        uint8_t* buffer,
                        size_t len) {
    ntlm::SecurityBuffer sec_buf;
    return reader->ReadSecurityBuffer(&sec_buf) && (sec_buf.length == len) &&
           reader->ReadBytesFrom(sec_buf, buffer);
  }

  // Reads bytes from a payload and assigns them to a string. This makes
  // no assumptions about the underlying encoding.
  bool ReadStringPayload(ntlm::NtlmBufferReader* reader, std::string* str) {
    ntlm::SecurityBuffer sec_buf;
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
  void ReadString16Payload(ntlm::NtlmBufferReader* reader,
                           base::string16* str) {
    ntlm::SecurityBuffer sec_buf;
    EXPECT_TRUE(reader->ReadSecurityBuffer(&sec_buf));
    EXPECT_EQ(0, sec_buf.length % 2);

    std::unique_ptr<uint8_t[]> raw(new uint8_t[sec_buf.length]);
    EXPECT_TRUE(reader->ReadBytesFrom(sec_buf, raw.get()));

#ifdef IS_BIG_ENDIAN
    for (size_t i = 0; i < sec_buf.length; i += 2) {
      std::swap(raw[i], raw[i + 1]);
    }
#endif

    str->assign(reinterpret_cast<const base::char16*>(raw.get()),
                sec_buf.length / 2);
  }

  int GetGenerateAuthTokenResult() {
    std::string token;
    return GenerateAuthToken(&token);
  }

  AuthCredentials* GetCreds() { return &creds_; }

  HttpAuthHandlerNTLM* GetAuthHandler() {
    return static_cast<HttpAuthHandlerNTLM*>(auth_handler_.get());
  }

  static void MockRandom(uint8_t* output, size_t n) {
    // This is set to 0xaa because the client challenge for testing in
    // [MS-NLMP] Section 4.2.1 is 8 bytes of 0xaa.
    memset(output, 0xaa, n);
  }

  static std::string MockGetHostName() { return ntlm::test::kHostnameAscii; }

 private:
  AuthCredentials creds_;
  std::unique_ptr<HttpAuthHandler> auth_handler_;
  std::unique_ptr<MockAllowHttpAuthPreferences> http_auth_preferences_;
  std::unique_ptr<HttpAuthHandlerNTLM::Factory> factory_;
};

TEST_F(HttpAuthHandlerNtlmPortableTest, SimpleConstruction) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_TRUE(GetAuthHandler() != nullptr);
}

TEST_F(HttpAuthHandlerNtlmPortableTest, DoNotAllowDefaultCreds) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_FALSE(GetAuthHandler()->AllowsDefaultCredentials());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, AllowsExplicitCredentials) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_TRUE(GetAuthHandler()->AllowsExplicitCredentials());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, VerifyType1Message) {
  ASSERT_EQ(OK, CreateHandler());

  std::string token;
  ASSERT_EQ(OK, GenerateAuthToken(&token));
  // The type 1 message generated is always the same. The only variable
  // part of the message is the flags and this implementation always offers
  // the same set of flags.
  ASSERT_EQ("NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=", token);
}

TEST_F(HttpAuthHandlerNtlmPortableTest, EmptyTokenFails) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // The encoded token for a type 2 message can't be empty.
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_REJECT,
            HandleAnotherChallenge("NTLM"));
}

TEST_F(HttpAuthHandlerNtlmPortableTest, InvalidBase64Encoding) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Token isn't valid base64.
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge("NTLM !!!!!!!!!!!!!"));
  ASSERT_EQ(ERR_UNEXPECTED, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, CantChangeSchemeMidway) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Can't switch to a different auth scheme in the middle of the process.
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_INVALID,
            HandleAnotherChallenge("Negotiate SSdtIG5vdCBhIHJlYWwgdG9rZW4h"));
}

TEST_F(HttpAuthHandlerNtlmPortableTest, MinimalStructurallyValidType2) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(
                ntlm::test::kMinChallengeMessage, ntlm::kChallengeHeaderLen)));
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type2MessageTooShort) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  uint8_t raw[31];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 31);

  // Fail because the minimum size valid message is 32 bytes.
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(ERR_UNEXPECTED, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type2MessageWrongSignature) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  uint8_t raw[32];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 32);
  // Modify the default valid message to overwrite the last byte of the
  // signature.
  raw[7] = 0xff;

  // Fail because the first 8 bytes don't match "NTLMSSP\0"
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(ERR_UNEXPECTED, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type2WrongMessageType) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  uint8_t raw[32];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 32);
  // Modify the message type so it is not 0x00000002
  raw[8] = 0x03;

  // Fail because the message type should be MessageType::kChallenge
  // (0x00000002)
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(ERR_UNEXPECTED, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type2MessageWithNoTargetName) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // The spec (2.2.1.2) states that the length SHOULD be 0 and the offset
  // SHOULD be where the payload would be if it was present. This is the
  // expected response from a compliant server when no target name is sent.
  // In reality the offset should always be ignored if the length is zero.
  // Also implementations often just write zeros.
  uint8_t raw[32];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 32);
  // Modify the default valid message to overwrite the offset to zero.
  raw[16] = 0x00;

  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type2MessageWithTargetName) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // One extra byte is provided for target name.
  uint8_t raw[33];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 32);
  // Modify the default valid message to indicate 1 byte is present in the
  // target name payload.
  raw[12] = 0x01;
  raw[14] = 0x01;
  // Put something in the target name.
  raw[32] = 'Z';

  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, NoTargetNameOverflowFromOffset) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  uint8_t raw[32];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 32);
  // Modify the default valid message to claim that the target name field is 1
  // byte long overrunning the end of the message message.
  raw[12] = 0x01;
  raw[14] = 0x01;

  // The above malformed message could cause an implementation to read outside
  // the message buffer because the offset is past the end of the message.
  // Verify it gets rejected.
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(ERR_UNEXPECTED, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, NoTargetNameOverflowFromLength) {
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Message has 1 extra byte of space after the header for the target name.
  // One extra byte is provided for target name.
  uint8_t raw[33];
  memcpy(raw, ntlm::test::kMinChallengeMessage, 32);
  // Modify the default valid message to indicate 2 bytes are present in the
  // target name payload (however there is only space for 1).
  raw[12] = 0x02;
  raw[14] = 0x02;
  // Put something in the target name.
  raw[32] = 'Z';

  // The above malformed message could cause an implementation to read outside
  // the message buffer because the length is longer than available space.
  // Verify it gets rejected.
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(raw, arraysize(raw))));
  ASSERT_EQ(ERR_UNEXPECTED, GetGenerateAuthTokenResult());
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type3RespectsUnicode) {
  HttpAuthHandlerNTLM::ScopedProcSetter proc_setter(MockRandom,
                                                    MockGetHostName);
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Generate the type 2 message from the server.
  ntlm::NtlmBufferWriter writer(ntlm::kChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteMessageHeader(ntlm::MessageType::kChallenge));
  // No target name. It is never used.
  ASSERT_TRUE(writer.WriteSecurityBuffer(
      ntlm::SecurityBuffer(ntlm::kChallengeHeaderLen, 0)));
  // Set the unicode flag.
  ASSERT_TRUE(writer.WriteFlags(ntlm::NegotiateFlags::kUnicode));

  std::string token;
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(writer.GetBuffer())));
  ASSERT_EQ(OK, GenerateAuthToken(&token));

  // Validate the type 3 message
  std::string decoded;
  ASSERT_TRUE(DecodeChallenge(token, &decoded));
  ntlm::NtlmBufferReader reader(decoded);
  ASSERT_TRUE(reader.MatchMessageHeader(ntlm::MessageType::kAuthenticate));

  // Skip the LM and NTLM Hash fields. This test isn't testing that.
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  base::string16 domain;
  base::string16 username;
  base::string16 hostname;
  ReadString16Payload(&reader, &domain);
  ASSERT_EQ(ntlm::test::kNtlmDomain, domain);
  ReadString16Payload(&reader, &username);
  ASSERT_EQ(ntlm::test::kUser, username);
  ReadString16Payload(&reader, &hostname);
  ASSERT_EQ(ntlm::test::kHostname, hostname);

  // The session key is not used for the NTLM scheme in HTTP. Since
  // NTLMSSP_NEGOTIATE_KEY_EXCH was not sent this is empty.
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());

  // Verify the unicode flag is set.
  ntlm::NegotiateFlags flags;
  ASSERT_TRUE(reader.ReadFlags(&flags));
  ASSERT_EQ(ntlm::NegotiateFlags::kUnicode,
            flags & ntlm::NegotiateFlags::kUnicode);
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type3WithoutUnicode) {
  HttpAuthHandlerNTLM::ScopedProcSetter proc_setter(MockRandom,
                                                    MockGetHostName);
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Generate the type 2 message from the server.
  ntlm::NtlmBufferWriter writer(ntlm::kChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteMessageHeader(ntlm::MessageType::kChallenge));
  // No target name. It is never used.
  ASSERT_TRUE(writer.WriteSecurityBuffer(
      ntlm::SecurityBuffer(ntlm::kChallengeHeaderLen, 0)));
  // Set the OEM flag.
  ASSERT_TRUE(writer.WriteFlags(ntlm::NegotiateFlags::kOem));

  std::string token;
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(writer.GetBuffer())));
  ASSERT_EQ(OK, GenerateAuthToken(&token));

  // Validate the type 3 message
  std::string decoded;
  ASSERT_TRUE(DecodeChallenge(token, &decoded));
  ntlm::NtlmBufferReader reader(decoded);
  ASSERT_TRUE(reader.MatchMessageHeader(ntlm::MessageType::kAuthenticate));

  // Skip the 2 hash fields. This test isn't testing that.
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  std::string domain;
  std::string username;
  std::string hostname;
  ASSERT_TRUE(ReadStringPayload(&reader, &domain));
  ASSERT_EQ(ntlm::test::kNtlmDomainAscii, domain);
  ASSERT_TRUE(ReadStringPayload(&reader, &username));
  ASSERT_EQ(ntlm::test::kUserAscii, username);
  ASSERT_TRUE(ReadStringPayload(&reader, &hostname));
  ASSERT_EQ(ntlm::test::kHostnameAscii, hostname);

  // The session key is not used for the NTLM scheme in HTTP. Since
  // NTLMSSP_NEGOTIATE_KEY_EXCH was not sent this is empty.
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());

  // Verify the unicode flag is not set and OEM flag is.
  ntlm::NegotiateFlags flags;
  ASSERT_TRUE(reader.ReadFlags(&flags));
  ASSERT_EQ(ntlm::NegotiateFlags::kNone,
            flags & ntlm::NegotiateFlags::kUnicode);
  ASSERT_EQ(ntlm::NegotiateFlags::kOem, flags & ntlm::NegotiateFlags::kOem);
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type3UnicodeNoSessionSecurity) {
  // Verify that the client won't be downgraded if the server clears
  // the session security flag.
  HttpAuthHandlerNTLM::ScopedProcSetter proc_setter(MockRandom,
                                                    MockGetHostName);
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Generate the type 2 message from the server.
  ntlm::NtlmBufferWriter writer(ntlm::kChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteMessageHeader(ntlm::MessageType::kChallenge));
  // No target name. It is never used.
  ASSERT_TRUE(writer.WriteSecurityBuffer(
      ntlm::SecurityBuffer(ntlm::kChallengeHeaderLen, 0)));
  // Set the unicode but not the session security flag.
  ASSERT_TRUE(writer.WriteFlags(ntlm::NegotiateFlags::kUnicode));

  ASSERT_TRUE(
      writer.WriteBytes(ntlm::test::kServerChallenge, ntlm::kChallengeLen));
  ASSERT_TRUE(writer.IsEndOfBuffer());

  std::string token;
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(writer.GetBuffer())));
  ASSERT_EQ(OK, GenerateAuthToken(&token));

  // Validate the type 3 message
  std::string decoded;
  ASSERT_TRUE(DecodeChallenge(token, &decoded));
  ntlm::NtlmBufferReader reader(decoded);
  ASSERT_TRUE(reader.MatchMessageHeader(ntlm::MessageType::kAuthenticate));

  // Read the LM and NTLM Response Payloads.
  uint8_t actual_lm_response[ntlm::kResponseLenV1];
  uint8_t actual_ntlm_response[ntlm::kResponseLenV1];
  ASSERT_TRUE(
      ReadBytesPayload(&reader, actual_lm_response, ntlm::kResponseLenV1));
  ASSERT_TRUE(
      ReadBytesPayload(&reader, actual_ntlm_response, ntlm::kResponseLenV1));

  // Verify that the client still generated a response that uses
  // session security.
  ASSERT_EQ(0, memcmp(ntlm::test::kExpectedLmResponseWithV1SS,
                      actual_lm_response, ntlm::kResponseLenV1));
  ASSERT_EQ(0, memcmp(ntlm::test::kExpectedNtlmResponseWithV1SS,
                      actual_ntlm_response, ntlm::kResponseLenV1));

  base::string16 domain;
  base::string16 username;
  base::string16 hostname;
  ReadString16Payload(&reader, &domain);
  ASSERT_EQ(ntlm::test::kNtlmDomain, domain);
  ReadString16Payload(&reader, &username);
  ASSERT_EQ(ntlm::test::kUser, username);
  ReadString16Payload(&reader, &hostname);
  ASSERT_EQ(ntlm::test::kHostname, hostname);

  // The session key is not used for the NTLM scheme in HTTP. Since
  // NTLMSSP_NEGOTIATE_KEY_EXCH was not sent this is empty.
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());

  // Verify the unicode flag is set.
  ntlm::NegotiateFlags flags;
  ASSERT_TRUE(reader.ReadFlags(&flags));
  ASSERT_EQ(ntlm::NegotiateFlags::kUnicode,
            flags & ntlm::NegotiateFlags::kUnicode);
}

TEST_F(HttpAuthHandlerNtlmPortableTest, Type3UnicodeWithSessionSecurity) {
  HttpAuthHandlerNTLM::ScopedProcSetter proc_setter(MockRandom,
                                                    MockGetHostName);
  ASSERT_EQ(OK, CreateHandler());
  ASSERT_EQ(OK, GetGenerateAuthTokenResult());

  // Generate the type 2 message from the server.
  ntlm::NtlmBufferWriter writer(ntlm::kChallengeHeaderLen);
  ASSERT_TRUE(writer.WriteMessageHeader(ntlm::MessageType::kChallenge));
  // No target name. It is never used.
  ASSERT_TRUE(writer.WriteSecurityBuffer(
      ntlm::SecurityBuffer(ntlm::kChallengeHeaderLen, 0)));
  // Set the unicode and session security flag.
  ASSERT_TRUE(
      writer.WriteFlags((ntlm::NegotiateFlags::kUnicode |
                         ntlm::NegotiateFlags::kExtendedSessionSecurity)));

  ASSERT_TRUE(
      writer.WriteBytes(ntlm::test::kServerChallenge, ntlm::kChallengeLen));
  ASSERT_TRUE(writer.IsEndOfBuffer());

  std::string token;
  ASSERT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            HandleAnotherChallenge(CreateNtlmAuthHeader(writer.GetBuffer())));
  ASSERT_EQ(OK, GenerateAuthToken(&token));

  // Validate the type 3 message
  std::string decoded;
  ASSERT_TRUE(DecodeChallenge(token, &decoded));
  ntlm::NtlmBufferReader reader(decoded);
  ASSERT_TRUE(reader.MatchMessageHeader(ntlm::MessageType::kAuthenticate));

  // Read the LM and NTLM Response Payloads.
  uint8_t actual_lm_response[ntlm::kResponseLenV1];
  uint8_t actual_ntlm_response[ntlm::kResponseLenV1];
  ASSERT_TRUE(
      ReadBytesPayload(&reader, actual_lm_response, ntlm::kResponseLenV1));
  ASSERT_TRUE(
      ReadBytesPayload(&reader, actual_ntlm_response, ntlm::kResponseLenV1));

  ASSERT_EQ(0, memcmp(ntlm::test::kExpectedLmResponseWithV1SS,
                      actual_lm_response, ntlm::kResponseLenV1));
  ASSERT_EQ(0, memcmp(ntlm::test::kExpectedNtlmResponseWithV1SS,
                      actual_ntlm_response, ntlm::kResponseLenV1));

  base::string16 domain;
  base::string16 username;
  base::string16 hostname;
  ReadString16Payload(&reader, &domain);
  ASSERT_EQ(ntlm::test::kNtlmDomain, domain);
  ReadString16Payload(&reader, &username);
  ASSERT_EQ(ntlm::test::kUser, username);
  ReadString16Payload(&reader, &hostname);
  ASSERT_EQ(ntlm::test::kHostname, hostname);

  // The session key is not used for the NTLM scheme in HTTP. Since
  // NTLMSSP_NEGOTIATE_KEY_EXCH was not sent this is empty.
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());

  // Verify the unicode flag is set.
  ntlm::NegotiateFlags flags;
  ASSERT_TRUE(reader.ReadFlags(&flags));
  ASSERT_EQ(ntlm::NegotiateFlags::kUnicode,
            flags & ntlm::NegotiateFlags::kUnicode);
}

}  // namespace net
