// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ntlm/ntlm_client.h"

#include <string.h>

#include "base/logging.h"
#include "base/strings/utf_string_conversions.h"
#include "net/ntlm/ntlm.h"
#include "net/ntlm/ntlm_buffer_reader.h"
#include "net/ntlm/ntlm_buffer_writer.h"

namespace net {
namespace ntlm {

namespace {
// Parses the challenge message and returns the |challenge_flags| and
// |server_challenge| into the supplied buffer.
// |server_challenge| must contain at least 8 bytes.
bool ParseChallengeMessage(const Buffer& challenge_message,
                           NegotiateFlags* challenge_flags,
                           uint8_t* server_challenge) {
  NtlmBufferReader challenge_reader(challenge_message);

  return challenge_reader.MatchMessageHeader(MessageType::kChallenge) &&
         challenge_reader.SkipSecurityBufferWithValidation() &&
         challenge_reader.ReadFlags(challenge_flags) &&
         challenge_reader.ReadBytes(server_challenge, kChallengeLen);
}

bool WriteAuthenticateMessage(NtlmBufferWriter* authenticate_writer,
                              SecurityBuffer lm_payload,
                              SecurityBuffer ntlm_payload,
                              SecurityBuffer domain_payload,
                              SecurityBuffer username_payload,
                              SecurityBuffer hostname_payload,
                              NegotiateFlags authenticate_flags) {
  return authenticate_writer->WriteMessageHeader(MessageType::kAuthenticate) &&
         authenticate_writer->WriteSecurityBuffer(lm_payload) &&
         authenticate_writer->WriteSecurityBuffer(ntlm_payload) &&
         authenticate_writer->WriteSecurityBuffer(domain_payload) &&
         authenticate_writer->WriteSecurityBuffer(username_payload) &&
         authenticate_writer->WriteSecurityBuffer(hostname_payload) &&
         authenticate_writer->WriteSecurityBuffer(
             SecurityBuffer(kAuthenticateHeaderLenV1, 0)) &&
         authenticate_writer->WriteFlags(authenticate_flags);
}

bool WriteResponsePayloads(NtlmBufferWriter* authenticate_writer,
                           const uint8_t* lm_response,
                           size_t lm_response_len,
                           const uint8_t* ntlm_response,
                           size_t ntlm_response_len) {
  return authenticate_writer->WriteBytes(lm_response, lm_response_len) &&
         authenticate_writer->WriteBytes(ntlm_response, ntlm_response_len);
}

bool WriteStringPayloads(NtlmBufferWriter* authenticate_writer,
                         bool is_unicode,
                         const base::string16& domain,
                         const base::string16& username,
                         const std::string& hostname) {
  if (is_unicode) {
    return authenticate_writer->WriteUtf16String(domain) &&
           authenticate_writer->WriteUtf16String(username) &&
           authenticate_writer->WriteUtf8AsUtf16String(hostname);
  } else {
    return authenticate_writer->WriteUtf16AsUtf8String(domain) &&
           authenticate_writer->WriteUtf16AsUtf8String(username) &&
           authenticate_writer->WriteUtf8String(hostname);
  }
}

// Returns the size in bytes of a string16 depending whether unicode
// was negotiated.
size_t GetStringPayloadLength(const base::string16& str, bool is_unicode) {
  if (is_unicode)
    return str.length() * 2;

  // When |WriteUtf16AsUtf8String| is called with a |base::string16|, the string
  // is converted to UTF8. Do the conversion to ensure that the character
  // count is correct.
  return base::UTF16ToUTF8(str).length();
}

// Returns the size in bytes of a std::string depending whether unicode
// was negotiated.
size_t GetStringPayloadLength(const std::string& str, bool is_unicode) {
  if (!is_unicode)
    return str.length();

  return base::UTF8ToUTF16(str).length() * 2;
}

}  // namespace

NtlmClient::NtlmClient() : negotiate_flags_(kNegotiateMessageFlags) {
  // Just generate the negotiate message once and hold on to it. It never
  // changes and in a NTLMv2 it's used as an input
  // to the Message Integrity Check in the Authenticate message.
  GenerateNegotiateMessage();
}

NtlmClient::~NtlmClient() {}

Buffer NtlmClient::GetNegotiateMessage() const {
  return negotiate_message_;
}

void NtlmClient::GenerateNegotiateMessage() {
  NtlmBufferWriter writer(kNegotiateMessageLen);
  bool result =
      writer.WriteMessageHeader(MessageType::kNegotiate) &&
      writer.WriteFlags(negotiate_flags_) &&
      writer.WriteSecurityBuffer(SecurityBuffer(kNegotiateMessageLen, 0)) &&
      writer.WriteSecurityBuffer(SecurityBuffer(kNegotiateMessageLen, 0)) &&
      writer.IsEndOfBuffer();

  DCHECK(result);

  negotiate_message_ = writer.Pass();
}

Buffer NtlmClient::GenerateAuthenticateMessage(
    const base::string16& domain,
    const base::string16& username,
    const base::string16& password,
    const std::string& hostname,
    const uint8_t* client_challenge,
    const Buffer& server_challenge_message) const {
  // Limit the size of strings that are accepted. As an absolute limit any
  // field represented by a |SecurityBuffer| or |AvPair| must be less than
  // UINT16_MAX bytes long. The strings are restricted to the maximum sizes
  // without regard to encoding. As such this isn't intended to restrict all
  // invalid inputs, only to allow all possible valid inputs.
  //
  // |domain| and |hostname| can be no longer than 255 characters.
  // |username| can be no longer than 104 characters. See [1].
  // |password| can be no longer than 256 characters. See [2].
  //
  // [1] - https://technet.microsoft.com/en-us/library/bb726984.aspx
  // [2] - https://technet.microsoft.com/en-us/library/cc512606.aspx
  if (hostname.length() > kMaxFqdnLen || domain.length() > kMaxFqdnLen ||
      username.length() > kMaxUsernameLen ||
      password.length() > kMaxPasswordLen)
    return Buffer();

  NegotiateFlags challenge_flags;
  uint8_t server_challenge[kChallengeLen];

  // Read the flags and the server's random challenge from the challenge
  // message.
  if (!ParseChallengeMessage(server_challenge_message, &challenge_flags,
                             server_challenge)) {
    return Buffer();
  }

  // Calculate the responses for the authenticate message.
  uint8_t lm_response[kResponseLenV1];
  uint8_t ntlm_response[kResponseLenV1];

  // Always use extended session security even if the server tries to downgrade.
  NegotiateFlags authenticate_flags = (challenge_flags & negotiate_flags_) |
                                      NegotiateFlags::kExtendedSessionSecurity;

  // Generate the LM and NTLM responses.
  GenerateResponsesV1WithSessionSecurity(
      password, server_challenge, client_challenge, lm_response, ntlm_response);

  // Calculate all the payload lengths and offsets.
  bool is_unicode = (authenticate_flags & NegotiateFlags::kUnicode) ==
                    NegotiateFlags::kUnicode;

  SecurityBuffer lm_info;
  SecurityBuffer ntlm_info;
  SecurityBuffer domain_info;
  SecurityBuffer username_info;
  SecurityBuffer hostname_info;
  size_t authenticate_message_len;
  CalculatePayloadLayout(is_unicode, domain, username, hostname, &lm_info,
                         &ntlm_info, &domain_info, &username_info,
                         &hostname_info, &authenticate_message_len);

  NtlmBufferWriter authenticate_writer(authenticate_message_len);
  bool writer_result = WriteAuthenticateMessage(
      &authenticate_writer, lm_info, ntlm_info, domain_info, username_info,
      hostname_info, authenticate_flags);
  DCHECK(writer_result);
  DCHECK_EQ(authenticate_writer.GetCursor(), GetAuthenticateHeaderLength());

  writer_result =
      WriteResponsePayloads(&authenticate_writer, lm_response, lm_info.length,
                            ntlm_response, ntlm_info.length);
  DCHECK(writer_result);
  DCHECK_EQ(authenticate_writer.GetCursor(), domain_info.offset);

  writer_result = WriteStringPayloads(&authenticate_writer, is_unicode, domain,
                                      username, hostname);
  DCHECK(writer_result);
  DCHECK(authenticate_writer.IsEndOfBuffer());
  DCHECK_EQ(authenticate_message_len, authenticate_writer.GetLength());

  return authenticate_writer.Pass();
}

void NtlmClient::CalculatePayloadLayout(
    bool is_unicode,
    const base::string16& domain,
    const base::string16& username,
    const std::string& hostname,
    SecurityBuffer* lm_info,
    SecurityBuffer* ntlm_info,
    SecurityBuffer* domain_info,
    SecurityBuffer* username_info,
    SecurityBuffer* hostname_info,
    size_t* authenticate_message_len) const {
  size_t upto = GetAuthenticateHeaderLength();

  lm_info->offset = upto;
  lm_info->length = kResponseLenV1;
  upto += lm_info->length;

  ntlm_info->offset = upto;
  ntlm_info->length = GetNtlmResponseLength();
  upto += ntlm_info->length;

  domain_info->offset = upto;
  domain_info->length = GetStringPayloadLength(domain, is_unicode);
  upto += domain_info->length;

  username_info->offset = upto;
  username_info->length = GetStringPayloadLength(username, is_unicode);
  upto += username_info->length;

  hostname_info->offset = upto;
  hostname_info->length = GetStringPayloadLength(hostname, is_unicode);
  upto += hostname_info->length;

  *authenticate_message_len = upto;
}

size_t NtlmClient::GetAuthenticateHeaderLength() const {
  return kAuthenticateHeaderLenV1;
}

size_t NtlmClient::GetNtlmResponseLength() const {
  return kResponseLenV1;
}

}  // namespace ntlm
}  // namespace net