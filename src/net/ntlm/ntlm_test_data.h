// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains common input and result values use to verify the NTLM
// implementation. They are defined in [MS-NLMP] Section 4.2 [1].
//
// [1] https://msdn.microsoft.com/en-us/library/cc236621.aspx

#ifndef NET_BASE_NTLM_TEST_DATA_H_
#define NET_BASE_NTLM_TEST_DATA_H_

#include "net/ntlm/ntlm_constants.h"

namespace net {
namespace ntlm {
namespace test {

// Common input values defined in [MS-NLMP] Section 4.2.1.
constexpr base::char16 kPassword[] = {'P', 'a', 's', 's', 'w',
                                      'o', 'r', 'd', '\0'};
constexpr base::char16 kNtlmDomain[] = {'D', 'o', 'm', 'a', 'i', 'n', '\0'};
constexpr base::char16 kUser[] = {'U', 's', 'e', 'r', '\0'};
constexpr base::char16 kHostname[] = {'C', 'O', 'M', 'P', 'U',
                                      'T', 'E', 'R', '\0'};

// ASCII Versions of the above strings.
constexpr char kNtlmDomainAscii[] = "Domain";
constexpr char kUserAscii[] = "User";
constexpr char kHostnameAscii[] = "COMPUTER";

// Challenge vectors defined in [MS-NLMP] Section 4.2.1.
constexpr uint8_t kServerChallenge[kChallengeLen] = {0x01, 0x23, 0x45, 0x67,
                                                     0x89, 0xab, 0xcd, 0xef};
constexpr uint8_t kClientChallenge[kChallengeLen] = {0xaa, 0xaa, 0xaa, 0xaa,
                                                     0xaa, 0xaa, 0xaa, 0xaa};

// Test input defined in [MS-NLMP] Section 4.2.3.3.
constexpr uint8_t kChallengeMsgV1[] = {
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x0c, 0x00, 0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x0a, 0x82,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f, 0x53, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00};

// A minimal challenge message for tests. For NTLMv1 this implementation only
// reads the smallest required version of the message (32 bytes). Some
// servers may still send messages this small. The only relevant flags
// that affect behavior are that both NTLMSSP_NEGOTIATE_UNICODE and
// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are set.
//
// [0-7]    - "NTLMSSP\0"                       (Signature)
// [9-11]   - |MessageType::kChallenge|          (Message Type = 0x00000002)
// [12-19]  - |SecBuf(kNegotiateMessageLen, 0)|(Target Name - Not Used)
// [20-23]  - |NEGOTIATE_MESSAGE_FLAGS|         (Flags = 0x00088207)
// [24-31]  - |SERVER_CHALLENGE|                (Server Challenge)
//
// See [MS-NLMP] Section 2.2.2.2 for more information about the Challenge
// message.
constexpr uint8_t kMinChallengeMessage[kChallengeHeaderLen] = {
    'N',  'T',  'L',  'M',  'S',  'S',  'P',  '\0', 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x07, 0x82,
    0x08, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

// The same message as |kMinChallengeMessage| but with the
// NTLMSSP_NEGOTIATE_UNICODE flag cleared.
constexpr uint8_t kMinChallengeMessageNoUnicode[kChallengeHeaderLen] = {
    'N',  'T',  'L',  'M',  'S',  'S',  'P',  '\0', 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x82,
    0x08, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

// The same message as |kMinChallengeMessage| but with the
// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag cleared.
constexpr uint8_t kMinChallengeMessageNoSS[kChallengeHeaderLen] = {
    'N',  'T',  'L',  'M',  'S',  'S',  'P',  '\0', 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x07, 0x82,
    0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

// Test result value for NTOWFv1() defined in [MS-NLMP] Section 4.2.2.1.2.
constexpr uint8_t kExpectedNtlmHashV1[kNtlmHashLen] = {
    0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca,
    0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52};

// Test result value defined in [MS-NLMP] Section 4.2.2.1.
constexpr uint8_t kExpectedNtlmResponseV1[kResponseLenV1] = {
    0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2, 0xad, 0x35, 0xec, 0xe6,
    0x4f, 0x16, 0x33, 0x1c, 0x44, 0xbd, 0xbe, 0xd9, 0x27, 0x84, 0x1f, 0x94};

// Test result value defined in [MS-NLMP] Section 4.2.3.2.2.
constexpr uint8_t kExpectedNtlmResponseWithV1SS[kResponseLenV1] = {
    0x75, 0x37, 0xf8, 0x03, 0xae, 0x36, 0x71, 0x28, 0xca, 0x45, 0x82, 0x04,
    0xbd, 0xe7, 0xca, 0xf8, 0x1e, 0x97, 0xed, 0x26, 0x83, 0x26, 0x72, 0x32};

// Test result value defined in [MS-NLMP] Section 4.2.3.2.1.
constexpr uint8_t kExpectedLmResponseWithV1SS[kResponseLenV1] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Expected negotiate message from this implementation.
// [0-7]    - "NTLMSSP\0"                       (Signature)
// [9-11]   - |MessageType::NEGOTIATE|          (Message Type = 0x00000001)
// [12-15]  - |NEGOTIATE_MESSAGE_FLAGS|         (Flags = 0x00088207)
// [16-23]  - |SecBuf(kNegotiateMessageLen, 0)|(Domain)
// [24-32]  - |SecBuf(kNegotiateMessageLen, 0)|(Workstation)
//
// NOTE: Message does not include Version field. Since
// NTLMSSP_NEGOTIATE_VERSION is never sent, it is not required, and the server
// won't try to read it. The field is currently omitted for test compatibility
// with the existing implementation. When NTLMv2 is implemented this field
// will be present for both NTLMv1 and NTLMv2, however it will always be set to
// all zeros. The version field is only used for debugging and only defines
// a mapping to Windows operating systems.
//
// Similarly both Domain and Workstation fields are are not strictly required
// either (though are included here) since neither
// NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED nor
// NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED are ever sent. A compliant server
// should never read past the 16th byte in this message.
//
// See [MS-NLMP] Section 2.2.2.5 for more detail on flags and 2.2.2.1 for the
// Negotiate message in general.
constexpr uint8_t kExpectedNegotiateMsg[kNegotiateMessageLen] = {
    'N',  'T',  'L',  'M',  'S',  'S',  'P',  '\0', 0x01, 0x00, 0x00,
    0x00, 0x07, 0x82, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00};

// Expected V1 Authenticate message from this implementation when sent
// |kChallengeMsgV1| as the challenge.
//
// [0-7]    - "NTLMSSP\0"                         (Signature)
// [9-11]   - |MessageType::kAuthenticate|        (Message Type = 0x00000003)
// [12-19]  - |SecBuf(64, RESPONSE_V1_LEN)|       (LM Response)
// [20-27]  - |SecBuf(88, RESPONSE_V1_LEN)|       (NTLM Response)
// [28-35]  - |SecBuf(112, 12)|                   (Target Name = L"Domain")
// [36-43]  - |SecBuf(124, 8)|                    (User = L"User")
// [44-51]  - |SecBuf(132, 16)|                   (Workstation = L"COMPUTER")
// [52-59]  - |SecBuf(64, 0)|                     (Session Key (empty))
// [60-63]  - 0x00088203                          (Flags)
// [64-87]  - |EXPECTED_V1_WITH_SS_LM_RESPONSE|   (LM Response Payload)
// [88-111] - |EXPECTED_V1_WITH_SS_NTLM_RESPONSE| (NTLM Response Payload)
// [112-123]- L"Domain"                           (Target Name Payload)
// [124-132]- L"User"                             (User Payload)
// [132-147]- L"COMPUTER"                         (Workstation Payload)
//
// NOTE: This is not identical to the message in [MS-NLMP] Section 4.2.2.3 for
// several reasons.
//
// 1) The flags are different because this implementation does not support
// the flags related to version, key exchange, signing and sealing. These
// flags are not relevant to implementing the NTLM scheme in HTTP.
// 2) Since key exchange is not required nor supported, the session base key
// payload is not required nor present.
// 3) The specification allows payloads to be in any order. This (and the
// prior) implementation uses a different payload order than the example.
// 4) The version field is Windows specific and there is no provision for
// non-Windows OS information. This message does not include a version field.
constexpr uint8_t kExpectedAuthenticateMsgV1[] = {
    'N',  'T',  'L',  'M',  'S',  'S',  'P',  '\0', 0x03, 0x00, 0x00, 0x00,
    0x18, 0x00, 0x18, 0x00, 0x40, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
    0x58, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0c, 0x00, 0x70, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x08, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x03, 0x82, 0x08, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x75, 0x37, 0xf8, 0x03, 0xae, 0x36, 0x71, 0x28,
    0xca, 0x45, 0x82, 0x04, 0xbd, 0xe7, 0xca, 0xf8, 0x1e, 0x97, 0xed, 0x26,
    0x83, 0x26, 0x72, 0x32, 'D',  0x00, 'o',  0x00, 'm',  0x00, 'a',  0x00,
    'i',  0x00, 'n',  0x00, 'U',  0x00, 's',  0x00, 'e',  0x00, 'r',  0x00,
    'C',  0x00, 'O',  0x00, 'M',  0x00, 'P',  0x00, 'U',  0x00, 'T',  0x00,
    'E',  0x00, 'R',  0x00,
};

}  // namespace test
}  // namespace ntlm
}  // namespace net

#endif  // NET_BASE_NTLM_TEST_DATA_H_