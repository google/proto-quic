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

}  // namespace test
}  // namespace ntlm
}  // namespace net

#endif  // NET_BASE_NTLM_TEST_DATA_H_