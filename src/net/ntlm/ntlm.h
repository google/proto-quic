// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Based on [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
// Specification version 28.0 [1]. Additional NTLM reference [2].
//
// [1] https://msdn.microsoft.com/en-us/library/cc236621.aspx
// [2] http://davenport.sourceforge.net/ntlm.html

#ifndef NET_BASE_NTLM_H_
#define NET_BASE_NTLM_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/ntlm/ntlm_constants.h"

namespace base {
struct MD5Digest;
}

namespace net {
namespace ntlm {

// Generates the NTLMv1 Hash and writes the |kNtlmHashLen| byte result to
// |hash|. Defined by NTOWFv1() in [MS-NLMP] Section 3.3.1.
NET_EXPORT_PRIVATE void GenerateNtlmHashV1(const base::string16& password,
                                           uint8_t* hash);

// Generates the |kResponseLenV1| byte NTLMv1 response field according to the
// DESL(K, V) function in [MS-NLMP] Section 6.
//
// |hash| must contain |kNtlmHashLen| bytes.
// |challenge| must contain |kChallengeLen| bytes.
// |response| must contain |kResponseLenV1| bytes.
NET_EXPORT_PRIVATE void GenerateResponseDesl(const uint8_t* hash,
                                             const uint8_t* challenge,
                                             uint8_t* response);

// Generates the NTLM Response field for NTLMv1 without extended session
// security. Defined by ComputeResponse() in [MS-NLMP] Section 3.3.1 for the
// case where NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is not set.
//
// |server_challenge| must contain |kChallengeLen| bytes.
// |ntlm_response| must contain |kResponseLenV1| bytes.
NET_EXPORT_PRIVATE void GenerateNtlmResponseV1(const base::string16& password,
                                               const uint8_t* server_challenge,
                                               uint8_t* ntlm_response);

// Generates both the LM Response and NTLM Response fields for NTLMv1 based
// on the users password and the servers challenge. Both the LM and NTLM
// Response are the result of |GenerateNtlmResponseV1|.
//
// NOTE: This should not be used. The default flags always include session
// security. Session security can however be disabled in NTLMv1 by omitting
// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY from the flag set used to
// initialize |NtlmClient|.
//
// The default flags include this flag and the client will not be
// downgraded by the server.
//
// |server_challenge| must contain |kChallengeLen| bytes.
// |lm_response| must contain |kResponseLenV1| bytes.
// |ntlm_response| must contain |kResponseLenV1| bytes.
NET_EXPORT_PRIVATE void GenerateResponsesV1(const base::string16& password,
                                            const uint8_t* server_challenge,
                                            uint8_t* lm_response,
                                            uint8_t* ntlm_response);

// The LM Response in V1 with extended session security is 8 bytes of the
// |client_challenge| then 16 bytes of zero. This is the value
// LmChallengeResponse in ComputeResponse() when
// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set. See [MS-NLMP] Section
// 3.3.1.
//
// |lm_response| must contain |kResponseLenV1| bytes.
NET_EXPORT_PRIVATE void GenerateLMResponseV1WithSessionSecurity(
    const uint8_t* client_challenge,
    uint8_t* lm_response);

// The |session_hash| is MD5(CONCAT(server_challenge, client_challenge)).
// It is used instead of just |server_challenge| in NTLMv1 when
// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set. See [MS-NLMP] Section
// 3.3.1.
//
// |server_challenge| must contain |kChallengeLen| bytes.
// |client_challenge| must contain |kChallengeLen| bytes.
NET_EXPORT_PRIVATE void GenerateSessionHashV1WithSessionSecurity(
    const uint8_t* server_challenge,
    const uint8_t* client_challenge,
    base::MD5Digest* session_hash);

// Generates the NTLM Response for NTLMv1 with session security.
// Defined by ComputeResponse() in [MS-NLMP] Section 3.3.1 for the
// case where NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY is set.
//
// |server_challenge| must contain |kChallengeLen| bytes.
// |client_challenge| must contain |kChallengeLen| bytes.
// |ntlm_response| must contain |kResponseLenV1| bytes.
NET_EXPORT_PRIVATE void GenerateNtlmResponseV1WithSessionSecurity(
    const base::string16& password,
    const uint8_t* server_challenge,
    const uint8_t* client_challenge,
    uint8_t* ntlm_response);

// Generates the responses for V1 with extended session security.
// This is also known as NTLM2 (which is not the same as NTLMv2).
// |lm_response| is the result of |GenerateLMResponseV1WithSessionSecurity| and
// |ntlm_response| is the result of |GenerateNtlmResponseV1WithSessionSecurity|.
// See [MS-NLMP] Section 3.3.1.
//
// |server_challenge| must contain |kChallengeLen| bytes.
// |client_challenge| must contain |kChallengeLen| bytes.
// |ntlm_response| must contain |kResponseLenV1| bytes.
NET_EXPORT_PRIVATE void GenerateResponsesV1WithSessionSecurity(
    const base::string16& password,
    const uint8_t* server_challenge,
    const uint8_t* client_challenge,
    uint8_t* lm_response,
    uint8_t* ntlm_response);

}  // namespace ntlm
}  // namespace net

#endif  // NET_BASE_NTLM_H_
