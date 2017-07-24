// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ntlm/ntlm.h"

#include <string.h>

#include "base/logging.h"
#include "base/md5.h"
#include "net/ntlm/des.h"
#include "net/ntlm/md4.h"
#include "net/ntlm/ntlm_buffer_writer.h"

namespace net {
namespace ntlm {

void GenerateNtlmHashV1(const base::string16& password, uint8_t* hash) {
  size_t length = password.length() * 2;
  NtlmBufferWriter writer(length);

  // The writer will handle the big endian case if necessary.
  bool result = writer.WriteUtf16String(password);
  DCHECK(result);

  weak_crypto::MD4Sum(
      reinterpret_cast<const uint8_t*>(writer.GetBuffer().data()), length,
      hash);
}

void GenerateResponseDesl(const uint8_t* hash,
                          const uint8_t* challenge,
                          uint8_t* response) {
  // See DESL(K, D) function in [MS-NLMP] Section 6
  uint8_t key1[8];
  uint8_t key2[8];
  uint8_t key3[8];

  // The last 2 bytes of the hash are zero padded (5 zeros) as the
  // input to generate key3.
  uint8_t padded_hash[7];
  padded_hash[0] = hash[14];
  padded_hash[1] = hash[15];
  memset(padded_hash + 2, 0, 5);

  DESMakeKey(hash, key1);
  DESMakeKey(hash + 7, key2);
  DESMakeKey(padded_hash, key3);

  DESEncrypt(key1, challenge, response);
  DESEncrypt(key2, challenge, response + 8);
  DESEncrypt(key3, challenge, response + 16);
}

void GenerateNtlmResponseV1(const base::string16& password,
                            const uint8_t* challenge,
                            uint8_t* ntlm_response) {
  uint8_t ntlm_hash[kNtlmHashLen];
  GenerateNtlmHashV1(password, ntlm_hash);
  GenerateResponseDesl(ntlm_hash, challenge, ntlm_response);
}

void GenerateResponsesV1(const base::string16& password,
                         const uint8_t* server_challenge,
                         uint8_t* lm_response,
                         uint8_t* ntlm_response) {
  GenerateNtlmResponseV1(password, server_challenge, ntlm_response);

  // In NTLM v1 (with LMv1 disabled), the lm_response and ntlm_response are the
  // same. So just copy the ntlm_response into the lm_response.
  memcpy(lm_response, ntlm_response, kResponseLenV1);
}

void GenerateLMResponseV1WithSessionSecurity(const uint8_t* client_challenge,
                                             uint8_t* lm_response) {
  // In NTLM v1 with Session Security (aka NTLM2) the lm_response is 8 bytes of
  // client challenge and 16 bytes of zeros. (See 3.3.1)
  memcpy(lm_response, client_challenge, kChallengeLen);
  memset(lm_response + kChallengeLen, 0, kResponseLenV1 - kChallengeLen);
}

void GenerateSessionHashV1WithSessionSecurity(const uint8_t* server_challenge,
                                              const uint8_t* client_challenge,
                                              base::MD5Digest* session_hash) {
  base::MD5Context ctx;
  base::MD5Init(&ctx);
  base::MD5Update(
      &ctx, base::StringPiece(reinterpret_cast<const char*>(server_challenge),
                              kChallengeLen));
  base::MD5Update(
      &ctx, base::StringPiece(reinterpret_cast<const char*>(client_challenge),
                              kChallengeLen));

  base::MD5Final(session_hash, &ctx);
}

void GenerateNtlmResponseV1WithSessionSecurity(const base::string16& password,
                                               const uint8_t* server_challenge,
                                               const uint8_t* client_challenge,
                                               uint8_t* ntlm_response) {
  // Generate the NTLMv1 Hash.
  uint8_t ntlm_hash[kNtlmHashLen];
  GenerateNtlmHashV1(password, ntlm_hash);

  // Generate the NTLMv1 Session Hash.
  base::MD5Digest session_hash;
  GenerateSessionHashV1WithSessionSecurity(server_challenge, client_challenge,
                                           &session_hash);

  // Only the first 8 bytes of |session_hash.a| are actually used.
  GenerateResponseDesl(ntlm_hash, session_hash.a, ntlm_response);
}

void GenerateResponsesV1WithSessionSecurity(const base::string16& password,
                                            const uint8_t* server_challenge,
                                            const uint8_t* client_challenge,
                                            uint8_t* lm_response,
                                            uint8_t* ntlm_response) {
  GenerateLMResponseV1WithSessionSecurity(client_challenge, lm_response);
  GenerateNtlmResponseV1WithSessionSecurity(password, server_challenge,
                                            client_challenge, ntlm_response);
}

}  // namespace ntlm
}  // namespace net
