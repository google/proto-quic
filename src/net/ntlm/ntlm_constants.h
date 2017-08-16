// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_NTLM_CONSTANTS_H_
#define NET_BASE_NTLM_CONSTANTS_H_

#include <stddef.h>
#include <stdint.h>
#include <string>
#include <type_traits>

#include "base/macros.h"
#include "net/base/net_export.h"

namespace net {
namespace ntlm {

using Buffer = std::basic_string<uint8_t>;

// A security buffer is a structure within an NTLM message that indicates
// the offset from the beginning of the message and the length of a payload
// that occurs later in the message. Within the raw message there is also
// an additional field, however the field is always written with the same
// value as length, and readers must always ignore it.
struct SecurityBuffer {
  SecurityBuffer(uint32_t offset, uint16_t length)
      : offset(offset), length(length) {}
  SecurityBuffer() : SecurityBuffer(0, 0) {}

  uint32_t offset;
  uint16_t length;
};

enum class NtlmVersion {
  kNtlmV1 = 0x01,
  kNtlmV2 = 0x02,
};

// There are 3 types of messages in NTLM. The message type is a field in
// every NTLM message header. See [MS-NLMP] Section 2.2.
enum class MessageType : uint32_t {
  kNegotiate = 0x01,
  kChallenge = 0x02,
  kAuthenticate = 0x03,
};

// Defined in [MS-NLMP] Section 2.2.2.5
// Only the used subset is defined.
enum class NegotiateFlags : uint32_t {
  kNone = 0,
  kUnicode = 0x01,
  kOem = 0x02,
  kRequestTarget = 0x04,
  kNtlm = 0x200,
  kAlwaysSign = 0x8000,
  kExtendedSessionSecurity = 0x80000,
};

constexpr inline NegotiateFlags operator|(NegotiateFlags lhs,
                                          NegotiateFlags rhs) {
  using TFlagsInt = std::underlying_type<NegotiateFlags>::type;

  return static_cast<NegotiateFlags>(static_cast<TFlagsInt>(lhs) |
                                     static_cast<TFlagsInt>(rhs));
}

constexpr inline NegotiateFlags operator&(NegotiateFlags lhs,
                                          NegotiateFlags rhs) {
  using TFlagsInt = std::underlying_type<NegotiateFlags>::type;

  return static_cast<NegotiateFlags>(static_cast<TFlagsInt>(lhs) &
                                     static_cast<TFlagsInt>(rhs));
}

static constexpr uint8_t kSignature[] = "NTLMSSP";
static constexpr size_t kSignatureLen = arraysize(kSignature);
static constexpr size_t kSecurityBufferLen =
    (2 * sizeof(uint16_t)) + sizeof(uint32_t);
static constexpr size_t kNegotiateMessageLen = 32;
static constexpr size_t kMinChallengeHeaderLen = 32;
static constexpr size_t kChallengeHeaderLen = 32;
static constexpr size_t kResponseLenV1 = 24;
static constexpr size_t kChallengeLen = 8;
static constexpr size_t kNtlmHashLen = 16;
static constexpr size_t kAuthenticateHeaderLenV1 = 64;
static constexpr size_t kMaxFqdnLen = 255;
static constexpr size_t kMaxUsernameLen = 104;
static constexpr size_t kMaxPasswordLen = 256;

static constexpr NegotiateFlags kNegotiateMessageFlags =
    NegotiateFlags::kUnicode | NegotiateFlags::kOem |
    NegotiateFlags::kRequestTarget | NegotiateFlags::kNtlm |
    NegotiateFlags::kAlwaysSign | NegotiateFlags::kExtendedSessionSecurity;

}  // namespace ntlm
}  // namespace net

#endif  // NET_BASE_NTLM_CONSTANTS_H_