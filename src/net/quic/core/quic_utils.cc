// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_utils.h"

#include <ctype.h>
#include <stdint.h>

#include <algorithm>
#include <vector>

#include "base/containers/adapters.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "net/quic/core/quic_constants.h"
#include "net/quic/core/quic_flags.h"

using base::StringPiece;
using std::string;

namespace net {
namespace {

// We know that >= GCC 4.8 and Clang have a __uint128_t intrinsic. Other
// compilers don't necessarily, notably MSVC.
#if defined(__x86_64__) &&                                         \
    ((defined(__GNUC__) &&                                         \
      (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8))) || \
     defined(__clang__))
#define QUIC_UTIL_HAS_UINT128 1
#endif

#ifdef QUIC_UTIL_HAS_UINT128
uint128 IncrementalHashFast(uint128 uhash, const char* data, size_t len) {
  // This code ends up faster than the naive implementation for 2 reasons:
  // 1. uint128 from base/int128.h is sufficiently complicated that the compiler
  //    cannot transform the multiplication by kPrime into a shift-multiply-add;
  //    it has go through all of the instructions for a 128-bit multiply.
  // 2. Because there are so fewer instructions (around 13), the hot loop fits
  //    nicely in the instruction queue of many Intel CPUs.
  // kPrime = 309485009821345068724781371
  static const __uint128_t kPrime =
      (static_cast<__uint128_t>(16777216) << 64) + 315;
  __uint128_t xhash = (static_cast<__uint128_t>(Uint128High64(uhash)) << 64) +
                      Uint128Low64(uhash);
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data);
  for (size_t i = 0; i < len; ++i) {
    xhash = (xhash ^ octets[i]) * kPrime;
  }
  return uint128(static_cast<uint64_t>(xhash >> 64),
                 static_cast<uint64_t>(xhash & UINT64_C(0xFFFFFFFFFFFFFFFF)));
}
#endif

#ifndef QUIC_UTIL_HAS_UINT128
// Slow implementation of IncrementalHash. In practice, only used by Chromium.
uint128 IncrementalHashSlow(uint128 hash, const char* data, size_t len) {
  // kPrime = 309485009821345068724781371
  static const uint128 kPrime(16777216, 315);
  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data);
  for (size_t i = 0; i < len; ++i) {
    hash = hash ^ uint128(0, octets[i]);
    hash = hash * kPrime;
  }
  return hash;
}
#endif

uint128 IncrementalHash(uint128 hash, const char* data, size_t len) {
#ifdef QUIC_UTIL_HAS_UINT128
  return IncrementalHashFast(hash, data, len);
#else
  return IncrementalHashSlow(hash, data, len);
#endif
}

}  // namespace

// static
uint64_t QuicUtils::FNV1a_64_Hash(const char* data, int len) {
  static const uint64_t kOffset = UINT64_C(14695981039346656037);
  static const uint64_t kPrime = UINT64_C(1099511628211);

  const uint8_t* octets = reinterpret_cast<const uint8_t*>(data);

  uint64_t hash = kOffset;

  for (int i = 0; i < len; ++i) {
    hash = hash ^ octets[i];
    hash = hash * kPrime;
  }

  return hash;
}

// static
uint128 QuicUtils::FNV1a_128_Hash(const char* data, int len) {
  return FNV1a_128_Hash_Two(data, len, nullptr, 0);
}

// static
uint128 QuicUtils::FNV1a_128_Hash_Two(const char* data1,
                                      int len1,
                                      const char* data2,
                                      int len2) {
  // The two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // kOffset = 144066263297769815596495629667062367629
  const uint128 kOffset(UINT64_C(7809847782465536322),
                        UINT64_C(7113472399480571277));

  uint128 hash = IncrementalHash(kOffset, data1, len1);
  if (data2 == nullptr) {
    return hash;
  }
  return IncrementalHash(hash, data2, len2);
}

// static
void QuicUtils::SerializeUint128Short(uint128 v, uint8_t* out) {
  const uint64_t lo = Uint128Low64(v);
  const uint64_t hi = Uint128High64(v);
  // This assumes that the system is little-endian.
  memcpy(out, &lo, sizeof(lo));
  memcpy(out + sizeof(lo), &hi, sizeof(hi) / 2);
}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x;

// static
const char* QuicUtils::EncryptionLevelToString(EncryptionLevel level) {
  switch (level) {
    RETURN_STRING_LITERAL(ENCRYPTION_NONE);
    RETURN_STRING_LITERAL(ENCRYPTION_INITIAL);
    RETURN_STRING_LITERAL(ENCRYPTION_FORWARD_SECURE);
    RETURN_STRING_LITERAL(NUM_ENCRYPTION_LEVELS);
  }
  return "INVALID_ENCRYPTION_LEVEL";
}

// static
const char* QuicUtils::TransmissionTypeToString(TransmissionType type) {
  switch (type) {
    RETURN_STRING_LITERAL(NOT_RETRANSMISSION);
    RETURN_STRING_LITERAL(HANDSHAKE_RETRANSMISSION);
    RETURN_STRING_LITERAL(LOSS_RETRANSMISSION);
    RETURN_STRING_LITERAL(ALL_UNACKED_RETRANSMISSION);
    RETURN_STRING_LITERAL(ALL_INITIAL_RETRANSMISSION);
    RETURN_STRING_LITERAL(RTO_RETRANSMISSION);
    RETURN_STRING_LITERAL(TLP_RETRANSMISSION);
  }
  return "INVALID_TRANSMISSION_TYPE";
}

// static
QuicTagVector QuicUtils::ParseQuicConnectionOptions(
    const std::string& connection_options) {
  QuicTagVector options;
  // Tokens are expected to be no more than 4 characters long, but we
  // handle overflow gracefully.
  for (const base::StringPiece& token :
       base::SplitStringPiece(connection_options, ",", base::TRIM_WHITESPACE,
                              base::SPLIT_WANT_ALL)) {
    uint32_t option = 0;
    for (char token_char : base::Reversed(token)) {
      option <<= 8;
      option |= static_cast<unsigned char>(token_char);
    }
    options.push_back(option);
  }
  return options;
}

string QuicUtils::PeerAddressChangeTypeToString(PeerAddressChangeType type) {
  switch (type) {
    RETURN_STRING_LITERAL(NO_CHANGE);
    RETURN_STRING_LITERAL(PORT_CHANGE);
    RETURN_STRING_LITERAL(IPV4_SUBNET_CHANGE);
    RETURN_STRING_LITERAL(IPV4_TO_IPV6_CHANGE);
    RETURN_STRING_LITERAL(IPV6_TO_IPV4_CHANGE);
    RETURN_STRING_LITERAL(IPV6_TO_IPV6_CHANGE);
    RETURN_STRING_LITERAL(IPV4_TO_IPV4_CHANGE);
  }
  return "INVALID_PEER_ADDRESS_CHANGE_TYPE";
}

// static
uint64_t QuicUtils::PackPathIdAndPacketNumber(QuicPathId path_id,
                                              QuicPacketNumber packet_number) {
  // Setting the nonce below relies on QuicPathId and QuicPacketNumber being
  // specific sizes.
  static_assert(sizeof(path_id) == 1, "Size of QuicPathId changed.");
  static_assert(sizeof(packet_number) == 8,
                "Size of QuicPacketNumber changed.");
  // Use path_id and lower 7 bytes of packet_number as lower 8 bytes of nonce.
  uint64_t path_id_packet_number =
      (static_cast<uint64_t>(path_id) << 56) | packet_number;
  DCHECK(path_id != kDefaultPathId || path_id_packet_number == packet_number);
  return path_id_packet_number;
}

// static
PeerAddressChangeType QuicUtils::DetermineAddressChangeType(
    const QuicSocketAddress& old_address,
    const QuicSocketAddress& new_address) {
  if (!old_address.IsInitialized() || !new_address.IsInitialized() ||
      old_address == new_address) {
    return NO_CHANGE;
  }

  if (old_address.host() == new_address.host()) {
    return PORT_CHANGE;
  }

  bool old_ip_is_ipv4 = old_address.host().IsIPv4() ? true : false;
  bool migrating_ip_is_ipv4 = new_address.host().IsIPv4() ? true : false;
  if (old_ip_is_ipv4 && !migrating_ip_is_ipv4) {
    return IPV4_TO_IPV6_CHANGE;
  }

  if (!old_ip_is_ipv4) {
    return migrating_ip_is_ipv4 ? IPV6_TO_IPV4_CHANGE : IPV6_TO_IPV6_CHANGE;
  }

  const int kSubnetMaskLength = 24;
  if (old_address.host().InSameSubnet(new_address.host(), kSubnetMaskLength)) {
    // Subnet part does not change (here, we use /24), which is considered to be
    // caused by NATs.
    return IPV4_SUBNET_CHANGE;
  }

  return IPV4_TO_IPV4_CHANGE;
}

string QuicUtils::HexEncode(const char* data, size_t length) {
  return HexEncode(StringPiece(data, length));
}

string QuicUtils::HexEncode(StringPiece data) {
  return ::base::HexEncode(data.data(), data.size());
}

string QuicUtils::HexDecode(StringPiece data) {
  if (data.empty())
    return "";
  std::vector<uint8_t> v;
  if (!base::HexStringToBytes(data.as_string(), &v))
    return "";
  string out;
  if (!v.empty())
    out.assign(reinterpret_cast<const char*>(&v[0]), v.size());
  return out;
}

string QuicUtils::HexDump(StringPiece binary_input) {
  int offset = 0;
  const int kBytesPerLine = 16;  // Max bytes dumped per line
  const char* buf = binary_input.data();
  int bytes_remaining = binary_input.size();
  string s;  // our output
  const char* p = buf;
  while (bytes_remaining > 0) {
    const int line_bytes = std::min(bytes_remaining, kBytesPerLine);
    base::StringAppendF(&s, "0x%04x:  ", offset);  // Do the line header
    for (int i = 0; i < kBytesPerLine; ++i) {
      if (i < line_bytes) {
        base::StringAppendF(&s, "%02x", static_cast<unsigned char>(p[i]));
      } else {
        s += "  ";  // two-space filler instead of two-space hex digits
      }
      if (i % 2)
        s += ' ';
    }
    s += ' ';
    for (int i = 0; i < line_bytes; ++i) {  // Do the ASCII dump
      s += (p[i] > 32 && p[i] < 127) ? p[i] : '.';
    }

    bytes_remaining -= line_bytes;
    offset += line_bytes;
    p += line_bytes;
    s += '\n';
  }
  return s;
}

}  // namespace net
