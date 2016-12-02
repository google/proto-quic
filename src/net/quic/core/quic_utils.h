// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_UTILS_H_
#define NET_QUIC_CORE_QUIC_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/net_export.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_tag.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_socket_address.h"

#ifdef _MSC_VER
// MSVC 2013 and prior don't have alignof or aligned(); they have __alignof and
// a __declspec instead.
#define QUIC_ALIGN_OF __alignof
#define QUIC_ALIGNED(X) __declspec(align(X))
#else
#define QUIC_ALIGN_OF alignof
#define QUIC_ALIGNED(X) __attribute__((aligned(X)))
#endif  // _MSC_VER

namespace net {

class NET_EXPORT_PRIVATE QuicUtils {
 public:
  // Returns the 64 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint64_t FNV1a_64_Hash(const char* data, int len);

  // returns the 128 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash(const char* data1, int len1);

  // returns the 128 bit FNV1a hash of the two sequences of data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash_Two(const char* data1,
                                    int len1,
                                    const char* data2,
                                    int len2);

  // SerializeUint128 writes the first 96 bits of |v| in little-endian form
  // to |out|.
  static void SerializeUint128Short(uint128 v, uint8_t* out);

  // Returns the level of encryption as a char*
  static const char* EncryptionLevelToString(EncryptionLevel level);

  // Returns TransmissionType as a char*
  static const char* TransmissionTypeToString(TransmissionType type);

  // Returns the list of QUIC tags represented by the comma separated
  // string in |connection_options|.
  static QuicTagVector ParseQuicConnectionOptions(
      const std::string& connection_options);

  // Returns PeerAddressChangeType as a std::string.
  static std::string PeerAddressChangeTypeToString(PeerAddressChangeType type);

  // Returns a packed representation of |path_id| and |packet_number| in which
  // the highest byte is set to |path_id| and the lower 7 bytes are the lower
  // 7 bytes of |packet_number|.
  static uint64_t PackPathIdAndPacketNumber(QuicPathId path_id,
                                            QuicPacketNumber packet_number);

  // Determines and returns change type of address change from |old_address| to
  // |new_address|.
  static PeerAddressChangeType DetermineAddressChangeType(
      const QuicSocketAddress& old_address,
      const QuicSocketAddress& new_address);

  // This converts |length| bytes of binary to a 2*|length|-character
  // hexadecimal representation.
  // Return value: 2*|length| characters of ASCII std::string.
  static std::string HexEncode(const char* data, size_t length);
  static std::string HexEncode(base::StringPiece data);

  // Converts |data| from a hexadecimal ASCII std::string to binary.
  static std::string HexDecode(base::StringPiece data);

  // Returns a std::string containing hex and ASCII representations of |binary|,
  // side-by-side in the style of hexdump. Non-printable characters will be
  // printed as '.' in the ASCII output.
  // "0x0000:  4865 6c6c 6f2c 2051 5549 4321 0102 0304  Hello,.QUIC!...."
  static std::string HexDump(base::StringPiece binary_data);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicUtils);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_UTILS_H_
