// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_QUIC_UTILS_H_
#define NET_QUIC_CORE_QUIC_UTILS_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_socket_address.h"

namespace net {

class QUIC_EXPORT_PRIVATE QuicUtils {
 public:
  // Returns the 64 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint64_t FNV1a_64_Hash(base::StringPiece data);

  // Returns the 128 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash(base::StringPiece data);

  // Returns the 128 bit FNV1a hash of the two sequences of data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash_Two(base::StringPiece data1,
                                    base::StringPiece data2);

  // Returns the 128 bit FNV1a hash of the three sequences of data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash_Three(base::StringPiece data1,
                                      base::StringPiece data2,
                                      base::StringPiece data3);

  // SerializeUint128 writes the first 96 bits of |v| in little-endian form
  // to |out|.
  static void SerializeUint128Short(uint128 v, uint8_t* out);

  // Returns the level of encryption as a char*
  static const char* EncryptionLevelToString(EncryptionLevel level);

  // Returns TransmissionType as a char*
  static const char* TransmissionTypeToString(TransmissionType type);

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

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicUtils);
};

}  // namespace net

#endif  // NET_QUIC_CORE_QUIC_UTILS_H_
