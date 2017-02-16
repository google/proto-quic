// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/crypto/null_decrypter.h"

#include <cstdint>

#include "net/base/int128.h"
#include "net/quic/core/quic_data_reader.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"

using base::StringPiece;
using std::string;

namespace net {

NullDecrypter::NullDecrypter(Perspective perspective)
    : perspective_(perspective) {}

bool NullDecrypter::SetKey(StringPiece key) {
  return key.empty();
}

bool NullDecrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  return nonce_prefix.empty();
}

bool NullDecrypter::SetPreliminaryKey(StringPiece key) {
  QUIC_BUG << "Should not be called";
  return false;
}

bool NullDecrypter::SetDiversificationNonce(const DiversificationNonce& nonce) {
  QUIC_BUG << "Should not be called";
  return true;
}

bool NullDecrypter::DecryptPacket(QuicVersion version,
                                  QuicPacketNumber /*packet_number*/,
                                  StringPiece associated_data,
                                  StringPiece ciphertext,
                                  char* output,
                                  size_t* output_length,
                                  size_t max_output_length) {
  QuicDataReader reader(ciphertext.data(), ciphertext.length());
  uint128 hash;

  if (!ReadHash(&reader, &hash)) {
    return false;
  }

  StringPiece plaintext = reader.ReadRemainingPayload();
  if (plaintext.length() > max_output_length) {
    QUIC_BUG << "Output buffer must be larger than the plaintext.";
    return false;
  }
  if (hash != ComputeHash(version, associated_data, plaintext)) {
    return false;
  }
  // Copy the plaintext to output.
  memcpy(output, plaintext.data(), plaintext.length());
  *output_length = plaintext.length();
  return true;
}

StringPiece NullDecrypter::GetKey() const {
  return StringPiece();
}

StringPiece NullDecrypter::GetNoncePrefix() const {
  return StringPiece();
}

const char* NullDecrypter::cipher_name() const {
  return "NULL";
}

uint32_t NullDecrypter::cipher_id() const {
  return 0;
}

bool NullDecrypter::ReadHash(QuicDataReader* reader, uint128* hash) {
  uint64_t lo;
  uint32_t hi;
  if (!reader->ReadUInt64(&lo) || !reader->ReadUInt32(&hi)) {
    return false;
  }
  *hash = MakeUint128(hi, lo);
  return true;
}

uint128 NullDecrypter::ComputeHash(QuicVersion version,
                                   const StringPiece data1,
                                   const StringPiece data2) const {
  uint128 correct_hash;
  if (version > QUIC_VERSION_36) {
    if (perspective_ == Perspective::IS_CLIENT) {
      // Peer is a server.
      correct_hash = QuicUtils::FNV1a_128_Hash_Three(data1, data2, "Server");

    } else {
      // Peer is a client.
      correct_hash = QuicUtils::FNV1a_128_Hash_Three(data1, data2, "Client");
    }
  } else {
    correct_hash = QuicUtils::FNV1a_128_Hash_Two(data1, data2);
  }
  uint128 mask = MakeUint128(UINT64_C(0x0), UINT64_C(0xffffffff));
  mask <<= 96;
  correct_hash &= ~mask;
  return correct_hash;
}

}  // namespace net
