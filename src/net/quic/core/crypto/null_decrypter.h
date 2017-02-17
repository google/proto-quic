// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_CRYPTO_NULL_DECRYPTER_H_
#define NET_QUIC_CORE_CRYPTO_NULL_DECRYPTER_H_

#include <cstddef>
#include <cstdint>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/int128.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

class QuicDataReader;

// A NullDecrypter is a QuicDecrypter used before a crypto negotiation
// has occurred.  It does not actually decrypt the payload, but does
// verify a hash (fnv128) over both the payload and associated data.
class QUIC_EXPORT_PRIVATE NullDecrypter : public QuicDecrypter {
 public:
  explicit NullDecrypter(Perspective perspective);
  ~NullDecrypter() override {}

  // QuicDecrypter implementation
  bool SetKey(base::StringPiece key) override;
  bool SetNoncePrefix(base::StringPiece nonce_prefix) override;
  bool SetPreliminaryKey(base::StringPiece key) override;
  bool SetDiversificationNonce(const DiversificationNonce& nonce) override;
  bool DecryptPacket(QuicVersion version,
                     QuicPacketNumber packet_number,
                     base::StringPiece associated_data,
                     base::StringPiece ciphertext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override;
  base::StringPiece GetKey() const override;
  base::StringPiece GetNoncePrefix() const override;

  const char* cipher_name() const override;
  uint32_t cipher_id() const override;

 private:
  bool ReadHash(QuicDataReader* reader, uint128* hash);
  uint128 ComputeHash(QuicVersion version,
                      base::StringPiece data1,
                      base::StringPiece data2) const;

  Perspective perspective_;

  DISALLOW_COPY_AND_ASSIGN(NullDecrypter);
};

}  // namespace net

#endif  // NET_QUIC_CORE_CRYPTO_NULL_DECRYPTER_H_
