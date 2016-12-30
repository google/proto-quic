// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_CRYPTO_LOCAL_STRIKE_REGISTER_CLIENT_H_
#define NET_QUIC_CORE_CRYPTO_LOCAL_STRIKE_REGISTER_CLIENT_H_

#include <cstdint>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/core/crypto/strike_register.h"
#include "net/quic/core/crypto/strike_register_client.h"
#include "net/quic/core/quic_time.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_mutex.h"

namespace net {

// StrikeRegisterClient implementation that wraps a local in-memory
// strike register.
class QUIC_EXPORT_PRIVATE LocalStrikeRegisterClient
    : public StrikeRegisterClient {
 public:
  LocalStrikeRegisterClient(unsigned max_entries,
                            uint32_t current_time_external,
                            uint32_t window_secs,
                            const uint8_t orbit[8],
                            StrikeRegister::StartupType startup);

  bool IsKnownOrbit(base::StringPiece orbit) const override;
  void VerifyNonceIsValidAndUnique(base::StringPiece nonce,
                                   QuicWallTime now,
                                   ResultCallback* cb) override;

 private:
  mutable QuicMutex m_;
  StrikeRegister strike_register_ GUARDED_BY(m_);

  DISALLOW_COPY_AND_ASSIGN(LocalStrikeRegisterClient);
};

}  // namespace net

#endif  // NET_QUIC_CORE_CRYPTO_LOCAL_STRIKE_REGISTER_CLIENT_H_
