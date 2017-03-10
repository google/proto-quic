// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/crypto/local_strike_register_client.h"

#include "net/quic/core/crypto/crypto_protocol.h"

using std::string;

namespace net {

LocalStrikeRegisterClient::LocalStrikeRegisterClient(
    unsigned max_entries,
    uint32_t current_time_external,
    uint32_t window_secs,
    const uint8_t orbit[8],
    StrikeRegister::StartupType startup)
    : strike_register_(max_entries,
                       current_time_external,
                       window_secs,
                       orbit,
                       startup) {}

bool LocalStrikeRegisterClient::IsKnownOrbit(QuicStringPiece orbit) const {
  QuicWriterMutexLock lock(&m_);
  if (orbit.length() != kOrbitSize) {
    return false;
  }
  return memcmp(orbit.data(), strike_register_.orbit(), kOrbitSize) == 0;
}

void LocalStrikeRegisterClient::VerifyNonceIsValidAndUnique(
    QuicStringPiece nonce,
    QuicWallTime now,
    ResultCallback* cb) {
  InsertStatus nonce_error;
  if (nonce.length() != kNonceSize) {
    nonce_error = NONCE_INVALID_FAILURE;
  } else {
    QuicWriterMutexLock lock(&m_);
    nonce_error =
        strike_register_.Insert(reinterpret_cast<const uint8_t*>(nonce.data()),
                                static_cast<uint32_t>(now.ToUNIXSeconds()));
  }

  // m_ must not be held when the ResultCallback runs.
  cb->Run((nonce_error == NONCE_OK), nonce_error);
}

}  // namespace net
