// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_DELAYED_VERIFY_STRIKE_REGISTER_CLIENT_H_
#define NET_QUIC_TEST_TOOLS_DELAYED_VERIFY_STRIKE_REGISTER_CLIENT_H_

#include <cstdint>
#include <string>
#include <vector>

#include "base/macros.h"
#include "net/quic/core/crypto/local_strike_register_client.h"
#include "net/quic/platform/api/quic_string_piece.h"

namespace net {
namespace test {

// Test helper that allows delaying execution of nonce verification
// callbacks until a later time.
class DelayedVerifyStrikeRegisterClient : public LocalStrikeRegisterClient {
 public:
  DelayedVerifyStrikeRegisterClient(unsigned max_entries,
                                    uint32_t current_time_external,
                                    uint32_t window_secs,
                                    const uint8_t orbit[8],
                                    StrikeRegister::StartupType startup);
  ~DelayedVerifyStrikeRegisterClient() override;

  void VerifyNonceIsValidAndUnique(QuicStringPiece nonce,
                                   QuicWallTime now,
                                   ResultCallback* cb) override;

  // Start queueing verifications instead of executing them immediately.
  void StartDelayingVerification() { delay_verifications_ = true; }
  // Number of verifications that are queued.
  int PendingVerifications() const;
  // Run all pending verifications.
  void RunPendingVerifications();

 private:
  struct VerifyArgs {
    VerifyArgs(QuicStringPiece in_nonce,
               QuicWallTime in_now,
               ResultCallback* in_cb)
        : nonce(in_nonce.as_string()), now(in_now), cb(in_cb) {}

    std::string nonce;
    QuicWallTime now;
    ResultCallback* cb;
  };

  bool delay_verifications_;
  std::vector<VerifyArgs> pending_verifications_;

  DISALLOW_COPY_AND_ASSIGN(DelayedVerifyStrikeRegisterClient);
};

}  // namespace test
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_DELAYED_VERIFY_STRIKE_REGISTER_CLIENT_H_
