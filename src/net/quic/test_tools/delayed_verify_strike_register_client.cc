// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/delayed_verify_strike_register_client.h"

using base::StringPiece;
using std::string;
using std::vector;

namespace net {
namespace test {

DelayedVerifyStrikeRegisterClient::DelayedVerifyStrikeRegisterClient(
    unsigned max_entries,
    uint32_t current_time_external,
    uint32_t window_secs,
    const uint8_t orbit[8],
    StrikeRegister::StartupType startup)
    : LocalStrikeRegisterClient(max_entries,
                                current_time_external,
                                window_secs,
                                orbit,
                                startup),
      delay_verifications_(false) {}

DelayedVerifyStrikeRegisterClient::~DelayedVerifyStrikeRegisterClient() {}

void DelayedVerifyStrikeRegisterClient::VerifyNonceIsValidAndUnique(
    StringPiece nonce,
    QuicWallTime now,
    ResultCallback* cb) {
  if (delay_verifications_) {
    pending_verifications_.push_back(VerifyArgs(nonce, now, cb));
  } else {
    LocalStrikeRegisterClient::VerifyNonceIsValidAndUnique(nonce, now, cb);
  }
}

int DelayedVerifyStrikeRegisterClient::PendingVerifications() const {
  return pending_verifications_.size();
}

void DelayedVerifyStrikeRegisterClient::RunPendingVerifications() {
  vector<VerifyArgs> pending;
  pending_verifications_.swap(pending);
  for (vector<VerifyArgs>::const_iterator it = pending.begin(),
                                          end = pending.end();
       it != end; ++it) {
    LocalStrikeRegisterClient::VerifyNonceIsValidAndUnique(it->nonce, it->now,
                                                           it->cb);
  }
}

}  // namespace test
}  // namespace net
