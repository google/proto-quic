// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_time_wait_list_manager_peer.h"

namespace net {
namespace test {

bool QuicTimeWaitListManagerPeer::ShouldSendResponse(
    QuicTimeWaitListManager* manager,
    int received_packet_count) {
  return manager->ShouldSendResponse(received_packet_count);
}

QuicTime::Delta QuicTimeWaitListManagerPeer::time_wait_period(
    QuicTimeWaitListManager* manager) {
  return manager->time_wait_period_;
}

QuicVersion QuicTimeWaitListManagerPeer::GetQuicVersionFromConnectionId(
    QuicTimeWaitListManager* manager,
    QuicConnectionId connection_id) {
  return manager->GetQuicVersionFromConnectionId(connection_id);
}

QuicAlarm* QuicTimeWaitListManagerPeer::expiration_alarm(
    QuicTimeWaitListManager* manager) {
  return manager->connection_id_clean_up_alarm_.get();
}

void QuicTimeWaitListManagerPeer::set_clock(QuicTimeWaitListManager* manager,
                                            const QuicClock* clock) {
  manager->clock_ = clock;
}

}  // namespace test
}  // namespace net
