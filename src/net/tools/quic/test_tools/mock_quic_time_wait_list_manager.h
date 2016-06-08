// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Common utilities for Quic tests

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_MOCK_QUIC_TIME_WAIT_LIST_MANAGER_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_MOCK_QUIC_TIME_WAIT_LIST_MANAGER_H_

#include "net/tools/quic/quic_time_wait_list_manager.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace net {
namespace test {

class MockTimeWaitListManager : public QuicTimeWaitListManager {
 public:
  MockTimeWaitListManager(QuicPacketWriter* writer,
                          QuicServerSessionBase::Visitor* visitor,
                          QuicConnectionHelperInterface* helper,
                          QuicAlarmFactory* alarm_factory);
  ~MockTimeWaitListManager() override;

  MOCK_METHOD4(AddConnectionIdToTimeWait,
               void(QuicConnectionId connection_id,
                    QuicVersion version,
                    bool connection_rejected_statelessly,
                    std::vector<std::unique_ptr<QuicEncryptedPacket>>*
                        termination_packets));

  void QuicTimeWaitListManager_AddConnectionIdToTimeWait(
      QuicConnectionId connection_id,
      QuicVersion version,
      bool connection_rejected_statelessly,
      std::vector<std::unique_ptr<QuicEncryptedPacket>>* termination_packets) {
    QuicTimeWaitListManager::AddConnectionIdToTimeWait(
        connection_id, version, connection_rejected_statelessly,
        termination_packets);
  }

  MOCK_METHOD5(ProcessPacket,
               void(const IPEndPoint& server_address,
                    const IPEndPoint& client_address,
                    QuicConnectionId connection_id,
                    QuicPacketNumber packet_number,
                    const QuicEncryptedPacket& packet));

  MOCK_METHOD4(SendVersionNegotiationPacket,
               void(QuicConnectionId connection_id,
                    const QuicVersionVector& supported_versions,
                    const IPEndPoint& server_address,
                    const IPEndPoint& client_address));
};

}  // namespace test
}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_MOCK_QUIC_TIME_WAIT_LIST_MANAGER_H_
