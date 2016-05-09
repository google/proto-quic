// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Handles packets for connection_ids in time wait state by discarding the
// packet and sending the clients a public reset packet with exponential
// backoff.

#ifndef NET_TOOLS_QUIC_QUIC_TIME_WAIT_LIST_MANAGER_H_
#define NET_TOOLS_QUIC_QUIC_TIME_WAIT_LIST_MANAGER_H_

#include <stddef.h>

#include <deque>
#include <memory>

#include "base/macros.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/quic_blocked_writer_interface.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_protocol.h"

namespace net {

class QuicServerSessionVisitor;

namespace test {
class QuicTimeWaitListManagerPeer;
}  // namespace test

// Maintains a list of all connection_ids that have been recently closed. A
// connection_id lives in this state for time_wait_period_. All packets received
// for connection_ids in this state are handed over to the
// QuicTimeWaitListManager by the QuicDispatcher.  Decides whether to send a
// public reset packet, a copy of the previously sent connection close packet,
// or nothing to the client which sent a packet with the connection_id in time
// wait state.  After the connection_id expires its time wait period, a new
// connection/session will be created if a packet is received for this
// connection_id.
class QuicTimeWaitListManager : public QuicBlockedWriterInterface {
 public:
  // writer - the entity that writes to the socket. (Owned by the dispatcher)
  // visitor - the entity that manages blocked writers. (The dispatcher)
  // helper - provides a clock (Owned by the dispatcher)
  // alarm_factory - used to run clean up alarms. (Owned by the dispatcher)
  QuicTimeWaitListManager(QuicPacketWriter* writer,
                          QuicServerSessionVisitor* visitor,
                          QuicConnectionHelperInterface* helper,
                          QuicAlarmFactory* alarm_factory);
  ~QuicTimeWaitListManager() override;

  // Adds the given connection_id to time wait state for time_wait_period_.
  // If |termination_packets| are provided, copies of these packets will be sent
  // when a packet with this connection ID is processed. If no termination
  // packets are provided, then a PUBLIC_RESET will be sent with the specified
  // |version|. Any termination packets will be move from |termination_packets|
  // and will become owned by the manager. If |connection_rejected_statelessly|
  // is true, it means that the connection was closed due to a stateless reject,
  // and termination packets are expected.
  virtual void AddConnectionIdToTimeWait(
      QuicConnectionId connection_id,
      QuicVersion version,
      bool connection_rejected_statelessly,
      std::vector<std::unique_ptr<QuicEncryptedPacket>>* termination_packets);

  // Returns true if the connection_id is in time wait state, false otherwise.
  // Packets received for this connection_id should not lead to creation of new
  // QuicSessions.
  bool IsConnectionIdInTimeWait(QuicConnectionId connection_id) const;

  // Called when a packet is received for a connection_id that is in time wait
  // state. Sends a public reset packet to the client which sent this
  // connection_id. Sending of the public reset packet is throttled by using
  // exponential back off. DCHECKs for the connection_id to be in time wait
  // state. virtual to override in tests.
  virtual void ProcessPacket(const IPEndPoint& server_address,
                             const IPEndPoint& client_address,
                             QuicConnectionId connection_id,
                             QuicPacketNumber packet_number,
                             const QuicEncryptedPacket& packet);

  // Called by the dispatcher when the underlying socket becomes writable again,
  // since we might need to send pending public reset packets which we didn't
  // send because the underlying socket was write blocked.
  void OnCanWrite() override;

  // Used to delete connection_id entries that have outlived their time wait
  // period.
  void CleanUpOldConnectionIds();

  // If necessary, trims the oldest connections from the time-wait list until
  // the size is under the configured maximum.
  void TrimTimeWaitListIfNeeded();

  // Given a ConnectionId that exists in the time wait list, returns the
  // QuicVersion associated with it.
  QuicVersion GetQuicVersionFromConnectionId(QuicConnectionId connection_id);

  // The number of connections on the time-wait list.
  size_t num_connections() const { return connection_id_map_.size(); }

  // Sends a version negotiation packet for |connection_id| announcing support
  // for |supported_versions| to |client_address| from |server_address|.
  virtual void SendVersionNegotiationPacket(
      QuicConnectionId connection_id,
      const QuicVersionVector& supported_versions,
      const IPEndPoint& server_address,
      const IPEndPoint& client_address);

 protected:
  virtual QuicEncryptedPacket* BuildPublicReset(
      const QuicPublicResetPacket& packet);

 private:
  friend class test::QuicTimeWaitListManagerPeer;

  // Internal structure to store pending public reset packets.
  class QueuedPacket;

  // Decides if a packet should be sent for this connection_id based on the
  // number of received packets.
  bool ShouldSendResponse(int received_packet_count);

  // Creates a public reset packet and sends it or queues it to be sent later.
  void SendPublicReset(const IPEndPoint& server_address,
                       const IPEndPoint& client_address,
                       QuicConnectionId connection_id,
                       QuicPacketNumber rejected_packet_number);

  // Either sends the packet and deletes it or makes pending_packets_queue_ the
  // owner of the packet.
  void SendOrQueuePacket(QueuedPacket* packet);

  // Sends the packet out. Returns true if the packet was successfully consumed.
  // If the writer got blocked and did not buffer the packet, we'll need to keep
  // the packet and retry sending. In case of all other errors we drop the
  // packet.
  bool WriteToWire(QueuedPacket* packet);

  // Register the alarm server to wake up at appropriate time.
  void SetConnectionIdCleanUpAlarm();

  // Removes the oldest connection from the time-wait list if it was added prior
  // to "expiration_time".  To unconditionally remove the oldest connection, use
  // a QuicTime::Delta:Infinity().  This function modifies the
  // connection_id_map_.  If you plan to call this function in a loop, any
  // iterators that you hold before the call to this function may be invalid
  // afterward.  Returns true if the oldest connection was expired.  Returns
  // false if the map is empty or the oldest connection has not expired.
  bool MaybeExpireOldestConnection(QuicTime expiration_time);

  // A map from a recently closed connection_id to the number of packets
  // received after the termination of the connection bound to the
  // connection_id.
  struct ConnectionIdData {
    ConnectionIdData(int num_packets_,
                     QuicVersion version_,
                     QuicTime time_added_,
                     bool connection_rejected_statelessly);

    ConnectionIdData(const ConnectionIdData& other) = delete;
    ConnectionIdData(ConnectionIdData&& other);

    ~ConnectionIdData();

    int num_packets;
    QuicVersion version;
    QuicTime time_added;
    // These packets may contain CONNECTION_CLOSE frames, or SREJ messages.
    std::vector<std::unique_ptr<QuicEncryptedPacket>> termination_packets;
    bool connection_rejected_statelessly;
  };

  // linked_hash_map allows lookup by ConnectionId and traversal in add order.
  typedef linked_hash_map<QuicConnectionId, ConnectionIdData> ConnectionIdMap;
  ConnectionIdMap connection_id_map_;

  // Pending public reset packets that need to be sent out to the client
  // when we are given a chance to write by the dispatcher.
  std::deque<QueuedPacket*> pending_packets_queue_;

  // Time period for which connection_ids should remain in time wait state.
  const QuicTime::Delta time_wait_period_;

  // Alarm to clean up connection_ids that have out lived their duration in
  // time wait state.
  std::unique_ptr<QuicAlarm> connection_id_clean_up_alarm_;

  // Clock to efficiently measure approximate time.
  const QuicClock* clock_;

  // Interface that writes given buffer to the socket.
  QuicPacketWriter* writer_;

  // Interface that manages blocked writers.
  QuicServerSessionVisitor* visitor_;

  DISALLOW_COPY_AND_ASSIGN(QuicTimeWaitListManager);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_TIME_WAIT_LIST_MANAGER_H_
