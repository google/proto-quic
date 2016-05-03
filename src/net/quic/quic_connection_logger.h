// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CONNECTION_LOGGER_H_
#define NET_QUIC_QUIC_CONNECTION_LOGGER_H_

#include <stddef.h>

#include <bitset>

#include "base/macros.h"
#include "net/base/ip_endpoint.h"
#include "net/base/network_change_notifier.h"
#include "net/log/net_log.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_spdy_session.h"
#include "net/socket/socket_performance_watcher.h"

namespace net {
namespace test {
class QuicConnectionLoggerPeer;
}  // namespace test

class CryptoHandshakeMessage;
class CertVerifyResult;

// This class is a debug visitor of a QuicConnection which logs
// events to |net_log|.
class NET_EXPORT_PRIVATE QuicConnectionLogger
    : public QuicConnectionDebugVisitor,
      public QuicPacketCreator::DebugDelegate {
 public:
  QuicConnectionLogger(
      QuicSpdySession* session,
      const char* const connection_description,
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      const BoundNetLog& net_log);

  ~QuicConnectionLogger() override;

  // QuicPacketCreator::DebugDelegateInterface
  void OnFrameAddedToPacket(const QuicFrame& frame) override;

  // QuicConnectionDebugVisitorInterface
  void OnPacketSent(const SerializedPacket& serialized_packet,
                    QuicPacketNumber original_packet_number,
                    TransmissionType transmission_type,
                    QuicTime sent_time) override;
  void OnPacketReceived(const IPEndPoint& self_address,
                        const IPEndPoint& peer_address,
                        const QuicEncryptedPacket& packet) override;
  void OnUnauthenticatedHeader(const QuicPacketHeader& header) override;
  void OnIncorrectConnectionId(QuicConnectionId connection_id) override;
  void OnUndecryptablePacket() override;
  void OnDuplicatePacket(QuicPacketNumber packet_number) override;
  void OnProtocolVersionMismatch(QuicVersion version) override;
  void OnPacketHeader(const QuicPacketHeader& header) override;
  void OnStreamFrame(const QuicStreamFrame& frame) override;
  void OnAckFrame(const QuicAckFrame& frame) override;
  void OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override;
  void OnRstStreamFrame(const QuicRstStreamFrame& frame) override;
  void OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override;
  void OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override;
  void OnBlockedFrame(const QuicBlockedFrame& frame) override;
  void OnGoAwayFrame(const QuicGoAwayFrame& frame) override;
  void OnPingFrame(const QuicPingFrame& frame) override;
  void OnPublicResetPacket(const QuicPublicResetPacket& packet) override;
  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& packet) override;
  void OnConnectionClosed(QuicErrorCode error,
                          const std::string& error_details,
                          ConnectionCloseSource source) override;
  void OnSuccessfulVersionNegotiation(const QuicVersion& version) override;
  void OnRttChanged(QuicTime::Delta rtt) const override;

  void OnCryptoHandshakeMessageReceived(const CryptoHandshakeMessage& message);
  void OnCryptoHandshakeMessageSent(const CryptoHandshakeMessage& message);
  void UpdateReceivedFrameCounts(QuicStreamId stream_id,
                                 int num_frames_received,
                                 int num_duplicate_frames_received);
  void OnCertificateVerified(const CertVerifyResult& result);

  // Returns connection's overall packet loss rate in fraction.
  float ReceivedPacketLossRate() const;

 private:
  friend class test::QuicConnectionLoggerPeer;

  // Do a factory get for a histogram for recording data, about individual
  // packet numbers, that was gathered in the vectors
  // received_packets_ and received_acks_. |statistic_name| identifies which
  // element of data is recorded, and is used to form the histogram name.
  base::HistogramBase* GetPacketNumberHistogram(
      const char* statistic_name) const;
  // Do a factory get for a histogram to record a 6-packet loss-sequence as a
  // sample. The histogram will record the 64 distinct possible combinations.
  // |which_6| is used to adjust the name of the histogram to distinguish the
  // first 6 packets in a connection, vs. some later 6 packets.
  base::HistogramBase* Get6PacketHistogram(const char* which_6) const;
  // Do a factory get for a histogram to record cumulative stats across a 21
  // packet sequence.  |which_21| is used to adjust the name of the histogram
  // to distinguish the first 21 packets' loss data, vs. some later 21 packet
  // sequences' loss data.
  base::HistogramBase* Get21CumulativeHistogram(const char* which_21) const;
  // Add samples associated with a |bit_mask_of_packets| to the given histogram
  // that was provided by Get21CumulativeHistogram().  The LSB of that mask
  // corresponds to the oldest packet number in the series of packets,
  // and the bit in the 2^20 position corresponds to the most recently received
  // packet.  Of the maximum of 21 bits that are valid (correspond to packets),
  // only the most significant |valid_bits_in_mask| are processed.
  // A bit value of 0 indicates that a packet was never received, and a 1
  // indicates the packet was received.
  static void AddTo21CumulativeHistogram(base::HistogramBase* histogram,
                                         int bit_mask_of_packets,
                                         int valid_bits_in_mask);
  // For connections longer than 21 received packets, this call will calculate
  // the overall packet loss rate, and record it into a histogram.
  void RecordAggregatePacketLossRate() const;
  // At destruction time, this records results of |pacaket_received_| into
  // histograms for specific connection types.
  void RecordLossHistograms() const;

  BoundNetLog net_log_;
  QuicSpdySession* session_;  // Unowned.
  // The last packet number received.
  QuicPacketNumber last_received_packet_number_;
  // The size of the most recently received packet.
  size_t last_received_packet_size_;
  // The size of the previously received packet.
  size_t previous_received_packet_size_;
  // The timestamp of last packet sent.
  QuicTime last_packet_sent_time_;
  // The largest packet number received.  In the case where a packet is
  // received late (out of order), this value will not be updated.
  QuicPacketNumber largest_received_packet_number_;
  // The largest packet number which the peer has failed to
  // receive, according to the missing packet set in their ack frames.
  QuicPacketNumber largest_received_missing_packet_number_;
  // Number of times that the current received packet number is
  // smaller than the last received packet number.
  size_t num_out_of_order_received_packets_;
  // Number of times that the current received packet number is
  // smaller than the last received packet number and where the
  // size of the current packet is larger than the size of the previous
  // packet.
  size_t num_out_of_order_large_received_packets_;
  // The number of times that OnPacketHeader was called.
  // If the network replicates packets, then this number may be slightly
  // different from the real number of distinct packets received.
  QuicPacketCount num_packets_received_;
  // Number of times a truncated ACK frame was sent.
  size_t num_truncated_acks_sent_;
  // Number of times a truncated ACK frame was received.
  size_t num_truncated_acks_received_;
  // The kCADR value provided by the server in ServerHello.
  IPEndPoint local_address_from_shlo_;
  // The first local address from which a packet was received.
  IPEndPoint local_address_from_self_;
  // Count of the number of frames received.
  int num_frames_received_;
  // Count of the number of duplicate frames received.
  int num_duplicate_frames_received_;
  // Count of the number of packets received with incorrect connection IDs.
  int num_incorrect_connection_ids_;
  // Count of the number of undecryptable packets received.
  int num_undecryptable_packets_;
  // Count of the number of duplicate packets received.
  int num_duplicate_packets_;
  // Count of the number of BLOCKED frames received.
  int num_blocked_frames_received_;
  // Count of the number of BLOCKED frames sent.
  int num_blocked_frames_sent_;
  // Vector of inital packets status' indexed by packet numbers, where
  // false means never received.  Zero is not a valid packet number, so
  // that offset is never used, and we'll track 150 packets.
  std::bitset<151> received_packets_;
  // Vector to indicate which of the initial 150 received packets turned out to
  // contain solo ACK frames.  An element is true iff an ACK frame was in the
  // corresponding packet, and there was very little else.
  std::bitset<151> received_acks_;
  // The available type of connection (WiFi, 3G, etc.) when connection was first
  // used.
  const char* const connection_description_;
  // Receives notifications regarding the performance of the underlying socket
  // for the QUIC connection. May be null.
  const std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher_;

  DISALLOW_COPY_AND_ASSIGN(QuicConnectionLogger);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CONNECTION_LOGGER_H_
