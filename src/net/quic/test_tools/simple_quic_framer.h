// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_SIMPLE_QUIC_FRAMER_H_
#define NET_QUIC_TEST_TOOLS_SIMPLE_QUIC_FRAMER_H_

#include <memory>
#include <vector>

#include "base/macros.h"
#include "net/quic/core/quic_framer.h"
#include "net/quic/core/quic_packets.h"

namespace net {

struct QuicAckFrame;

namespace test {

class SimpleFramerVisitor;

// Peer to make public a number of otherwise private QuicFramer methods.
class SimpleQuicFramer {
 public:
  SimpleQuicFramer();
  explicit SimpleQuicFramer(const QuicVersionVector& supported_versions);
  SimpleQuicFramer(const QuicVersionVector& supported_versions,
                   Perspective perspective);
  ~SimpleQuicFramer();

  bool ProcessPacket(const QuicEncryptedPacket& packet);
  void Reset();

  const QuicPacketHeader& header() const;
  size_t num_frames() const;
  const std::vector<QuicAckFrame>& ack_frames() const;
  const std::vector<QuicConnectionCloseFrame>& connection_close_frames() const;
  const std::vector<QuicStopWaitingFrame>& stop_waiting_frames() const;
  const std::vector<QuicPingFrame>& ping_frames() const;
  const std::vector<QuicGoAwayFrame>& goaway_frames() const;
  const std::vector<QuicRstStreamFrame>& rst_stream_frames() const;
  const std::vector<std::unique_ptr<QuicStreamFrame>>& stream_frames() const;
  const QuicVersionNegotiationPacket* version_negotiation_packet() const;

  QuicFramer* framer();

  void SetSupportedVersions(const QuicVersionVector& versions) {
    framer_.SetSupportedVersions(versions);
  }

 private:
  QuicFramer framer_;
  std::unique_ptr<SimpleFramerVisitor> visitor_;
  DISALLOW_COPY_AND_ASSIGN(SimpleQuicFramer);
};

}  // namespace test

}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_SIMPLE_QUIC_FRAMER_H_
