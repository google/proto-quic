// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_TEST_TOOLS_SIMULATOR_QUEUE_H_
#define NET_QUIC_TEST_TOOLS_SIMULATOR_QUEUE_H_

#include "net/quic/test_tools/simulator/link.h"

namespace net {
namespace simulator {

// A finitely sized queue which egresses packets onto a constrained link.  The
// capacity of the queue is measured in bytes as opposed to packets.
class Queue : public Actor, public UnconstrainedPortInterface {
 public:
  class ListenerInterface {
   public:
    virtual ~ListenerInterface();

    // Called whenever a packet is removed from the queue.
    virtual void OnPacketDequeued() = 0;
  };

  Queue(Simulator* simulator, std::string name, QuicByteCount capacity);
  ~Queue() override;

  void set_tx_port(ConstrainedPortInterface* port);

  void AcceptPacket(std::unique_ptr<Packet> packet) override;

  void Act() override;

  inline QuicByteCount capacity() const { return capacity_; }
  inline QuicByteCount bytes_queued() const { return bytes_queued_; }
  inline QuicPacketCount packets_queued() const { return queue_.size(); }

  inline void set_listener_interface(ListenerInterface* listener) {
    listener_ = listener;
  }

 private:
  void ScheduleNextPacketDequeue();

  const QuicByteCount capacity_;
  QuicByteCount bytes_queued_;

  ConstrainedPortInterface* tx_port_;
  std::queue<std::unique_ptr<Packet>> queue_;

  ListenerInterface* listener_;

  DISALLOW_COPY_AND_ASSIGN(Queue);
};

}  // namespace simulator
}  // namespace net

#endif  // NET_QUIC_TEST_TOOLS_SIMULATOR_QUEUE_H_
