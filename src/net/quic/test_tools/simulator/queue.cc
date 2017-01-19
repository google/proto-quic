// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/test_tools/simulator/queue.h"

using std::string;

namespace net {
namespace simulator {

Queue::ListenerInterface::~ListenerInterface() {}

Queue::Queue(Simulator* simulator, string name, QuicByteCount capacity)
    : Actor(simulator, name),
      capacity_(capacity),
      bytes_queued_(0),
      listener_(nullptr) {}

Queue::~Queue() {}

void Queue::set_tx_port(ConstrainedPortInterface* port) {
  tx_port_ = port;
}

void Queue::AcceptPacket(std::unique_ptr<Packet> packet) {
  if (packet->size + bytes_queued_ > capacity_) {
    QUIC_DVLOG(1) << "Queue [" << name() << "] has received a packet from ["
                  << packet->source << "] to [" << packet->destination
                  << "] which is over capacity.  Dropping it.";
    QUIC_DVLOG(1) << "Queue size: " << bytes_queued_ << " out of " << capacity_
                  << ".  Packet size: " << packet->size;
    return;
  }

  bytes_queued_ += packet->size;
  queue_.emplace(std::move(packet));
  ScheduleNextPacketDequeue();
}

void Queue::Act() {
  DCHECK(!queue_.empty());
  if (tx_port_->TimeUntilAvailable().IsZero()) {
    DCHECK(bytes_queued_ >= queue_.front()->size);
    bytes_queued_ -= queue_.front()->size;

    tx_port_->AcceptPacket(std::move(queue_.front()));
    queue_.pop();
    if (listener_ != nullptr) {
      listener_->OnPacketDequeued();
    }
  }

  ScheduleNextPacketDequeue();
}

void Queue::ScheduleNextPacketDequeue() {
  if (queue_.empty()) {
    DCHECK_EQ(bytes_queued_, 0u);
    return;
  }

  Schedule(clock_->Now() + tx_port_->TimeUntilAvailable());
}

}  // namespace simulator
}  // namespace net
