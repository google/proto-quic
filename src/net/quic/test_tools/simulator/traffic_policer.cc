// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/simulator/traffic_policer.h"

#include <algorithm>

namespace net {
namespace simulator {

TrafficPolicer::TrafficPolicer(Simulator* simulator,
                               std::string name,
                               QuicByteCount initial_bucket_size,
                               QuicByteCount max_bucket_size,
                               QuicBandwidth target_bandwidth,
                               Endpoint* input)
    : Actor(simulator, name),
      initial_bucket_size_(initial_bucket_size),
      max_bucket_size_(max_bucket_size),
      target_bandwidth_(target_bandwidth),
      last_refill_time_(clock_->Now()),
      input_(input),
      output_(this) {
  input_->SetTxPort(this);
}

TrafficPolicer::~TrafficPolicer() {}

void TrafficPolicer::Act() {}

void TrafficPolicer::Refill() {
  QuicTime::Delta time_passed = clock_->Now() - last_refill_time_;
  QuicByteCount refill_size = time_passed * target_bandwidth_;

  for (auto& bucket : token_buckets_) {
    bucket.second = std::min(bucket.second + refill_size, max_bucket_size_);
  }

  last_refill_time_ = clock_->Now();
}

void TrafficPolicer::AcceptPacket(std::unique_ptr<Packet> packet) {
  // Refill existing buckets.
  Refill();

  // Create a new bucket if one does not exist.
  if (token_buckets_.count(packet->destination) == 0) {
    token_buckets_.insert(
        std::make_pair(packet->destination, initial_bucket_size_));
  }

  auto bucket = token_buckets_.find(packet->destination);
  DCHECK(bucket != token_buckets_.end());

  // Silently drop the packet on the floor if out of tokens
  if (bucket->second < packet->size) {
    return;
  }

  bucket->second -= packet->size;
  output_tx_port_->AcceptPacket(std::move(packet));
}

QuicTime::Delta TrafficPolicer::TimeUntilAvailable() {
  return output_tx_port_->TimeUntilAvailable();
}

TrafficPolicer::Output::Output(TrafficPolicer* policer)
    : Endpoint(policer->simulator(), policer->name() + " (output port)"),
      policer_(policer) {}

TrafficPolicer::Output::~Output() {}

UnconstrainedPortInterface* TrafficPolicer::Output::GetRxPort() {
  return policer_->input_->GetRxPort();
}

void TrafficPolicer::Output::SetTxPort(ConstrainedPortInterface* port) {
  policer_->output_tx_port_ = port;
}

void TrafficPolicer::Output::Act() {}

}  // namespace simulator
}  // namespace net
