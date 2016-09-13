// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/congestion_control/simulation/port.h"

namespace net {
namespace simulation {

Packet::Packet()
    : source(), destination(), tx_timestamp(QuicTime::Zero()), size(0) {}

Packet::~Packet() {}

Packet::Packet(const Packet& packet) = default;

Endpoint::Endpoint(Simulator* simulator, std::string name)
    : Actor(simulator, name) {}

}  // namespace simulation
}  // namespace net
