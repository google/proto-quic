// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_QUIC_PROCESS_PACKET_INTERFACE_H_
#define NET_TOOLS_QUIC_QUIC_PROCESS_PACKET_INTERFACE_H_

#include "base/macros.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_protocol.h"

namespace net {

// A class to process each incoming packet.
class ProcessPacketInterface {
 public:
  virtual ~ProcessPacketInterface() {}
  virtual void ProcessPacket(const IPEndPoint& server_address,
                             const IPEndPoint& client_address,
                             const QuicReceivedPacket& packet) = 0;
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_PROCESS_PACKET_INTERFACE_H_
