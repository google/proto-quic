// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUARTC_QUARTC_FACTORY_INTERFACE_H_
#define NET_QUIC_QUARTC_QUARTC_FACTORY_INTERFACE_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "net/quic/platform/api/quic_export.h"
#include "net/quic/quartc/quartc_clock_interface.h"
#include "net/quic/quartc/quartc_session_interface.h"
#include "net/quic/quartc/quartc_task_runner_interface.h"

namespace net {

// Algorithm to use for congestion control.
enum class QuartcCongestionControl {
  kDefault,  // Use an arbitrary algorithm chosen by QUIC.
  kBBR,      // Use BBR.
};

// Used to create instances for Quartc objects such as QuartcSession.
class QUIC_EXPORT_PRIVATE QuartcFactoryInterface {
 public:
  virtual ~QuartcFactoryInterface() {}

  struct QuartcSessionConfig {
    // When using Quartc, there are two endpoints. The QuartcSession on one
    // endpoint must act as a server and the one on the other side must act as a
    // client.
    bool is_server = false;
    // This is only needed when is_server = false.  It must be unique
    // for each endpoint the local endpoint may communicate with. For example,
    // a WebRTC client could use the remote endpoint's crypto fingerprint
    std::string unique_remote_server_id;
    // The way the QuicConnection will send and receive packets, like a virtual
    // UDP socket. For WebRTC, this will typically be an IceTransport.
    QuartcSessionInterface::PacketTransport* packet_transport = nullptr;
    // The maximum size of the packet can be written with the packet writer.
    // 1200 bytes by default.
    uint64_t max_packet_size = 1200;
    // Algorithm to use for congestion control.  By default, uses an arbitrary
    // congestion control algorithm chosen by QUIC.
    QuartcCongestionControl congestion_control =
        QuartcCongestionControl::kDefault;
  };

  virtual std::unique_ptr<QuartcSessionInterface> CreateQuartcSession(
      const QuartcSessionConfig& quartc_config) = 0;
};

// The configuration for creating a QuartcFactory.
struct QuartcFactoryConfig {
  // The task runner used by the QuartcAlarm. Implemented by the Quartc user
  // with different mechanism. For example in WebRTC, it is implemented with
  // rtc::Thread. Owned by the user, and needs to stay alive for as long
  // as the QuartcFactory exists.
  QuartcTaskRunnerInterface* task_runner = nullptr;
  // The clock used by QuartcAlarms. Implemented by the Quartc user. Owned by
  // the user, and needs to stay alive for as long as the QuartcFactory exists.
  QuartcClockInterface* clock = nullptr;
};

// Creates a new instance of QuartcFactoryInterface.
std::unique_ptr<QuartcFactoryInterface> CreateQuartcFactory(
    const QuartcFactoryConfig& factory_config);

}  // namespace net

#endif  // NET_QUIC_QUARTC_QUARTC_FACTORY_INTERFACE_H_
