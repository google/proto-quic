// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A toy client, which connects to a specified port and sends QUIC
// request to that endpoint.

#ifndef NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_
#define NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/core/quic_config.h"
#include "net/quic/core/quic_spdy_stream.h"
#include "net/tools/quic/quic_client_base.h"

namespace net {

class QuicChromiumAlarmFactory;
class QuicChromiumConnectionHelper;
class UDPClientSocket;


namespace test {
class QuicClientPeer;
}  // namespace test

class QuicSimpleClient : public QuicClientBase,
                         public QuicChromiumPacketReader::Visitor {
 public:
  // Create a quic client, which will have events managed by an externally owned
  // EpollServer.
  QuicSimpleClient(IPEndPoint server_address,
                   const QuicServerId& server_id,
                   const QuicVersionVector& supported_versions,
                   std::unique_ptr<ProofVerifier> proof_verifier);
  QuicSimpleClient(IPEndPoint server_address,
                   const QuicServerId& server_id,
                   const QuicVersionVector& supported_versions,
                   const QuicConfig& config,
                   std::unique_ptr<ProofVerifier> proof_verifier);

  ~QuicSimpleClient() override;

  // QuicChromiumPacketReader::Visitor
  void OnReadError(int result, const DatagramClientSocket* socket) override;
  bool OnPacket(const QuicReceivedPacket& packet,
                IPEndPoint local_address,
                IPEndPoint peer_address) override;

  // From QuicClientBase
  QuicSocketAddress GetLatestClientAddress() const override;

 protected:
  // From QuicClientBase
  QuicPacketWriter* CreateQuicPacketWriter() override;
  void RunEventLoop() override;
  bool CreateUDPSocketAndBind(QuicSocketAddress server_address,
                              QuicIpAddress bind_to_address,
                              int bind_to_port) override;
  void CleanUpAllUDPSockets() override;

 private:
  friend class net::test::QuicClientPeer;

  QuicChromiumAlarmFactory* CreateQuicAlarmFactory();
  QuicChromiumConnectionHelper* CreateQuicConnectionHelper();

  // Read a UDP packet and hand it to the framer.
  bool ReadAndProcessPacket();

  void StartPacketReaderIfNotStarted();

  //  Used by |helper_| to time alarms.
  QuicClock clock_;

  // Address of the client if the client is connected to the server.
  IPEndPoint client_address_;

  // UDP socket connected to the server.
  std::unique_ptr<UDPClientSocket> socket_;

  // Tracks if the client is initialized to connect.
  bool initialized_;

  // The log used for the sockets.
  NetLog net_log_;

  std::unique_ptr<QuicChromiumPacketReader> packet_reader_;

  bool packet_reader_started_;

  base::WeakPtrFactory<QuicSimpleClient> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(QuicSimpleClient);
};

}  // namespace net

#endif  // NET_TOOLS_QUIC_QUIC_SIMPLE_CLIENT_H_
