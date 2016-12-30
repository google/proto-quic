// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_client.h"

#include <utility>

#include "base/logging.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/chromium/quic_chromium_connection_helper.h"
#include "net/quic/chromium/quic_chromium_packet_reader.h"
#include "net/quic/chromium/quic_chromium_packet_writer.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"
#include "net/socket/udp_client_socket.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"

using std::string;
using base::StringPiece;

namespace net {

QuicSimpleClient::QuicSimpleClient(
    QuicSocketAddress server_address,
    const QuicServerId& server_id,
    const QuicVersionVector& supported_versions,
    std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClientBase(server_id,
                     supported_versions,
                     QuicConfig(),
                     CreateQuicConnectionHelper(),
                     CreateQuicAlarmFactory(),
                     std::move(proof_verifier)),
      initialized_(false),
      packet_reader_started_(false),
      weak_factory_(this) {
  set_server_address(server_address);
}

QuicSimpleClient::~QuicSimpleClient() {
  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Shutting down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}

bool QuicSimpleClient::CreateUDPSocketAndBind(QuicSocketAddress server_address,
                                              QuicIpAddress bind_to_address,
                                              int bind_to_port) {
  std::unique_ptr<UDPClientSocket> socket(
      new UDPClientSocket(DatagramSocket::DEFAULT_BIND, RandIntCallback(),
                          &net_log_, NetLogSource()));

  if (bind_to_address.IsInitialized()) {
    client_address_ = QuicSocketAddress(bind_to_address, local_port());
  } else if (server_address.host().address_family() == IpAddressFamily::IP_V4) {
    client_address_ = QuicSocketAddress(QuicIpAddress::Any4(), bind_to_port);
  } else {
    client_address_ = QuicSocketAddress(QuicIpAddress::Any6(), bind_to_port);
  }

  int rc = socket->Connect(server_address.impl().socket_address());
  if (rc != OK) {
    LOG(ERROR) << "Connect failed: " << ErrorToShortString(rc);
    return false;
  }

  rc = socket->SetReceiveBufferSize(kDefaultSocketReceiveBuffer);
  if (rc != OK) {
    LOG(ERROR) << "SetReceiveBufferSize() failed: " << ErrorToShortString(rc);
    return false;
  }

  rc = socket->SetSendBufferSize(kDefaultSocketReceiveBuffer);
  if (rc != OK) {
    LOG(ERROR) << "SetSendBufferSize() failed: " << ErrorToShortString(rc);
    return false;
  }

  IPEndPoint address;
  rc = socket->GetLocalAddress(&address);
  if (rc != OK) {
    LOG(ERROR) << "GetLocalAddress failed: " << ErrorToShortString(rc);
    return false;
  }
  client_address_ = QuicSocketAddress(QuicSocketAddressImpl(address));

  socket_.swap(socket);
  packet_reader_.reset(new QuicChromiumPacketReader(
      socket_.get(), &clock_, this, kQuicYieldAfterPacketsRead,
      QuicTime::Delta::FromMilliseconds(kQuicYieldAfterDurationMilliseconds),
      NetLogWithSource()));

  if (socket != nullptr) {
    socket->Close();
  }

  return true;
}

void QuicSimpleClient::CleanUpAllUDPSockets() {
  reset_writer();
  packet_reader_.reset();
  packet_reader_started_ = false;

}

void QuicSimpleClient::StartPacketReaderIfNotStarted() {
  if (!packet_reader_started_) {
    packet_reader_->StartReading();
    packet_reader_started_ = true;
  }
}

void QuicSimpleClient::RunEventLoop() {
  StartPacketReaderIfNotStarted();
  base::RunLoop().RunUntilIdle();
}

QuicChromiumConnectionHelper* QuicSimpleClient::CreateQuicConnectionHelper() {
  return new QuicChromiumConnectionHelper(&clock_, QuicRandom::GetInstance());
}

QuicChromiumAlarmFactory* QuicSimpleClient::CreateQuicAlarmFactory() {
  return new QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(),
                                      &clock_);
}

QuicPacketWriter* QuicSimpleClient::CreateQuicPacketWriter() {
  return new QuicChromiumPacketWriter(socket_.get());
}

void QuicSimpleClient::OnReadError(int result,
                                   const DatagramClientSocket* socket) {
  LOG(ERROR) << "QuicSimpleClient read failed: " << ErrorToShortString(result);
  Disconnect();
}

QuicSocketAddress QuicSimpleClient::GetLatestClientAddress() const {
  return client_address_;
}

bool QuicSimpleClient::OnPacket(const QuicReceivedPacket& packet,
                                IPEndPoint local_address,
                                IPEndPoint peer_address) {
  session()->connection()->ProcessUdpPacket(
      QuicSocketAddress(QuicSocketAddressImpl(local_address)),
      QuicSocketAddress(QuicSocketAddressImpl(peer_address)), packet);
  if (!session()->connection()->connected()) {
    return false;
  }

  return true;
}

}  // namespace net
