// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client.h"

#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "base/run_loop.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_data_reader.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/tools/quic/platform/impl/quic_socket_utils.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

// TODO(rtenneti): Add support for MMSG_MORE.
#define MMSG_MORE 0
using std::string;

namespace net {

const int kEpollFlags = EPOLLIN | EPOLLOUT | EPOLLET;

QuicClient::QuicClient(QuicSocketAddress server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       EpollServer* epoll_server,
                       std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClient(server_address,
                 server_id,
                 supported_versions,
                 QuicConfig(),
                 epoll_server,
                 std::move(proof_verifier)) {}

QuicClient::QuicClient(QuicSocketAddress server_address,
                       const QuicServerId& server_id,
                       const QuicVersionVector& supported_versions,
                       const QuicConfig& config,
                       EpollServer* epoll_server,
                       std::unique_ptr<ProofVerifier> proof_verifier)
    : QuicClientBase(
          server_id,
          supported_versions,
          config,
          new QuicEpollConnectionHelper(epoll_server, QuicAllocator::SIMPLE),
          new QuicEpollAlarmFactory(epoll_server),
          std::move(proof_verifier)),
      epoll_server_(epoll_server),
      packets_dropped_(0),
      overflow_supported_(false),
      packet_reader_(new QuicPacketReader()) {
  set_server_address(server_address);
}

QuicClient::~QuicClient() {
  if (connected()) {
    session()->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Client being torn down",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }

  CleanUpAllUDPSockets();
}

bool QuicClient::CreateUDPSocketAndBind(QuicSocketAddress server_address,
                                        QuicIpAddress bind_to_address,
                                        int bind_to_port) {
  epoll_server_->set_timeout_in_us(50 * 1000);

  int fd =
      QuicSocketUtils::CreateUDPSocket(server_address, &overflow_supported_);
  if (fd < 0) {
    return false;
  }

  QuicSocketAddress client_address;
  if (bind_to_address.IsInitialized()) {
    client_address = QuicSocketAddress(bind_to_address, local_port());
  } else if (server_address.host().address_family() == IpAddressFamily::IP_V4) {
    client_address = QuicSocketAddress(QuicIpAddress::Any4(), bind_to_port);
  } else {
    client_address = QuicSocketAddress(QuicIpAddress::Any6(), bind_to_port);
  }

  sockaddr_storage addr = client_address.generic_address();
  int rc = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (rc < 0) {
    QUIC_LOG(ERROR) << "Bind failed: " << strerror(errno);
    return false;
  }

  if (client_address.FromSocket(fd) != 0) {
    QUIC_LOG(ERROR) << "Unable to get self address.  Error: "
                    << strerror(errno);
  }

  fd_address_map_[fd] = client_address;

  epoll_server_->RegisterFD(fd, this, kEpollFlags);
  return true;
}

void QuicClient::CleanUpUDPSocket(int fd) {
  CleanUpUDPSocketImpl(fd);
  fd_address_map_.erase(fd);
}

void QuicClient::CleanUpAllUDPSockets() {
  for (std::pair<int, QuicSocketAddress> fd_address : fd_address_map_) {
    CleanUpUDPSocketImpl(fd_address.first);
  }
  fd_address_map_.clear();
}

void QuicClient::CleanUpUDPSocketImpl(int fd) {
  if (fd > -1) {
    epoll_server_->UnregisterFD(fd);
    int rc = close(fd);
    DCHECK_EQ(0, rc);
  }
}

void QuicClient::RunEventLoop() {
  base::RunLoop().RunUntilIdle();
  epoll_server_->WaitForEventsAndExecuteCallbacks();
}

void QuicClient::OnEvent(int fd, EpollEvent* event) {
  DCHECK_EQ(fd, GetLatestFD());

  if (event->in_events & EPOLLIN) {
    bool more_to_read = true;
    while (connected() && more_to_read) {
      more_to_read = packet_reader_->ReadAndDispatchPackets(
          GetLatestFD(), QuicClient::GetLatestClientAddress().port(),
          *helper()->GetClock(), this,
          overflow_supported_ ? &packets_dropped_ : nullptr);
    }
  }
  if (connected() && (event->in_events & EPOLLOUT)) {
    writer()->SetWritable();
    session()->connection()->OnCanWrite();
  }
  if (event->in_events & EPOLLERR) {
    QUIC_DLOG(INFO) << "Epollerr";
  }
}

QuicPacketWriter* QuicClient::CreateQuicPacketWriter() {
  return new QuicDefaultPacketWriter(GetLatestFD());
}

QuicSocketAddress QuicClient::GetLatestClientAddress() const {
  if (fd_address_map_.empty()) {
    return QuicSocketAddress();
  }

  return fd_address_map_.back().second;
}

int QuicClient::GetLatestFD() const {
  if (fd_address_map_.empty()) {
    return -1;
  }

  return fd_address_map_.back().first;
}

void QuicClient::ProcessPacket(const QuicSocketAddress& self_address,
                               const QuicSocketAddress& peer_address,
                               const QuicReceivedPacket& packet) {
  session()->ProcessUdpPacket(self_address, peer_address, packet);
}

}  // namespace net
