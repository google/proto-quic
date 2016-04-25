// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_packet_reader.h"

#include <errno.h>
#ifndef __APPLE__
// This is a GNU header that is not present in /usr/include on MacOS
#include <features.h>
#endif
#include <string.h>
#include <sys/epoll.h>

#include "base/logging.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/tools/quic/quic_dispatcher.h"
#include "net/tools/quic/quic_process_packet_interface.h"
#include "net/tools/quic/quic_socket_utils.h"

#define MMSG_MORE 0

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

namespace net {


QuicPacketReader::QuicPacketReader() {
  Initialize();
}

void QuicPacketReader::Initialize() {
#if MMSG_MORE
  // Zero initialize uninitialized memory.
  memset(mmsg_hdr_, 0, sizeof(mmsg_hdr_));

  for (int i = 0; i < kNumPacketsPerReadMmsgCall; ++i) {
    packets_[i].iov.iov_base = packets_[i].buf;
    packets_[i].iov.iov_len = kMaxPacketSize;
    memset(&packets_[i].raw_address, 0, sizeof(packets_[i].raw_address));
    memset(packets_[i].cbuf, 0, sizeof(packets_[i].cbuf));
    memset(packets_[i].buf, 0, sizeof(packets_[i].buf));

    msghdr* hdr = &mmsg_hdr_[i].msg_hdr;
    hdr->msg_name = &packets_[i].raw_address;
    hdr->msg_namelen = sizeof(sockaddr_storage);
    hdr->msg_iov = &packets_[i].iov;
    hdr->msg_iovlen = 1;

    hdr->msg_control = packets_[i].cbuf;
    hdr->msg_controllen = QuicSocketUtils::kSpaceForCmsg;
  }
#endif
}

QuicPacketReader::~QuicPacketReader() {}

bool QuicPacketReader::ReadAndDispatchPackets(
    int fd,
    int port,
    const QuicClock& clock,
    ProcessPacketInterface* processor,
    QuicPacketCount* packets_dropped) {
#if MMSG_MORE
  return ReadAndDispatchManyPackets(fd, port, clock, processor,
                                    packets_dropped);
#else
  return ReadAndDispatchSinglePacket(fd, port, clock, processor,
                                     packets_dropped);
#endif
}

bool QuicPacketReader::ReadAndDispatchManyPackets(
    int fd,
    int port,
    const QuicClock& clock,
    ProcessPacketInterface* processor,
    QuicPacketCount* packets_dropped) {
#if MMSG_MORE
  // Re-set the length fields in case recvmmsg has changed them.
  for (int i = 0; i < kNumPacketsPerReadMmsgCall; ++i) {
    DCHECK_EQ(kMaxPacketSize, packets_[i].iov.iov_len);
    msghdr* hdr = &mmsg_hdr_[i].msg_hdr;
    hdr->msg_namelen = sizeof(sockaddr_storage);
    DCHECK_EQ(1, hdr->msg_iovlen);
    hdr->msg_controllen = QuicSocketUtils::kSpaceForCmsg;
  }

  int packets_read =
      recvmmsg(fd, mmsg_hdr_, kNumPacketsPerReadMmsgCall, 0, nullptr);

  if (packets_read <= 0) {
    return false;  // recvmmsg failed.
  }

  QuicTime fallback_timestamp = QuicTime::Zero();
  for (int i = 0; i < packets_read; ++i) {
    if (mmsg_hdr_[i].msg_len == 0) {
      continue;
    }

    if (mmsg_hdr_[i].msg_hdr.msg_controllen >= QuicSocketUtils::kSpaceForCmsg) {
      QUIC_BUG << "Incorrectly set control length: "
               << mmsg_hdr_[i].msg_hdr.msg_controllen << ", expected "
               << QuicSocketUtils::kSpaceForCmsg;
      continue;
    }

    IPEndPoint client_address = IPEndPoint(packets_[i].raw_address);
    IPAddress server_ip;
    QuicTime packet_timestamp = QuicTime::Zero();
    QuicSocketUtils::GetAddressAndTimestampFromMsghdr(
        &mmsg_hdr_[i].msg_hdr, &server_ip, &packet_timestamp);
    if (!IsInitializedAddress(server_ip)) {
      QUIC_BUG << "Unable to get server address.";
      continue;
    }

    if (FLAGS_quic_use_socket_timestamp) {
      if (packet_timestamp == QuicTime::Zero()) {
        // This isn't particularly desirable, but not all platforms support
        // socket timestamping.
        if (fallback_timestamp == QuicTime::Zero()) {
          fallback_timestamp = clock.Now();
        }
        packet_timestamp = fallback_timestamp;
      }
    }

    QuicReceivedPacket packet(reinterpret_cast<char*>(packets_[i].iov.iov_base),
                              mmsg_hdr_[i].msg_len, packet_timestamp, false);
    IPEndPoint server_address(server_ip, port);
    processor->ProcessPacket(server_address, client_address, packet);
  }

  if (packets_dropped != nullptr) {
    QuicSocketUtils::GetOverflowFromMsghdr(&mmsg_hdr_[0].msg_hdr,
                                           packets_dropped);
  }

  // We may not have read all of the packets available on the socket.
  return packets_read == kNumPacketsPerReadMmsgCall;
#else
  LOG(FATAL) << "Unsupported";
  return false;
#endif
}

/* static */
bool QuicPacketReader::ReadAndDispatchSinglePacket(
    int fd,
    int port,
    const QuicClock& clock,
    ProcessPacketInterface* processor,
    QuicPacketCount* packets_dropped) {
  char buf[kMaxPacketSize];

  IPEndPoint client_address;
  IPAddress server_ip;
  QuicTime timestamp = QuicTime::Zero();
  int bytes_read =
      QuicSocketUtils::ReadPacket(fd, buf, arraysize(buf), packets_dropped,
                                  &server_ip, &timestamp, &client_address);

  if (bytes_read < 0) {
    return false;  // ReadPacket failed.
  }

  if (server_ip.empty()) {
    QUIC_BUG << "Unable to get server address.";
    return false;
  }
  if (FLAGS_quic_use_socket_timestamp && timestamp == QuicTime::Zero()) {
    // This isn't particularly desirable, but not all platforms support socket
    // timestamping.
    timestamp = clock.Now();
  }

  QuicReceivedPacket packet(buf, bytes_read, timestamp, false);
  IPEndPoint server_address(server_ip, port);
  processor->ProcessPacket(server_address, client_address, packet);

  // The socket read was successful, so return true even if packet dispatch
  // failed.
  return true;
}


}  // namespace net
