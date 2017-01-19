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

#include "net/quic/core/quic_flags.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/tools/quic/platform/impl/quic_socket_utils.h"
#include "net/tools/quic/quic_dispatcher.h"
#include "net/tools/quic/quic_process_packet_interface.h"

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

  QuicWallTime fallback_walltimestamp = QuicWallTime::Zero();
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

    QuicSocketAddress client_address =
        QuicSocketAddress(packets_[i].raw_address);
    QuicIpAddress server_ip;
    QuicWallTime packet_walltimestamp = QuicWallTime::Zero();
    QuicSocketUtils::GetAddressAndTimestampFromMsghdr(
        &mmsg_hdr_[i].msg_hdr, &server_ip, &packet_walltimestamp);
    if (!server_ip.IsInitialized()) {
      QUIC_BUG << "Unable to get server address.";
      continue;
    }

    // This isn't particularly desirable, but not all platforms support socket
    // timestamping.
    if (packet_walltimestamp.IsZero()) {
      if (fallback_walltimestamp.IsZero()) {
        fallback_walltimestamp = clock.WallNow();
      }
      packet_walltimestamp = fallback_walltimestamp;
    }
    QuicTime timestamp = clock.ConvertWallTimeToQuicTime(packet_walltimestamp);
    int ttl = 0;
    bool has_ttl =
        QuicSocketUtils::GetTtlFromMsghdr(&mmsg_hdr_[i].msg_hdr, &ttl);
    QuicReceivedPacket packet(reinterpret_cast<char*>(packets_[i].iov.iov_base),
                              mmsg_hdr_[i].msg_len, timestamp, false, ttl,
                              has_ttl);
    QuicSocketAddress server_address(server_ip, port);
    processor->ProcessPacket(server_address, client_address, packet);
  }

  if (packets_dropped != nullptr) {
    QuicSocketUtils::GetOverflowFromMsghdr(&mmsg_hdr_[0].msg_hdr,
                                           packets_dropped);
  }

  // We may not have read all of the packets available on the socket.
  return packets_read == kNumPacketsPerReadMmsgCall;
#else
  QUIC_LOG(FATAL) << "Unsupported";
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

  QuicSocketAddress client_address;
  QuicIpAddress server_ip;
  QuicWallTime walltimestamp = QuicWallTime::Zero();
  int bytes_read =
      QuicSocketUtils::ReadPacket(fd, buf, arraysize(buf), packets_dropped,
                                  &server_ip, &walltimestamp, &client_address);
  if (bytes_read < 0) {
    return false;  // ReadPacket failed.
  }

  if (!server_ip.IsInitialized()) {
    QUIC_BUG << "Unable to get server address.";
    return false;
  }
  // This isn't particularly desirable, but not all platforms support socket
  // timestamping.
  if (walltimestamp.IsZero()) {
    walltimestamp = clock.WallNow();
  }
  QuicTime timestamp = clock.ConvertWallTimeToQuicTime(walltimestamp);

  QuicReceivedPacket packet(buf, bytes_read, timestamp, false);
  QuicSocketAddress server_address(server_ip, port);
  processor->ProcessPacket(server_address, client_address, packet);

  // The socket read was successful, so return true even if packet dispatch
  // failed.
  return true;
}


}  // namespace net
