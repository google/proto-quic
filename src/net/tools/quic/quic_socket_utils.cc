// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_socket_utils.h"

#include <errno.h>
#include <linux/net_tstamp.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <string>

#include "base/logging.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

namespace net {

// static
void QuicSocketUtils::GetAddressAndTimestampFromMsghdr(
    struct msghdr* hdr,
    IPAddress* address,
    QuicTime* timestamp,
    QuicWallTime* walltimestamp,
    bool latched_walltimestamps) {
  if (hdr->msg_controllen > 0) {
    for (cmsghdr* cmsg = CMSG_FIRSTHDR(hdr); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(hdr, cmsg)) {
      const uint8_t* addr_data = nullptr;
      int len = 0;
      if (cmsg->cmsg_type == IPV6_PKTINFO) {
        in6_pktinfo* info = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
        addr_data = reinterpret_cast<const uint8_t*>(&info->ipi6_addr);
        len = sizeof(in6_addr);
        *address = IPAddress(addr_data, len);
      } else if (cmsg->cmsg_type == IP_PKTINFO) {
        in_pktinfo* info = reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
        addr_data = reinterpret_cast<const uint8_t*>(&info->ipi_addr);
        len = sizeof(in_addr);
        *address = IPAddress(addr_data, len);
      } else if (cmsg->cmsg_level == SOL_SOCKET &&
                 cmsg->cmsg_type == SO_TIMESTAMPING) {
        LinuxTimestamping* lts =
            reinterpret_cast<LinuxTimestamping*>(CMSG_DATA(cmsg));
        timespec* ts = &lts->systime;
        int64_t usec = (static_cast<int64_t>(ts->tv_sec) * 1000 * 1000) +
                       (static_cast<int64_t>(ts->tv_nsec) / 1000);
        if (latched_walltimestamps) {
          *walltimestamp = QuicWallTime::FromUNIXMicroseconds(usec);
        } else {
          *timestamp =
              QuicTime::Zero().Add(QuicTime::Delta::FromMicroseconds(usec));
        }
      }
    }
  }
}

// static
bool QuicSocketUtils::GetOverflowFromMsghdr(struct msghdr* hdr,
                                            QuicPacketCount* dropped_packets) {
  if (hdr->msg_controllen > 0) {
    struct cmsghdr* cmsg;
    for (cmsg = CMSG_FIRSTHDR(hdr); cmsg != nullptr;
         cmsg = CMSG_NXTHDR(hdr, cmsg)) {
      if (cmsg->cmsg_type == SO_RXQ_OVFL) {
        *dropped_packets = *(reinterpret_cast<int*> CMSG_DATA(cmsg));
        return true;
      }
    }
  }
  return false;
}

// static
int QuicSocketUtils::SetGetAddressInfo(int fd, int address_family) {
  int get_local_ip = 1;
  int rc = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &get_local_ip,
                      sizeof(get_local_ip));
  if (rc == 0 && address_family == AF_INET6) {
    rc = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &get_local_ip,
                    sizeof(get_local_ip));
  }
  return rc;
}

// static
int QuicSocketUtils::SetGetSoftwareReceiveTimestamp(int fd) {
  int timestamping = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
  return setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &timestamping,
                    sizeof(timestamping));
}

// static
bool QuicSocketUtils::SetSendBufferSize(int fd, size_t size) {
  if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0) {
    LOG(ERROR) << "Failed to set socket send size";
    return false;
  }
  return true;
}

// static
bool QuicSocketUtils::SetReceiveBufferSize(int fd, size_t size) {
  if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) != 0) {
    LOG(ERROR) << "Failed to set socket recv size";
    return false;
  }
  return true;
}

// static
int QuicSocketUtils::ReadPacket(int fd,
                                char* buffer,
                                size_t buf_len,
                                QuicPacketCount* dropped_packets,
                                IPAddress* self_address,
                                QuicTime* timestamp,
                                QuicWallTime* walltimestamp,
                                bool latched_walltimestamps,
                                IPEndPoint* peer_address) {
  DCHECK(peer_address != nullptr);
  char cbuf[kSpaceForCmsg];
  memset(cbuf, 0, arraysize(cbuf));

  iovec iov = {buffer, buf_len};
  struct sockaddr_storage raw_address;
  msghdr hdr;

  hdr.msg_name = &raw_address;
  hdr.msg_namelen = sizeof(sockaddr_storage);
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  hdr.msg_flags = 0;

  struct cmsghdr* cmsg = reinterpret_cast<struct cmsghdr*>(cbuf);
  cmsg->cmsg_len = arraysize(cbuf);
  hdr.msg_control = cmsg;
  hdr.msg_controllen = arraysize(cbuf);

  int bytes_read = recvmsg(fd, &hdr, 0);

  // Return before setting dropped packets: if we get EAGAIN, it will
  // be 0.
  if (bytes_read < 0 && errno != 0) {
    if (errno != EAGAIN) {
      LOG(ERROR) << "Error reading " << strerror(errno);
    }
    return -1;
  }

  if (hdr.msg_controllen >= arraysize(cbuf)) {
    QUIC_BUG << "Incorrectly set control length: " << hdr.msg_controllen
             << ", expected " << arraysize(cbuf);
    return -1;
  }

  if (dropped_packets != nullptr) {
    GetOverflowFromMsghdr(&hdr, dropped_packets);
  }

  IPAddress stack_address;
  if (self_address == nullptr) {
    self_address = &stack_address;
  }

  QuicWallTime stack_walltimestamp = QuicWallTime::FromUNIXMicroseconds(0);
  if (walltimestamp == nullptr) {
    walltimestamp = &stack_walltimestamp;
  }

  QuicTime stack_timestamp = QuicTime::Zero();
  if (timestamp == nullptr) {
    timestamp = &stack_timestamp;
  }

  GetAddressAndTimestampFromMsghdr(&hdr, self_address, timestamp, walltimestamp,
                                   latched_walltimestamps);

  if (raw_address.ss_family == AF_INET) {
    CHECK(peer_address->FromSockAddr(
        reinterpret_cast<const sockaddr*>(&raw_address),
        sizeof(struct sockaddr_in)));
  } else if (raw_address.ss_family == AF_INET6) {
    CHECK(peer_address->FromSockAddr(
        reinterpret_cast<const sockaddr*>(&raw_address),
        sizeof(struct sockaddr_in6)));
  }

  return bytes_read;
}

size_t QuicSocketUtils::SetIpInfoInCmsg(const IPAddress& self_address,
                                        cmsghdr* cmsg) {
  if (self_address.IsIPv4()) {
    cmsg->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
    cmsg->cmsg_level = IPPROTO_IP;
    cmsg->cmsg_type = IP_PKTINFO;
    in_pktinfo* pktinfo = reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
    memset(pktinfo, 0, sizeof(in_pktinfo));
    pktinfo->ipi_ifindex = 0;
    memcpy(&pktinfo->ipi_spec_dst, self_address.bytes().data(),
           self_address.size());
    return sizeof(in_pktinfo);
  } else if (self_address.IsIPv6()) {
    cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    in6_pktinfo* pktinfo = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
    memset(pktinfo, 0, sizeof(in6_pktinfo));
    memcpy(&pktinfo->ipi6_addr, self_address.bytes().data(),
           self_address.size());
    return sizeof(in6_pktinfo);
  } else {
    NOTREACHED() << "Unrecognized IPAddress";
    return 0;
  }
}

// static
WriteResult QuicSocketUtils::WritePacket(int fd,
                                         const char* buffer,
                                         size_t buf_len,
                                         const IPAddress& self_address,
                                         const IPEndPoint& peer_address) {
  sockaddr_storage raw_address;
  socklen_t address_len = sizeof(raw_address);
  CHECK(peer_address.ToSockAddr(
      reinterpret_cast<struct sockaddr*>(&raw_address), &address_len));
  iovec iov = {const_cast<char*>(buffer), buf_len};

  msghdr hdr;
  hdr.msg_name = &raw_address;
  hdr.msg_namelen = address_len;
  hdr.msg_iov = &iov;
  hdr.msg_iovlen = 1;
  hdr.msg_flags = 0;

  const int kSpaceForIpv4 = CMSG_SPACE(sizeof(in_pktinfo));
  const int kSpaceForIpv6 = CMSG_SPACE(sizeof(in6_pktinfo));
  // kSpaceForIp should be big enough to hold both IPv4 and IPv6 packet info.
  const int kSpaceForIp =
      (kSpaceForIpv4 < kSpaceForIpv6) ? kSpaceForIpv6 : kSpaceForIpv4;
  char cbuf[kSpaceForIp];
  if (self_address.empty()) {
    hdr.msg_control = 0;
    hdr.msg_controllen = 0;
  } else {
    hdr.msg_control = cbuf;
    hdr.msg_controllen = kSpaceForIp;
    cmsghdr* cmsg = CMSG_FIRSTHDR(&hdr);
    SetIpInfoInCmsg(self_address, cmsg);
    hdr.msg_controllen = cmsg->cmsg_len;
  }

  int rc;
  do {
    rc = sendmsg(fd, &hdr, 0);
  } while (rc < 0 && errno == EINTR);
  if (rc >= 0) {
    return WriteResult(WRITE_STATUS_OK, rc);
  }
  return WriteResult((errno == EAGAIN || errno == EWOULDBLOCK)
                         ? WRITE_STATUS_BLOCKED
                         : WRITE_STATUS_ERROR,
                     errno);
}

// static
int QuicSocketUtils::CreateUDPSocket(const IPEndPoint& address,
                                     bool* overflow_supported) {
  int address_family = address.GetSockAddrFamily();
  int fd = socket(address_family, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
  if (fd < 0) {
    LOG(ERROR) << "socket() failed: " << strerror(errno);
    return -1;
  }

  int get_overflow = 1;
  int rc = setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, &get_overflow,
                      sizeof(get_overflow));
  if (rc < 0) {
    DLOG(WARNING) << "Socket overflow detection not supported";
  } else {
    *overflow_supported = true;
  }

  if (!SetReceiveBufferSize(fd, kDefaultSocketReceiveBuffer)) {
    return -1;
  }

  if (!SetSendBufferSize(fd, kDefaultSocketReceiveBuffer)) {
    return -1;
  }

  rc = SetGetAddressInfo(fd, address_family);
  if (rc < 0) {
    LOG(ERROR) << "IP detection not supported" << strerror(errno);
    return -1;
  }

  rc = SetGetSoftwareReceiveTimestamp(fd);
  if (rc < 0) {
    LOG(WARNING) << "SO_TIMESTAMPING not supported; using fallback: "
                 << strerror(errno);
  }

  return fd;
}

}  // namespace net
