// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_UDP_DATAGRAM_SOCKET_H_
#define NET_UDP_DATAGRAM_SOCKET_H_

#include "net/base/net_export.h"

namespace net {

class NetLogWithSource;
class IPEndPoint;

// A datagram socket is an interface to a protocol which exchanges
// datagrams, like UDP.
class NET_EXPORT_PRIVATE DatagramSocket {
 public:
  // Type of source port binding to use.
  enum BindType {
    RANDOM_BIND,
    DEFAULT_BIND,
  };

  virtual ~DatagramSocket() {}

  // Close the socket.
  virtual void Close() = 0;

  // Copy the remote udp address into |address| and return a network error code.
  virtual int GetPeerAddress(IPEndPoint* address) const = 0;

  // Copy the local udp address into |address| and return a network error code.
  // (similar to getsockname)
  virtual int GetLocalAddress(IPEndPoint* address) const = 0;

  // Switch to use non-blocking IO. Must be called right after construction and
  // before other calls.
  virtual void UseNonBlockingIO() = 0;

  // Requests that packets sent by this socket not be fragment, either locally
  // by the host, or by routers (via the DF bit in the IPv4 packet header).
  // May not be supported by all platforms. Returns a return a network error
  // code if there was a problem, but the socket will still be usable. Can not
  // return ERR_IO_PENDING.
  virtual int SetDoNotFragment() = 0;

  // Gets the NetLog for this socket.
  virtual const NetLogWithSource& NetLog() const = 0;
};

}  // namespace net

#endif  // NET_UDP_DATAGRAM_SOCKET_H_
