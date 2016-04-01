// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_UDP_DATAGRAM_SOCKET_H_
#define NET_UDP_DATAGRAM_SOCKET_H_

#include "net/base/net_export.h"

namespace net {

class BoundNetLog;
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

  // Gets the NetLog for this socket.
  virtual const BoundNetLog& NetLog() const = 0;
};

}  // namespace net

#endif  // NET_UDP_DATAGRAM_SOCKET_H_
