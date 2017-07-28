// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_SOCKET_PERFORMANCE_WATCHER_FACTORY_H_
#define NET_SOCKET_SOCKET_PERFORMANCE_WATCHER_FACTORY_H_

#include <memory>

#include "base/macros.h"
#include "net/base/net_export.h"

namespace net {

class AddressList;
class SocketPerformanceWatcher;

// SocketPerformanceWatcherFactory creates socket performance watcher for
// different type of sockets.
class NET_EXPORT_PRIVATE SocketPerformanceWatcherFactory {
 public:
  // Transport layer protocol used by the socket that are supported by
  // |SocketPerformanceWatcherFactory|.
  enum Protocol { PROTOCOL_TCP, PROTOCOL_QUIC };

  virtual ~SocketPerformanceWatcherFactory() {}

  // Creates a socket performance watcher that will record statistics for a
  // single socket that uses |protocol| as the transport layer protocol.
  // |address_list| is the list of addresses that the socket is going to connect
  // to. Implementations must return a valid, unique SocketRecorder for every
  // call; recorders must not be shared across calls or objects, nor is nullptr
  // valid.
  virtual std::unique_ptr<SocketPerformanceWatcher>
  CreateSocketPerformanceWatcher(const Protocol protocol,
                                 const AddressList& address_list) = 0;

 protected:
  SocketPerformanceWatcherFactory() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(SocketPerformanceWatcherFactory);
};

}  // namespace net

#endif  // NET_SOCKET_SOCKET_PERFORMANCE_WATCHER_FACTORY_H_
