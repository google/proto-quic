// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SOCKET_PERFORMANCE_WATCHER_FACTORY_H_
#define NET_BASE_SOCKET_PERFORMANCE_WATCHER_FACTORY_H_

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"

namespace base {
class TimeDelta;
}  // namespace base

namespace net {

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
  // Implementations must return a valid, unique SocketRecorder for every call;
  // recorders must not be shared across calls or objects, nor is nullptr valid.
  virtual scoped_ptr<SocketPerformanceWatcher> CreateSocketPerformanceWatcher(
      const Protocol protocol) = 0;

  // Called when updated transport layer RTT information is available from one
  // of the watchers created by |this|. |protocol| is the protocol that was used
  // by the watcher. |rtt| must be the transport layer RTT from this device to
  // the remote transport layer endpoint. These methods are called immediately
  // after the observation is made, hence no timestamp.
  virtual void OnUpdatedRTTAvailable(const Protocol protocol,
                                     const base::TimeDelta& rtt) = 0;

 protected:
  SocketPerformanceWatcherFactory() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(SocketPerformanceWatcherFactory);
};

}  // namespace net

#endif  // NET_BASE_SOCKET_PERFORMANCE_WATCHER_FACTORY_H_
