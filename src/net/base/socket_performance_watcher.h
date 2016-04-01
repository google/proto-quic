// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SOCKET_PERFORMANCE_WATCHER_H_
#define NET_BASE_SOCKET_PERFORMANCE_WATCHER_H_

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/base/socket_performance_watcher_factory.h"

namespace base {
class TimeDelta;
}  // namespace base

namespace net {

// SocketPerformanceWatcher is the base class for recording and aggregating
// socket statistics.
class NET_EXPORT_PRIVATE SocketPerformanceWatcher {
 public:
  // |socket_performance_watcher_factory| is the factory that constructed
  // |this| watcher.
  SocketPerformanceWatcher(
      const SocketPerformanceWatcherFactory::Protocol protocol,
      SocketPerformanceWatcherFactory* socket_performance_watcher_factory);

  virtual ~SocketPerformanceWatcher();

  // Called when updated transport layer RTT information is available. This
  // must be the transport layer RTT from this device to the remote transport
  // layer endpoint. This method is called immediately after the observation is
  // made, hence no timestamp.
  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) const;

 private:
  // Transport layer protocol used by the socket that |this| is watching.
  const SocketPerformanceWatcherFactory::Protocol protocol_;

  // |socket_performance_watcher_factory_| is the factory that created
  // |this| watcher.
  SocketPerformanceWatcherFactory* socket_performance_watcher_factory_;

  DISALLOW_COPY_AND_ASSIGN(SocketPerformanceWatcher);
};

}  // namespace net

#endif  // NET_BASE_SOCKET_PERFORMANCE_WATCHER_H_
