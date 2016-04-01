// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/socket_performance_watcher.h"

#include "base/logging.h"

namespace net {

SocketPerformanceWatcher::SocketPerformanceWatcher(
    const SocketPerformanceWatcherFactory::Protocol protocol,
    SocketPerformanceWatcherFactory* socket_performance_watcher_factory)
    : protocol_(protocol),
      socket_performance_watcher_factory_(socket_performance_watcher_factory) {
  DCHECK(socket_performance_watcher_factory_);

  switch (protocol) {
    case SocketPerformanceWatcherFactory::PROTOCOL_TCP:
    case SocketPerformanceWatcherFactory::PROTOCOL_QUIC:
      return;
    default:
      NOTREACHED();
  }
}

SocketPerformanceWatcher::~SocketPerformanceWatcher() {}

void SocketPerformanceWatcher::OnUpdatedRTTAvailable(
    const base::TimeDelta& rtt) const {
  socket_performance_watcher_factory_->OnUpdatedRTTAvailable(protocol_, rtt);
}

}  // namespace net
