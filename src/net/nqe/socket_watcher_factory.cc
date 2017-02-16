// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/socket_watcher_factory.h"

#include "base/memory/ptr_util.h"
#include "base/time/time.h"
#include "net/nqe/socket_watcher.h"

namespace net {

namespace nqe {

namespace internal {

SocketWatcherFactory::SocketWatcherFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    base::TimeDelta min_notification_interval,
    OnUpdatedRTTAvailableCallback updated_rtt_observation_callback,
    base::TickClock* tick_clock)
    : task_runner_(std::move(task_runner)),
      min_notification_interval_(min_notification_interval),
      updated_rtt_observation_callback_(updated_rtt_observation_callback),
      tick_clock_(tick_clock) {
  DCHECK(tick_clock_);
}

SocketWatcherFactory::~SocketWatcherFactory() {}

std::unique_ptr<SocketPerformanceWatcher>
SocketWatcherFactory::CreateSocketPerformanceWatcher(const Protocol protocol) {
  return base::MakeUnique<SocketWatcher>(
      protocol, min_notification_interval_, task_runner_,
      updated_rtt_observation_callback_, tick_clock_);
}

}  // namespace internal

}  // namespace nqe

}  // namespace net
