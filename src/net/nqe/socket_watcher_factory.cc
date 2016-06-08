// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/socket_watcher_factory.h"

#include "base/time/time.h"
#include "net/nqe/socket_watcher.h"

namespace net {

namespace nqe {

namespace internal {

SocketWatcherFactory::SocketWatcherFactory(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    OnUpdatedRTTAvailableCallback updated_rtt_observation_callback)
    : task_runner_(std::move(task_runner)),
      updated_rtt_observation_callback_(updated_rtt_observation_callback) {}

SocketWatcherFactory::~SocketWatcherFactory() {}

std::unique_ptr<SocketPerformanceWatcher>
SocketWatcherFactory::CreateSocketPerformanceWatcher(const Protocol protocol) {
  return std::unique_ptr<SocketPerformanceWatcher>(new SocketWatcher(
      protocol, task_runner_, updated_rtt_observation_callback_));
}

}  // namespace internal

}  // namespace nqe

}  // namespace net
