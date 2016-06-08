// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/socket_watcher.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/time/time.h"

namespace net {

namespace nqe {

namespace internal {

SocketWatcher::SocketWatcher(
    SocketPerformanceWatcherFactory::Protocol protocol,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    OnUpdatedRTTAvailableCallback updated_rtt_observation_callback)
    : protocol_(protocol),
      task_runner_(std::move(task_runner)),
      updated_rtt_observation_callback_(updated_rtt_observation_callback) {}

SocketWatcher::~SocketWatcher() {}

bool SocketWatcher::ShouldNotifyUpdatedRTT() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  return true;
}

void SocketWatcher::OnUpdatedRTTAvailable(const base::TimeDelta& rtt) {
  DCHECK(thread_checker_.CalledOnValidThread());

  task_runner_->PostTask(
      FROM_HERE, base::Bind(updated_rtt_observation_callback_, protocol_, rtt));
}

void SocketWatcher::OnConnectionChanged() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

}  // namespace internal

}  // namespace nqe

}  // namespace net
