// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/socket_watcher.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/single_thread_task_runner.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"

namespace net {

namespace nqe {

namespace internal {

SocketWatcher::SocketWatcher(
    SocketPerformanceWatcherFactory::Protocol protocol,
    base::TimeDelta min_notification_interval,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    OnUpdatedRTTAvailableCallback updated_rtt_observation_callback,
    base::TickClock* tick_clock)
    : protocol_(protocol),
      task_runner_(std::move(task_runner)),
      updated_rtt_observation_callback_(updated_rtt_observation_callback),
      rtt_notifications_minimum_interval_(min_notification_interval),
      tick_clock_(tick_clock) {
  DCHECK(tick_clock_);
}

SocketWatcher::~SocketWatcher() {}

bool SocketWatcher::ShouldNotifyUpdatedRTT() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Do not allow incoming notifications if the last notification was more
  // recent than |rtt_notifications_minimum_interval_| ago. This helps in
  // reducing the overhead of obtaining the RTT values.
  return tick_clock_->NowTicks() - last_rtt_notification_ >=
         rtt_notifications_minimum_interval_;
}

void SocketWatcher::OnUpdatedRTTAvailable(const base::TimeDelta& rtt) {
  DCHECK(thread_checker_.CalledOnValidThread());

  last_rtt_notification_ = tick_clock_->NowTicks();
  task_runner_->PostTask(
      FROM_HERE, base::Bind(updated_rtt_observation_callback_, protocol_, rtt));
}

void SocketWatcher::OnConnectionChanged() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

}  // namespace internal

}  // namespace nqe

}  // namespace net
