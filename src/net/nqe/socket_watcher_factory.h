// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_SOCKET_WATCHER_FACTORY_H_
#define NET_NQE_SOCKET_WATCHER_FACTORY_H_

#include <memory>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"

namespace base {
class TickClock;
class TimeDelta;
}  // namespace base

namespace net {

namespace {
typedef base::Callback<void(SocketPerformanceWatcherFactory::Protocol protocol,
                            const base::TimeDelta& rtt)>
    OnUpdatedRTTAvailableCallback;
}

namespace nqe {

namespace internal {

// SocketWatcherFactory implements SocketPerformanceWatcherFactory.
// SocketWatcherFactory is thread safe.
class SocketWatcherFactory : public SocketPerformanceWatcherFactory {
 public:
  // Creates a SocketWatcherFactory.  All socket watchers created by
  // SocketWatcherFactory call |updated_rtt_observation_callback| on
  // |task_runner| every time a new RTT observation is available.
  // |min_notification_interval| is the minimum interval betweeen consecutive
  // notifications to the socket watchers created by this factory. |tick_clock|
  // is guaranteed to be non-null.
  SocketWatcherFactory(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      base::TimeDelta min_notification_interval,
      OnUpdatedRTTAvailableCallback updated_rtt_observation_callback,
      base::TickClock* tick_clock);

  ~SocketWatcherFactory() override;

  // SocketPerformanceWatcherFactory implementation:
  std::unique_ptr<SocketPerformanceWatcher> CreateSocketPerformanceWatcher(
      const Protocol protocol) override;

 private:
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // Minimum interval betweeen consecutive notifications to the socket watchers
  // created by this factory.
  const base::TimeDelta min_notification_interval_;

  // Called every time a new RTT observation is available.
  OnUpdatedRTTAvailableCallback updated_rtt_observation_callback_;

  base::TickClock* tick_clock_;

  DISALLOW_COPY_AND_ASSIGN(SocketWatcherFactory);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_SOCKET_WATCHER_FACTORY_H_
