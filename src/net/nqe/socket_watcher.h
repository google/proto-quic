// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_NQE_SOCKET_WATCHER_H_
#define NET_NQE_SOCKET_WATCHER_H_

#include <memory>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"

namespace base {
class SingleThreadTaskRunner;
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

// SocketWatcher implements SocketPerformanceWatcher, and is not thread-safe.
class NET_EXPORT_PRIVATE SocketWatcher : public SocketPerformanceWatcher {
 public:
  // Creates a SocketWatcher which can be used to watch a socket that uses
  // |protocol| as the transport layer protocol. The socket watcher will call
  // |updated_rtt_observation_callback| on |task_runner| every time a new RTT
  // observation is available. |min_notification_interval| is the minimum
  // interval betweeen consecutive notifications to this socket watcher.
  // |tick_clock| is guaranteed to be non-null.
  SocketWatcher(SocketPerformanceWatcherFactory::Protocol protocol,
                base::TimeDelta min_notification_interval,
                scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                OnUpdatedRTTAvailableCallback updated_rtt_observation_callback,
                base::TickClock* tick_clock);

  ~SocketWatcher() override;

  // SocketPerformanceWatcher implementation:
  bool ShouldNotifyUpdatedRTT() const override;
  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) override;
  void OnConnectionChanged() override;

 private:
  // Transport layer protocol used by the socket that |this| is watching.
  const SocketPerformanceWatcherFactory::Protocol protocol_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // Called every time a new RTT observation is available.
  OnUpdatedRTTAvailableCallback updated_rtt_observation_callback_;

  // Minimum interval betweeen consecutive incoming notifications.
  const base::TimeDelta rtt_notifications_minimum_interval_;

  // Time when this was last notified of updated RTT.
  base::TimeTicks last_rtt_notification_;

  base::TickClock* tick_clock_;

  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(SocketWatcher);
};

}  // namespace internal

}  // namespace nqe

}  // namespace net

#endif  // NET_NQE_SOCKET_WATCHER_H_
