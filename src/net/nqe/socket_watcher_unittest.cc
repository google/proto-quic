// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/socket_watcher.h"

#include "base/bind.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace nqe {

namespace internal {

namespace {

void OnUpdatedRTTAvailable(SocketPerformanceWatcherFactory::Protocol protocol,
                           const base::TimeDelta& rtt) {}

// Verify that the buffer size is never exceeded.
TEST(NetworkQualitySocketWatcherTest, NotificationsThrottled) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.SetNowTicks(base::TimeTicks::Now());

  SocketWatcher socket_watcher(SocketPerformanceWatcherFactory::PROTOCOL_QUIC,
                               base::TimeDelta::FromMilliseconds(2000),
                               base::ThreadTaskRunnerHandle::Get(),
                               base::Bind(OnUpdatedRTTAvailable), &tick_clock);

  EXPECT_TRUE(socket_watcher.ShouldNotifyUpdatedRTT());
  socket_watcher.OnUpdatedRTTAvailable(base::TimeDelta::FromSeconds(10));

  EXPECT_FALSE(socket_watcher.ShouldNotifyUpdatedRTT());

  tick_clock.Advance(base::TimeDelta::FromMilliseconds(1000));
  // Minimum interval between consecutive notifications is 2000 msec.
  EXPECT_FALSE(socket_watcher.ShouldNotifyUpdatedRTT());

  // Advance the clock by 1000 msec more so that the current time is at least
  // 2000 msec more than the last time |socket_watcher| received a notification.
  tick_clock.Advance(base::TimeDelta::FromMilliseconds(1000));
  EXPECT_TRUE(socket_watcher.ShouldNotifyUpdatedRTT());
}

}  // namespace

}  // namespace internal

}  // namespace nqe

}  // namespace net