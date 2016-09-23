// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_service_thread.h"

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_worker_pool_impl.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/task_scheduler/task_traits.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {
namespace {

// The goal of the tests here is to verify the behavior of the Service Thread.
// Some tests may be better part of DelayedTaskManager unit tests depending on
// the nature of the test.
//
// Timed waits are inherent in the service thread because one of its main
// purposes is to tell the delayed task manager when to post ready tasks.
// This also makes writing tests tricky since the goal isn't to test if
// WaitableEvent works but rather do the correct callbacks occur at the right
// time.
//
// As a result, there are a few assumptions that are made in the test:
// 1) Tests execute with balanced context switching. This means that there isn't
//    an adversary that context switches test main thread for an extended period
//    of time when the test main thread isn't waiting.
// 2) Time proceeds normally. Since timed waits determine how long the service
//    thread will wait, and timed waits is currently not mockable, time needs to
//    proceed in a forward fashion. If time is frozen (e.g. TimeTicks::Now()
//    doesn't advance), some tests below may fail.
// 3) Short waits sufficiently cover longer waits. Having tests run quickly is
//    desirable. Since the tests can't change the behavior of timed waiting, the
//    delay durations should be reasonably short on the order of hundreds of
//    milliseconds.
class TaskSchedulerServiceThreadTest : public testing::Test {
 protected:
  TaskSchedulerServiceThreadTest() : delayed_task_manager_(Bind(&DoNothing)) {}

  void SetUp() override {
    scheduler_worker_pool_ = SchedulerWorkerPoolImpl::Create(
        SchedulerWorkerPoolParams("TestWorkerPoolForSchedulerServiceThread",
                                  ThreadPriority::BACKGROUND,
                                  SchedulerWorkerPoolParams::IORestriction::
                                      DISALLOWED,
                                  1u,
                                  TimeDelta::Max()),
        Bind(&ReEnqueueSequenceCallback), &task_tracker_,
        &delayed_task_manager_);
    ASSERT_TRUE(scheduler_worker_pool_);
    service_thread_ = SchedulerServiceThread::Create(
        &task_tracker_, &delayed_task_manager_);
    ASSERT_TRUE(service_thread_);
  }

  void TearDown() override {
    scheduler_worker_pool_->JoinForTesting();
    service_thread_->JoinForTesting();
  }

  SchedulerServiceThread* service_thread() {
    return service_thread_.get();
  }

  DelayedTaskManager& delayed_task_manager() {
    return delayed_task_manager_;
  }

  SchedulerWorkerPoolImpl* worker_pool() {
    return scheduler_worker_pool_.get();
  }

 private:
  static void ReEnqueueSequenceCallback(scoped_refptr<Sequence> sequence) {
    ADD_FAILURE() << "This test only expects one task per sequence.";
  }

  DelayedTaskManager delayed_task_manager_;
  TaskTracker task_tracker_;
  std::unique_ptr<SchedulerWorkerPoolImpl> scheduler_worker_pool_;
  std::unique_ptr<SchedulerServiceThread> service_thread_;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerServiceThreadTest);
};

}  // namespace

// Tests that the service thread can handle a single delayed task.
TEST_F(TaskSchedulerServiceThreadTest, RunSingleDelayedTask) {
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  delayed_task_manager().AddDelayedTask(
      WrapUnique(new Task(FROM_HERE,
                          Bind(&WaitableEvent::Signal, Unretained(&event)),
                          TaskTraits(), TimeDelta::FromMilliseconds(100))),
      make_scoped_refptr(new Sequence), nullptr, worker_pool());
  // Waking the service thread shouldn't cause the task to be executed per its
  // delay not having expired (racy in theory, see test-fixture meta-comment).
  service_thread()->WakeUp();
  // Yield to increase the likelihood of catching a bug where these tasks would
  // be released before their delay is passed.
  PlatformThread::YieldCurrentThread();
  EXPECT_FALSE(event.IsSignaled());
  // When the delay expires, the delayed task is posted, signaling |event|.
  event.Wait();
}

// Tests that the service thread can handle more than one delayed task with
// different delays.
TEST_F(TaskSchedulerServiceThreadTest, RunMultipleDelayedTasks) {
  const TimeTicks test_begin_time = TimeTicks::Now();
  const TimeDelta delay1 = TimeDelta::FromMilliseconds(100);
  const TimeDelta delay2 = TimeDelta::FromMilliseconds(200);

  WaitableEvent event1(WaitableEvent::ResetPolicy::MANUAL,
                       WaitableEvent::InitialState::NOT_SIGNALED);
  delayed_task_manager().AddDelayedTask(
      WrapUnique(new Task(FROM_HERE,
                          Bind(&WaitableEvent::Signal, Unretained(&event1)),
                          TaskTraits(), delay1)),
      make_scoped_refptr(new Sequence), nullptr, worker_pool());

  WaitableEvent event2(WaitableEvent::ResetPolicy::MANUAL,
                       WaitableEvent::InitialState::NOT_SIGNALED);
  delayed_task_manager().AddDelayedTask(
      WrapUnique(new Task(FROM_HERE,
                          Bind(&WaitableEvent::Signal, Unretained(&event2)),
                          TaskTraits(), delay2)),
      make_scoped_refptr(new Sequence), nullptr, worker_pool());

  // Adding the task shouldn't have caused them to be executed.
  EXPECT_FALSE(event1.IsSignaled());
  EXPECT_FALSE(event2.IsSignaled());

  // Waking the service thread shouldn't cause the tasks to be executed per
  // their delays not having expired (note: this is racy if the delay somehow
  // expires before this runs but 100ms is a long time in a unittest...). It
  // should instead cause the service thread to schedule itself for wakeup when
  // |delay1| expires.
  service_thread()->WakeUp();
  // Yield to increase the likelihood of catching a bug where these tasks would
  // be released before their delay is passed.
  PlatformThread::YieldCurrentThread();
  EXPECT_FALSE(event1.IsSignaled());
  EXPECT_FALSE(event2.IsSignaled());

  // Confirm the above assumption about the evolution of time in the test.
  EXPECT_LT(TimeTicks::Now() - test_begin_time, delay1);

  // Wait until |delay1| expires and service thread wakes up to schedule the
  // first task, signalling |event1|.
  event1.Wait();

  // Only the first task should have been released.
  EXPECT_TRUE(event1.IsSignaled());
  EXPECT_FALSE(event2.IsSignaled());

  // At least |delay1| should have passed for |event1| to fire.
  EXPECT_GE(TimeTicks::Now() - test_begin_time, delay1);

  // And assuming a sane test timeline |delay2| shouldn't have expired yet.
  EXPECT_LT(TimeTicks::Now() - test_begin_time, delay2);

  // Now wait for the second task to be fired.
  event2.Wait();

  // Which should only have fired after |delay2| was expired.
  EXPECT_GE(TimeTicks::Now() - test_begin_time, delay2);
}

}  // namespace internal
}  // namespace base
