// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_environment.h"

#include "base/bind.h"
#include "base/synchronization/atomic_flag.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/post_task.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace test {

namespace {

void VerifyRunUntilIdleDidNotReturnAndSetFlag(
    AtomicFlag* run_until_idle_returned,
    AtomicFlag* task_ran) {
  EXPECT_FALSE(run_until_idle_returned->IsSet());
  task_ran->Set();
}

void RunUntilIdleTest(
    ScopedTaskEnvironment::ExecutionMode execution_control_mode) {
  AtomicFlag run_until_idle_returned;
  ScopedTaskEnvironment scoped_task_environment(
      ScopedTaskEnvironment::MainThreadType::DEFAULT, execution_control_mode);

  AtomicFlag first_main_thread_task_ran;
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&VerifyRunUntilIdleDidNotReturnAndSetFlag,
                          Unretained(&run_until_idle_returned),
                          Unretained(&first_main_thread_task_ran)));

  AtomicFlag first_task_scheduler_task_ran;
  PostTask(FROM_HERE, BindOnce(&VerifyRunUntilIdleDidNotReturnAndSetFlag,
                               Unretained(&run_until_idle_returned),
                               Unretained(&first_task_scheduler_task_ran)));

  AtomicFlag second_task_scheduler_task_ran;
  AtomicFlag second_main_thread_task_ran;
  PostTaskAndReply(FROM_HERE,
                   BindOnce(&VerifyRunUntilIdleDidNotReturnAndSetFlag,
                            Unretained(&run_until_idle_returned),
                            Unretained(&second_task_scheduler_task_ran)),
                   BindOnce(&VerifyRunUntilIdleDidNotReturnAndSetFlag,
                            Unretained(&run_until_idle_returned),
                            Unretained(&second_main_thread_task_ran)));

  scoped_task_environment.RunUntilIdle();
  run_until_idle_returned.Set();

  EXPECT_TRUE(first_main_thread_task_ran.IsSet());
  EXPECT_TRUE(first_task_scheduler_task_ran.IsSet());
  EXPECT_TRUE(second_task_scheduler_task_ran.IsSet());
  EXPECT_TRUE(second_main_thread_task_ran.IsSet());
}

}  // namespace

TEST(ScopedTaskEnvironmentTest, QueuedRunUntilIdle) {
  RunUntilIdleTest(ScopedTaskEnvironment::ExecutionMode::QUEUED);
}

TEST(ScopedTaskEnvironmentTest, AsyncRunUntilIdle) {
  RunUntilIdleTest(ScopedTaskEnvironment::ExecutionMode::ASYNC);
}

// Verify that tasks posted to an ExecutionMode::QUEUED ScopedTaskEnvironment do
// not run outside of RunUntilIdle().
TEST(ScopedTaskEnvironmentTest, QueuedTasksDoNotRunOutsideOfRunUntilIdle) {
  ScopedTaskEnvironment scoped_task_environment(
      ScopedTaskEnvironment::MainThreadType::DEFAULT,
      ScopedTaskEnvironment::ExecutionMode::QUEUED);

  AtomicFlag run_until_idle_called;
  PostTask(FROM_HERE, BindOnce(
                          [](AtomicFlag* run_until_idle_called) {
                            EXPECT_TRUE(run_until_idle_called->IsSet());
                          },
                          Unretained(&run_until_idle_called)));
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  run_until_idle_called.Set();
  scoped_task_environment.RunUntilIdle();

  AtomicFlag other_run_until_idle_called;
  PostTask(FROM_HERE, BindOnce(
                          [](AtomicFlag* other_run_until_idle_called) {
                            EXPECT_TRUE(other_run_until_idle_called->IsSet());
                          },
                          Unretained(&other_run_until_idle_called)));
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  other_run_until_idle_called.Set();
  scoped_task_environment.RunUntilIdle();
}

// Verify that a task posted to an ExecutionMode::ASYNC ScopedTaskEnvironment
// can run without a call to RunUntilIdle().
TEST(ScopedTaskEnvironmentTest, AsyncTasksRunAsTheyArePosted) {
  ScopedTaskEnvironment scoped_task_environment(
      ScopedTaskEnvironment::MainThreadType::DEFAULT,
      ScopedTaskEnvironment::ExecutionMode::ASYNC);

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  PostTask(FROM_HERE,
           BindOnce([](WaitableEvent* task_ran) { task_ran->Signal(); },
                    Unretained(&task_ran)));
  task_ran.Wait();
}

// Verify that a task posted to an ExecutionMode::ASYNC ScopedTaskEnvironment
// after a call to RunUntilIdle() can run without another call to
// RunUntilIdle().
TEST(ScopedTaskEnvironmentTest, AsyncTasksRunAsTheyArePostedAfterRunUntilIdle) {
  ScopedTaskEnvironment scoped_task_environment(
      ScopedTaskEnvironment::MainThreadType::DEFAULT,
      ScopedTaskEnvironment::ExecutionMode::ASYNC);

  scoped_task_environment.RunUntilIdle();

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  PostTask(FROM_HERE,
           BindOnce([](WaitableEvent* task_ran) { task_ran->Signal(); },
                    Unretained(&task_ran)));
  task_ran.Wait();
}

}  // namespace test
}  // namespace base
