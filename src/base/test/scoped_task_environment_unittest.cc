// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_environment.h"

#include "base/bind.h"
#include "base/synchronization/atomic_flag.h"
#include "base/task_scheduler/post_task.h"
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

}  // namespace

TEST(ScopedTaskEnvironmentTest, RunUntilIdle) {
  AtomicFlag run_until_idle_returned;
  ScopedTaskEnvironment scoped_task_environment;

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

}  // namespace test
}  // namespace base
