// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/run_loop.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

void QuitWhenIdleTask(RunLoop* run_loop, int* counter) {
  run_loop->QuitWhenIdle();
  ++(*counter);
}

void ShouldRunTask(int* counter) {
  ++(*counter);
}

void ShouldNotRunTask() {
  ADD_FAILURE() << "Ran a task that shouldn't run.";
}

void RunNestedLoopTask(int* counter) {
  RunLoop nested_run_loop;

  // This task should quit |nested_run_loop| but not the main RunLoop.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, Bind(&QuitWhenIdleTask, Unretained(&nested_run_loop),
                      Unretained(counter)));

  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, Bind(&ShouldNotRunTask), TimeDelta::FromDays(1));

  MessageLoop::ScopedNestableTaskAllower allower(MessageLoop::current());
  nested_run_loop.Run();

  ++(*counter);
}

class RunLoopTest : public testing::Test {
 protected:
  RunLoopTest() = default;

  MessageLoop message_loop_;
  RunLoop run_loop_;
  int counter_ = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(RunLoopTest);
};

}  // namespace

TEST_F(RunLoopTest, QuitWhenIdle) {
  message_loop_.task_runner()->PostTask(
      FROM_HERE,
      Bind(&QuitWhenIdleTask, Unretained(&run_loop_), Unretained(&counter_)));
  message_loop_.task_runner()->PostTask(
      FROM_HERE, Bind(&ShouldRunTask, Unretained(&counter_)));
  message_loop_.task_runner()->PostDelayedTask(
      FROM_HERE, Bind(&ShouldNotRunTask), TimeDelta::FromDays(1));

  run_loop_.Run();
  EXPECT_EQ(2, counter_);
}

TEST_F(RunLoopTest, QuitWhenIdleNestedLoop) {
  message_loop_.task_runner()->PostTask(
      FROM_HERE, Bind(&RunNestedLoopTask, Unretained(&counter_)));
  message_loop_.task_runner()->PostTask(
      FROM_HERE,
      Bind(&QuitWhenIdleTask, Unretained(&run_loop_), Unretained(&counter_)));
  message_loop_.task_runner()->PostTask(
      FROM_HERE, Bind(&ShouldRunTask, Unretained(&counter_)));
  message_loop_.task_runner()->PostDelayedTask(
      FROM_HERE, Bind(&ShouldNotRunTask), TimeDelta::FromDays(1));

  run_loop_.Run();
  EXPECT_EQ(4, counter_);
}

TEST_F(RunLoopTest, QuitWhenIdleClosure) {
  message_loop_.task_runner()->PostTask(FROM_HERE,
                                        run_loop_.QuitWhenIdleClosure());
  message_loop_.task_runner()->PostTask(
      FROM_HERE, Bind(&ShouldRunTask, Unretained(&counter_)));
  message_loop_.task_runner()->PostDelayedTask(
      FROM_HERE, Bind(&ShouldNotRunTask), TimeDelta::FromDays(1));

  run_loop_.Run();
  EXPECT_EQ(1, counter_);
}

// Verify that the QuitWhenIdleClosure() can run after the RunLoop has been
// deleted. It should have no effect.
TEST_F(RunLoopTest, QuitWhenIdleClosureAfterRunLoopScope) {
  Closure quit_when_idle_closure;
  {
    RunLoop run_loop;
    quit_when_idle_closure = run_loop.QuitWhenIdleClosure();
    run_loop.RunUntilIdle();
  }
  quit_when_idle_closure.Run();
}

}  // namespace base
