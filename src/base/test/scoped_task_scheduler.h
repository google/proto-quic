// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SCOPED_TASK_SCHEDULER_H_
#define BASE_TEST_SCOPED_TASK_SCHEDULER_H_

#include "base/macros.h"
#include "base/threading/thread_checker.h"

namespace base {

class MessageLoop;
class TaskScheduler;

namespace test {

// Allows usage of the base/task_scheduler/post_task.h API within its scope.
//
// To run pending tasks synchronously, call RunLoop::Run/RunUntilIdle() on the
// thread where the ScopedTaskScheduler lives. The destructor runs remaining
// BLOCK_SHUTDOWN tasks synchronously.
//
// Example usage:
//
// In this snippet, RunUntilIdle() returns after "A" is run.
// base::test::ScopedTaskScheduler scoped_task_scheduler;
// base::PostTask(FROM_HERE, base::Bind(&A));
// base::RunLoop::RunUntilIdle(); // Returns after running A.
//
// In this snippet, run_loop.Run() returns after running "B" and
// "RunLoop::Quit".
// base::RunLoop run_loop;
// base::PostTask(FROM_HERE, base::Bind(&B));
// base::PostTask(FROM_HERE, base::Bind(&RunLoop::Quit, &run_loop));
// base::PostTask(FROM_HERE, base::Bind(&C));
// base::PostTaskWithTraits(
//     base::TaskTraits().WithShutdownBehavior(
//         base::TaskShutdownBehavior::BLOCK_SHUTDOWN),
//     base::Bind(&D));
// run_loop.Run();  // Returns after running B and RunLoop::Quit.
//
// At this point, |scoped_task_scheduler| will be destroyed. The destructor
// runs "D" because it's BLOCK_SHUTDOWN. "C" is skipped.
class ScopedTaskScheduler {
 public:
  // Registers a TaskScheduler that instantiates a MessageLoop on the current
  // thread and runs its tasks on it.
  ScopedTaskScheduler();

  // Registers a TaskScheduler that runs its tasks on |external_message_loop|.
  // |external_message_loop| must be bound to the current thread.
  explicit ScopedTaskScheduler(MessageLoop* external_message_loop);

  // Runs all pending BLOCK_SHUTDOWN tasks and unregisters the TaskScheduler.
  ~ScopedTaskScheduler();

 private:
  const TaskScheduler* task_scheduler_ = nullptr;
  ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(ScopedTaskScheduler);
};

}  // namespace test
}  // namespace base

#endif  // BASE_TEST_SCOPED_TASK_SCHEDULER_H_
