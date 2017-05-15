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

// DEPRECATED. Use ScopedTaskEnvironment instead.
//
// TODO(fdoray): Replace ScopedTaskScheduler instances by ScopedTaskEnvironment.
// https://crbug.com/708584
//
// Allows usage of the base/task_scheduler/post_task.h API within its scope.
//
// To run pending tasks synchronously, call RunLoop::Run/RunUntilIdle() on the
// thread where the ScopedTaskScheduler lives. The destructor runs remaining
// BLOCK_SHUTDOWN tasks synchronously.
//
// Note: ScopedTaskScheduler intentionally breaks the TaskScheduler contract of
// always running its tasks on threads it owns, instead opting to run its tasks
// on the main thread for determinism in tests. Components that depend on
// TaskScheduler using independent threads should use ScopedAsyncTaskScheduler
// for testing.
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
//     {base::TaskShutdownBehavior::BLOCK_SHUTDOWN},
//     base::Bind(&D));
// run_loop.Run();  // Returns after running B and RunLoop::Quit.
//
// At this point, |scoped_task_scheduler| will be destroyed. The destructor
// runs "D" because it's BLOCK_SHUTDOWN. "C" is skipped.
class ScopedTaskScheduler {
 public:
  // Registers a synchronous TaskScheduler on a thread that doesn't have a
  // MessageLoop.
  //
  // This constructor handles most common cases.
  ScopedTaskScheduler();

  // Registers a synchronous TaskScheduler on a thread that already has a
  // |message_loop| assumed to be associated with the caller's thread. Calling
  // RunLoop::Run/RunUntilIdle() on the thread where this lives runs the
  // MessageLoop and TaskScheduler tasks in posting order.
  //
  // In general, you don't need a ScopedTaskScheduler and a MessageLoop because
  // ScopedTaskScheduler provides most MessageLoop features.
  //
  //     ScopedTaskScheduler scoped_task_scheduler;
  //     ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, Bind(&Task));
  //     RunLoop().RunUntilIdle();  // Runs Task.
  //
  //     is equivalent to
  //
  //     MessageLoop message_loop;
  //     ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, Bind(&Task));
  //     RunLoop().RunUntilIdle();  // Runs Task.
  //
  // Use this constructor if you need a non-default MessageLoop (e.g.
  // MessageLoopFor(UI|IO)).
  //
  //    MessageLoopForIO message_loop_for_io;
  //    ScopedTaskScheduler scoped_task_scheduler(&message_loop_for_io);
  //    message_loop_for_io->WatchFileDescriptor(...);
  //    message_loop_for_io->task_runner()->PostTask(
  //        FROM_HERE, &MessageLoopTask);
  //    PostTaskWithTraits(FROM_HERE, TaskTraits(), Bind(&TaskSchedulerTask));
  //    RunLoop().RunUntilIdle();  // Runs both MessageLoopTask and
  //                               // TaskSchedulerTask.
  explicit ScopedTaskScheduler(MessageLoop* message_loop);

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
