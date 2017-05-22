// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SCOPED_TASK_ENVIRONMENT_H_
#define BASE_TEST_SCOPED_TASK_ENVIRONMENT_H_

#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"

namespace base {

class TaskScheduler;

namespace test {

// ScopedTaskEnvironment allows usage of these APIs within its scope:
// - (Thread|Sequenced)TaskRunnerHandle, on the thread where it lives
// - base/task_scheduler/post_task.h, on any thread
//
// Tests that need either of these APIs should instantiate a
// ScopedTaskEnvironment.
//
// Tasks posted to the (Thread|Sequenced)TaskRunnerHandle run synchronously when
// RunLoop::Run(UntilIdle) or ScopedTaskEnvironment::RunUntilIdle is called on
// the thread where the ScopedTaskEnvironment lives.
//
// Tasks posted through base/task_scheduler/post_task.h run on dedicated threads
// as they are posted.
//
// All methods of ScopedTaskEnvironment must be called from the same thread.
//
// Usage:
//
//   class MyTestFixture : public testing::Test {
//    public:
//     (...)
//
//    protected:
//     // Must be the first member (or at least before any member that cares
//     // about tasks) to be initialized first and destroyed last. protected
//     // instead of private visibility will allow controlling the task
//     // environment (e.g. clock) once such features are added (see design doc
//     // below for details), until then it at least doesn't hurt :).
//     base::test::ScopedTaskEnvironment scoped_task_environment_;
//
//     // Other members go here (or further below in private section.)
//   };
//
// Design and future improvements documented in
// https://docs.google.com/document/d/1QabRo8c7D9LsYY3cEcaPQbOCLo8Tu-6VLykYXyl3Pkk/edit
class ScopedTaskEnvironment {
 public:
  enum class MainThreadType {
    // The main thread doesn't pump system messages.
    DEFAULT,
    // The main thread pumps UI messages.
    UI,
    // The main thread pumps asynchronous IO messages.
    IO,
  };

  ScopedTaskEnvironment(
      MainThreadType main_thread_type = MainThreadType::DEFAULT);

  // Waits until no undelayed TaskScheduler tasks remain. Then, unregisters the
  // TaskScheduler and the (Thread|Sequenced)TaskRunnerHandle.
  ~ScopedTaskEnvironment();

  // Returns a TaskRunner that schedules tasks on the main thread.
  scoped_refptr<base::SingleThreadTaskRunner> GetMainThreadTaskRunner();

  // Synchronously runs (Thread|Sequenced)TaskRunnerHandle tasks until no
  // undelayed (Thread|Sequenced)TaskRunnerHandle or TaskScheduler tasks remain.
  void RunUntilIdle();

 private:
  // Note: |message_loop_| is an implementation detail and will be replaced in
  // the future, do NOT rely on the presence of a MessageLoop beyond
  // (Thread|Sequenced)TaskRunnerHandle and RunLoop.
  MessageLoop message_loop_;

  const TaskScheduler* task_scheduler_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(ScopedTaskEnvironment);
};

}  // namespace test
}  // namespace base

#endif  // BASE_TEST_SCOPED_ASYNC_TASK_SCHEDULER_H_
