// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SCOPED_TASK_ENVIRONMENT_H_
#define BASE_TEST_SCOPED_TASK_ENVIRONMENT_H_

#include "base/macros.h"
#include "base/message_loop/message_loop.h"

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
// RunLoop::Run(UntilIdle) is called on the thread where the
// ScopedTaskEnvironment lives.
//
// Tasks posted through base/task_scheduler/post_task.h run on dedicated threads
// as they are posted.
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

  // Runs pending (Thread|Sequenced)TaskRunnerHandle tasks and pending
  // BLOCK_SHUTDOWN TaskScheduler tasks. Then, unregisters the TaskScheduler and
  // the (Thread|Sequenced)TaskRunnerHandle.
  ~ScopedTaskEnvironment();

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
