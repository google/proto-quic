// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SCOPED_ASYNC_TASK_SCHEDULER_H_
#define BASE_TEST_SCOPED_ASYNC_TASK_SCHEDULER_H_

#include "base/macros.h"

namespace base {

class TaskScheduler;

namespace test {

// Allows usage of the base/task_scheduler/post_task.h API within its scope.
// Tasks run asynchronously, one at a time.
//
// To wait until all posted tasks have run, use
// TaskScheduler::GetInstance()->FlushForTesting().
//
// When possible, use ScopedTaskScheduler instead of this. Tasks posted within
// the scope of a ScopedTaskScheduler run synchronously, which makes tests
// easier to understand.
class ScopedAsyncTaskScheduler {
 public:
  // Registers a single-threaded TaskScheduler.
  ScopedAsyncTaskScheduler();

  // Shuts down and unregisters the TaskScheduler.
  ~ScopedAsyncTaskScheduler();

 private:
  const TaskScheduler* task_scheduler_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(ScopedAsyncTaskScheduler);
};

}  // namespace test
}  // namespace base

#endif  // BASE_TEST_SCOPED_ASYNC_TASK_SCHEDULER_H_
