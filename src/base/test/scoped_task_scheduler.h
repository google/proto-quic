// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_SCOPED_TASK_SCHEDULER_H_
#define BASE_TEST_SCOPED_TASK_SCHEDULER_H_

#include "base/macros.h"

namespace base {

class TaskScheduler;

namespace test {

// Initializes a TaskScheduler and allows usage of the
// base/task_scheduler/post_task.h API within its scope.
class ScopedTaskScheduler {
 public:
  // Initializes a TaskScheduler with default arguments.
  ScopedTaskScheduler();

  // Waits until all TaskScheduler tasks blocking shutdown complete their
  // execution (see TaskShutdownBehavior). Then, joins all TaskScheduler threads
  // and deletes the TaskScheduler.
  //
  // Note that joining TaskScheduler threads may involve waiting for
  // CONTINUE_ON_SHUTDOWN tasks to complete their execution. Normally, in
  // production, the process exits without joining TaskScheduler threads.
  ~ScopedTaskScheduler();

 private:
  const TaskScheduler* task_scheduler_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(ScopedTaskScheduler);
};

}  // namespace test
}  // namespace base

#endif  // BASE_TEST_SCOPED_TASK_SCHEDULER_H_
