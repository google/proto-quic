// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_DELAYED_TASK_MANAGER_H_
#define BASE_TASK_SCHEDULER_DELAYED_TASK_MANAGER_H_

#include <memory>

#include "base/base_export.h"
#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"

namespace base {

class TaskRunner;

namespace internal {

struct Task;

// The DelayedTaskManager forwards tasks to various scheduler components when
// they become ripe for execution. This class is thread-safe.
class BASE_EXPORT DelayedTaskManager {
 public:
  // Posts |task| for execution immediately.
  using PostTaskNowCallback = Callback<void(std::unique_ptr<Task> task)>;

  // |service_thread_task_runner| posts tasks to the TaskScheduler service
  // thread.
  explicit DelayedTaskManager(
      scoped_refptr<TaskRunner> service_thread_task_runner);
  ~DelayedTaskManager();

  // Calls |post_task_now_callback| with |task| when |task| is ripe for
  // execution.
  void AddDelayedTask(std::unique_ptr<Task> task,
                      const PostTaskNowCallback& post_task_now_callback);

 private:
  const scoped_refptr<TaskRunner> service_thread_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(DelayedTaskManager);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_DELAYED_TASK_MANAGER_H_
