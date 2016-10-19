// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_DELAYED_TASK_MANAGER_H_
#define BASE_TASK_SCHEDULER_DELAYED_TASK_MANAGER_H_

#include <memory>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/time/time.h"

namespace base {

class TaskRunner;

namespace internal {

class SchedulerWorker;
class SchedulerWorkerPool;
class Sequence;
struct Task;

// A DelayedTaskManager forwards Tasks to a SchedulerWorkerPool when they become
// ripe for execution. This class is thread-safe.
class BASE_EXPORT DelayedTaskManager {
 public:
  // |service_thread_task_runner| posts tasks to the TaskScheduler service
  // thread.
  explicit DelayedTaskManager(
      scoped_refptr<TaskRunner> service_thread_task_runner);
  ~DelayedTaskManager();

  // Posts |task|. The task will be forwarded to |worker_pool| with |sequence|
  // and |worker| when it becomes ripe for execution. |worker| is a
  // SchedulerWorker owned by |worker_pool| or nullptr.
  //
  // TODO(robliao): Find a concrete way to manage the memory of |worker| and
  // |worker_pool|. These objects are never deleted in production, but it is
  // better not to spread this assumption throughout the scheduler.
  void AddDelayedTask(std::unique_ptr<Task> task,
                      scoped_refptr<Sequence> sequence,
                      SchedulerWorker* worker,
                      SchedulerWorkerPool* worker_pool);

 private:
  const scoped_refptr<TaskRunner> service_thread_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(DelayedTaskManager);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_DELAYED_TASK_MANAGER_H_
