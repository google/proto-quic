// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_SINGLE_THREAD_TASK_RUNNER_MANAGER_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_SINGLE_THREAD_TASK_RUNNER_MANAGER_H_

#include <memory>
#include <vector>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_scheduler.h"
#include "build/build_config.h"

namespace base {

class TaskTraits;
class SingleThreadTaskRunner;

namespace internal {

class DelayedTaskManager;
class SchedulerWorker;
class TaskTracker;

namespace {

class SchedulerWorkerDelegate;

}  // namespace

class BASE_EXPORT SchedulerSingleThreadTaskRunnerManager final {
 public:
  SchedulerSingleThreadTaskRunnerManager(
      const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector,
      const TaskScheduler::WorkerPoolIndexForTraitsCallback&
          worker_pool_index_for_traits_callback,
      TaskTracker* task_tracker,
      DelayedTaskManager* delayed_task_manager);
  ~SchedulerSingleThreadTaskRunnerManager();

  scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
      const TaskTraits& traits);

#if defined(OS_WIN)
  scoped_refptr<SingleThreadTaskRunner> CreateCOMSTATaskRunnerWithTraits(
      const TaskTraits& traits);
#endif  // defined(OS_WIN)

  void JoinForTesting();

 private:
  class SchedulerSingleThreadTaskRunner;

  template <typename DelegateType>
  scoped_refptr<SingleThreadTaskRunner>
  CreateSingleThreadTaskRunnerWithDelegate(const TaskTraits& traits);

  template <typename DelegateType>
  std::unique_ptr<SchedulerWorkerDelegate> CreateSchedulerWorkerDelegate(
      const SchedulerWorkerPoolParams& params,
      int id);

  template <typename DelegateType>
  SchedulerWorker* CreateAndRegisterSchedulerWorker(
      const SchedulerWorkerPoolParams& params);

  void UnregisterSchedulerWorker(SchedulerWorker* worker);

  const std::vector<SchedulerWorkerPoolParams> worker_pool_params_vector_;
  const TaskScheduler::WorkerPoolIndexForTraitsCallback
      worker_pool_index_for_traits_callback_;
  TaskTracker* const task_tracker_;
  DelayedTaskManager* const delayed_task_manager_;

  // Synchronizes access to |workers_| and |worker_id_|.
  SchedulerLock workers_lock_;
  std::vector<scoped_refptr<SchedulerWorker>> workers_;
  int next_worker_id_ = 0;

#if DCHECK_IS_ON()
  subtle::Atomic32 workers_unregistered_during_join_ = 0;
#endif

  DISALLOW_COPY_AND_ASSIGN(SchedulerSingleThreadTaskRunnerManager);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_SINGLE_THREAD_TASK_RUNNER_MANAGER_H_
