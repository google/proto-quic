// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TASK_SCHEDULER_IMPL_H_
#define BASE_TASK_SCHEDULER_TASK_SCHEDULER_IMPL_H_

#include <memory>
#include <vector>

#include "base/base_export.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/atomic_flag.h"
#include "base/task_scheduler/scheduler_worker_pool_impl.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/task_traits.h"
#include "base/threading/thread.h"

namespace base {

class HistogramBase;
class SchedulerWorkerPoolParams;

namespace internal {

class DelayedTaskManager;
class TaskTracker;

// Default TaskScheduler implementation. This class is thread-safe.
class BASE_EXPORT TaskSchedulerImpl : public TaskScheduler {
 public:
  // Creates and returns an initialized TaskSchedulerImpl. CHECKs on failure.
  // |worker_pool_params_vector| describes the worker pools to create.
  // |worker_pool_index_for_traits_callback| returns the index in |worker_pools|
  // of the worker pool in which a task with given traits should run.
  static std::unique_ptr<TaskSchedulerImpl> Create(
      const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector,
      const WorkerPoolIndexForTraitsCallback&
          worker_pool_index_for_traits_callback);

  ~TaskSchedulerImpl() override;

  // TaskScheduler:
  void PostDelayedTaskWithTraits(const tracked_objects::Location& from_here,
                                 const TaskTraits& traits,
                                 const Closure& task,
                                 TimeDelta delay) override;
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SequencedTaskRunner> CreateSequencedTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  std::vector<const HistogramBase*> GetHistograms() const override;
  int GetMaxConcurrentTasksWithTraitsDeprecated(
      const TaskTraits& traits) const override;
  void Shutdown() override;
  void FlushForTesting() override;
  void JoinForTesting() override;

 private:
  explicit TaskSchedulerImpl(const WorkerPoolIndexForTraitsCallback&
                                 worker_pool_index_for_traits_callback);

  void Initialize(
      const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector);

  // Returns the worker pool that runs Tasks with |traits|.
  SchedulerWorkerPoolImpl* GetWorkerPoolForTraits(
      const TaskTraits& traits) const;

  // Callback invoked when a non-single-thread |sequence| isn't empty after a
  // worker pops a Task from it.
  void ReEnqueueSequenceCallback(scoped_refptr<Sequence> sequence);

  Thread service_thread_;
  std::unique_ptr<TaskTracker> task_tracker_;
  std::unique_ptr<DelayedTaskManager> delayed_task_manager_;
  const WorkerPoolIndexForTraitsCallback worker_pool_index_for_traits_callback_;
  std::vector<std::unique_ptr<SchedulerWorkerPoolImpl>> worker_pools_;

#if DCHECK_IS_ON()
  // Set once JoinForTesting() has returned.
  AtomicFlag join_for_testing_returned_;
#endif

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerImpl);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_TASK_SCHEDULER_IMPL_H_
