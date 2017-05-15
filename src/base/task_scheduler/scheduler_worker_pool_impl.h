// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_IMPL_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_IMPL_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <vector>

#include "base/base_export.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/atomic_flag.h"
#include "base/synchronization/condition_variable.h"
#include "base/task_scheduler/priority_queue.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/scheduler_worker.h"
#include "base/task_scheduler/scheduler_worker_pool.h"
#include "base/task_scheduler/scheduler_worker_stack.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/time/time.h"

namespace base {

class HistogramBase;
class SchedulerWorkerPoolParams;
class TaskTraits;

namespace internal {

class DelayedTaskManager;
class TaskTracker;

// A pool of workers that run Tasks.
//
// The pool doesn't create threads until Start() is called. Tasks can be posted
// at any time but will not run until after Start() is called.
//
// This class is thread-safe.
class BASE_EXPORT SchedulerWorkerPoolImpl : public SchedulerWorkerPool {
 public:
  // Constructs a pool without workers.
  //
  // |name| is used to label the pool's threads ("TaskScheduler" + |name| +
  // index) and histograms ("TaskScheduler." + histogram name + "." + |name| +
  // extra suffixes). |priority_hint| is the preferred thread priority; the
  // actual thread priority depends on shutdown state and platform capabilities.
  // |task_tracker| keeps track of tasks. |delayed_task_manager| handles tasks
  // posted with a delay.
  SchedulerWorkerPoolImpl(
      const std::string& name,
      ThreadPriority priority_hint,
      TaskTracker* task_tracker,
      DelayedTaskManager* delayed_task_manager);

  // Creates workers following the |params| specification, allowing existing and
  // future tasks to run. Can only be called once. CHECKs on failure.
  void Start(const SchedulerWorkerPoolParams& params);

  // Destroying a SchedulerWorkerPoolImpl returned by Create() is not allowed in
  // production; it is always leaked. In tests, it can only be destroyed after
  // JoinForTesting() has returned.
  ~SchedulerWorkerPoolImpl() override;

  // SchedulerWorkerPool:
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SequencedTaskRunner> CreateSequencedTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  bool PostTaskWithSequence(std::unique_ptr<Task> task,
                            scoped_refptr<Sequence> sequence) override;
  void PostTaskWithSequenceNow(std::unique_ptr<Task> task,
                               scoped_refptr<Sequence> sequence) override;

  const HistogramBase* num_tasks_before_detach_histogram() const {
    return num_tasks_before_detach_histogram_;
  }

  const HistogramBase* num_tasks_between_waits_histogram() const {
    return num_tasks_between_waits_histogram_;
  }

  void GetHistograms(std::vector<const HistogramBase*>* histograms) const;

  // Returns the maximum number of tasks that can run concurrently in this pool.
  //
  // TODO(fdoray): Remove this method. https://crbug.com/687264
  int GetMaxConcurrentTasksDeprecated() const;

  // Waits until all workers are idle.
  void WaitForAllWorkersIdleForTesting();

  // Joins all workers of this worker pool. Tasks that are already running are
  // allowed to complete their execution. This can only be called once.
  void JoinForTesting();

  // Disallows worker detachment. If the suggested reclaim time is not
  // TimeDelta::Max(), the test must call this before JoinForTesting() to reduce
  // the chance of thread detachment during the process of joining all of the
  // threads, and as a result, threads running after JoinForTesting().
  void DisallowWorkerDetachmentForTesting();

  // Returns the number of workers alive in this worker pool. The value may
  // change if workers are woken up or detached during this call.
  size_t NumberOfAliveWorkersForTesting();

 private:
  class SchedulerWorkerDelegateImpl;

  SchedulerWorkerPoolImpl(const SchedulerWorkerPoolParams& params,
                          TaskTracker* task_tracker,
                          DelayedTaskManager* delayed_task_manager);

  // Wakes up the last worker from this worker pool to go idle, if any.
  void WakeUpOneWorker();

  // Adds |worker| to |idle_workers_stack_|.
  void AddToIdleWorkersStack(SchedulerWorker* worker);

  // Peeks from |idle_workers_stack_|.
  const SchedulerWorker* PeekAtIdleWorkersStack() const;

  // Removes |worker| from |idle_workers_stack_|.
  void RemoveFromIdleWorkersStack(SchedulerWorker* worker);

  // Returns true if worker thread detachment is permitted.
  bool CanWorkerDetachForTesting();

  const std::string name_;
  const ThreadPriority priority_hint_;

  // PriorityQueue from which all threads of this worker pool get work.
  PriorityQueue shared_priority_queue_;

  // All workers owned by this worker pool. Initialized by Start() within the
  // scope of |idle_workers_stack_lock_|. Never modified afterwards (i.e. can be
  // read without synchronization once |workers_created_.IsSet()|).
  std::vector<scoped_refptr<SchedulerWorker>> workers_;

  // Suggested reclaim time for workers. Initialized by Start(). Never modified
  // afterwards (i.e. can be read without synchronization once
  // |workers_created_.IsSet()|).
  TimeDelta suggested_reclaim_time_;

  // Synchronizes access to |idle_workers_stack_|,
  // |idle_workers_stack_cv_for_testing_| and |num_wake_ups_before_start_|. Has
  // |shared_priority_queue_|'s lock as its predecessor so that a worker can be
  // pushed to |idle_workers_stack_| within the scope of a Transaction (more
  // details in GetWork()).
  mutable SchedulerLock idle_workers_stack_lock_;

  // Stack of idle workers. Initially, all workers are on this stack. A worker
  // is removed from the stack before its WakeUp() function is called and when
  // it receives work from GetWork() (a worker calls GetWork() when its sleep
  // timeout expires, even if its WakeUp() method hasn't been called). A worker
  // is pushed on this stack when it receives nullptr from GetWork().
  SchedulerWorkerStack idle_workers_stack_;

  // Signaled when all workers become idle.
  std::unique_ptr<ConditionVariable> idle_workers_stack_cv_for_testing_;

  // Number of wake ups that occurred before Start(). Never modified after
  // Start() (i.e. can be read without synchronization once
  // |workers_created_.IsSet()|).
  int num_wake_ups_before_start_ = 0;

  // Signaled once JoinForTesting() has returned.
  WaitableEvent join_for_testing_returned_;

  // Indicates to the delegates that workers are not permitted to detach their
  // threads.
  AtomicFlag worker_detachment_disallowed_;

#if DCHECK_IS_ON()
  // Set when all workers have been created.
  AtomicFlag workers_created_;
#endif

  // TaskScheduler.DetachDuration.[worker pool name] histogram. Intentionally
  // leaked.
  HistogramBase* const detach_duration_histogram_;

  // TaskScheduler.NumTasksBeforeDetach.[worker pool name] histogram.
  // Intentionally leaked.
  HistogramBase* const num_tasks_before_detach_histogram_;

  // TaskScheduler.NumTasksBetweenWaits.[worker pool name] histogram.
  // Intentionally leaked.
  HistogramBase* const num_tasks_between_waits_histogram_;

  TaskTracker* const task_tracker_;
  DelayedTaskManager* const delayed_task_manager_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerPoolImpl);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_IMPL_H_
