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
#include "base/callback.h"
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

// A pool of workers that run Tasks. This class is thread-safe.
class BASE_EXPORT SchedulerWorkerPoolImpl : public SchedulerWorkerPool {
 public:
  // Callback invoked when a Sequence isn't empty after a worker pops a Task
  // from it.
  using ReEnqueueSequenceCallback = Callback<void(scoped_refptr<Sequence>)>;

  // Destroying a SchedulerWorkerPoolImpl returned by Create() is not allowed in
  // production; it is always leaked. In tests, it can only be destroyed after
  // JoinForTesting() has returned.
  ~SchedulerWorkerPoolImpl() override;

  // Creates a SchedulerWorkerPoolImpl following the |worker_pool_params|
  // specification. |re_enqueue_sequence_callback| will be invoked after a
  // worker of this worker pool tries to run a Task. |task_tracker| is used to
  // handle shutdown behavior of Tasks. |delayed_task_manager| handles Tasks
  // posted with a delay. Returns nullptr on failure to create a worker pool
  // with at least one thread.
  static std::unique_ptr<SchedulerWorkerPoolImpl> Create(
      const SchedulerWorkerPoolParams& params,
      const ReEnqueueSequenceCallback& re_enqueue_sequence_callback,
      TaskTracker* task_tracker,
      DelayedTaskManager* delayed_task_manager);

  // SchedulerWorkerPool:
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SequencedTaskRunner> CreateSequencedTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  void ReEnqueueSequence(scoped_refptr<Sequence> sequence,
                         const SequenceSortKey& sequence_sort_key) override;
  bool PostTaskWithSequence(std::unique_ptr<Task> task,
                            scoped_refptr<Sequence> sequence,
                            SchedulerWorker* worker) override;
  void PostTaskWithSequenceNow(std::unique_ptr<Task> task,
                               scoped_refptr<Sequence> sequence,
                               SchedulerWorker* worker) override;

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
  class SchedulerSingleThreadTaskRunner;
  class SchedulerWorkerDelegateImpl;

  SchedulerWorkerPoolImpl(const SchedulerWorkerPoolParams& params,
                          TaskTracker* task_tracker,
                          DelayedTaskManager* delayed_task_manager);

  bool Initialize(
      const SchedulerWorkerPoolParams& params,
      const ReEnqueueSequenceCallback& re_enqueue_sequence_callback);

  // Wakes up |worker|.
  void WakeUpWorker(SchedulerWorker* worker);

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

  // The name of this worker pool, used to label its worker threads.
  const std::string name_;

  // All worker owned by this worker pool. Only modified during initialization
  // of the worker pool.
  std::vector<scoped_refptr<SchedulerWorker>> workers_;

  // Synchronizes access to |next_worker_index_|.
  SchedulerLock next_worker_index_lock_;

  // Index of the worker that will be assigned to the next single-threaded
  // TaskRunner returned by this pool.
  size_t next_worker_index_ = 0;

  // PriorityQueue from which all threads of this worker pool get work.
  PriorityQueue shared_priority_queue_;

  // Suggested reclaim time for workers.
  const TimeDelta suggested_reclaim_time_;

  // Synchronizes access to |idle_workers_stack_| and
  // |idle_workers_stack_cv_for_testing_|. Has |shared_priority_queue_|'s
  // lock as its predecessor so that a worker can be pushed to
  // |idle_workers_stack_| within the scope of a Transaction (more
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

  // Signaled once JoinForTesting() has returned.
  WaitableEvent join_for_testing_returned_;

  // Indicates to the delegates that workers are not permitted to detach their
  // threads.
  AtomicFlag worker_detachment_disallowed_;

#if DCHECK_IS_ON()
  // Signaled when all workers have been created.
  WaitableEvent workers_created_;
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
