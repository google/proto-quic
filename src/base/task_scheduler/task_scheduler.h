// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TASK_SCHEDULER_H_
#define BASE_TASK_SCHEDULER_TASK_SCHEDULER_H_

#include <memory>
#include <vector>

#include "base/base_export.h"
#include "base/callback_forward.h"
#include "base/memory/ref_counted.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/task_scheduler/task_traits.h"
#include "base/time/time.h"

namespace gin {
class V8Platform;
}

namespace tracked_objects {
class Location;
}

namespace base {

class HistogramBase;
class SchedulerWorkerPoolParams;

// Interface for a task scheduler and static methods to manage the instance used
// by the post_task.h API. Note: all base/task_scheduler users should go through
// post_task.h instead of TaskScheduler except for the one callsite per process
// which manages the process' instance.
class BASE_EXPORT TaskScheduler {
 public:
  // Returns the index of the worker pool in which a task with |traits| should
  // run. This should be coded in a future-proof way: new traits should
  // gracefully map to a default pool.
  using WorkerPoolIndexForTraitsCallback =
      Callback<size_t(const TaskTraits& traits)>;

  // Destroying a TaskScheduler is not allowed in production; it is always
  // leaked. In tests, it should only be destroyed after JoinForTesting() has
  // returned.
  virtual ~TaskScheduler() = default;

  // Posts |task| with a |delay| and specific |traits|. |delay| can be zero.
  // For one off tasks that don't require a TaskRunner.
  virtual void PostDelayedTaskWithTraits(
      const tracked_objects::Location& from_here,
      const TaskTraits& traits,
      const Closure& task,
      TimeDelta delay) = 0;

  // Returns a TaskRunner whose PostTask invocations result in scheduling tasks
  // using |traits|. Tasks may run in any order and in parallel.
  virtual scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits) = 0;

  // Returns a SequencedTaskRunner whose PostTask invocations result in
  // scheduling tasks using |traits|. Tasks run one at a time in posting order.
  virtual scoped_refptr<SequencedTaskRunner>
  CreateSequencedTaskRunnerWithTraits(const TaskTraits& traits) = 0;

  // Returns a SingleThreadTaskRunner whose PostTask invocations result in
  // scheduling tasks using |traits|. Tasks run on a single thread in posting
  // order.
  virtual scoped_refptr<SingleThreadTaskRunner>
  CreateSingleThreadTaskRunnerWithTraits(const TaskTraits& traits) = 0;

  // Returns a vector of all histograms available in this task scheduler.
  virtual std::vector<const HistogramBase*> GetHistograms() const = 0;

  // Synchronously shuts down the scheduler. Once this is called, only tasks
  // posted with the BLOCK_SHUTDOWN behavior will be run. When this returns:
  // - All SKIP_ON_SHUTDOWN tasks that were already running have completed their
  //   execution.
  // - All posted BLOCK_SHUTDOWN tasks have completed their execution.
  // - CONTINUE_ON_SHUTDOWN tasks might still be running.
  // Note that an implementation can keep threads and other resources alive to
  // support running CONTINUE_ON_SHUTDOWN after this returns. This can only be
  // called once.
  virtual void Shutdown() = 0;

  // Waits until there are no pending undelayed tasks. May be called in tests
  // to validate that a condition is met after all undelayed tasks have run.
  //
  // Does not wait for delayed tasks. Waits for undelayed tasks posted from
  // other threads during the call. Returns immediately when shutdown completes.
  virtual void FlushForTesting() = 0;

  // Joins all threads. Tasks that are already running are allowed to complete
  // their execution. This can only be called once. Using this task scheduler
  // instance to create task runners or post tasks is not permitted during or
  // after this call.
  virtual void JoinForTesting() = 0;

  // CreateAndSetSimpleTaskScheduler(), CreateAndSetDefaultTaskScheduler(), and
  // SetInstance() register a TaskScheduler to handle tasks posted through the
  // post_task.h API for this process. The registered TaskScheduler will only be
  // deleted when a new TaskScheduler is registered and is leaked on shutdown.
  // The methods must not be called when TaskRunners created by the previous
  // TaskScheduler are still alive. The methods are not thread-safe; proper
  // synchronization is required to use the post_task.h API after registering a
  // new TaskScheduler.

  // Creates and sets a task scheduler with one worker pool that can have up to
  // |max_threads| threads. CHECKs on failure. For tests, prefer
  // base::test::ScopedTaskScheduler (ensures isolation).
  static void CreateAndSetSimpleTaskScheduler(int max_threads);

  // Creates and sets a task scheduler with custom worker pools. CHECKs on
  // failure. |worker_pool_params_vector| describes the worker pools to create.
  // |worker_pool_index_for_traits_callback| returns the index in |worker_pools|
  // of the worker pool in which a task with given traits should run. For tests,
  // prefer base::test::ScopedTaskScheduler (ensures isolation).
  static void CreateAndSetDefaultTaskScheduler(
      const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector,
      const WorkerPoolIndexForTraitsCallback&
          worker_pool_index_for_traits_callback);

  // Registers |task_scheduler| to handle tasks posted through the post_task.h
  // API for this process. For tests, prefer base::test::ScopedTaskScheduler
  // (ensures isolation).
  static void SetInstance(std::unique_ptr<TaskScheduler> task_scheduler);

  // Retrieve the TaskScheduler set via SetInstance() or
  // CreateAndSet(Simple|Default)TaskScheduler(). This should be used very
  // rarely; most users of TaskScheduler should use the post_task.h API. In
  // particular, refrain from doing
  //   if (!TaskScheduler::GetInstance()) {
  //     TaskScheduler::SetInstance(...);
  //     base::PostTask(...);
  //   }
  // instead make sure to SetInstance() early in one determinstic place in the
  // process' initialization phase.
  // In doubt, consult with //base/task_scheduler/OWNERS.
  static TaskScheduler* GetInstance();

 private:
  friend class gin::V8Platform;

  // Returns the maximum number of non-single-threaded tasks posted with
  // |traits| that can run concurrently in this TaskScheduler.
  //
  // Do not use this method. To process n items, post n tasks that each process
  // 1 item rather than GetMaxConcurrentTasksWithTraitsDeprecated() tasks that
  // each process n/GetMaxConcurrentTasksWithTraitsDeprecated() items.
  //
  // TODO(fdoray): Remove this method. https://crbug.com/687264
  virtual int GetMaxConcurrentTasksWithTraitsDeprecated(
      const TaskTraits& traits) const = 0;
};

}  // namespace base

#endif  // BASE_TASK_SCHEDULER_TASK_SCHEDULER_H_
