// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TASK_SCHEDULER_H_
#define BASE_TASK_SCHEDULER_TASK_SCHEDULER_H_

#include <memory>
#include <vector>

#include "base/base_export.h"
#include "base/callback.h"
#include "base/gtest_prod_util.h"
#include "base/memory/ref_counted.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_piece.h"
#include "base/task_runner.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/single_thread_task_runner_thread_mode.h"
#include "base/task_scheduler/task_traits.h"
#include "base/time/time.h"
#include "build/build_config.h"

namespace gin {
class V8Platform;
}

namespace content {
// Can't use the FRIEND_TEST_ALL_PREFIXES macro because the test is in a
// different namespace.
class BrowserMainLoopTest_CreateThreadsInSingleProcess_Test;
}  // namespace content

namespace tracked_objects {
class Location;
}

namespace base {

class HistogramBase;

// Interface for a task scheduler and static methods to manage the instance used
// by the post_task.h API.
//
// The task scheduler doesn't create threads until Start() is called. Tasks can
// be posted at any time but will not run until after Start() is called.
//
// The instance methods of this class are thread-safe.
//
// Note: All base/task_scheduler users should go through post_task.h instead of
// TaskScheduler except for the one callsite per process which manages the
// process's instance.
class BASE_EXPORT TaskScheduler {
 public:
  struct BASE_EXPORT InitParams {
    InitParams(
        const SchedulerWorkerPoolParams& background_worker_pool_params_in,
        const SchedulerWorkerPoolParams&
            background_blocking_worker_pool_params_in,
        const SchedulerWorkerPoolParams& foreground_worker_pool_params_in,
        const SchedulerWorkerPoolParams&
            foreground_blocking_worker_pool_params_in);
    ~InitParams();

    SchedulerWorkerPoolParams background_worker_pool_params;
    SchedulerWorkerPoolParams background_blocking_worker_pool_params;
    SchedulerWorkerPoolParams foreground_worker_pool_params;
    SchedulerWorkerPoolParams foreground_blocking_worker_pool_params;
  };

  // Destroying a TaskScheduler is not allowed in production; it is always
  // leaked. In tests, it should only be destroyed after JoinForTesting() has
  // returned.
  virtual ~TaskScheduler() = default;

  // Allows the task scheduler to create threads and run tasks following the
  // |init_params| specification. CHECKs on failure.
  virtual void Start(const InitParams& init_params) = 0;

  // Posts |task| with a |delay| and specific |traits|. |delay| can be zero.
  // For one off tasks that don't require a TaskRunner.
  virtual void PostDelayedTaskWithTraits(
      const tracked_objects::Location& from_here,
      const TaskTraits& traits,
      OnceClosure task,
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
  CreateSingleThreadTaskRunnerWithTraits(
      const TaskTraits& traits,
      SingleThreadTaskRunnerThreadMode thread_mode) = 0;

#if defined(OS_WIN)
  // Returns a SingleThreadTaskRunner whose PostTask invocations result in
  // scheduling tasks using |traits| in a COM Single-Threaded Apartment. Tasks
  // run in the same Single-Threaded Apartment in posting order for the returned
  // SingleThreadTaskRunner. There is not necessarily a one-to-one
  // correspondence between SingleThreadTaskRunners and Single-Threaded
  // Apartments. The implementation is free to share apartments or create new
  // apartments as necessary. In either case, care should be taken to make sure
  // COM pointers are not smuggled across apartments.
  virtual scoped_refptr<SingleThreadTaskRunner>
  CreateCOMSTATaskRunnerWithTraits(
      const TaskTraits& traits,
      SingleThreadTaskRunnerThreadMode thread_mode) = 0;
#endif  // defined(OS_WIN)

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

// CreateAndStartWithDefaultParams(), Create(), and SetInstance() register a
// TaskScheduler to handle tasks posted through the post_task.h API for this
// process.
//
// Processes that need to initialize TaskScheduler with custom params or that
// need to allow tasks to be posted before the TaskScheduler creates its
// threads should use Create() followed by Start(). Other processes can use
// CreateAndStartWithDefaultParams().
//
// A registered TaskScheduler is only deleted when a new TaskScheduler is
// registered. The last registered TaskScheduler is leaked on shutdown. The
// methods below must not be called when TaskRunners created by a previous
// TaskScheduler are still alive. The methods are not thread-safe; proper
// synchronization is required to use the post_task.h API after registering a
// new TaskScheduler.

#if !defined(OS_NACL)
  // Creates and starts a task scheduler using default params. |name| is used to
  // label threads and histograms. It should identify the component that calls
  // this. Start() is called by this method; it is invalid to call it again
  // afterwards. CHECKs on failure. For tests, prefer
  // base::test::ScopedTaskEnvironment (ensures isolation).
  static void CreateAndStartWithDefaultParams(StringPiece name);
#endif  // !defined(OS_NACL)

  // Creates a ready to start task scheduler. |name| is used to label threads
  // and histograms. It should identify the component that creates the
  // TaskScheduler. The task scheduler doesn't create threads until Start() is
  // called. Tasks can be posted at any time but will not run until after
  // Start() is called. For tests, prefer base::test::ScopedTaskEnvironment
  // (ensures isolation).
  static void Create(StringPiece name);

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
  friend class content::BrowserMainLoopTest_CreateThreadsInSingleProcess_Test;

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
