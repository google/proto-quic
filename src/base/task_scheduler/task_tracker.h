// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TASK_TRACKER_H_
#define BASE_TASK_SCHEDULER_TASK_TRACKER_H_

#include <memory>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/callback_forward.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram_base.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_traits.h"

namespace base {

class ConditionVariable;
class HistogramBase;
class SequenceToken;

namespace internal {

// All tasks go through the scheduler's TaskTracker when they are posted and
// when they are executed. The TaskTracker sets up the environment to run tasks,
// enforces shutdown semantics, records metrics, and takes care of tracing and
// profiling. This class is thread-safe.
class BASE_EXPORT TaskTracker {
 public:
  TaskTracker();
  ~TaskTracker();

  // Synchronously shuts down the scheduler. Once this is called, only tasks
  // posted with the BLOCK_SHUTDOWN behavior will be run. Returns when:
  // - All SKIP_ON_SHUTDOWN tasks that were already running have completed their
  //   execution.
  // - All posted BLOCK_SHUTDOWN tasks have completed their execution.
  // CONTINUE_ON_SHUTDOWN tasks still may be running after Shutdown returns.
  // This can only be called once.
  void Shutdown();

  // Waits until there are no pending undelayed tasks. May be called in tests
  // to validate that a condition is met after all undelayed tasks have run.
  //
  // Does not wait for delayed tasks. Waits for undelayed tasks posted from
  // other threads during the call. Returns immediately when shutdown completes.
  void Flush();

  // Informs this TaskTracker that |task| is about to be posted. Returns true if
  // this operation is allowed (|task| should be posted if-and-only-if it is).
  bool WillPostTask(const Task* task);

  // Runs |task| unless the current shutdown state prevents that.
  // |sequence_token| is the token identifying the sequence from which |task|
  // was extracted. Returns true if |task| ran. WillPostTask() must have allowed
  // |task| to be posted before this is called.
  bool RunTask(std::unique_ptr<Task> task, const SequenceToken& sequence_token);

  // Returns true once shutdown has started (Shutdown() has been called but
  // might not have returned). Note: sequential consistency with the thread
  // calling Shutdown() (or SetHasShutdownStartedForTesting()) isn't guaranteed
  // by this call.
  bool HasShutdownStarted() const;

  // Returns true if shutdown has completed (Shutdown() has returned).
  bool IsShutdownComplete() const;

  // Causes HasShutdownStarted() to return true. Unlike when Shutdown() returns,
  // IsShutdownComplete() won't return true after this returns. Shutdown()
  // cannot be called after this.
  void SetHasShutdownStartedForTesting();

 protected:
  // Runs |task|. |sequence_token| is the token identifying the sequence from
  // which |task| was extracted. An override is expected to call its parent's
  // implementation but is free to perform extra work before and after doing so.
  virtual void PerformRunTask(std::unique_ptr<Task> task,
                              const SequenceToken& sequence_token);

#if DCHECK_IS_ON()
  // Returns true if this context should be exempt from blocking shutdown
  // DCHECKs.
  // TODO(robliao): Remove when http://crbug.com/698140 is fixed.
  virtual bool IsPostingBlockShutdownTaskAfterShutdownAllowed();
#endif

 private:
  class State;

  void PerformShutdown();

  // Called before WillPostTask() informs the tracing system that a task has
  // been posted. Updates |num_tasks_blocking_shutdown_| if necessary and
  // returns true if the current shutdown state allows the task to be posted.
  bool BeforePostTask(TaskShutdownBehavior shutdown_behavior);

  // Called before a task with |shutdown_behavior| is run by RunTask(). Updates
  // |num_tasks_blocking_shutdown_| if necessary and returns true if the current
  // shutdown state allows the task to be run.
  bool BeforeRunTask(TaskShutdownBehavior shutdown_behavior);

  // Called after a task with |shutdown_behavior| has been run by RunTask().
  // Updates |num_tasks_blocking_shutdown_| and signals |shutdown_cv_| if
  // necessary.
  void AfterRunTask(TaskShutdownBehavior shutdown_behavior);

  // Called when the number of tasks blocking shutdown becomes zero after
  // shutdown has started.
  void OnBlockingShutdownTasksComplete();

  // Decrements the number of pending undelayed tasks and signals |flush_cv_| if
  // it reaches zero.
  void DecrementNumPendingUndelayedTasks();

  // Records the TaskScheduler.TaskLatency.[task priority].[may block] histogram
  // for |task|.
  void RecordTaskLatencyHistogram(Task* task);

  // Number of tasks blocking shutdown and boolean indicating whether shutdown
  // has started.
  const std::unique_ptr<State> state_;

  // Number of undelayed tasks that haven't completed their execution. Is
  // decremented with a memory barrier after a task runs. Is accessed with an
  // acquire memory barrier in Flush(). The memory barriers ensure that the
  // memory written by flushed tasks is visible when Flush() returns.
  subtle::Atomic32 num_pending_undelayed_tasks_ = 0;

  // Lock associated with |flush_cv_|. Partially synchronizes access to
  // |num_pending_undelayed_tasks_|. Full synchronization isn't needed because
  // it's atomic, but synchronization is needed to coordinate waking and
  // sleeping at the right time.
  mutable SchedulerLock flush_lock_;

  // Signaled when |num_pending_undelayed_tasks_| is zero or when shutdown
  // completes.
  const std::unique_ptr<ConditionVariable> flush_cv_;

  // Synchronizes access to shutdown related members below.
  mutable SchedulerLock shutdown_lock_;

  // Event instantiated when shutdown starts and signaled when shutdown
  // completes.
  std::unique_ptr<WaitableEvent> shutdown_event_;

  // TaskScheduler.TaskLatency.[task priority].[may block] histograms. The first
  // index is a TaskPriority. The second index is 0 for non-blocking tasks, 1
  // for blocking tasks. Intentionally leaked.
  HistogramBase* const
      task_latency_histograms_[static_cast<int>(TaskPriority::HIGHEST) + 1][2];

  // Number of BLOCK_SHUTDOWN tasks posted during shutdown.
  HistogramBase::Sample num_block_shutdown_tasks_posted_during_shutdown_ = 0;

  DISALLOW_COPY_AND_ASSIGN(TaskTracker);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_TASK_TRACKER_H_
