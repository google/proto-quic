// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_tracker.h"

#include <limits>

#include "base/callback.h"
#include "base/debug/task_annotator.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/sequence_token.h"
#include "base/synchronization/condition_variable.h"
#include "base/task_scheduler/scoped_set_task_priority_for_current_thread.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"

namespace base {
namespace internal {

namespace {

constexpr char kParallelExecutionMode[] = "parallel";
constexpr char kSequencedExecutionMode[] = "sequenced";
constexpr char kSingleThreadExecutionMode[] = "single thread";

// An immutable copy of a scheduler task's info required by tracing.
class TaskTracingInfo : public trace_event::ConvertableToTraceFormat {
 public:
  TaskTracingInfo(const TaskTraits& task_traits,
                  const char* execution_mode,
                  const SequenceToken& sequence_token)
      : task_traits_(task_traits),
        execution_mode_(execution_mode),
        sequence_token_(sequence_token) {}

  // trace_event::ConvertableToTraceFormat implementation.
  void AppendAsTraceFormat(std::string* out) const override;

 private:
  const TaskTraits task_traits_;
  const char* const execution_mode_;
  const SequenceToken sequence_token_;

  DISALLOW_COPY_AND_ASSIGN(TaskTracingInfo);
};

void TaskTracingInfo::AppendAsTraceFormat(std::string* out) const {
  DictionaryValue dict;

  dict.SetString("task_priority",
                 base::TaskPriorityToString(task_traits_.priority()));
  dict.SetString("execution_mode", execution_mode_);
  if (execution_mode_ != kParallelExecutionMode)
    dict.SetInteger("sequence_token", sequence_token_.ToInternalValue());

  std::string tmp;
  JSONWriter::Write(dict, &tmp);
  out->append(tmp);
}

const char kQueueFunctionName[] = "base::PostTask";

// This name conveys that a Task is run by the task scheduler without revealing
// its implementation details.
const char kRunFunctionName[] = "TaskSchedulerRunTask";

// Upper bound for the
// TaskScheduler.BlockShutdownTasksPostedDuringShutdown histogram.
const HistogramBase::Sample kMaxBlockShutdownTasksPostedDuringShutdown = 1000;

void RecordNumBlockShutdownTasksPostedDuringShutdown(
    HistogramBase::Sample value) {
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "TaskScheduler.BlockShutdownTasksPostedDuringShutdown", value, 1,
      kMaxBlockShutdownTasksPostedDuringShutdown, 50);
}

}  // namespace

// Atomic internal state used by TaskTracker. Sequential consistency shouldn't
// be assumed from these calls (i.e. a thread reading
// |HasShutdownStarted() == true| isn't guaranteed to see all writes made before
// |StartShutdown()| on the thread that invoked it).
class TaskTracker::State {
 public:
  State() = default;

  // Sets a flag indicating that shutdown has started. Returns true if there are
  // tasks blocking shutdown. Can only be called once.
  bool StartShutdown() {
    const auto new_value =
        subtle::NoBarrier_AtomicIncrement(&bits_, kShutdownHasStartedMask);

    // Check that the "shutdown has started" bit isn't zero. This would happen
    // if it was incremented twice.
    DCHECK(new_value & kShutdownHasStartedMask);

    const auto num_tasks_blocking_shutdown =
        new_value >> kNumTasksBlockingShutdownBitOffset;
    return num_tasks_blocking_shutdown != 0;
  }

  // Returns true if shutdown has started.
  bool HasShutdownStarted() const {
    return subtle::NoBarrier_Load(&bits_) & kShutdownHasStartedMask;
  }

  // Returns true if there are tasks blocking shutdown.
  bool AreTasksBlockingShutdown() const {
    const auto num_tasks_blocking_shutdown =
        subtle::NoBarrier_Load(&bits_) >> kNumTasksBlockingShutdownBitOffset;
    DCHECK_GE(num_tasks_blocking_shutdown, 0);
    return num_tasks_blocking_shutdown != 0;
  }

  // Increments the number of tasks blocking shutdown. Returns true if shutdown
  // has started.
  bool IncrementNumTasksBlockingShutdown() {
#if DCHECK_IS_ON()
    // Verify that no overflow will occur.
    const auto num_tasks_blocking_shutdown =
        subtle::NoBarrier_Load(&bits_) >> kNumTasksBlockingShutdownBitOffset;
    DCHECK_LT(num_tasks_blocking_shutdown,
              std::numeric_limits<subtle::Atomic32>::max() -
                  kNumTasksBlockingShutdownIncrement);
#endif

    const auto new_bits = subtle::NoBarrier_AtomicIncrement(
        &bits_, kNumTasksBlockingShutdownIncrement);
    return new_bits & kShutdownHasStartedMask;
  }

  // Decrements the number of tasks blocking shutdown. Returns true if shutdown
  // has started and the number of tasks blocking shutdown becomes zero.
  bool DecrementNumTasksBlockingShutdown() {
    const auto new_bits = subtle::NoBarrier_AtomicIncrement(
        &bits_, -kNumTasksBlockingShutdownIncrement);
    const bool shutdown_has_started = new_bits & kShutdownHasStartedMask;
    const auto num_tasks_blocking_shutdown =
        new_bits >> kNumTasksBlockingShutdownBitOffset;
    DCHECK_GE(num_tasks_blocking_shutdown, 0);
    return shutdown_has_started && num_tasks_blocking_shutdown == 0;
  }

 private:
  static constexpr subtle::Atomic32 kShutdownHasStartedMask = 1;
  static constexpr subtle::Atomic32 kNumTasksBlockingShutdownBitOffset = 1;
  static constexpr subtle::Atomic32 kNumTasksBlockingShutdownIncrement =
      1 << kNumTasksBlockingShutdownBitOffset;

  // The LSB indicates whether shutdown has started. The other bits count the
  // number of tasks blocking shutdown.
  // No barriers are required to read/write |bits_| as this class is only used
  // as an atomic state checker, it doesn't provide sequential consistency
  // guarantees w.r.t. external state. Sequencing of the TaskTracker::State
  // operations themselves is guaranteed by the AtomicIncrement RMW (read-
  // modify-write) semantics however. For example, if two threads are racing to
  // call IncrementNumTasksBlockingShutdown() and StartShutdown() respectively,
  // either the first thread will win and the StartShutdown() call will see the
  // blocking task or the second thread will win and
  // IncrementNumTasksBlockingShutdown() will know that shutdown has started.
  subtle::Atomic32 bits_ = 0;

  DISALLOW_COPY_AND_ASSIGN(State);
};

TaskTracker::TaskTracker()
    : state_(new State),
      flush_cv_(flush_lock_.CreateConditionVariable()),
      shutdown_lock_(&flush_lock_) {}
TaskTracker::~TaskTracker() = default;

void TaskTracker::Shutdown() {
  PerformShutdown();
  DCHECK(IsShutdownComplete());

  // Unblock Flush() when shutdown completes.
  AutoSchedulerLock auto_lock(flush_lock_);
  flush_cv_->Signal();
}

void TaskTracker::Flush() {
  AutoSchedulerLock auto_lock(flush_lock_);
  while (subtle::NoBarrier_Load(&num_pending_undelayed_tasks_) != 0 &&
         !IsShutdownComplete()) {
    flush_cv_->Wait();
  }
}

bool TaskTracker::WillPostTask(const Task* task) {
  DCHECK(task);

  if (!BeforePostTask(task->traits.shutdown_behavior()))
    return false;

  if (task->delayed_run_time.is_null())
    subtle::NoBarrier_AtomicIncrement(&num_pending_undelayed_tasks_, 1);

  debug::TaskAnnotator task_annotator;
  task_annotator.DidQueueTask(kQueueFunctionName, *task);

  return true;
}

bool TaskTracker::RunTask(std::unique_ptr<Task> task,
                          const SequenceToken& sequence_token) {
  DCHECK(task);
  DCHECK(sequence_token.IsValid());

  const TaskShutdownBehavior shutdown_behavior =
      task->traits.shutdown_behavior();
  const bool can_run_task = BeforeRunTask(shutdown_behavior);
  const bool is_delayed = !task->delayed_run_time.is_null();

  if (can_run_task) {
    // All tasks run through here and the scheduler itself doesn't use
    // singletons. Therefore, it isn't necessary to reset the singleton allowed
    // bit after running the task.
    ThreadRestrictions::SetSingletonAllowed(
        task->traits.shutdown_behavior() !=
        TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN);

    const bool previous_wait_allowed =
        ThreadRestrictions::SetWaitAllowed(task->traits.with_wait());

    {
      ScopedSetSequenceTokenForCurrentThread
          scoped_set_sequence_token_for_current_thread(sequence_token);
      ScopedSetTaskPriorityForCurrentThread
          scoped_set_task_priority_for_current_thread(task->traits.priority());

      // Set up TaskRunnerHandle as expected for the scope of the task.
      std::unique_ptr<SequencedTaskRunnerHandle> sequenced_task_runner_handle;
      std::unique_ptr<ThreadTaskRunnerHandle> single_thread_task_runner_handle;
      DCHECK(!task->sequenced_task_runner_ref ||
             !task->single_thread_task_runner_ref);
      if (task->sequenced_task_runner_ref) {
        sequenced_task_runner_handle.reset(
            new SequencedTaskRunnerHandle(task->sequenced_task_runner_ref));
      } else if (task->single_thread_task_runner_ref) {
        single_thread_task_runner_handle.reset(
            new ThreadTaskRunnerHandle(task->single_thread_task_runner_ref));
      }

      TRACE_TASK_EXECUTION(kRunFunctionName, *task);

      const char* const execution_mode =
          task->single_thread_task_runner_ref
              ? kSingleThreadExecutionMode
              : (task->sequenced_task_runner_ref ? kSequencedExecutionMode
                                                 : kParallelExecutionMode);
      // TODO(gab): In a better world this would be tacked on as an extra arg
      // to the trace event generated above. This is not possible however until
      // http://crbug.com/652692 is resolved.
      TRACE_EVENT1("task_scheduler", "TaskTracker::RunTask", "task_info",
                   MakeUnique<TaskTracingInfo>(task->traits, execution_mode,
                                               sequence_token));

      PerformRunTask(std::move(task));
    }

    ThreadRestrictions::SetWaitAllowed(previous_wait_allowed);

    AfterRunTask(shutdown_behavior);
  }

  if (!is_delayed)
    DecrementNumPendingUndelayedTasks();

  return can_run_task;
}

bool TaskTracker::HasShutdownStarted() const {
  return state_->HasShutdownStarted();
}

bool TaskTracker::IsShutdownComplete() const {
  AutoSchedulerLock auto_lock(shutdown_lock_);
  return shutdown_event_ && shutdown_event_->IsSignaled();
}

void TaskTracker::SetHasShutdownStartedForTesting() {
  state_->StartShutdown();
}

void TaskTracker::PerformRunTask(std::unique_ptr<Task> task) {
  debug::TaskAnnotator().RunTask(kQueueFunctionName, task.get());
}

void TaskTracker::PerformShutdown() {
  {
    AutoSchedulerLock auto_lock(shutdown_lock_);

    // This method can only be called once.
    DCHECK(!shutdown_event_);
    DCHECK(!num_block_shutdown_tasks_posted_during_shutdown_);
    DCHECK(!state_->HasShutdownStarted());

    shutdown_event_.reset(
        new WaitableEvent(WaitableEvent::ResetPolicy::MANUAL,
                          WaitableEvent::InitialState::NOT_SIGNALED));

    const bool tasks_are_blocking_shutdown = state_->StartShutdown();

    // From now, if a thread causes the number of tasks blocking shutdown to
    // become zero, it will call OnBlockingShutdownTasksComplete().

    if (!tasks_are_blocking_shutdown) {
      // If another thread posts a BLOCK_SHUTDOWN task at this moment, it will
      // block until this method releases |shutdown_lock_|. Then, it will fail
      // DCHECK(!shutdown_event_->IsSignaled()). This is the desired behavior
      // because posting a BLOCK_SHUTDOWN task when TaskTracker::Shutdown() has
      // started and no tasks are blocking shutdown isn't allowed.
      shutdown_event_->Signal();
      return;
    }
  }

  // It is safe to access |shutdown_event_| without holding |lock_| because the
  // pointer never changes after being set above.
  {
    base::ThreadRestrictions::ScopedAllowWait allow_wait;
    shutdown_event_->Wait();
  }

  {
    AutoSchedulerLock auto_lock(shutdown_lock_);

    // Record TaskScheduler.BlockShutdownTasksPostedDuringShutdown if less than
    // |kMaxBlockShutdownTasksPostedDuringShutdown| BLOCK_SHUTDOWN tasks were
    // posted during shutdown. Otherwise, the histogram has already been
    // recorded in BeforePostTask().
    if (num_block_shutdown_tasks_posted_during_shutdown_ <
        kMaxBlockShutdownTasksPostedDuringShutdown) {
      RecordNumBlockShutdownTasksPostedDuringShutdown(
          num_block_shutdown_tasks_posted_during_shutdown_);
    }
  }
}

bool TaskTracker::BeforePostTask(TaskShutdownBehavior shutdown_behavior) {
  if (shutdown_behavior == TaskShutdownBehavior::BLOCK_SHUTDOWN) {
    // BLOCK_SHUTDOWN tasks block shutdown between the moment they are posted
    // and the moment they complete their execution.
    const bool shutdown_started = state_->IncrementNumTasksBlockingShutdown();

    if (shutdown_started) {
      AutoSchedulerLock auto_lock(shutdown_lock_);

      // A BLOCK_SHUTDOWN task posted after shutdown has completed is an
      // ordering bug. This aims to catch those early.
      DCHECK(shutdown_event_);
      DCHECK(!shutdown_event_->IsSignaled());

      ++num_block_shutdown_tasks_posted_during_shutdown_;

      if (num_block_shutdown_tasks_posted_during_shutdown_ ==
          kMaxBlockShutdownTasksPostedDuringShutdown) {
        // Record the TaskScheduler.BlockShutdownTasksPostedDuringShutdown
        // histogram as soon as its upper bound is hit. That way, a value will
        // be recorded even if an infinite number of BLOCK_SHUTDOWN tasks are
        // posted, preventing shutdown to complete.
        RecordNumBlockShutdownTasksPostedDuringShutdown(
            num_block_shutdown_tasks_posted_during_shutdown_);
      }
    }

    return true;
  }

  // A non BLOCK_SHUTDOWN task is allowed to be posted iff shutdown hasn't
  // started.
  return !state_->HasShutdownStarted();
}

bool TaskTracker::BeforeRunTask(TaskShutdownBehavior shutdown_behavior) {
  switch (shutdown_behavior) {
    case TaskShutdownBehavior::BLOCK_SHUTDOWN: {
      // The number of tasks blocking shutdown has been incremented when the
      // task was posted.
      DCHECK(state_->AreTasksBlockingShutdown());

      // Trying to run a BLOCK_SHUTDOWN task after shutdown has completed is
      // unexpected as it either shouldn't have been posted if shutdown
      // completed or should be blocking shutdown if it was posted before it
      // did.
      DCHECK(!state_->HasShutdownStarted() || !IsShutdownComplete());

      return true;
    }

    case TaskShutdownBehavior::SKIP_ON_SHUTDOWN: {
      // SKIP_ON_SHUTDOWN tasks block shutdown while they are running.
      const bool shutdown_started = state_->IncrementNumTasksBlockingShutdown();

      if (shutdown_started) {
        // The SKIP_ON_SHUTDOWN task isn't allowed to run during shutdown.
        // Decrement the number of tasks blocking shutdown that was wrongly
        // incremented.
        const bool shutdown_started_and_no_tasks_block_shutdown =
            state_->DecrementNumTasksBlockingShutdown();
        if (shutdown_started_and_no_tasks_block_shutdown)
          OnBlockingShutdownTasksComplete();

        return false;
      }

      return true;
    }

    case TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN: {
      return !state_->HasShutdownStarted();
    }
  }

  NOTREACHED();
  return false;
}

void TaskTracker::AfterRunTask(TaskShutdownBehavior shutdown_behavior) {
  if (shutdown_behavior == TaskShutdownBehavior::BLOCK_SHUTDOWN ||
      shutdown_behavior == TaskShutdownBehavior::SKIP_ON_SHUTDOWN) {
    const bool shutdown_started_and_no_tasks_block_shutdown =
        state_->DecrementNumTasksBlockingShutdown();
    if (shutdown_started_and_no_tasks_block_shutdown)
      OnBlockingShutdownTasksComplete();
  }
}

void TaskTracker::OnBlockingShutdownTasksComplete() {
  AutoSchedulerLock auto_lock(shutdown_lock_);

  // This method can only be called after shutdown has started.
  DCHECK(state_->HasShutdownStarted());
  DCHECK(shutdown_event_);

  shutdown_event_->Signal();
}

void TaskTracker::DecrementNumPendingUndelayedTasks() {
  const auto new_num_pending_undelayed_tasks =
      subtle::NoBarrier_AtomicIncrement(&num_pending_undelayed_tasks_, -1);
  DCHECK_GE(new_num_pending_undelayed_tasks, 0);
  if (new_num_pending_undelayed_tasks == 0) {
    AutoSchedulerLock auto_lock(flush_lock_);
    flush_cv_->Signal();
  }
}

}  // namespace internal
}  // namespace base
