// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker_pool_impl.h"

#include <stddef.h>

#include <algorithm>
#include <utility>

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/lazy_instance.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram.h"
#include "base/sequence_token.h"
#include "base/sequenced_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/task_runner.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/task_scheduler/task_traits.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_restrictions.h"

namespace base {
namespace internal {

namespace {

constexpr char kPoolNameSuffix[] = "Pool";
constexpr char kDetachDurationHistogramPrefix[] =
    "TaskScheduler.DetachDuration.";
constexpr char kNumTasksBeforeDetachHistogramPrefix[] =
    "TaskScheduler.NumTasksBeforeDetach.";
constexpr char kNumTasksBetweenWaitsHistogramPrefix[] =
    "TaskScheduler.NumTasksBetweenWaits.";

// SchedulerWorkerPool that owns the current thread, if any.
LazyInstance<ThreadLocalPointer<const SchedulerWorkerPool>>::Leaky
    tls_current_worker_pool = LAZY_INSTANCE_INITIALIZER;

// A task runner that runs tasks with the PARALLEL ExecutionMode.
class SchedulerParallelTaskRunner : public TaskRunner {
 public:
  // Constructs a SchedulerParallelTaskRunner which can be used to post tasks so
  // long as |worker_pool| is alive.
  // TODO(robliao): Find a concrete way to manage |worker_pool|'s memory.
  SchedulerParallelTaskRunner(const TaskTraits& traits,
                              SchedulerWorkerPool* worker_pool)
      : traits_(traits), worker_pool_(worker_pool) {
    DCHECK(worker_pool_);
  }

  // TaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure closure,
                       TimeDelta delay) override {
    // Post the task as part of a one-off single-task Sequence.
    return worker_pool_->PostTaskWithSequence(
        MakeUnique<Task>(from_here, std::move(closure), traits_, delay),
        make_scoped_refptr(new Sequence));
  }

  bool RunsTasksInCurrentSequence() const override {
    return tls_current_worker_pool.Get().Get() == worker_pool_;
  }

 private:
  ~SchedulerParallelTaskRunner() override = default;

  const TaskTraits traits_;
  SchedulerWorkerPool* const worker_pool_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerParallelTaskRunner);
};

// A task runner that runs tasks with the SEQUENCED ExecutionMode.
class SchedulerSequencedTaskRunner : public SequencedTaskRunner {
 public:
  // Constructs a SchedulerSequencedTaskRunner which can be used to post tasks
  // so long as |worker_pool| is alive.
  // TODO(robliao): Find a concrete way to manage |worker_pool|'s memory.
  SchedulerSequencedTaskRunner(const TaskTraits& traits,
                               SchedulerWorkerPool* worker_pool)
      : traits_(traits), worker_pool_(worker_pool) {
    DCHECK(worker_pool_);
  }

  // SequencedTaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure closure,
                       TimeDelta delay) override {
    std::unique_ptr<Task> task(
        new Task(from_here, std::move(closure), traits_, delay));
    task->sequenced_task_runner_ref = this;

    // Post the task as part of |sequence_|.
    return worker_pool_->PostTaskWithSequence(std::move(task), sequence_);
  }

  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  OnceClosure closure,
                                  base::TimeDelta delay) override {
    // Tasks are never nested within the task scheduler.
    return PostDelayedTask(from_here, std::move(closure), delay);
  }

  bool RunsTasksInCurrentSequence() const override {
    return sequence_->token() == SequenceToken::GetForCurrentThread();
  }

 private:
  ~SchedulerSequencedTaskRunner() override = default;

  // Sequence for all Tasks posted through this TaskRunner.
  const scoped_refptr<Sequence> sequence_ = new Sequence;

  const TaskTraits traits_;
  SchedulerWorkerPool* const worker_pool_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerSequencedTaskRunner);
};

// Only used in DCHECKs.
bool ContainsWorker(const std::vector<scoped_refptr<SchedulerWorker>>& workers,
                    const SchedulerWorker* worker) {
  auto it = std::find_if(workers.begin(), workers.end(),
                         [worker](const scoped_refptr<SchedulerWorker>& i) {
                           return i.get() == worker;
                         });
  return it != workers.end();
}

}  // namespace

class SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl
    : public SchedulerWorker::Delegate {
 public:
  // |outer| owns the worker for which this delegate is constructed. |index|
  // will be appended to the pool name to label the underlying worker threads.
  SchedulerWorkerDelegateImpl(
      SchedulerWorkerPoolImpl* outer,
      int index);
  ~SchedulerWorkerDelegateImpl() override;

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker) override;
  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override;
  void DidRunTask() override;
  void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override;
  TimeDelta GetSleepTimeout() override;
  bool CanDetach(SchedulerWorker* worker) override;
  void OnDetach() override;

 private:
  SchedulerWorkerPoolImpl* outer_;

  // Time of the last detach.
  TimeTicks last_detach_time_;

  // Time when GetWork() first returned nullptr.
  TimeTicks idle_start_time_;

  // Indicates whether the last call to GetWork() returned nullptr.
  bool last_get_work_returned_nullptr_ = false;

  // Indicates whether the SchedulerWorker was detached since the last call to
  // GetWork().
  bool did_detach_since_last_get_work_ = false;

  // Number of tasks executed since the last time the
  // TaskScheduler.NumTasksBetweenWaits histogram was recorded.
  size_t num_tasks_since_last_wait_ = 0;

  // Number of tasks executed since the last time the
  // TaskScheduler.NumTasksBeforeDetach histogram was recorded.
  size_t num_tasks_since_last_detach_ = 0;

  const int index_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerDelegateImpl);
};

SchedulerWorkerPoolImpl::SchedulerWorkerPoolImpl(
    const std::string& name,
    ThreadPriority priority_hint,
    TaskTracker* task_tracker,
    DelayedTaskManager* delayed_task_manager)
    : name_(name),
      priority_hint_(priority_hint),
      idle_workers_stack_lock_(shared_priority_queue_.container_lock()),
      idle_workers_stack_cv_for_testing_(
          idle_workers_stack_lock_.CreateConditionVariable()),
      join_for_testing_returned_(WaitableEvent::ResetPolicy::MANUAL,
                                 WaitableEvent::InitialState::NOT_SIGNALED),
      // Mimics the UMA_HISTOGRAM_LONG_TIMES macro.
      detach_duration_histogram_(Histogram::FactoryTimeGet(
          kDetachDurationHistogramPrefix + name_ + kPoolNameSuffix,
          TimeDelta::FromMilliseconds(1),
          TimeDelta::FromHours(1),
          50,
          HistogramBase::kUmaTargetedHistogramFlag)),
      // Mimics the UMA_HISTOGRAM_COUNTS_1000 macro. When a worker runs more
      // than 1000 tasks before detaching, there is no need to know the exact
      // number of tasks that ran.
      num_tasks_before_detach_histogram_(Histogram::FactoryGet(
          kNumTasksBeforeDetachHistogramPrefix + name_ + kPoolNameSuffix,
          1,
          1000,
          50,
          HistogramBase::kUmaTargetedHistogramFlag)),
      // Mimics the UMA_HISTOGRAM_COUNTS_100 macro. A SchedulerWorker is
      // expected to run between zero and a few tens of tasks between waits.
      // When it runs more than 100 tasks, there is no need to know the exact
      // number of tasks that ran.
      num_tasks_between_waits_histogram_(Histogram::FactoryGet(
          kNumTasksBetweenWaitsHistogramPrefix + name_ + kPoolNameSuffix,
          1,
          100,
          50,
          HistogramBase::kUmaTargetedHistogramFlag)),
      task_tracker_(task_tracker),
      delayed_task_manager_(delayed_task_manager) {
  DCHECK(task_tracker_);
  DCHECK(delayed_task_manager_);
}

void SchedulerWorkerPoolImpl::Start(const SchedulerWorkerPoolParams& params) {
  suggested_reclaim_time_ = params.suggested_reclaim_time();

  {
    AutoSchedulerLock auto_lock(idle_workers_stack_lock_);

#if DCHECK_IS_ON()
    DCHECK(!workers_created_.IsSet());
#endif

    DCHECK(workers_.empty());
    workers_.resize(params.max_threads());

    // The number of workers created alive is |num_wake_ups_before_start_|, plus
    // one if the standby thread policy is ONE (in order to start with one alive
    // idle worker).
    const int num_alive_workers =
        num_wake_ups_before_start_ +
        (params.standby_thread_policy() ==
                 SchedulerWorkerPoolParams::StandbyThreadPolicy::ONE
             ? 1
             : 0);

    // Create workers in reverse order of index so that the worker with the
    // highest index is at the bottom of the idle stack.
    for (int index = params.max_threads() - 1; index >= 0; --index) {
      workers_[index] = make_scoped_refptr(new SchedulerWorker(
          priority_hint_, MakeUnique<SchedulerWorkerDelegateImpl>(this, index),
          task_tracker_, params.backward_compatibility(),
          index < num_alive_workers ? SchedulerWorker::InitialState::ALIVE
                                    : SchedulerWorker::InitialState::DETACHED));

      // Put workers that won't be woken up at the end of this method on the
      // idle stack.
      if (index >= num_wake_ups_before_start_)
        idle_workers_stack_.Push(workers_[index].get());
    }

#if DCHECK_IS_ON()
    workers_created_.Set();
#endif
  }

  // Start all workers. CHECK that the first worker can be started (assume that
  // failure means that threads can't be created on this machine). Wake up one
  // worker for each wake up that occurred before Start().
  for (size_t index = 0; index < workers_.size(); ++index) {
    const bool start_success = workers_[index]->Start();
    CHECK(start_success || index > 0);
    if (static_cast<int>(index) < num_wake_ups_before_start_)
      workers_[index]->WakeUp();
  }
}

SchedulerWorkerPoolImpl::~SchedulerWorkerPoolImpl() {
  // SchedulerWorkerPool should never be deleted in production unless its
  // initialization failed.
  DCHECK(join_for_testing_returned_.IsSignaled() || workers_.empty());
}

scoped_refptr<TaskRunner> SchedulerWorkerPoolImpl::CreateTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return make_scoped_refptr(new SchedulerParallelTaskRunner(traits, this));
}

scoped_refptr<SequencedTaskRunner>
SchedulerWorkerPoolImpl::CreateSequencedTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return make_scoped_refptr(new SchedulerSequencedTaskRunner(traits, this));
}

bool SchedulerWorkerPoolImpl::PostTaskWithSequence(
    std::unique_ptr<Task> task,
    scoped_refptr<Sequence> sequence) {
  DCHECK(task);
  DCHECK(sequence);

  if (!task_tracker_->WillPostTask(task.get()))
    return false;

  if (task->delayed_run_time.is_null()) {
    PostTaskWithSequenceNow(std::move(task), std::move(sequence));
  } else {
    // Use CHECK instead of DCHECK to crash earlier. See http://crbug.com/711167
    // for details.
    CHECK(task->task);
    delayed_task_manager_->AddDelayedTask(
        std::move(task),
        Bind(
            [](scoped_refptr<Sequence> sequence,
               SchedulerWorkerPool* worker_pool, std::unique_ptr<Task> task) {
              worker_pool->PostTaskWithSequenceNow(std::move(task),
                                                   std::move(sequence));
            },
            std::move(sequence), Unretained(this)));
  }

  return true;
}

void SchedulerWorkerPoolImpl::PostTaskWithSequenceNow(
    std::unique_ptr<Task> task,
    scoped_refptr<Sequence> sequence) {
  DCHECK(task);
  DCHECK(sequence);

  // Confirm that |task| is ready to run (its delayed run time is either null or
  // in the past).
  DCHECK_LE(task->delayed_run_time, TimeTicks::Now());

  const bool sequence_was_empty = sequence->PushTask(std::move(task));
  if (sequence_was_empty) {
    // Insert |sequence| in |shared_priority_queue_| if it was empty before
    // |task| was inserted into it. Otherwise, one of these must be true:
    // - |sequence| is already in a PriorityQueue, or,
    // - A worker is running a Task from |sequence|. It will insert |sequence|
    //   in a PriorityQueue once it's done running the Task.
    const auto sequence_sort_key = sequence->GetSortKey();
    shared_priority_queue_.BeginTransaction()->Push(std::move(sequence),
                                                    sequence_sort_key);

    // Wake up a worker to process |sequence|.
    WakeUpOneWorker();
  }
}

void SchedulerWorkerPoolImpl::GetHistograms(
    std::vector<const HistogramBase*>* histograms) const {
  histograms->push_back(detach_duration_histogram_);
  histograms->push_back(num_tasks_between_waits_histogram_);
}

int SchedulerWorkerPoolImpl::GetMaxConcurrentTasksDeprecated() const {
#if DCHECK_IS_ON()
  DCHECK(workers_created_.IsSet());
#endif
  return workers_.size();
}

void SchedulerWorkerPoolImpl::WaitForAllWorkersIdleForTesting() {
#if DCHECK_IS_ON()
  DCHECK(workers_created_.IsSet());
#endif
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  while (idle_workers_stack_.Size() < workers_.size())
    idle_workers_stack_cv_for_testing_->Wait();
}

void SchedulerWorkerPoolImpl::JoinForTesting() {
#if DCHECK_IS_ON()
  DCHECK(workers_created_.IsSet());
#endif
  DCHECK(!CanWorkerDetachForTesting() || suggested_reclaim_time_.is_max())
      << "Workers can detach during join.";
  for (const auto& worker : workers_)
    worker->JoinForTesting();

  DCHECK(!join_for_testing_returned_.IsSignaled());
  join_for_testing_returned_.Signal();
}

void SchedulerWorkerPoolImpl::DisallowWorkerDetachmentForTesting() {
  worker_detachment_disallowed_.Set();
}

size_t SchedulerWorkerPoolImpl::NumberOfAliveWorkersForTesting() {
  size_t num_alive_workers = 0;
  for (const auto& worker : workers_) {
    if (worker->ThreadAliveForTesting())
      ++num_alive_workers;
  }
  return num_alive_workers;
}

SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    SchedulerWorkerDelegateImpl(
        SchedulerWorkerPoolImpl* outer,
        int index)
    : outer_(outer),
      index_(index) {}

SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    ~SchedulerWorkerDelegateImpl() = default;

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::OnMainEntry(
    SchedulerWorker* worker) {
#if DCHECK_IS_ON()
  DCHECK(outer_->workers_created_.IsSet());
  DCHECK(ContainsWorker(outer_->workers_, worker));
#endif
  DCHECK_EQ(num_tasks_since_last_wait_, 0U);

  if (!last_detach_time_.is_null()) {
    outer_->detach_duration_histogram_->AddTime(TimeTicks::Now() -
                                                last_detach_time_);
  }

  PlatformThread::SetName(
      StringPrintf("TaskScheduler%sWorker%d", outer_->name_.c_str(), index_));

  DCHECK(!tls_current_worker_pool.Get().Get());
  tls_current_worker_pool.Get().Set(outer_);

  // New threads haven't run GetWork() yet, so reset the |idle_start_time_|.
  idle_start_time_ = TimeTicks();
}

scoped_refptr<Sequence>
SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::GetWork(
    SchedulerWorker* worker) {
  DCHECK(ContainsWorker(outer_->workers_, worker));

  // Record the TaskScheduler.NumTasksBetweenWaits histogram if the
  // SchedulerWorker waited on its WaitableEvent since the last GetWork().
  //
  // Note: When GetWork() starts returning nullptr, the SchedulerWorker waits on
  // its WaitableEvent. When it wakes up (either because WakeUp() was called or
  // because the sleep timeout expired), it calls GetWork() again. The code
  // below records the histogram and, if GetWork() returns nullptr again, the
  // SchedulerWorker may detach. If that happens,
  // |did_detach_since_last_get_work_| is set to true and the next call to
  // GetWork() won't record the histogram  (which is correct since the
  // SchedulerWorker didn't wait on its WaitableEvent since the last time the
  // histogram was recorded).
  if (last_get_work_returned_nullptr_ && !did_detach_since_last_get_work_) {
    outer_->num_tasks_between_waits_histogram_->Add(num_tasks_since_last_wait_);
    num_tasks_since_last_wait_ = 0;
  }

  scoped_refptr<Sequence> sequence;
  {
    std::unique_ptr<PriorityQueue::Transaction> shared_transaction(
        outer_->shared_priority_queue_.BeginTransaction());

    if (shared_transaction->IsEmpty()) {
      // |shared_transaction| is kept alive while |worker| is added to
      // |idle_workers_stack_| to avoid this race:
      // 1. This thread creates a Transaction, finds |shared_priority_queue_|
      //    empty and ends the Transaction.
      // 2. Other thread creates a Transaction, inserts a Sequence into
      //    |shared_priority_queue_| and ends the Transaction. This can't happen
      //    if the Transaction of step 1 is still active because because there
      //    can only be one active Transaction per PriorityQueue at a time.
      // 3. Other thread calls WakeUpOneWorker(). No thread is woken up because
      //    |idle_workers_stack_| is empty.
      // 4. This thread adds itself to |idle_workers_stack_| and goes to sleep.
      //    No thread runs the Sequence inserted in step 2.
      outer_->AddToIdleWorkersStack(worker);
      if (idle_start_time_.is_null())
        idle_start_time_ = TimeTicks::Now();
      did_detach_since_last_get_work_ = false;
      last_get_work_returned_nullptr_ = true;
      return nullptr;
    }

    sequence = shared_transaction->PopSequence();
  }
  DCHECK(sequence);

  outer_->RemoveFromIdleWorkersStack(worker);
  idle_start_time_ = TimeTicks();
  did_detach_since_last_get_work_ = false;
  last_get_work_returned_nullptr_ = false;

  return sequence;
}

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::DidRunTask() {
  ++num_tasks_since_last_wait_;
  ++num_tasks_since_last_detach_;
}

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    ReEnqueueSequence(scoped_refptr<Sequence> sequence) {
  const SequenceSortKey sequence_sort_key = sequence->GetSortKey();
  outer_->shared_priority_queue_.BeginTransaction()->Push(std::move(sequence),
                                                          sequence_sort_key);
  // The thread calling this method will soon call GetWork(). Therefore, there
  // is no need to wake up a worker to run the sequence that was just inserted
  // into |outer_->shared_priority_queue_|.
}

TimeDelta SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    GetSleepTimeout() {
  return outer_->suggested_reclaim_time_;
}

bool SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::CanDetach(
    SchedulerWorker* worker) {
  const bool can_detach =
      !idle_start_time_.is_null() &&
      (TimeTicks::Now() - idle_start_time_) > outer_->suggested_reclaim_time_ &&
      worker != outer_->PeekAtIdleWorkersStack() &&
      outer_->CanWorkerDetachForTesting();
  return can_detach;
}

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::OnDetach() {
  DCHECK(!did_detach_since_last_get_work_);
  outer_->num_tasks_before_detach_histogram_->Add(num_tasks_since_last_detach_);
  num_tasks_since_last_detach_ = 0;
  did_detach_since_last_get_work_ = true;
  last_detach_time_ = TimeTicks::Now();
}

void SchedulerWorkerPoolImpl::WakeUpOneWorker() {
  SchedulerWorker* worker = nullptr;
  {
    AutoSchedulerLock auto_lock(idle_workers_stack_lock_);

#if DCHECK_IS_ON()
    DCHECK_EQ(workers_.empty(), !workers_created_.IsSet());
#endif

    if (workers_.empty())
      ++num_wake_ups_before_start_;
    else
      worker = idle_workers_stack_.Pop();
  }

  if (worker)
    worker->WakeUp();
  // TODO(robliao): Honor StandbyThreadPolicy::ONE here and consider adding
  // hysteresis to the CanDetach check. See https://crbug.com/666041.
}

void SchedulerWorkerPoolImpl::AddToIdleWorkersStack(
    SchedulerWorker* worker) {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  // Detachment may cause multiple attempts to add because the delegate cannot
  // determine who woke it up. As a result, when it wakes up, it may conclude
  // there's no work to be done and attempt to add itself to the idle stack
  // again.
  if (!idle_workers_stack_.Contains(worker))
    idle_workers_stack_.Push(worker);

  DCHECK_LE(idle_workers_stack_.Size(), workers_.size());

  if (idle_workers_stack_.Size() == workers_.size())
    idle_workers_stack_cv_for_testing_->Broadcast();
}

const SchedulerWorker* SchedulerWorkerPoolImpl::PeekAtIdleWorkersStack() const {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  return idle_workers_stack_.Peek();
}

void SchedulerWorkerPoolImpl::RemoveFromIdleWorkersStack(
    SchedulerWorker* worker) {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  idle_workers_stack_.Remove(worker);
}

bool SchedulerWorkerPoolImpl::CanWorkerDetachForTesting() {
  return !worker_detachment_disallowed_.IsSet();
}

}  // namespace internal
}  // namespace base
