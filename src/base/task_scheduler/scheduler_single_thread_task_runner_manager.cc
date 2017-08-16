// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_single_thread_task_runner_manager.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/debug/stack_trace.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/atomic_flag.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_worker.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/task_scheduler/task_traits.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

#if defined(OS_WIN)
#include <windows.h>

#include "base/win/scoped_com_initializer.h"
#endif  // defined(OS_WIN)

namespace base {
namespace internal {

namespace {

// Allows for checking the PlatformThread::CurrentRef() against a set
// PlatformThreadRef atomically without using locks.
class AtomicThreadRefChecker {
 public:
  AtomicThreadRefChecker() = default;
  ~AtomicThreadRefChecker() = default;

  void Set() {
    thread_ref_ = PlatformThread::CurrentRef();
    is_set_.Set();
  }

  bool IsCurrentThreadSameAsSetThread() {
    return is_set_.IsSet() && thread_ref_ == PlatformThread::CurrentRef();
  }

 private:
  AtomicFlag is_set_;
  PlatformThreadRef thread_ref_;

  DISALLOW_COPY_AND_ASSIGN(AtomicThreadRefChecker);
};

class SchedulerWorkerDelegate : public SchedulerWorker::Delegate {
 public:
  SchedulerWorkerDelegate(const std::string& thread_name)
      : thread_name_(thread_name) {}

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker) override {
    thread_ref_checker_.Set();
    PlatformThread::SetName(thread_name_);
  }

  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    AutoSchedulerLock auto_lock(sequence_lock_);
    bool has_work = has_work_;
    has_work_ = false;
    return has_work ? sequence_ : nullptr;
  }

  void DidRunTask() override {}

  void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override {
    AutoSchedulerLock auto_lock(sequence_lock_);
    // We've shut down, so no-op this work request. Any sequence cleanup will
    // occur in the caller's context.
    if (!sequence_)
      return;

    DCHECK_EQ(sequence, sequence_);
    has_work_ = true;
  }

  TimeDelta GetSleepTimeout() override { return TimeDelta::Max(); }

  bool RunsTasksInCurrentSequence() {
    // We check the thread ref instead of the sequence for the benefit of COM
    // callbacks which may execute without a sequence context.
    return thread_ref_checker_.IsCurrentThreadSameAsSetThread();
  }

  void OnMainExit(SchedulerWorker* /* worker */) override {
    // Move |sequence_| to |local_sequence| so that if we have the last
    // reference to the sequence we don't destroy it (and its tasks) within
    // |sequence_lock_|.
    scoped_refptr<Sequence> local_sequence;
    {
      AutoSchedulerLock auto_lock(sequence_lock_);
      // To reclaim skipped tasks on shutdown, we null out the sequence to allow
      // the tasks to destroy themselves.
      local_sequence = std::move(sequence_);
    }
  }

  // SchedulerWorkerDelegate:

  // Consumers should release their sequence reference as soon as possible to
  // ensure timely cleanup for general shutdown.
  scoped_refptr<Sequence> sequence() {
    AutoSchedulerLock auto_lock(sequence_lock_);
    return sequence_;
  }

 private:
  const std::string thread_name_;

  // Synchronizes access to |sequence_| and |has_work_|.
  SchedulerLock sequence_lock_;
  scoped_refptr<Sequence> sequence_ = new Sequence;
  bool has_work_ = false;

  AtomicThreadRefChecker thread_ref_checker_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerDelegate);
};

#if defined(OS_WIN)

class SchedulerWorkerCOMDelegate : public SchedulerWorkerDelegate {
 public:
  SchedulerWorkerCOMDelegate(const std::string& thread_name,
                             TaskTracker* task_tracker)
      : SchedulerWorkerDelegate(thread_name), task_tracker_(task_tracker) {}

  ~SchedulerWorkerCOMDelegate() override { DCHECK(!scoped_com_initializer_); }

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker) override {
    SchedulerWorkerDelegate::OnMainEntry(worker);

    scoped_com_initializer_ = MakeUnique<win::ScopedCOMInitializer>();
  }

  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    // This scheme below allows us to cover the following scenarios:
    // * Only SchedulerWorkerDelegate::GetWork() has work:
    //   Always return the sequence from GetWork().
    // * Only the Windows Message Queue has work:
    //   Always return the sequence from GetWorkFromWindowsMessageQueue();
    // * Both SchedulerWorkerDelegate::GetWork() and the Windows Message Queue
    //   have work:
    //   Process sequences from each source round-robin style.
    scoped_refptr<Sequence> sequence;
    if (get_work_first_) {
      sequence = SchedulerWorkerDelegate::GetWork(worker);
      if (sequence)
        get_work_first_ = false;
    }

    if (!sequence) {
      sequence = GetWorkFromWindowsMessageQueue();
      if (sequence)
        get_work_first_ = true;
    }

    if (!sequence && !get_work_first_) {
      // This case is important if we checked the Windows Message Queue first
      // and found there was no work. We don't want to return null immediately
      // as that could cause the thread to go to sleep while work is waiting via
      // SchedulerWorkerDelegate::GetWork().
      sequence = SchedulerWorkerDelegate::GetWork(worker);
    }
    return sequence;
  }

  void OnMainExit(SchedulerWorker* /* worker */) override {
    scoped_com_initializer_.reset();
  }

  void WaitForWork(WaitableEvent* wake_up_event) override {
    DCHECK(wake_up_event);
    const TimeDelta sleep_time = GetSleepTimeout();
    const DWORD milliseconds_wait =
        sleep_time.is_max() ? INFINITE : sleep_time.InMilliseconds();
    HANDLE wake_up_event_handle = wake_up_event->handle();
    DWORD result = MsgWaitForMultipleObjectsEx(
        1, &wake_up_event_handle, milliseconds_wait, QS_ALLINPUT, 0);
    if (result == WAIT_OBJECT_0) {
      // Reset the event since we woke up due to it.
      wake_up_event->Reset();
    }
  }

 private:
  scoped_refptr<Sequence> GetWorkFromWindowsMessageQueue() {
    MSG msg;
    if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE) != FALSE) {
      auto pump_message_task =
          MakeUnique<Task>(FROM_HERE,
                           Bind(
                               [](MSG msg) {
                                 TranslateMessage(&msg);
                                 DispatchMessage(&msg);
                               },
                               std::move(msg)),
                           TaskTraits(MayBlock()), TimeDelta());
      if (task_tracker_->WillPostTask(pump_message_task.get())) {
        bool was_empty =
            message_pump_sequence_->PushTask(std::move(pump_message_task));
        DCHECK(was_empty) << "GetWorkFromWindowsMessageQueue() does not expect "
                             "queueing of pump tasks.";
        return message_pump_sequence_;
      }
    }
    return nullptr;
  }

  bool get_work_first_ = true;
  const scoped_refptr<Sequence> message_pump_sequence_ = new Sequence;
  TaskTracker* const task_tracker_;
  std::unique_ptr<win::ScopedCOMInitializer> scoped_com_initializer_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerCOMDelegate);
};

#endif  // defined(OS_WIN)

}  // namespace

class SchedulerSingleThreadTaskRunnerManager::SchedulerSingleThreadTaskRunner
    : public SingleThreadTaskRunner {
 public:
  // Constructs a SchedulerSingleThreadTaskRunner that indirectly controls the
  // lifetime of a dedicated |worker| for |traits|.
  SchedulerSingleThreadTaskRunner(
      SchedulerSingleThreadTaskRunnerManager* const outer,
      const TaskTraits& traits,
      SchedulerWorker* worker,
      SingleThreadTaskRunnerThreadMode thread_mode)
      : outer_(outer),
        traits_(traits),
        worker_(worker),
        thread_mode_(thread_mode) {
    DCHECK(outer_);
    DCHECK(worker_);
  }

  // SingleThreadTaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure closure,
                       TimeDelta delay) override {
    auto task = MakeUnique<Task>(from_here, std::move(closure), traits_, delay);
    task->single_thread_task_runner_ref = this;

    if (!outer_->task_tracker_->WillPostTask(task.get()))
      return false;

    if (task->delayed_run_time.is_null()) {
      PostTaskNow(std::move(task));
    } else {
      outer_->delayed_task_manager_->AddDelayedTask(
          std::move(task),
          BindOnce(&SchedulerSingleThreadTaskRunner::PostTaskNow,
                   Unretained(this)));
    }
    return true;
  }

  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  OnceClosure closure,
                                  TimeDelta delay) override {
    // Tasks are never nested within the task scheduler.
    return PostDelayedTask(from_here, std::move(closure), delay);
  }

  bool RunsTasksInCurrentSequence() const override {
    return GetDelegate()->RunsTasksInCurrentSequence();
  }

 private:
  ~SchedulerSingleThreadTaskRunner() override {
    // Only unregister if this is a DEDICATED SingleThreadTaskRunner. SHARED
    // task runner SchedulerWorkers are managed separately as they are reused.
    if (thread_mode_ == SingleThreadTaskRunnerThreadMode::DEDICATED) {
      // Note: This will crash if SchedulerSingleThreadTaskRunnerManager is
      // incorrectly destroyed first in tests (in production the TaskScheduler
      // and all of its state are intentionally leaked after
      // TaskScheduler::Shutdown(). See
      // ~SchedulerSingleThreadTaskRunnerManager() for more details.
      outer_->UnregisterSchedulerWorker(worker_);
    }
  }

  void PostTaskNow(std::unique_ptr<Task> task) {
    scoped_refptr<Sequence> sequence = GetDelegate()->sequence();
    // If |sequence| is null, then the thread is effectively gone (either
    // shutdown or joined).
    if (!sequence)
      return;

    const bool sequence_was_empty = sequence->PushTask(std::move(task));
    if (sequence_was_empty) {
      GetDelegate()->ReEnqueueSequence(std::move(sequence));
      worker_->WakeUp();
    }
  }

  SchedulerWorkerDelegate* GetDelegate() const {
    return static_cast<SchedulerWorkerDelegate*>(worker_->delegate());
  }

  SchedulerSingleThreadTaskRunnerManager* const outer_;
  const TaskTraits traits_;
  SchedulerWorker* const worker_;
  const SingleThreadTaskRunnerThreadMode thread_mode_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerSingleThreadTaskRunner);
};

SchedulerSingleThreadTaskRunnerManager::SchedulerSingleThreadTaskRunnerManager(
    TaskTracker* task_tracker,
    DelayedTaskManager* delayed_task_manager)
    : task_tracker_(task_tracker), delayed_task_manager_(delayed_task_manager) {
  DCHECK(task_tracker_);
  DCHECK(delayed_task_manager_);
#if defined(OS_WIN)
  static_assert(arraysize(shared_com_scheduler_workers_) ==
                    arraysize(shared_scheduler_workers_),
                "The size of |shared_com_scheduler_workers_| must match "
                "|shared_scheduler_workers_|");
#endif  // defined(OS_WIN)
}

SchedulerSingleThreadTaskRunnerManager::
    ~SchedulerSingleThreadTaskRunnerManager() {
#if DCHECK_IS_ON()
  size_t workers_unregistered_during_join =
      subtle::NoBarrier_Load(&workers_unregistered_during_join_);
  // Log an ERROR instead of DCHECK'ing as it's often useful to have both the
  // stack trace of this call and the crash stack trace of the upcoming
  // out-of-order ~SchedulerSingleThreadTaskRunner() call to know what to flip.
  DLOG_IF(ERROR, workers_unregistered_during_join != workers_.size())
      << "Expect incoming crash in ~SchedulerSingleThreadTaskRunner()!!! There "
         "cannot be outstanding SingleThreadTaskRunners upon destruction "
         "of SchedulerSingleThreadTaskRunnerManager in tests "
      << workers_.size() - workers_unregistered_during_join << " outstanding). "
      << "Hint 1: If you're hitting this it's most likely because your test "
         "fixture is destroying its TaskScheduler too early (e.g. via "
         "base::test::~ScopedTaskEnvironment() or "
         "content::~TestBrowserThreadBundle()). Refer to the following stack "
         "trace to know what caused this destruction as well as to the "
         "upcoming crash in ~SchedulerSingleThreadTaskRunner() to know what "
         "should have happened before. "
         "Hint 2: base::test::ScopedTaskEnvironment et al. should typically "
         "be the first member in a test fixture to ensure it's initialized "
         "first and destroyed last.\n"
#if !defined(OS_NACL)  // We don't build base/debug/stack_trace.cc for NaCl.
      << base::debug::StackTrace().ToString()
#endif  // !defined(OS_NACL)
      ;
#endif  // DCHECK_IS_ON()
}

void SchedulerSingleThreadTaskRunnerManager::Start() {
  decltype(workers_) workers_to_start;
  {
    AutoSchedulerLock auto_lock(lock_);
    started_ = true;
    workers_to_start = workers_;
  }

  // Start workers that were created before this method was called. Other
  // workers are started as they are created.
  for (scoped_refptr<SchedulerWorker> worker : workers_to_start) {
    worker->Start();
    worker->WakeUp();
  }
}

scoped_refptr<SingleThreadTaskRunner>
SchedulerSingleThreadTaskRunnerManager::CreateSingleThreadTaskRunnerWithTraits(
    const std::string& name,
    const TaskTraits& traits,
    SingleThreadTaskRunnerThreadMode thread_mode) {
  return CreateTaskRunnerWithTraitsImpl<SchedulerWorkerDelegate>(name, traits,
                                                                 thread_mode);
}

#if defined(OS_WIN)
scoped_refptr<SingleThreadTaskRunner>
SchedulerSingleThreadTaskRunnerManager::CreateCOMSTATaskRunnerWithTraits(
    const std::string& name,
    const TaskTraits& traits,
    SingleThreadTaskRunnerThreadMode thread_mode) {
  return CreateTaskRunnerWithTraitsImpl<SchedulerWorkerCOMDelegate>(
      name, traits, thread_mode);
}
#endif  // defined(OS_WIN)

template <typename DelegateType>
scoped_refptr<
    SchedulerSingleThreadTaskRunnerManager::SchedulerSingleThreadTaskRunner>
SchedulerSingleThreadTaskRunnerManager::CreateTaskRunnerWithTraitsImpl(
    const std::string& name,
    const TaskTraits& traits,
    SingleThreadTaskRunnerThreadMode thread_mode) {
  DCHECK(thread_mode != SingleThreadTaskRunnerThreadMode::SHARED ||
         !traits.with_base_sync_primitives())
      << "Using WithBaseSyncPrimitives() on a shared SingleThreadTaskRunner "
         "may cause deadlocks. Either reevaluate your usage (e.g. use "
         "SequencedTaskRunner) or use "
         "SingleThreadTaskRunnerThreadMode::DEDICATED.";
  // To simplify the code, |dedicated_worker| is a local only variable that
  // allows the code to treat both the DEDICATED and SHARED cases similarly for
  // SingleThreadTaskRunnerThreadMode. In DEDICATED, the scoped_refptr is backed
  // by a local variable and in SHARED, the scoped_refptr is backed by a member
  // variable.
  SchedulerWorker* dedicated_worker = nullptr;
  SchedulerWorker*& worker =
      thread_mode == SingleThreadTaskRunnerThreadMode::DEDICATED
          ? dedicated_worker
          : GetSharedSchedulerWorkerForTraits<DelegateType>(traits);
  bool new_worker = false;
  bool started;
  {
    AutoSchedulerLock auto_lock(lock_);
    if (!worker) {
      const auto& environment_params =
          kEnvironmentParams[GetEnvironmentIndexForTraits(traits)];
      std::string processed_name =
          thread_mode == SingleThreadTaskRunnerThreadMode::DEDICATED
              ? name + environment_params.name_suffix
              : "Shared" + name + environment_params.name_suffix;
      worker = CreateAndRegisterSchedulerWorker<DelegateType>(
          processed_name, environment_params.priority_hint);
      new_worker = true;
    }
    started = started_;
  }

  if (new_worker && started)
    worker->Start();

  return MakeRefCounted<SchedulerSingleThreadTaskRunner>(this, traits, worker,
                                                         thread_mode);
}

void SchedulerSingleThreadTaskRunnerManager::JoinForTesting() {
  decltype(workers_) local_workers;
  {
    AutoSchedulerLock auto_lock(lock_);
    local_workers = std::move(workers_);
  }

  for (const auto& worker : local_workers)
    worker->JoinForTesting();

  {
    AutoSchedulerLock auto_lock(lock_);
    DCHECK(workers_.empty())
        << "New worker(s) unexpectedly registered during join.";
    workers_ = std::move(local_workers);
  }

  // Release shared SchedulerWorkers at the end so they get joined above. If
  // this call happens before the joins, the SchedulerWorkers are effectively
  // detached and may outlive the SchedulerSingleThreadTaskRunnerManager.
  ReleaseSharedSchedulerWorkers();
}

template <>
std::unique_ptr<SchedulerWorkerDelegate>
SchedulerSingleThreadTaskRunnerManager::CreateSchedulerWorkerDelegate<
    SchedulerWorkerDelegate>(const std::string& name, int id) {
  return MakeUnique<SchedulerWorkerDelegate>(
      StringPrintf("TaskSchedulerSingleThread%s%d", name.c_str(), id));
}

#if defined(OS_WIN)
template <>
std::unique_ptr<SchedulerWorkerDelegate>
SchedulerSingleThreadTaskRunnerManager::CreateSchedulerWorkerDelegate<
    SchedulerWorkerCOMDelegate>(const std::string& name, int id) {
  return MakeUnique<SchedulerWorkerCOMDelegate>(
      StringPrintf("TaskSchedulerSingleThreadCOMSTA%s%d", name.c_str(), id),
      task_tracker_);
}
#endif  // defined(OS_WIN)

template <typename DelegateType>
SchedulerWorker*
SchedulerSingleThreadTaskRunnerManager::CreateAndRegisterSchedulerWorker(
    const std::string& name,
    ThreadPriority priority_hint) {
  lock_.AssertAcquired();
  int id = next_worker_id_++;
  workers_.emplace_back(make_scoped_refptr(new SchedulerWorker(
      priority_hint, CreateSchedulerWorkerDelegate<DelegateType>(name, id),
      task_tracker_)));
  return workers_.back().get();
}

template <>
SchedulerWorker*&
SchedulerSingleThreadTaskRunnerManager::GetSharedSchedulerWorkerForTraits<
    SchedulerWorkerDelegate>(const TaskTraits& traits) {
  return shared_scheduler_workers_[GetEnvironmentIndexForTraits(traits)];
}

#if defined(OS_WIN)
template <>
SchedulerWorker*&
SchedulerSingleThreadTaskRunnerManager::GetSharedSchedulerWorkerForTraits<
    SchedulerWorkerCOMDelegate>(const TaskTraits& traits) {
  return shared_com_scheduler_workers_[GetEnvironmentIndexForTraits(traits)];
}
#endif  // defined(OS_WIN)

void SchedulerSingleThreadTaskRunnerManager::UnregisterSchedulerWorker(
    SchedulerWorker* worker) {
  // Cleanup uses a SchedulerLock, so call Cleanup() after releasing
  // |lock_|.
  scoped_refptr<SchedulerWorker> worker_to_destroy;
  {
    AutoSchedulerLock auto_lock(lock_);

    // We might be joining, so record that a worker was unregistered for
    // verification at destruction.
    if (workers_.empty()) {
#if DCHECK_IS_ON()
      subtle::NoBarrier_AtomicIncrement(&workers_unregistered_during_join_, 1);
#endif
      return;
    }

    auto worker_iter =
        std::find_if(workers_.begin(), workers_.end(),
                     [worker](const scoped_refptr<SchedulerWorker>& candidate) {
                       return candidate.get() == worker;
                     });
    DCHECK(worker_iter != workers_.end());
    worker_to_destroy = std::move(*worker_iter);
    workers_.erase(worker_iter);
  }
  worker_to_destroy->Cleanup();
}

void SchedulerSingleThreadTaskRunnerManager::ReleaseSharedSchedulerWorkers() {
  decltype(shared_scheduler_workers_) local_shared_scheduler_workers;
#if defined(OS_WIN)
  decltype(shared_com_scheduler_workers_) local_shared_com_scheduler_workers;
#endif
  {
    AutoSchedulerLock auto_lock(lock_);
    for (size_t i = 0; i < arraysize(shared_scheduler_workers_); ++i) {
      local_shared_scheduler_workers[i] = shared_scheduler_workers_[i];
      shared_scheduler_workers_[i] = nullptr;
#if defined(OS_WIN)
      local_shared_com_scheduler_workers[i] = shared_com_scheduler_workers_[i];
      shared_com_scheduler_workers_[i] = nullptr;
#endif
    }
  }

  for (size_t i = 0; i < arraysize(local_shared_scheduler_workers); ++i) {
    if (local_shared_scheduler_workers[i])
      UnregisterSchedulerWorker(local_shared_scheduler_workers[i]);
#if defined(OS_WIN)
    if (local_shared_com_scheduler_workers[i])
      UnregisterSchedulerWorker(local_shared_com_scheduler_workers[i]);
#endif
  }
}

}  // namespace internal
}  // namespace base
