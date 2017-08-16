// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_environment.h"

#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/task_scheduler_impl.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"

namespace base {
namespace test {

namespace {

class TaskObserver : public MessageLoop::TaskObserver {
 public:
  TaskObserver() = default;

  // MessageLoop::TaskObserver:
  void WillProcessTask(const PendingTask& pending_task) override {}
  void DidProcessTask(const PendingTask& pending_task) override {
    ++task_count_;
  }

  int task_count() const { return task_count_; }

 private:
  int task_count_ = 0;

  DISALLOW_COPY_AND_ASSIGN(TaskObserver);
};

}  // namespace

class ScopedTaskEnvironment::TestTaskTracker
    : public internal::TaskSchedulerImpl::TaskTrackerImpl {
 public:
  TestTaskTracker();

  void RegisterOnQueueEmptyClosure(OnceClosure queue_empty_closure);

  // Returns true if closure needed reset.
  bool ResetOnQueueEmptyClosureIfNotNull();

  // Allow running tasks.
  void AllowRunRask();

  // Disallow running tasks. No-ops and returns false if a task is running.
  bool DisallowRunTasks();

 private:
  friend class ScopedTaskEnvironment;

  // internal::TaskSchedulerImpl::TaskTrackerImpl:
  void PerformRunTask(std::unique_ptr<internal::Task> task,
                      internal::Sequence* sequence) override;
  void OnRunNextTaskCompleted() override;

  // Synchronizes accesses to members below.
  Lock lock_;

  // Closure posted to the main thread when the task queue becomes empty.
  OnceClosure queue_empty_closure_;

  // True if running tasks is allowed.
  bool can_run_tasks_ = true;

  // Signaled when |can_run_tasks_| becomes true.
  ConditionVariable can_run_tasks_cv_;

  // Number of tasks that are currently running.
  int num_tasks_running_ = 0;

  DISALLOW_COPY_AND_ASSIGN(TestTaskTracker);
};

ScopedTaskEnvironment::ScopedTaskEnvironment(
    MainThreadType main_thread_type,
    ExecutionMode execution_control_mode)
    : execution_control_mode_(execution_control_mode),
      message_loop_(main_thread_type == MainThreadType::DEFAULT
                        ? MessageLoop::TYPE_DEFAULT
                        : (main_thread_type == MainThreadType::UI
                               ? MessageLoop::TYPE_UI
                               : MessageLoop::TYPE_IO)),
      task_tracker_(new TestTaskTracker()) {
  CHECK(!TaskScheduler::GetInstance());

  // Instantiate a TaskScheduler with 2 threads in each of its 4 pools. Threads
  // stay alive even when they don't have work.
  // Each pool uses two threads to prevent deadlocks in unit tests that have a
  // sequence that uses WithBaseSyncPrimitives() to wait on the result of
  // another sequence. This isn't perfect (doesn't solve wait chains) but solves
  // the basic use case for now.
  // TODO(fdoray/jeffreyhe): Make the TaskScheduler dynamically replace blocked
  // threads and get rid of this limitation. http://crbug.com/738104
  constexpr int kMaxThreads = 2;
  const TimeDelta kSuggestedReclaimTime = TimeDelta::Max();
  const SchedulerWorkerPoolParams worker_pool_params(kMaxThreads,
                                                     kSuggestedReclaimTime);
  TaskScheduler::SetInstance(MakeUnique<internal::TaskSchedulerImpl>(
      "ScopedTaskEnvironment", WrapUnique(task_tracker_)));
  task_scheduler_ = TaskScheduler::GetInstance();
  TaskScheduler::GetInstance()->Start({worker_pool_params, worker_pool_params,
                                       worker_pool_params, worker_pool_params});

  if (execution_control_mode_ == ExecutionMode::QUEUED)
    CHECK(task_tracker_->DisallowRunTasks());
}

ScopedTaskEnvironment::~ScopedTaskEnvironment() {
  // Ideally this would RunLoop().RunUntilIdle() here to catch any errors or
  // infinite post loop in the remaining work but this isn't possible right now
  // because base::~MessageLoop() didn't use to do this and adding it here would
  // make the migration away from MessageLoop that much harder.
  CHECK_EQ(TaskScheduler::GetInstance(), task_scheduler_);
  // Without FlushForTesting(), DeleteSoon() and ReleaseSoon() tasks could be
  // skipped, resulting in memory leaks.
  task_tracker_->AllowRunRask();
  TaskScheduler::GetInstance()->FlushForTesting();
  TaskScheduler::GetInstance()->Shutdown();
  TaskScheduler::GetInstance()->JoinForTesting();
  TaskScheduler::SetInstance(nullptr);
}

scoped_refptr<base::SingleThreadTaskRunner>
ScopedTaskEnvironment::GetMainThreadTaskRunner() {
  return message_loop_.task_runner();
}

void ScopedTaskEnvironment::RunUntilIdle() {
  for (;;) {
    RunLoop run_loop;

    // Register a closure to stop running tasks on the main thread when the
    // TaskScheduler queue becomes empty.
    task_tracker_->RegisterOnQueueEmptyClosure(run_loop.QuitWhenIdleClosure());

    // The closure registered above may never run if the TaskScheduler queue
    // starts empty. Post a TaskScheduler tasks to make sure that the queue
    // doesn't start empty.
    PostTask(FROM_HERE, BindOnce(&DoNothing));

    // Run main thread and TaskScheduler tasks.
    task_tracker_->AllowRunRask();
    TaskObserver task_observer;
    MessageLoop::current()->AddTaskObserver(&task_observer);
    run_loop.Run();
    MessageLoop::current()->RemoveTaskObserver(&task_observer);

    // If |task_tracker_|'s |queue_empty_closure_| is not null, it means that
    // external code exited the RunLoop (through deprecated static methods) and
    // that the MessageLoop and TaskScheduler queues might not be empty. Run the
    // loop again to make sure that no task remains.
    if (task_tracker_->ResetOnQueueEmptyClosureIfNotNull())
      continue;

    // If tasks other than the QuitWhenIdle closure ran on the main thread, they
    // may have posted TaskScheduler tasks that didn't run yet. Another
    // iteration is required to run them.
    //
    // If the ExecutionMode is QUEUED and DisallowRunTasks() fails,
    // another iteration is required to make sure that RunUntilIdle() doesn't
    // return while TaskScheduler tasks are still allowed to run.
    //
    // Note: DisallowRunTasks() fails when a TaskScheduler task is running. A
    // TaskScheduler task may be running after the TaskScheduler queue became
    // empty even if no tasks ran on the main thread in these cases:
    // - An undelayed task became ripe for execution.
    // - A task was posted from an external thread.
    if (task_observer.task_count() == 1 &&
        (execution_control_mode_ != ExecutionMode::QUEUED ||
         task_tracker_->DisallowRunTasks())) {
      break;
    }
  }
}

ScopedTaskEnvironment::TestTaskTracker::TestTaskTracker()
    : can_run_tasks_cv_(&lock_) {}

void ScopedTaskEnvironment::TestTaskTracker::RegisterOnQueueEmptyClosure(
    OnceClosure queue_empty_closure) {
  AutoLock auto_lock(lock_);
  CHECK(!queue_empty_closure_);
  queue_empty_closure_ = std::move(queue_empty_closure);
}

bool ScopedTaskEnvironment::TestTaskTracker::
    ResetOnQueueEmptyClosureIfNotNull() {
  AutoLock auto_lock(lock_);
  if (queue_empty_closure_) {
    queue_empty_closure_ = Closure();
    return true;
  }

  return false;
}

void ScopedTaskEnvironment::TestTaskTracker::AllowRunRask() {
  AutoLock auto_lock(lock_);
  can_run_tasks_ = true;
  can_run_tasks_cv_.Broadcast();
}

bool ScopedTaskEnvironment::TestTaskTracker::DisallowRunTasks() {
  AutoLock auto_lock(lock_);

  // Can't disallow run task if there are tasks running.
  if (num_tasks_running_ > 0)
    return false;

  can_run_tasks_ = false;
  return true;
}

void ScopedTaskEnvironment::TestTaskTracker::PerformRunTask(
    std::unique_ptr<internal::Task> task,
    internal::Sequence* sequence) {
  {
    AutoLock auto_lock(lock_);

    while (!can_run_tasks_)
      can_run_tasks_cv_.Wait();

    ++num_tasks_running_;
  }

  internal::TaskSchedulerImpl::TaskTrackerImpl::PerformRunTask(std::move(task),
                                                               sequence);

  {
    AutoLock auto_lock(lock_);

    CHECK_GT(num_tasks_running_, 0);
    CHECK(can_run_tasks_);

    --num_tasks_running_;
  }
}

void ScopedTaskEnvironment::TestTaskTracker::OnRunNextTaskCompleted() {
  // Notify the main thread when no tasks are running or queued.
  AutoLock auto_lock(lock_);
  if (num_tasks_running_ == 0 && GetNumPendingUndelayedTasksForTesting() == 0 &&
      queue_empty_closure_) {
    std::move(queue_empty_closure_).Run();
  }
}

}  // namespace test
}  // namespace base
