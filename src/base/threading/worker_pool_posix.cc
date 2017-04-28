// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/worker_pool_posix.h"

#include <stddef.h>

#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/stringprintf.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_local.h"
#include "base/threading/worker_pool.h"
#include "base/trace_event/trace_event.h"
#include "base/tracked_objects.h"

using tracked_objects::TrackedTime;

namespace base {

namespace {

base::LazyInstance<ThreadLocalBoolean>::Leaky
    g_worker_pool_running_on_this_thread = LAZY_INSTANCE_INITIALIZER;

const int kIdleSecondsBeforeExit = 10 * 60;

#if defined(OS_MACOSX)
// On Mac OS X a background thread's default stack size is 512Kb. We need at
// least 1MB for compilation tasks in V8, so increase this default.
const int kStackSize = 1 * 1024 * 1024;
#else
const int kStackSize = 0;
#endif

class WorkerPoolImpl {
 public:
  WorkerPoolImpl();

  // WorkerPoolImpl is only instantiated as a leaky LazyInstance, so the
  // destructor is never called.
  ~WorkerPoolImpl() = delete;

  void PostTask(const tracked_objects::Location& from_here,
                base::OnceClosure task,
                bool task_is_slow);

 private:
  scoped_refptr<base::PosixDynamicThreadPool> pool_;
};

WorkerPoolImpl::WorkerPoolImpl()
    : pool_(new base::PosixDynamicThreadPool("WorkerPool",
                                             kIdleSecondsBeforeExit)) {}

void WorkerPoolImpl::PostTask(const tracked_objects::Location& from_here,
                              base::OnceClosure task,
                              bool task_is_slow) {
  pool_->PostTask(from_here, std::move(task));
}

base::LazyInstance<WorkerPoolImpl>::Leaky g_lazy_worker_pool =
    LAZY_INSTANCE_INITIALIZER;

class WorkerThread : public PlatformThread::Delegate {
 public:
  WorkerThread(const std::string& name_prefix,
               base::PosixDynamicThreadPool* pool)
      : name_prefix_(name_prefix), pool_(pool) {}

  void ThreadMain() override;

 private:
  const std::string name_prefix_;
  scoped_refptr<base::PosixDynamicThreadPool> pool_;

  DISALLOW_COPY_AND_ASSIGN(WorkerThread);
};

void WorkerThread::ThreadMain() {
  g_worker_pool_running_on_this_thread.Get().Set(true);
  const std::string name = base::StringPrintf("%s/%d", name_prefix_.c_str(),
                                              PlatformThread::CurrentId());
  // Note |name.c_str()| must remain valid for for the whole life of the thread.
  PlatformThread::SetName(name);

  for (;;) {
    PendingTask pending_task = pool_->WaitForTask();
    if (pending_task.task.is_null())
      break;
    TRACE_TASK_EXECUTION("WorkerThread::ThreadMain::Run", pending_task);

    tracked_objects::TaskStopwatch stopwatch;
    stopwatch.Start();
    std::move(pending_task.task).Run();
    stopwatch.Stop();

    tracked_objects::ThreadData::TallyRunOnWorkerThreadIfTracking(
        pending_task.birth_tally, pending_task.time_posted, stopwatch);
  }

  // The WorkerThread is non-joinable, so it deletes itself.
  delete this;
}

}  // namespace

// static
bool WorkerPool::PostTask(const tracked_objects::Location& from_here,
                          base::OnceClosure task,
                          bool task_is_slow) {
  g_lazy_worker_pool.Pointer()->PostTask(from_here, std::move(task),
                                         task_is_slow);
  return true;
}

// static
bool WorkerPool::RunsTasksOnCurrentThread() {
  return g_worker_pool_running_on_this_thread.Get().Get();
}

PosixDynamicThreadPool::PosixDynamicThreadPool(const std::string& name_prefix,
                                               int idle_seconds_before_exit)
    : name_prefix_(name_prefix),
      idle_seconds_before_exit_(idle_seconds_before_exit),
      pending_tasks_available_cv_(&lock_),
      num_idle_threads_(0) {}

PosixDynamicThreadPool::~PosixDynamicThreadPool() {
  while (!pending_tasks_.empty())
    pending_tasks_.pop();
}

void PosixDynamicThreadPool::PostTask(
    const tracked_objects::Location& from_here,
    base::OnceClosure task) {
  PendingTask pending_task(from_here, std::move(task));
  AddTask(&pending_task);
}

void PosixDynamicThreadPool::AddTask(PendingTask* pending_task) {
  DCHECK(pending_task);

  // Use CHECK instead of DCHECK to crash earlier. See http://crbug.com/711167
  // for details.
  CHECK(pending_task->task);

  AutoLock locked(lock_);

  pending_tasks_.push(std::move(*pending_task));

  // We have enough worker threads.
  if (static_cast<size_t>(num_idle_threads_) >= pending_tasks_.size()) {
    pending_tasks_available_cv_.Signal();
  } else {
    // The new PlatformThread will take ownership of the WorkerThread object,
    // which will delete itself on exit.
    WorkerThread* worker = new WorkerThread(name_prefix_, this);
    PlatformThread::CreateNonJoinable(kStackSize, worker);
  }
}

PendingTask PosixDynamicThreadPool::WaitForTask() {
  AutoLock locked(lock_);

  if (pending_tasks_.empty()) {  // No work available, wait for work.
    num_idle_threads_++;
    if (num_idle_threads_cv_.get())
      num_idle_threads_cv_->Signal();
    pending_tasks_available_cv_.TimedWait(
        TimeDelta::FromSeconds(idle_seconds_before_exit_));
    num_idle_threads_--;
    if (num_idle_threads_cv_.get())
      num_idle_threads_cv_->Signal();
    if (pending_tasks_.empty()) {
      // We waited for work, but there's still no work.  Return NULL to signal
      // the thread to terminate.
      return PendingTask(FROM_HERE, base::Closure());
    }
  }

  PendingTask pending_task = std::move(pending_tasks_.front());
  pending_tasks_.pop();
  return pending_task;
}

}  // namespace base
