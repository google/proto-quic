// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_environment.h"

#include "base/run_loop.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_scheduler.h"
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
    ran_task_ = true;
  }

  bool ran_task() const { return ran_task_; }

 private:
  bool ran_task_ = false;
  DISALLOW_COPY_AND_ASSIGN(TaskObserver);
};

}  // namespace

ScopedTaskEnvironment::ScopedTaskEnvironment(MainThreadType main_thread_type)
    : message_loop_(main_thread_type == MainThreadType::DEFAULT
                        ? MessageLoop::TYPE_DEFAULT
                        : (main_thread_type == MainThreadType::UI
                               ? MessageLoop::TYPE_UI
                               : MessageLoop::TYPE_IO)) {
  DCHECK(!TaskScheduler::GetInstance());

  // Instantiate a TaskScheduler with 1 thread in each of its 4 pools. Threads
  // stay alive even when they don't have work.
  constexpr int kMaxThreads = 1;
  const TimeDelta kSuggestedReclaimTime = TimeDelta::Max();
  const SchedulerWorkerPoolParams worker_pool_params(
      SchedulerWorkerPoolParams::StandbyThreadPolicy::ONE, kMaxThreads,
      kSuggestedReclaimTime);
  TaskScheduler::Create("ScopedTaskEnvironment");
  task_scheduler_ = TaskScheduler::GetInstance();
  TaskScheduler::GetInstance()->Start({worker_pool_params, worker_pool_params,
                                       worker_pool_params, worker_pool_params});
}

ScopedTaskEnvironment::~ScopedTaskEnvironment() {
  // Ideally this would RunLoop().RunUntilIdle() here to catch any errors or
  // infinite post loop in the remaining work but this isn't possible right now
  // because base::~MessageLoop() didn't use to do this and adding it here would
  // make the migration away from MessageLoop that much harder.

  DCHECK_EQ(TaskScheduler::GetInstance(), task_scheduler_);
  // Without FlushForTesting(), DeleteSoon() and ReleaseSoon() tasks could be
  // skipped, resulting in memory leaks.
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
    TaskScheduler::GetInstance()->FlushForTesting();

    TaskObserver task_observer;
    MessageLoop::current()->AddTaskObserver(&task_observer);
    RunLoop().RunUntilIdle();
    MessageLoop::current()->RemoveTaskObserver(&task_observer);

    if (!task_observer.ran_task())
      return;
  }
}

}  // namespace test
}  // namespace base
