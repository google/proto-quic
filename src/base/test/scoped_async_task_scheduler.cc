// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_async_task_scheduler.h"

#include "base/logging.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_scheduler.h"

namespace base {
namespace test {

ScopedAsyncTaskScheduler::ScopedAsyncTaskScheduler() {
  DCHECK(!TaskScheduler::GetInstance());

  // Instantiate a TaskScheduler with 1 thread in each of its 4 pools. Threads
  // stay alive even when they don't have work.
  constexpr int kMaxThreads = 1;
  const TimeDelta kSuggestedReclaimTime = TimeDelta::Max();
  const SchedulerWorkerPoolParams worker_pool_params(
      SchedulerWorkerPoolParams::StandbyThreadPolicy::ONE, kMaxThreads,
      kSuggestedReclaimTime);
  TaskScheduler::Create("ScopedAsync");
  task_scheduler_ = TaskScheduler::GetInstance();
  TaskScheduler::GetInstance()->Start({worker_pool_params, worker_pool_params,
                                       worker_pool_params, worker_pool_params});
}

ScopedAsyncTaskScheduler::~ScopedAsyncTaskScheduler() {
  DCHECK_EQ(TaskScheduler::GetInstance(), task_scheduler_);
  // Without FlushForTesting(), DeleteSoon() and ReleaseSoon() tasks could be
  // skipped, resulting in memory leaks.
  TaskScheduler::GetInstance()->FlushForTesting();
  TaskScheduler::GetInstance()->Shutdown();
  TaskScheduler::GetInstance()->JoinForTesting();
  TaskScheduler::SetInstance(nullptr);
}

}  // namespace test
}  // namespace base
