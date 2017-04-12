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

ScopedTaskEnvironment::ScopedTaskEnvironment() {
  DCHECK(!TaskScheduler::GetInstance());

  // Instantiate a TaskScheduler with 1 thread in each of its 4 pools. Threads
  // stay alive even when they don't have work.
  constexpr int kMaxThreads = 1;
  const TimeDelta kSuggestedReclaimTime = TimeDelta::Max();
  const SchedulerWorkerPoolParams worker_pool_params(
      SchedulerWorkerPoolParams::StandbyThreadPolicy::ONE, kMaxThreads,
      kSuggestedReclaimTime);
  TaskScheduler::CreateAndSetDefaultTaskScheduler(
      "ScopedTaskEnvironment", {worker_pool_params, worker_pool_params,
                                worker_pool_params, worker_pool_params});
  task_scheduler_ = TaskScheduler::GetInstance();
}

ScopedTaskEnvironment::~ScopedTaskEnvironment() {
  RunLoop().RunUntilIdle();

  DCHECK_EQ(TaskScheduler::GetInstance(), task_scheduler_);
  TaskScheduler::GetInstance()->Shutdown();
  TaskScheduler::GetInstance()->JoinForTesting();
  TaskScheduler::SetInstance(nullptr);
}

}  // namespace test
}  // namespace base
