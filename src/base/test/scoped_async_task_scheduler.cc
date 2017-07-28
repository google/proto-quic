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
