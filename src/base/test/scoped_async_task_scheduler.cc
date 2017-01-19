// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_async_task_scheduler.h"

#include <vector>

#include "base/bind.h"
#include "base/logging.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/task_scheduler_impl.h"

namespace base {
namespace test {

ScopedAsyncTaskScheduler::ScopedAsyncTaskScheduler() {
  DCHECK(!TaskScheduler::GetInstance());
  constexpr int kMaxThreads = 1;
  const TimeDelta kSuggestedReclaimTime = TimeDelta::Max();
  std::vector<SchedulerWorkerPoolParams> worker_pool_params_vector;
  worker_pool_params_vector.emplace_back(
      "ScopedAsyncTaskScheduler", ThreadPriority::NORMAL,
      SchedulerWorkerPoolParams::StandbyThreadPolicy::LAZY, kMaxThreads,
      kSuggestedReclaimTime);
  TaskScheduler::CreateAndSetDefaultTaskScheduler(
      worker_pool_params_vector,
      Bind([](const TaskTraits&) -> size_t { return 0; }));
  task_scheduler_ = TaskScheduler::GetInstance();
}

ScopedAsyncTaskScheduler::~ScopedAsyncTaskScheduler() {
  DCHECK_EQ(TaskScheduler::GetInstance(), task_scheduler_);
  TaskScheduler::GetInstance()->Shutdown();
  static_cast<internal::TaskSchedulerImpl*>(TaskScheduler::GetInstance())
      ->JoinForTesting();
  TaskScheduler::SetInstance(nullptr);
}

}  // namespace test
}  // namespace base
