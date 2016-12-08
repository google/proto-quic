// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_scheduler.h"

#include <vector>

#include "base/bind.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

namespace base {
namespace test {

ScopedTaskScheduler::ScopedTaskScheduler() {
  DCHECK(!TaskScheduler::GetInstance());

  // Create a TaskScheduler with a single thread to make tests deterministic.
  constexpr int kMaxThreads = 1;
  std::vector<SchedulerWorkerPoolParams> worker_pool_params_vector;
  worker_pool_params_vector.emplace_back(
      "Simple", ThreadPriority::NORMAL,
      SchedulerWorkerPoolParams::StandbyThreadPolicy::LAZY, kMaxThreads,
      TimeDelta::Max());
  TaskScheduler::CreateAndSetDefaultTaskScheduler(
      worker_pool_params_vector,
      Bind([](const TaskTraits&) -> size_t { return 0; }));
  task_scheduler_ = TaskScheduler::GetInstance();
}

ScopedTaskScheduler::~ScopedTaskScheduler() {
  DCHECK_EQ(task_scheduler_, TaskScheduler::GetInstance());
  TaskScheduler::GetInstance()->Shutdown();
  TaskScheduler::GetInstance()->JoinForTesting();
  TaskScheduler::SetInstance(nullptr);
}

}  // namespace test
}  // namespace base
