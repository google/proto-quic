// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker_pool_params.h"

namespace base {

SchedulerWorkerPoolParams::SchedulerWorkerPoolParams(
    const std::string& name,
    ThreadPriority priority_hint,
    StandbyThreadPolicy standby_thread_policy,
    int max_threads,
    TimeDelta suggested_reclaim_time,
    SchedulerBackwardCompatibility backward_compatibility)
    : name_(name),
      priority_hint_(priority_hint),
      standby_thread_policy_(standby_thread_policy),
      max_threads_(max_threads),
      suggested_reclaim_time_(suggested_reclaim_time),
      backward_compatibility_(backward_compatibility) {}

SchedulerWorkerPoolParams::SchedulerWorkerPoolParams(
    SchedulerWorkerPoolParams&& other) = default;

SchedulerWorkerPoolParams& SchedulerWorkerPoolParams::operator=(
    SchedulerWorkerPoolParams&& other) = default;

}  // namespace base
