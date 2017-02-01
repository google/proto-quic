// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_PARAMS_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_PARAMS_H_

#include <string>

#include "base/macros.h"
#include "base/task_scheduler/scheduler_worker_params.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

namespace base {

class BASE_EXPORT SchedulerWorkerPoolParams final {
 public:
  enum class StandbyThreadPolicy {
    // Create threads as needed on demand, reclaimed as necessary.
    LAZY,
    // When possible, keep one idle thread alive on standby, reclaimed as
    // necessary.
    ONE,
  };

  // Construct a scheduler worker pool parameter object. |name| will be used to
  // label the pool's threads ("TaskScheduler" + |name| + index) and histograms
  // ("TaskScheduler." + histogram name + "." + |name| + extra suffixes). The
  // pool will contain up to |max_threads|. |priority_hint| is the preferred
  // thread priority; the actual thread priority depends on shutdown state and
  // platform capabilities. |standby_thread_policy| indicates whether an idle
  // thread should be kept alive on standby. |suggested_reclaim_time| sets a
  // suggestion on when to reclaim idle threads. The pool is free to ignore this
  // value for performance or correctness reasons. |backward_compatibility|
  // indicates whether backward compatibility is enabled.
  SchedulerWorkerPoolParams(
      const std::string& name,
      ThreadPriority priority_hint,
      StandbyThreadPolicy standby_thread_policy,
      int max_threads,
      TimeDelta suggested_reclaim_time,
      SchedulerBackwardCompatibility backward_compatibility =
          SchedulerBackwardCompatibility::DISABLED);
  SchedulerWorkerPoolParams(SchedulerWorkerPoolParams&& other);
  SchedulerWorkerPoolParams& operator=(SchedulerWorkerPoolParams&& other);

  const std::string& name() const { return name_; }
  ThreadPriority priority_hint() const { return priority_hint_; }
  StandbyThreadPolicy standby_thread_policy() const {
    return standby_thread_policy_;
  }
  size_t max_threads() const { return max_threads_; }
  TimeDelta suggested_reclaim_time() const { return suggested_reclaim_time_; }
  SchedulerBackwardCompatibility backward_compatibility() const {
    return backward_compatibility_;
  }

 private:
  std::string name_;
  ThreadPriority priority_hint_;
  StandbyThreadPolicy standby_thread_policy_;
  size_t max_threads_;
  TimeDelta suggested_reclaim_time_;
  SchedulerBackwardCompatibility backward_compatibility_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerPoolParams);
};

}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_PARAMS_H_
