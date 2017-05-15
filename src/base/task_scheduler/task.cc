// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task.h"

#include <utility>

#include "base/critical_closure.h"

namespace base {
namespace internal {

Task::Task(const tracked_objects::Location& posted_from,
           OnceClosure task,
           const TaskTraits& traits,
           TimeDelta delay)
    : PendingTask(
          posted_from,
          traits.shutdown_behavior() == TaskShutdownBehavior::BLOCK_SHUTDOWN
              ? MakeCriticalClosure(std::move(task))
              : std::move(task),
          delay.is_zero() ? TimeTicks() : TimeTicks::Now() + delay,
          false),  // Not nestable.
      // Prevent a delayed BLOCK_SHUTDOWN task from blocking shutdown before
      // being scheduled by changing its shutdown behavior to SKIP_ON_SHUTDOWN.
      traits(
          (!delay.is_zero() &&
           traits.shutdown_behavior() == TaskShutdownBehavior::BLOCK_SHUTDOWN)
              ? TaskTraits::Override(traits,
                                     {TaskShutdownBehavior::SKIP_ON_SHUTDOWN})
              : traits),
      delay(delay) {}

Task::~Task() = default;

}  // namespace internal
}  // namespace base
