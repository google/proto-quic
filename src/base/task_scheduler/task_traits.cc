// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_traits.h"

#include <stddef.h>

#include <ostream>

#include "base/logging.h"

namespace base {

// Do not rely on defaults hard-coded below beyond the guarantees described in
// the header; anything else is subject to change. Tasks should explicitly
// request defaults if the behavior is critical to the task.
TaskTraits::TaskTraits()
    : with_file_io_(false),
      with_wait_(false),
      priority_(TaskPriority::BACKGROUND),
      shutdown_behavior_(TaskShutdownBehavior::SKIP_ON_SHUTDOWN) {}

TaskTraits::~TaskTraits() = default;

TaskTraits& TaskTraits::WithFileIO() {
  with_file_io_ = true;
  return *this;
}

TaskTraits& TaskTraits::WithWait() {
  with_wait_ = true;
  return *this;
}

TaskTraits& TaskTraits::WithPriority(TaskPriority priority) {
  priority_ = priority;
  return *this;
}

TaskTraits& TaskTraits::WithShutdownBehavior(
    TaskShutdownBehavior shutdown_behavior) {
  shutdown_behavior_ = shutdown_behavior;
  return *this;
}

const char* TaskPriorityToString(TaskPriority task_priority) {
  switch (task_priority) {
    case TaskPriority::BACKGROUND:
      return "BACKGROUND";
    case TaskPriority::USER_VISIBLE:
      return "USER_VISIBLE";
    case TaskPriority::USER_BLOCKING:
      return "USER_BLOCKING";
  }
  NOTREACHED();
  return "";
}

const char* TaskShutdownBehaviorToString(
    TaskShutdownBehavior shutdown_behavior) {
  switch (shutdown_behavior) {
    case TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN:
      return "CONTINUE_ON_SHUTDOWN";
    case TaskShutdownBehavior::SKIP_ON_SHUTDOWN:
      return "SKIP_ON_SHUTDOWN";
    case TaskShutdownBehavior::BLOCK_SHUTDOWN:
      return "BLOCK_SHUTDOWN";
  }
  NOTREACHED();
  return "";
}

std::ostream& operator<<(std::ostream& os, const TaskPriority& task_priority) {
  os << TaskPriorityToString(task_priority);
  return os;
}

std::ostream& operator<<(std::ostream& os,
                         const TaskShutdownBehavior& shutdown_behavior) {
  os << TaskShutdownBehaviorToString(shutdown_behavior);
  return os;
}

}  // namespace base
