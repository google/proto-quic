// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_tracker_posix.h"

#include <utility>

#include "base/files/file_descriptor_watcher_posix.h"
#include "base/logging.h"

namespace base {
namespace internal {

TaskTrackerPosix::TaskTrackerPosix(
    MessageLoopForIO* watch_file_descriptor_message_loop)
    : watch_file_descriptor_message_loop_(watch_file_descriptor_message_loop) {
  DCHECK(watch_file_descriptor_message_loop_);
}

TaskTrackerPosix::~TaskTrackerPosix() = default;

void TaskTrackerPosix::PerformRunTask(std::unique_ptr<Task> task) {
  FileDescriptorWatcher file_descriptor_watcher(
      watch_file_descriptor_message_loop_);
  TaskTracker::PerformRunTask(std::move(task));
}

}  // namespace internal
}  // namespace base
