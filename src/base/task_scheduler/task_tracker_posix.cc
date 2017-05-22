// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_tracker_posix.h"

#include <utility>

#include "base/files/file_descriptor_watcher_posix.h"

namespace base {
namespace internal {

TaskTrackerPosix::TaskTrackerPosix() = default;
TaskTrackerPosix::~TaskTrackerPosix() = default;

void TaskTrackerPosix::PerformRunTask(std::unique_ptr<Task> task,
                                      const SequenceToken& sequence_token) {
  DCHECK(watch_file_descriptor_message_loop_);
  FileDescriptorWatcher file_descriptor_watcher(
      watch_file_descriptor_message_loop_);
  TaskTracker::PerformRunTask(std::move(task), sequence_token);
}

#if DCHECK_IS_ON()
bool TaskTrackerPosix::IsPostingBlockShutdownTaskAfterShutdownAllowed() {
  return service_thread_handle_.is_equal(PlatformThread::CurrentHandle());
}
#endif

}  // namespace internal
}  // namespace base
