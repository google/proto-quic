// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TASK_TRACKER_POSIX_H_
#define BASE_TASK_SCHEDULER_TASK_TRACKER_POSIX_H_

#include <memory>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/task_scheduler/task_tracker.h"

namespace base {

class MessageLoopForIO;

namespace internal {

struct Task;

// A TaskTracker that instantiates a FileDescriptorWatcher in the scope in which
// a task runs. Used on all POSIX platforms except NaCl SFI.
// set_watch_file_descriptor_message_loop() must be called before the
// TaskTracker can run tasks.
class BASE_EXPORT TaskTrackerPosix : public TaskTracker {
 public:
  TaskTrackerPosix();
  ~TaskTrackerPosix();

  // Sets the MessageLoopForIO with which to setup FileDescriptorWatcher in the
  // scope in which tasks run. Must be called before starting to run tasks.
  // External synchronization is required between a call to this and a call to
  // RunTask().
  void set_watch_file_descriptor_message_loop(
      MessageLoopForIO* watch_file_descriptor_message_loop) {
    watch_file_descriptor_message_loop_ = watch_file_descriptor_message_loop;
  }

 private:
  // TaskTracker:
  void PerformRunTask(std::unique_ptr<Task> task) override;

  MessageLoopForIO* watch_file_descriptor_message_loop_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(TaskTrackerPosix);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_TASK_TRACKER_POSIX_H_
