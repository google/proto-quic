// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_tracker_posix.h"

#include <unistd.h>

#include <utility>

#include "base/bind.h"
#include "base/files/file_descriptor_watcher_posix.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/posix/eintr_wrapper.h"
#include "base/run_loop.h"
#include "base/sequence_token.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_traits.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

// Verify that TaskTrackerPosix runs a Task it receives.
TEST(TaskSchedulerTaskTrackerPosixTest, RunTask) {
  MessageLoopForIO message_loop;
  bool did_run = false;
  auto task = MakeUnique<Task>(
      FROM_HERE,
      Bind([](bool* did_run) { *did_run = true; }, Unretained(&did_run)),
      TaskTraits(), TimeDelta());
  TaskTrackerPosix tracker;
  tracker.set_watch_file_descriptor_message_loop(&message_loop);

  EXPECT_TRUE(tracker.WillPostTask(task.get()));
  EXPECT_TRUE(tracker.RunTask(std::move(task), SequenceToken::Create()));
  EXPECT_TRUE(did_run);
}

// Verify that FileDescriptorWatcher::WatchReadable() can be called from a task
// running in TaskTrackerPosix without a crash.
TEST(TaskSchedulerTaskTrackerPosixTest, FileDescriptorWatcher) {
  MessageLoopForIO message_loop;
  int fds[2];
  ASSERT_EQ(0, pipe(fds));
  auto task = MakeUnique<Task>(
      FROM_HERE, Bind(IgnoreResult(&FileDescriptorWatcher::WatchReadable),
                      fds[0], Bind(&DoNothing)),
      TaskTraits(), TimeDelta());
  TaskTrackerPosix tracker;
  tracker.set_watch_file_descriptor_message_loop(&message_loop);

  EXPECT_TRUE(tracker.WillPostTask(task.get()));
  EXPECT_TRUE(tracker.RunTask(std::move(task), SequenceToken::Create()));

  // Run the MessageLoop to allow the read watch to be registered and
  // unregistered. This prevents a memory leak.
  RunLoop().RunUntilIdle();

  EXPECT_EQ(0, IGNORE_EINTR(close(fds[0])));
  EXPECT_EQ(0, IGNORE_EINTR(close(fds[1])));
}

}  // namespace internal
}  // namespace base
