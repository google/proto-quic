// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_traits.h"

#include "base/task_scheduler/scoped_set_task_priority_for_current_thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

// Verify that TaskTraits is initialized with the priority of the task running
// on the current thread.
TEST(TaskSchedulerTaskTraitsTest, DefaultPriority) {
  {
    internal::ScopedSetTaskPriorityForCurrentThread scope(
        TaskPriority::BACKGROUND);
    EXPECT_EQ(TaskPriority::BACKGROUND, TaskTraits().priority());
  }
  {
    internal::ScopedSetTaskPriorityForCurrentThread scope(
        TaskPriority::USER_VISIBLE);
    EXPECT_EQ(TaskPriority::USER_VISIBLE, TaskTraits().priority());
  }
  {
    internal::ScopedSetTaskPriorityForCurrentThread scope(
        TaskPriority::USER_BLOCKING);
    EXPECT_EQ(TaskPriority::USER_BLOCKING, TaskTraits().priority());
  }
}

}  // namespace base
