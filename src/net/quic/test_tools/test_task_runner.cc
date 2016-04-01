// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/test_task_runner.h"

#include <algorithm>

#include "net/quic/test_tools/mock_clock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

TestTaskRunner::TestTaskRunner(MockClock* clock) : clock_(clock) {}

TestTaskRunner::~TestTaskRunner() {}

bool TestTaskRunner::PostDelayedTask(const tracked_objects::Location& from_here,
                                     const base::Closure& task,
                                     base::TimeDelta delay) {
  EXPECT_GE(delay, base::TimeDelta());
  tasks_.push_back(PostedTask(from_here, task, clock_->NowInTicks(), delay,
                              base::TestPendingTask::NESTABLE));
  return false;
}

bool TestTaskRunner::RunsTasksOnCurrentThread() const {
  return true;
}

const std::vector<PostedTask>& TestTaskRunner::GetPostedTasks() const {
  return tasks_;
}

void TestTaskRunner::RunNextTask() {
  // Find the next task to run, advance the time to the correct time
  // and then run the task.
  std::vector<PostedTask>::iterator next = FindNextTask();
  DCHECK(next != tasks_.end());
  clock_->AdvanceTime(QuicTime::Delta::FromMicroseconds(
      (next->GetTimeToRun() - clock_->NowInTicks()).InMicroseconds()));
  PostedTask task = *next;
  tasks_.erase(next);
  task.task.Run();
}

namespace {

struct ShouldRunBeforeLessThan {
  bool operator()(const PostedTask& task1, const PostedTask& task2) const {
    return task1.ShouldRunBefore(task2);
  }
};

}  // namespace

std::vector<PostedTask>::iterator TestTaskRunner::FindNextTask() {
  return std::min_element(tasks_.begin(), tasks_.end(),
                          ShouldRunBeforeLessThan());
}

}  // namespace test
}  // namespace net
