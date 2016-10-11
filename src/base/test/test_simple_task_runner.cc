// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/test_simple_task_runner.h"

#include "base/logging.h"

namespace base {

TestSimpleTaskRunner::TestSimpleTaskRunner() = default;

TestSimpleTaskRunner::~TestSimpleTaskRunner() = default;

bool TestSimpleTaskRunner::PostDelayedTask(
    const tracked_objects::Location& from_here,
    const Closure& task,
    TimeDelta delay) {
  AutoLock auto_lock(lock_);
  pending_tasks_.push_back(
      TestPendingTask(from_here, task, TimeTicks(), delay,
                      TestPendingTask::NESTABLE));
  return true;
}

bool TestSimpleTaskRunner::PostNonNestableDelayedTask(
    const tracked_objects::Location& from_here,
    const Closure& task,
    TimeDelta delay) {
  AutoLock auto_lock(lock_);
  pending_tasks_.push_back(
      TestPendingTask(from_here, task, TimeTicks(), delay,
                      TestPendingTask::NON_NESTABLE));
  return true;
}

bool TestSimpleTaskRunner::RunsTasksOnCurrentThread() const {
  return thread_ref_ == PlatformThread::CurrentRef();
}

std::deque<TestPendingTask> TestSimpleTaskRunner::TakePendingTasks() {
  AutoLock auto_lock(lock_);
  return std::move(pending_tasks_);
}

size_t TestSimpleTaskRunner::NumPendingTasks() const {
  AutoLock auto_lock(lock_);
  return pending_tasks_.size();
}

bool TestSimpleTaskRunner::HasPendingTask() const {
  AutoLock auto_lock(lock_);
  return !pending_tasks_.empty();
}

base::TimeDelta TestSimpleTaskRunner::NextPendingTaskDelay() const {
  AutoLock auto_lock(lock_);
  return pending_tasks_.front().GetTimeToRun() - base::TimeTicks();
}

base::TimeDelta TestSimpleTaskRunner::FinalPendingTaskDelay() const {
  AutoLock auto_lock(lock_);
  return pending_tasks_.back().GetTimeToRun() - base::TimeTicks();
}

void TestSimpleTaskRunner::ClearPendingTasks() {
  AutoLock auto_lock(lock_);
  pending_tasks_.clear();
}

void TestSimpleTaskRunner::RunPendingTasks() {
  DCHECK(RunsTasksOnCurrentThread());

  // Swap with a local variable to avoid re-entrancy problems.
  std::deque<TestPendingTask> tasks_to_run;
  {
    AutoLock auto_lock(lock_);
    tasks_to_run.swap(pending_tasks_);
  }

  for (const auto& task : tasks_to_run)
    task.task.Run();
}

void TestSimpleTaskRunner::RunUntilIdle() {
  while (!pending_tasks_.empty()) {
    RunPendingTasks();
  }
}

}  // namespace base
