// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/worker_pool.h"

#include <utility>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/debug/leak_annotations.h"
#include "base/macros.h"
#include "base/task_runner.h"
#include "base/threading/post_task_and_reply_impl.h"
#include "base/tracked_objects.h"

namespace base {

namespace {

class PostTaskAndReplyWorkerPool : public internal::PostTaskAndReplyImpl {
 public:
  explicit PostTaskAndReplyWorkerPool(bool task_is_slow)
      : task_is_slow_(task_is_slow) {
  }
  ~PostTaskAndReplyWorkerPool() override = default;

 private:
  bool PostTask(const tracked_objects::Location& from_here,
                OnceClosure task) override {
    return WorkerPool::PostTask(from_here, std::move(task), task_is_slow_);
  }

  bool task_is_slow_;
};

// WorkerPoolTaskRunner ---------------------------------------------
// A TaskRunner which posts tasks to a WorkerPool with a
// fixed ShutdownBehavior.
//
// Note that this class is RefCountedThreadSafe (inherited from TaskRunner).
class WorkerPoolTaskRunner : public TaskRunner {
 public:
  explicit WorkerPoolTaskRunner(bool tasks_are_slow);

  // TaskRunner implementation
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure task,
                       TimeDelta delay) override;
  bool RunsTasksInCurrentSequence() const override;

 private:
  ~WorkerPoolTaskRunner() override;

  // Helper function for posting a delayed task. Asserts that the delay is
  // zero because non-zero delays are not supported.
  bool PostDelayedTaskAssertZeroDelay(
      const tracked_objects::Location& from_here,
      OnceClosure task,
      base::TimeDelta delay);

  const bool tasks_are_slow_;

  DISALLOW_COPY_AND_ASSIGN(WorkerPoolTaskRunner);
};

WorkerPoolTaskRunner::WorkerPoolTaskRunner(bool tasks_are_slow)
    : tasks_are_slow_(tasks_are_slow) {
}

WorkerPoolTaskRunner::~WorkerPoolTaskRunner() {
}

bool WorkerPoolTaskRunner::PostDelayedTask(
    const tracked_objects::Location& from_here,
    OnceClosure task,
    TimeDelta delay) {
  return PostDelayedTaskAssertZeroDelay(from_here, std::move(task), delay);
}

bool WorkerPoolTaskRunner::RunsTasksInCurrentSequence() const {
  return WorkerPool::RunsTasksOnCurrentThread();
}

bool WorkerPoolTaskRunner::PostDelayedTaskAssertZeroDelay(
    const tracked_objects::Location& from_here,
    OnceClosure task,
    base::TimeDelta delay) {
  DCHECK_EQ(delay.InMillisecondsRoundedUp(), 0)
      << "WorkerPoolTaskRunner does not support non-zero delays";
  return WorkerPool::PostTask(from_here, std::move(task), tasks_are_slow_);
}

struct TaskRunnerHolder {
  TaskRunnerHolder() {
    taskrunners_[0] = new WorkerPoolTaskRunner(false);
    taskrunners_[1] = new WorkerPoolTaskRunner(true);
  }
  scoped_refptr<TaskRunner> taskrunners_[2];
};

}  // namespace

bool WorkerPool::PostTaskAndReply(const tracked_objects::Location& from_here,
                                  OnceClosure task,
                                  OnceClosure reply,
                                  bool task_is_slow) {
  // Do not report PostTaskAndReplyRelay leaks in tests. There's nothing we can
  // do about them because WorkerPool doesn't have a flushing API.
  // http://crbug.com/248513
  // http://crbug.com/290897
  // Note: this annotation does not cover tasks posted through a TaskRunner.
  ANNOTATE_SCOPED_MEMORY_LEAK;
  return PostTaskAndReplyWorkerPool(task_is_slow)
      .PostTaskAndReply(from_here, std::move(task), std::move(reply));
}

// static
const scoped_refptr<TaskRunner>&
WorkerPool::GetTaskRunner(bool tasks_are_slow) {
  static auto* task_runner_holder = new TaskRunnerHolder();
  return task_runner_holder->taskrunners_[tasks_are_slow];
}

}  // namespace base
