// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_mock_time_message_loop_task_runner.h"

#include <deque>

#include "base/bind.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/test/test_pending_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"

namespace base {
namespace {

void RunOnceClosure(OnceClosure closure) {
  std::move(closure).Run();
}

}  // namespace

ScopedMockTimeMessageLoopTaskRunner::ScopedMockTimeMessageLoopTaskRunner()
    : task_runner_(new TestMockTimeTaskRunner),
      previous_task_runner_(ThreadTaskRunnerHandle::Get()) {
  DCHECK(MessageLoop::current());
  // To ensure that we process any initialization tasks posted to the
  // MessageLoop by a test fixture before replacing its TaskRunner.
  RunLoop().RunUntilIdle();
  MessageLoop::current()->SetTaskRunner(task_runner_);
}

ScopedMockTimeMessageLoopTaskRunner::~ScopedMockTimeMessageLoopTaskRunner() {
  DCHECK(previous_task_runner_->RunsTasksOnCurrentThread());
  DCHECK_EQ(task_runner_, ThreadTaskRunnerHandle::Get());
  for (auto& pending_task : task_runner_->TakePendingTasks()) {
    // TODO(tzik): Remove RunOnceClosure once TaskRunner migrates from Closure
    // to OnceClosure.
    previous_task_runner_->PostDelayedTask(
        pending_task.location,
        BindOnce(&RunOnceClosure, Passed(&pending_task.task)),
        pending_task.GetTimeToRun() - task_runner_->NowTicks());
  }
  MessageLoop::current()->SetTaskRunner(std::move(previous_task_runner_));
}

}  // namespace base
