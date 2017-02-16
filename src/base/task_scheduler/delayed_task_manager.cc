// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/delayed_task_manager.h"

#include <utility>

#include "base/bind.h"
#include "base/logging.h"
#include "base/task_runner.h"
#include "base/task_scheduler/task.h"

namespace base {
namespace internal {

DelayedTaskManager::DelayedTaskManager(
    scoped_refptr<TaskRunner> service_thread_task_runner)
    : service_thread_task_runner_(std::move(service_thread_task_runner)) {
  DCHECK(service_thread_task_runner_);
}

DelayedTaskManager::~DelayedTaskManager() = default;

void DelayedTaskManager::AddDelayedTask(
    std::unique_ptr<Task> task,
    const PostTaskNowCallback& post_task_now_callback) {
  DCHECK(task);

  const TimeDelta delay = task->delay;
  DCHECK(!delay.is_zero());

  // TODO(fdoray): Use |task->delayed_run_time| on the service thread
  // MessageLoop rather than recomputing it from |delay|.
  service_thread_task_runner_->PostDelayedTask(
      FROM_HERE, Bind(post_task_now_callback, Passed(std::move(task))), delay);
}

}  // namespace internal
}  // namespace base
