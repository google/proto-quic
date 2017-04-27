// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_SINGLE_THREAD_TASK_RUNNER_MANAGER_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_SINGLE_THREAD_TASK_RUNNER_MANAGER_H_

#include <memory>
#include <string>
#include <vector>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/threading/platform_thread.h"
#include "build/build_config.h"

namespace base {

class TaskTraits;
class SingleThreadTaskRunner;

namespace internal {

class DelayedTaskManager;
class SchedulerWorker;
class TaskTracker;

namespace {

class SchedulerWorkerDelegate;

}  // namespace

// Manages a pool of threads which are each associated with one
// SingleThreadTaskRunner.
//
// No threads are created (and hence no tasks can run) before Start() is called.
//
// This class is thread-safe.
class BASE_EXPORT SchedulerSingleThreadTaskRunnerManager final {
 public:
  SchedulerSingleThreadTaskRunnerManager(
      TaskTracker* task_tracker,
      DelayedTaskManager* delayed_task_manager);
  ~SchedulerSingleThreadTaskRunnerManager();

  // Starts threads for existing SingleThreadTaskRunners and allows threads to
  // be started when SingleThreadTaskRunners are created in the future.
  void Start();

  // Creates a SingleThreadTaskRunner which runs tasks with |traits| on a
  // dedicated thread named "TaskSchedulerSingleThread" + |name| +  index.
  // |priority_hint| is the preferred thread priority; the actual thread
  // priority depends on shutdown state and platform capabilities.
  scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
      const std::string& name,
      ThreadPriority priority_hint,
      const TaskTraits& traits);

#if defined(OS_WIN)
  // Creates a SingleThreadTaskRunner which runs tasks with |traits| on a
  // dedicated COM STA thread named "TaskSchedulerSingleThreadCOMSTA" + |name| +
  // index. |priority_hint| is the preferred thread priority; the actual thread
  // priority depends on shutdown state and platform capabilities.
  scoped_refptr<SingleThreadTaskRunner> CreateCOMSTATaskRunnerWithTraits(
      const std::string& name,
      ThreadPriority priority_hint,
      const TaskTraits& traits);
#endif  // defined(OS_WIN)

  void JoinForTesting();

 private:
  class SchedulerSingleThreadTaskRunner;

  template <typename DelegateType>
  scoped_refptr<SingleThreadTaskRunner>
  CreateSingleThreadTaskRunnerWithDelegate(const std::string& name,
                                           ThreadPriority priority_hint,
                                           const TaskTraits& traits);

  template <typename DelegateType>
  std::unique_ptr<SchedulerWorkerDelegate> CreateSchedulerWorkerDelegate(
      const std::string& name,
      int id);

  template <typename DelegateType>
  SchedulerWorker* CreateAndRegisterSchedulerWorker(
      const std::string& name,
      ThreadPriority priority_hint);

  void UnregisterSchedulerWorker(SchedulerWorker* worker);

  TaskTracker* const task_tracker_;
  DelayedTaskManager* const delayed_task_manager_;

  // Synchronizes access to |workers_|, |next_worker_id_| and |started_|.
  SchedulerLock lock_;
  std::vector<scoped_refptr<SchedulerWorker>> workers_;
  int next_worker_id_ = 0;

  // Set to true when Start() is called.
  bool started_ = false;

#if DCHECK_IS_ON()
  subtle::Atomic32 workers_unregistered_during_join_ = 0;
#endif

  DISALLOW_COPY_AND_ASSIGN(SchedulerSingleThreadTaskRunnerManager);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_SINGLE_THREAD_TASK_RUNNER_MANAGER_H_
