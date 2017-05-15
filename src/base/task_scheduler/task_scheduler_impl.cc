// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_scheduler_impl.h"

#include <utility>

#include "base/memory/ptr_util.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/sequence_sort_key.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_tracker.h"

namespace base {
namespace internal {

namespace {

enum EnvironmentType {
  BACKGROUND = 0,
  BACKGROUND_BLOCKING,
  FOREGROUND,
  FOREGROUND_BLOCKING,
  ENVIRONMENT_COUNT  // Always last.
};

// Order must match the EnvironmentType enum.
constexpr struct {
  // The threads and histograms of this environment will be labeled with
  // the task scheduler name concatenated to this.
  const char* name_suffix;

  // Preferred priority for threads in this environment; the actual thread
  // priority depends on shutdown state and platform capabilities.
  ThreadPriority priority_hint;
} kEnvironmentParams[] = {
    {"Background", base::ThreadPriority::BACKGROUND},
    {"BackgroundBlocking", base::ThreadPriority::BACKGROUND},
    {"Foreground", base::ThreadPriority::NORMAL},
    {"ForegroundBlocking", base::ThreadPriority::NORMAL},
};

size_t GetEnvironmentIndexForTraits(const TaskTraits& traits) {
  const bool is_background =
      traits.priority() == base::TaskPriority::BACKGROUND;
  if (traits.may_block() || traits.with_base_sync_primitives())
    return is_background ? BACKGROUND_BLOCKING : FOREGROUND_BLOCKING;
  return is_background ? BACKGROUND : FOREGROUND;
}

}  // namespace

TaskSchedulerImpl::TaskSchedulerImpl(StringPiece name)
    : name_(name),
      service_thread_("TaskSchedulerServiceThread"),
      single_thread_task_runner_manager_(&task_tracker_,
                                         &delayed_task_manager_) {
  static_assert(arraysize(worker_pools_) == ENVIRONMENT_COUNT,
                "The size of |worker_pools_| must match ENVIRONMENT_COUNT.");
  static_assert(
      arraysize(kEnvironmentParams) == ENVIRONMENT_COUNT,
      "The size of |kEnvironmentParams| must match ENVIRONMENT_COUNT.");

  for (int environment_type = 0; environment_type < ENVIRONMENT_COUNT;
       ++environment_type) {
    worker_pools_[environment_type] = MakeUnique<SchedulerWorkerPoolImpl>(
        name_ + kEnvironmentParams[environment_type].name_suffix,
        kEnvironmentParams[environment_type].priority_hint, &task_tracker_,
        &delayed_task_manager_);
  }
}

TaskSchedulerImpl::~TaskSchedulerImpl() {
#if DCHECK_IS_ON()
  DCHECK(join_for_testing_returned_.IsSet());
#endif
}

void TaskSchedulerImpl::Start(const TaskScheduler::InitParams& init_params) {
  // Start the service thread. On platforms that support it (POSIX except NaCL
  // SFI), the service thread runs a MessageLoopForIO which is used to support
  // FileDescriptorWatcher in the scope in which tasks run.
  Thread::Options service_thread_options;
  service_thread_options.message_loop_type =
#if defined(OS_POSIX) && !defined(OS_NACL_SFI)
      MessageLoop::TYPE_IO;
#else
      MessageLoop::TYPE_DEFAULT;
#endif
  service_thread_options.timer_slack = TIMER_SLACK_MAXIMUM;
  CHECK(service_thread_.StartWithOptions(service_thread_options));

#if defined(OS_POSIX) && !defined(OS_NACL_SFI)
  // Needs to happen after starting the service thread to get its
  // message_loop().
  task_tracker_.set_watch_file_descriptor_message_loop(
      static_cast<MessageLoopForIO*>(service_thread_.message_loop()));

#if DCHECK_IS_ON()
  task_tracker_.set_service_thread_handle(service_thread_.GetThreadHandle());
#endif  // DCHECK_IS_ON()
#endif  // defined(OS_POSIX) && !defined(OS_NACL_SFI)

  // Needs to happen after starting the service thread to get its task_runner().
  delayed_task_manager_.Start(service_thread_.task_runner());

  single_thread_task_runner_manager_.Start();

  worker_pools_[BACKGROUND]->Start(init_params.background_worker_pool_params);
  worker_pools_[BACKGROUND_BLOCKING]->Start(
      init_params.background_blocking_worker_pool_params);
  worker_pools_[FOREGROUND]->Start(init_params.foreground_worker_pool_params);
  worker_pools_[FOREGROUND_BLOCKING]->Start(
      init_params.foreground_blocking_worker_pool_params);
}

void TaskSchedulerImpl::PostDelayedTaskWithTraits(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    OnceClosure task,
    TimeDelta delay) {
  // Post |task| as part of a one-off single-task Sequence.
  GetWorkerPoolForTraits(traits)->PostTaskWithSequence(
      MakeUnique<Task>(from_here, std::move(task), traits, delay),
      make_scoped_refptr(new Sequence));
}

scoped_refptr<TaskRunner> TaskSchedulerImpl::CreateTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return GetWorkerPoolForTraits(traits)->CreateTaskRunnerWithTraits(traits);
}

scoped_refptr<SequencedTaskRunner>
TaskSchedulerImpl::CreateSequencedTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return GetWorkerPoolForTraits(traits)->CreateSequencedTaskRunnerWithTraits(
      traits);
}

scoped_refptr<SingleThreadTaskRunner>
TaskSchedulerImpl::CreateSingleThreadTaskRunnerWithTraits(
    const TaskTraits& traits,
    SingleThreadTaskRunnerThreadMode thread_mode) {
  const auto& environment_params =
      kEnvironmentParams[GetEnvironmentIndexForTraits(traits)];
  return single_thread_task_runner_manager_
      .CreateSingleThreadTaskRunnerWithTraits(
          name_ + environment_params.name_suffix,
          environment_params.priority_hint, traits);
}

#if defined(OS_WIN)
scoped_refptr<SingleThreadTaskRunner>
TaskSchedulerImpl::CreateCOMSTATaskRunnerWithTraits(
    const TaskTraits& traits,
    SingleThreadTaskRunnerThreadMode thread_mode) {
  const auto& environment_params =
      kEnvironmentParams[GetEnvironmentIndexForTraits(traits)];
  return single_thread_task_runner_manager_.CreateCOMSTATaskRunnerWithTraits(
      environment_params.name_suffix, environment_params.priority_hint, traits);
}
#endif  // defined(OS_WIN)

std::vector<const HistogramBase*> TaskSchedulerImpl::GetHistograms() const {
  std::vector<const HistogramBase*> histograms;
  for (const auto& worker_pool : worker_pools_)
    worker_pool->GetHistograms(&histograms);

  return histograms;
}

int TaskSchedulerImpl::GetMaxConcurrentTasksWithTraitsDeprecated(
    const TaskTraits& traits) const {
  return GetWorkerPoolForTraits(traits)->GetMaxConcurrentTasksDeprecated();
}

void TaskSchedulerImpl::Shutdown() {
  // TODO(fdoray): Increase the priority of BACKGROUND tasks blocking shutdown.
  task_tracker_.Shutdown();
}

void TaskSchedulerImpl::FlushForTesting() {
  task_tracker_.Flush();
}

void TaskSchedulerImpl::JoinForTesting() {
#if DCHECK_IS_ON()
  DCHECK(!join_for_testing_returned_.IsSet());
#endif
  single_thread_task_runner_manager_.JoinForTesting();
  for (const auto& worker_pool : worker_pools_)
    worker_pool->DisallowWorkerDetachmentForTesting();
  for (const auto& worker_pool : worker_pools_)
    worker_pool->JoinForTesting();
  service_thread_.Stop();
#if DCHECK_IS_ON()
  join_for_testing_returned_.Set();
#endif
}

SchedulerWorkerPoolImpl* TaskSchedulerImpl::GetWorkerPoolForTraits(
    const TaskTraits& traits) const {
  return worker_pools_[GetEnvironmentIndexForTraits(traits)].get();
}

}  // namespace internal
}  // namespace base
