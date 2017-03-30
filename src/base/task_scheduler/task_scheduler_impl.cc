// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_scheduler_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_single_thread_task_runner_manager.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/sequence_sort_key.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_tracker.h"
#include "build/build_config.h"

#if defined(OS_POSIX) && !defined(OS_NACL_SFI)
#include "base/task_scheduler/task_tracker_posix.h"
#endif

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

void AddAugmentedSchedulerWorkerPoolParamsToVector(
    EnvironmentType environment_type,
    const std::string& task_scheduler_name,
    const SchedulerWorkerPoolParams& params,
    std::vector<SchedulerWorkerPoolParams>*
        scheduler_worker_pool_params_vector) {
  DCHECK_EQ(static_cast<size_t>(environment_type),
            scheduler_worker_pool_params_vector->size());
  scheduler_worker_pool_params_vector->emplace_back(
      task_scheduler_name + kEnvironmentParams[environment_type].name_suffix,
      kEnvironmentParams[environment_type].priority_hint,
      params.standby_thread_policy(), params.max_threads(),
      params.suggested_reclaim_time(), params.backward_compatibility());
}

}  // namespace

// static
std::unique_ptr<TaskSchedulerImpl> TaskSchedulerImpl::Create(
    const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector,
    const WorkerPoolIndexForTraitsCallback&
        worker_pool_index_for_traits_callback) {
  std::unique_ptr<TaskSchedulerImpl> scheduler(
      new TaskSchedulerImpl(worker_pool_index_for_traits_callback));
  scheduler->Initialize(worker_pool_params_vector);
  return scheduler;
}

// static
std::unique_ptr<TaskSchedulerImpl> TaskSchedulerImpl::Create(
    const std::string& name,
    const TaskScheduler::InitParams& init_params) {
  // Create a vector of SchedulerWorkerPoolParams using names and priority hints
  // derived from |kEnvironmentParams| and other params from |init_params|.
  std::vector<SchedulerWorkerPoolParams> worker_pool_params_vector;
  AddAugmentedSchedulerWorkerPoolParamsToVector(
      BACKGROUND, name, init_params.background_worker_pool_params,
      &worker_pool_params_vector);
  AddAugmentedSchedulerWorkerPoolParamsToVector(
      BACKGROUND_BLOCKING, name,
      init_params.background_blocking_worker_pool_params,
      &worker_pool_params_vector);
  AddAugmentedSchedulerWorkerPoolParamsToVector(
      FOREGROUND, name, init_params.foreground_worker_pool_params,
      &worker_pool_params_vector);
  AddAugmentedSchedulerWorkerPoolParamsToVector(
      FOREGROUND_BLOCKING, name,
      init_params.foreground_blocking_worker_pool_params,
      &worker_pool_params_vector);
  DCHECK_EQ(static_cast<size_t>(ENVIRONMENT_COUNT),
            worker_pool_params_vector.size());

  return Create(worker_pool_params_vector, Bind(&GetEnvironmentIndexForTraits));
}

TaskSchedulerImpl::~TaskSchedulerImpl() {
#if DCHECK_IS_ON()
  DCHECK(join_for_testing_returned_.IsSet());
#endif
}

void TaskSchedulerImpl::PostDelayedTaskWithTraits(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    Closure task,
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
    const TaskTraits& traits) {
  return single_thread_task_runner_manager_
      ->CreateSingleThreadTaskRunnerWithTraits(traits);
}

#if defined(OS_WIN)
scoped_refptr<SingleThreadTaskRunner>
TaskSchedulerImpl::CreateCOMSTATaskRunnerWithTraits(const TaskTraits& traits) {
  return single_thread_task_runner_manager_->CreateCOMSTATaskRunnerWithTraits(
      traits);
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
  DCHECK(task_tracker_);
  task_tracker_->Shutdown();
}

void TaskSchedulerImpl::FlushForTesting() {
  DCHECK(task_tracker_);
  task_tracker_->Flush();
}

void TaskSchedulerImpl::JoinForTesting() {
#if DCHECK_IS_ON()
  DCHECK(!join_for_testing_returned_.IsSet());
#endif
  single_thread_task_runner_manager_->JoinForTesting();
  for (const auto& worker_pool : worker_pools_)
    worker_pool->DisallowWorkerDetachmentForTesting();
  for (const auto& worker_pool : worker_pools_)
    worker_pool->JoinForTesting();
  service_thread_.Stop();
#if DCHECK_IS_ON()
  join_for_testing_returned_.Set();
#endif
}

TaskSchedulerImpl::TaskSchedulerImpl(const WorkerPoolIndexForTraitsCallback&
                                         worker_pool_index_for_traits_callback)
    : service_thread_("TaskSchedulerServiceThread"),
      worker_pool_index_for_traits_callback_(
          worker_pool_index_for_traits_callback) {
  DCHECK(!worker_pool_index_for_traits_callback_.is_null());
}

void TaskSchedulerImpl::Initialize(
    const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector) {
  DCHECK(!worker_pool_params_vector.empty());

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

  // Instantiate TaskTracker. Needs to happen after starting the service thread
  // to get its message_loop().
  task_tracker_ =
#if defined(OS_POSIX) && !defined(OS_NACL_SFI)
      base::MakeUnique<TaskTrackerPosix>(
          static_cast<MessageLoopForIO*>(service_thread_.message_loop()));
#else
      base::MakeUnique<TaskTracker>();
#endif

  // Instantiate DelayedTaskManager. Needs to happen after starting the service
  // thread to get its task_runner().
  delayed_task_manager_ =
      base::MakeUnique<DelayedTaskManager>(service_thread_.task_runner());

  single_thread_task_runner_manager_ =
      MakeUnique<SchedulerSingleThreadTaskRunnerManager>(
          worker_pool_params_vector, worker_pool_index_for_traits_callback_,
          task_tracker_.get(), delayed_task_manager_.get());

  // Callback invoked by workers to re-enqueue a sequence in the appropriate
  // PriorityQueue.
  const SchedulerWorkerPoolImpl::ReEnqueueSequenceCallback
      re_enqueue_sequence_callback =
          Bind(&TaskSchedulerImpl::ReEnqueueSequenceCallback, Unretained(this));

  // Start worker pools.
  for (const auto& worker_pool_params : worker_pool_params_vector) {
    // Passing pointers to objects owned by |this| to
    // SchedulerWorkerPoolImpl::Create() is safe because a TaskSchedulerImpl
    // can't be deleted before all its worker pools have been joined.
    worker_pools_.push_back(SchedulerWorkerPoolImpl::Create(
        worker_pool_params, re_enqueue_sequence_callback, task_tracker_.get(),
        delayed_task_manager_.get()));
    CHECK(worker_pools_.back());
  }
}

SchedulerWorkerPoolImpl* TaskSchedulerImpl::GetWorkerPoolForTraits(
    const TaskTraits& traits) const {
  const size_t index = worker_pool_index_for_traits_callback_.Run(traits);
  DCHECK_LT(index, worker_pools_.size());
  return worker_pools_[index].get();
}

void TaskSchedulerImpl::ReEnqueueSequenceCallback(
    scoped_refptr<Sequence> sequence) {
  DCHECK(sequence);

  const SequenceSortKey sort_key = sequence->GetSortKey();

  // The next task in |sequence| should run in a worker pool suited for its
  // traits, except for the priority which is adjusted to the highest priority
  // in |sequence|.
  const TaskTraits traits =
      sequence->PeekTaskTraits().WithPriority(sort_key.priority());

  GetWorkerPoolForTraits(traits)->ReEnqueueSequence(std::move(sequence),
                                                    sort_key);
}

}  // namespace internal
}  // namespace base
