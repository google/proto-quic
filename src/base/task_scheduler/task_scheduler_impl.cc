// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_scheduler_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/task_scheduler/delayed_task_manager.h"
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

TaskSchedulerImpl::~TaskSchedulerImpl() {
#if DCHECK_IS_ON()
  DCHECK(join_for_testing_returned_.IsSet());
#endif
}

void TaskSchedulerImpl::PostDelayedTaskWithTraits(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    const Closure& task,
    TimeDelta delay) {
  // Post |task| as part of a one-off single-task Sequence.
  GetWorkerPoolForTraits(traits)->PostTaskWithSequence(
      MakeUnique<Task>(from_here, task, traits, delay),
      make_scoped_refptr(new Sequence), nullptr);
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
  return GetWorkerPoolForTraits(traits)->CreateSingleThreadTaskRunnerWithTraits(
      traits);
}

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
