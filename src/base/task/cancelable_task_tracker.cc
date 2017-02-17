// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task/cancelable_task_tracker.h"

#include <stddef.h>

#include <utility>

#include "base/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/cancellation_flag.h"
#include "base/task_runner.h"
#include "base/threading/sequenced_task_runner_handle.h"

namespace base {

namespace {

void RunIfNotCanceled(const CancellationFlag* flag, const Closure& task) {
  if (!flag->IsSet())
    task.Run();
}

void RunIfNotCanceledThenUntrack(const CancellationFlag* flag,
                                 const Closure& task,
                                 const Closure& untrack) {
  RunIfNotCanceled(flag, task);
  untrack.Run();
}

bool IsCanceled(const CancellationFlag* flag,
                base::ScopedClosureRunner* cleanup_runner) {
  return flag->IsSet();
}

void RunAndDeleteFlag(const Closure& closure, const CancellationFlag* flag) {
  closure.Run();
  delete flag;
}

void RunOrPostToTaskRunner(TaskRunner* task_runner, const Closure& closure) {
  if (task_runner->RunsTasksOnCurrentThread())
    closure.Run();
  else
    task_runner->PostTask(FROM_HERE, closure);
}

}  // namespace

// static
const CancelableTaskTracker::TaskId CancelableTaskTracker::kBadTaskId = 0;

CancelableTaskTracker::CancelableTaskTracker()
    : next_id_(1),weak_factory_(this) {}

CancelableTaskTracker::~CancelableTaskTracker() {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  TryCancelAll();
}

CancelableTaskTracker::TaskId CancelableTaskTracker::PostTask(
    TaskRunner* task_runner,
    const tracked_objects::Location& from_here,
    const Closure& task) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  return PostTaskAndReply(task_runner, from_here, task, Bind(&base::DoNothing));
}

CancelableTaskTracker::TaskId CancelableTaskTracker::PostTaskAndReply(
    TaskRunner* task_runner,
    const tracked_objects::Location& from_here,
    Closure task,
    Closure reply) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  // We need a SequencedTaskRunnerHandle to run |reply|.
  DCHECK(base::SequencedTaskRunnerHandle::IsSet());

  // Owned by reply callback below.
  CancellationFlag* flag = new CancellationFlag();

  TaskId id = next_id_;
  next_id_++;  // int64_t is big enough that we ignore the potential overflow.

  Closure untrack_closure =
      Bind(&CancelableTaskTracker::Untrack, weak_factory_.GetWeakPtr(), id);
  bool success = task_runner->PostTaskAndReply(
      from_here, Bind(&RunIfNotCanceled, flag, std::move(task)),
      Bind(&RunIfNotCanceledThenUntrack, base::Owned(flag), std::move(reply),
           std::move(untrack_closure)));

  if (!success)
    return kBadTaskId;

  Track(id, flag);
  return id;
}

CancelableTaskTracker::TaskId CancelableTaskTracker::NewTrackedTaskId(
    IsCanceledCallback* is_canceled_cb) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  DCHECK(base::SequencedTaskRunnerHandle::IsSet());

  TaskId id = next_id_;
  next_id_++;  // int64_t is big enough that we ignore the potential overflow.

  // Will be deleted by |untrack_and_delete_flag| after Untrack().
  CancellationFlag* flag = new CancellationFlag();

  Closure untrack_and_delete_flag = Bind(
      &RunAndDeleteFlag,
      Bind(&CancelableTaskTracker::Untrack, weak_factory_.GetWeakPtr(), id),
      flag);

  // Will always run |untrack_and_delete_flag| on current sequence.
  base::ScopedClosureRunner* untrack_and_delete_flag_runner =
      new base::ScopedClosureRunner(
          Bind(&RunOrPostToTaskRunner,
               RetainedRef(base::SequencedTaskRunnerHandle::Get()),
               untrack_and_delete_flag));

  *is_canceled_cb =
      Bind(&IsCanceled, flag, base::Owned(untrack_and_delete_flag_runner));

  Track(id, flag);
  return id;
}

void CancelableTaskTracker::TryCancel(TaskId id) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  hash_map<TaskId, CancellationFlag*>::const_iterator it = task_flags_.find(id);
  if (it == task_flags_.end()) {
    // Two possibilities:
    //
    //   1. The task has already been untracked.
    //   2. The TaskId is bad or unknown.
    //
    // Since this function is best-effort, it's OK to ignore these.
    return;
  }
  it->second->Set();
}

void CancelableTaskTracker::TryCancelAll() {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  for (hash_map<TaskId, CancellationFlag*>::const_iterator it =
           task_flags_.begin();
       it != task_flags_.end();
       ++it) {
    it->second->Set();
  }
}

bool CancelableTaskTracker::HasTrackedTasks() const {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  return !task_flags_.empty();
}

void CancelableTaskTracker::Track(TaskId id, CancellationFlag* flag) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  bool success = task_flags_.insert(std::make_pair(id, flag)).second;
  DCHECK(success);
}

void CancelableTaskTracker::Untrack(TaskId id) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  size_t num = task_flags_.erase(id);
  DCHECK_EQ(1u, num);
}

}  // namespace base
