// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/blockfile/in_flight_io.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/profiler/scoped_tracker.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/trace_event.h"

namespace disk_cache {

BackgroundIO::BackgroundIO(InFlightIO* controller)
    : result_(-1),
      io_completed_(base::WaitableEvent::ResetPolicy::MANUAL,
                    base::WaitableEvent::InitialState::NOT_SIGNALED),
      controller_(controller) {}

// Runs on the primary thread.
void BackgroundIO::OnIOSignalled() {
  // TODO(pkasting): Remove ScopedTracker below once crbug.com/477117 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION("477117 BackgroundIO::OnIOSignalled"));
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("net"), "BackgroundIO::OnIOSignalled");
  if (controller_)
    controller_->InvokeCallback(this, false);
}

void BackgroundIO::Cancel() {
  // controller_ may be in use from the background thread at this time.
  base::AutoLock lock(controller_lock_);
  DCHECK(controller_);
  controller_ = NULL;
}

BackgroundIO::~BackgroundIO() {
}

// ---------------------------------------------------------------------------

InFlightIO::InFlightIO()
    : callback_task_runner_(base::ThreadTaskRunnerHandle::Get()),
      running_(false) {}

InFlightIO::~InFlightIO() {
}

// Runs on the background thread.
void BackgroundIO::NotifyController() {
  base::AutoLock lock(controller_lock_);
  if (controller_)
    controller_->OnIOComplete(this);
}

void InFlightIO::WaitForPendingIO() {
  while (!io_list_.empty()) {
    // Block the current thread until all pending IO completes.
    IOList::iterator it = io_list_.begin();
    InvokeCallback(it->get(), true);
  }
}

void InFlightIO::DropPendingIO() {
  while (!io_list_.empty()) {
    IOList::iterator it = io_list_.begin();
    BackgroundIO* operation = it->get();
    operation->Cancel();
    DCHECK(io_list_.find(operation) != io_list_.end());
    io_list_.erase(make_scoped_refptr(operation));
  }
}

// Runs on a background thread.
void InFlightIO::OnIOComplete(BackgroundIO* operation) {
#if DCHECK_IS_ON()
  if (callback_task_runner_->RunsTasksOnCurrentThread()) {
    DCHECK(single_thread_ || !running_);
    single_thread_ = true;
  }
#endif

  callback_task_runner_->PostTask(
      FROM_HERE, base::Bind(&BackgroundIO::OnIOSignalled, operation));
  operation->io_completed()->Signal();
}

// Runs on the primary thread.
void InFlightIO::InvokeCallback(BackgroundIO* operation, bool cancel_task) {
  {
    // http://crbug.com/74623
    base::ThreadRestrictions::ScopedAllowWait allow_wait;
    operation->io_completed()->Wait();
  }
  running_ = true;

  if (cancel_task)
    operation->Cancel();

  // Make sure that we remove the operation from the list before invoking the
  // callback (so that a subsequent cancel does not invoke the callback again).
  DCHECK(io_list_.find(operation) != io_list_.end());
  DCHECK(!operation->HasOneRef());
  io_list_.erase(make_scoped_refptr(operation));
  OnOperationComplete(operation, cancel_task);
}

// Runs on the primary thread.
void InFlightIO::OnOperationPosted(BackgroundIO* operation) {
  DCHECK(callback_task_runner_->RunsTasksOnCurrentThread());
  io_list_.insert(make_scoped_refptr(operation));
}

}  // namespace disk_cache
