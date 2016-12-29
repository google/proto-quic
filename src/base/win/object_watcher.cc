// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/win/object_watcher.h"

#include "base/bind.h"
#include "base/logging.h"
#include "base/threading/sequenced_task_runner_handle.h"

namespace base {
namespace win {

//-----------------------------------------------------------------------------

ObjectWatcher::ObjectWatcher() : weak_factory_(this) {}

ObjectWatcher::~ObjectWatcher() {
  StopWatching();
}

bool ObjectWatcher::StartWatchingOnce(HANDLE object, Delegate* delegate) {
  return StartWatchingInternal(object, delegate, true);
}

bool ObjectWatcher::StartWatchingMultipleTimes(HANDLE object,
                                               Delegate* delegate) {
  return StartWatchingInternal(object, delegate, false);
}

bool ObjectWatcher::StopWatching() {
  if (!wait_object_)
    return false;

  // Make sure ObjectWatcher is used in a sequenced fashion.
  DCHECK(task_runner_->RunsTasksOnCurrentThread());

  // Blocking call to cancel the wait. Any callbacks already in progress will
  // finish before we return from this call.
  if (!UnregisterWaitEx(wait_object_, INVALID_HANDLE_VALUE)) {
    DPLOG(FATAL) << "UnregisterWaitEx failed";
    return false;
  }

  Reset();
  return true;
}

bool ObjectWatcher::IsWatching() const {
  return object_ != nullptr;
}

HANDLE ObjectWatcher::GetWatchedObject() const {
  return object_;
}

// static
void CALLBACK ObjectWatcher::DoneWaiting(void* param, BOOLEAN timed_out) {
  DCHECK(!timed_out);

  // The destructor blocks on any callbacks that are in flight, so we know that
  // that is always a pointer to a valid ObjectWater.
  ObjectWatcher* that = static_cast<ObjectWatcher*>(param);
  that->task_runner_->PostTask(FROM_HERE, that->callback_);
  if (that->run_once_)
    that->callback_.Reset();
}

bool ObjectWatcher::StartWatchingInternal(HANDLE object, Delegate* delegate,
                                          bool execute_only_once) {
  DCHECK(delegate);
  DCHECK(!wait_object_) << "Already watching an object";
  DCHECK(SequencedTaskRunnerHandle::IsSet());

  task_runner_ = SequencedTaskRunnerHandle::Get();

  run_once_ = execute_only_once;

  // Since our job is to just notice when an object is signaled and report the
  // result back to this sequence, we can just run on a Windows wait thread.
  DWORD wait_flags = WT_EXECUTEINWAITTHREAD;
  if (run_once_)
    wait_flags |= WT_EXECUTEONLYONCE;

  // DoneWaiting can be synchronously called from RegisterWaitForSingleObject,
  // so set up all state now.
  callback_ =
      Bind(&ObjectWatcher::Signal, weak_factory_.GetWeakPtr(), delegate);
  object_ = object;

  if (!RegisterWaitForSingleObject(&wait_object_, object, DoneWaiting,
                                   this, INFINITE, wait_flags)) {
    DPLOG(FATAL) << "RegisterWaitForSingleObject failed";
    Reset();
    return false;
  }

  return true;
}

void ObjectWatcher::Signal(Delegate* delegate) {
  // Signaling the delegate may result in our destruction or a nested call to
  // StartWatching(). As a result, we save any state we need and clear previous
  // watcher state before signaling the delegate.
  HANDLE object = object_;
  if (run_once_)
    StopWatching();
  delegate->OnObjectSignaled(object);
}

void ObjectWatcher::Reset() {
  callback_.Reset();
  object_ = nullptr;
  wait_object_ = nullptr;
  task_runner_ = nullptr;
  run_once_ = true;
  weak_factory_.InvalidateWeakPtrs();
}

}  // namespace win
}  // namespace base
