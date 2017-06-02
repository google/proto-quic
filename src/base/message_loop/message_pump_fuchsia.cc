// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/message_loop/message_pump_fuchsia.h"

#include "base/logging.h"

namespace base {

MessagePumpFuchsia::FileDescriptorWatcher::FileDescriptorWatcher(
    const tracked_objects::Location& from_here)
    : created_from_location_(from_here) {
  NOTIMPLEMENTED();
}

MessagePumpFuchsia::FileDescriptorWatcher::~FileDescriptorWatcher() {}

bool MessagePumpFuchsia::FileDescriptorWatcher::StopWatchingFileDescriptor() {
  NOTIMPLEMENTED();
  return false;
}

MessagePumpFuchsia::MessagePumpFuchsia()
    : keep_running_(true),
      event_(WaitableEvent::ResetPolicy::AUTOMATIC,
             WaitableEvent::InitialState::NOT_SIGNALED) {}

MessagePumpFuchsia::~MessagePumpFuchsia() {}

bool MessagePumpFuchsia::WatchFileDescriptor(int fd,
                                             bool persistent,
                                             int mode,
                                             FileDescriptorWatcher* controller,
                                             Watcher* delegate) {
  NOTIMPLEMENTED();
  return false;
}

void MessagePumpFuchsia::Run(Delegate* delegate) {
  DCHECK(keep_running_);

  for (;;) {
    bool did_work = delegate->DoWork();
    if (!keep_running_)
      break;

    did_work |= delegate->DoDelayedWork(&delayed_work_time_);
    if (!keep_running_)
      break;

    if (did_work)
      continue;

    did_work = delegate->DoIdleWork();
    if (!keep_running_)
      break;

    if (did_work)
      continue;

    if (delayed_work_time_.is_null()) {
      event_.Wait();
    } else {
      // No need to handle already expired |delayed_work_time_| in any special
      // way. When |delayed_work_time_| is in the past TimeWaitUntil returns
      // promptly and |delayed_work_time_| will re-initialized on a next
      // DoDelayedWork call which has to be called in order to get here again.
      event_.TimedWaitUntil(delayed_work_time_);
    }

    // TODO(fuchsia): Handle file descriptor watching here. (maybe?)
  }

  keep_running_ = true;
}

void MessagePumpFuchsia::Quit() {
  keep_running_ = false;
}

void MessagePumpFuchsia::ScheduleWork() {
  // Since this can be called on any thread, we need to ensure that our Run
  // loop wakes up.
  event_.Signal();
}

void MessagePumpFuchsia::ScheduleDelayedWork(
    const TimeTicks& delayed_work_time) {
  // We know that we can't be blocked on Wait right now since this method can
  // only be called on the same thread as Run, so we only need to update our
  // record of how long to sleep when we do sleep.
  delayed_work_time_ = delayed_work_time;
}

}  // namespace base
