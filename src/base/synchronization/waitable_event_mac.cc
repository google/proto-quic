// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/waitable_event.h"

#include <sys/event.h>

#include <vector>

#include "base/debug/activity_tracker.h"
#include "base/logging.h"
#include "base/posix/eintr_wrapper.h"
#include "base/threading/thread_restrictions.h"

namespace base {

WaitableEvent::WaitableEvent(ResetPolicy reset_policy,
                             InitialState initial_state)
    : kqueue_(kqueue()) {
  PCHECK(kqueue_.is_valid()) << "kqueue";
  uint16_t flags = EV_ADD;

  if (reset_policy == ResetPolicy::AUTOMATIC)
    flags |= EV_CLEAR;

  // The initial event registration.
  PostEvent(flags, 0);

  if (initial_state == InitialState::SIGNALED)
    Signal();
}

WaitableEvent::~WaitableEvent() = default;

void WaitableEvent::Reset() {
  PostEvent(EV_DISABLE, 0);
}

void WaitableEvent::Signal() {
  PostEvent(EV_ENABLE, NOTE_TRIGGER);
}

bool WaitableEvent::IsSignaled() {
  // TODO(rsesek): Use KEVENT_FLAG_IMMEDIATE rather than an empty timeout.
  timespec ts{};
  kevent64_s event;
  int rv = kevent64(kqueue_.get(), nullptr, 0, &event, 1, 0, &ts);
  PCHECK(rv >= 0) << "kevent64 IsSignaled";
  return rv > 0;
}

void WaitableEvent::Wait() {
  bool result = TimedWaitUntil(TimeTicks::Max());
  DCHECK(result) << "TimedWait() should never fail with infinite timeout";
}

bool WaitableEvent::TimedWait(const TimeDelta& wait_delta) {
  return TimedWaitUntil(TimeTicks::Now() + wait_delta);
}

bool WaitableEvent::TimedWaitUntil(const TimeTicks& end_time) {
  ThreadRestrictions::AssertWaitAllowed();
  // Record the event that this thread is blocking upon (for hang diagnosis).
  debug::ScopedEventWaitActivity event_activity(this);

  bool indefinite = end_time.is_max();

  int rv = 0;

  do {
    TimeDelta wait_time = end_time - TimeTicks::Now();
    if (wait_time < TimeDelta()) {
      // A negative delta would be treated by the system as indefinite, but
      // it needs to be treated as a poll instead.
      wait_time = TimeDelta();
    }

    timespec timeout = wait_time.ToTimeSpec();

    // This does not use HANDLE_EINTR, since retrying the syscall requires
    // adjusting the timeout to account for time already waited.
    kevent64_s event;
    rv = kevent64(kqueue_.get(), nullptr, 0, &event, 1, 0,
                  indefinite ? nullptr : &timeout);
  } while (rv < 0 && errno == EINTR);

  PCHECK(rv >= 0) << "kevent64 TimedWait";
  return rv > 0;
}

// static
size_t WaitableEvent::WaitMany(WaitableEvent** raw_waitables, size_t count) {
  ThreadRestrictions::AssertWaitAllowed();
  DCHECK(count) << "Cannot wait on no events";

  // Record an event (the first) that this thread is blocking upon.
  debug::ScopedEventWaitActivity event_activity(raw_waitables[0]);

  std::vector<kevent64_s> events(count);
  for (size_t i = 0; i < count; ++i) {
    EV_SET64(&events[i], raw_waitables[i]->kqueue_.get(), EVFILT_READ,
             EV_ADD | EV_CLEAR, 0, 0, i, 0, 0);
  }

  std::vector<kevent64_s> out_events(count);

  ScopedFD wait_many(kqueue());
  PCHECK(wait_many.is_valid()) << "kqueue WaitMany";

  int rv = HANDLE_EINTR(kevent64(wait_many.get(), events.data(), count,
                                 out_events.data(), count, 0, nullptr));
  PCHECK(rv > 0) << "kevent64: WaitMany";

  size_t triggered = -1;
  for (size_t i = 0; i < static_cast<size_t>(rv); ++i) {
    // WaitMany should return the lowest index in |raw_waitables| that was
    // triggered.
    size_t index = static_cast<size_t>(out_events[i].udata);
    triggered = std::min(triggered, index);
  }

  // The WaitMany kevent has identified which kqueue was signaled. Trigger
  // a Wait on it to clear the event within WaitableEvent's kqueue. This
  // will not block, since it has been triggered.
  raw_waitables[triggered]->Wait();

  return triggered;
}

void WaitableEvent::PostEvent(uint16_t flags, uint32_t fflags) {
  kevent64_s event;
  EV_SET64(&event, reinterpret_cast<uint64_t>(this), EVFILT_USER, flags, fflags,
           0, 0, 0, 0);
  int rv =
      HANDLE_EINTR(kevent64(kqueue_.get(), &event, 1, nullptr, 0, 0, nullptr));
  PCHECK(rv == 0) << "kevent64";
}

}  // namespace base
