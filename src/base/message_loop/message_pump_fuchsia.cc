// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/message_loop/message_pump_fuchsia.h"

#include <magenta/syscalls.h>

#include "base/logging.h"

namespace base {

MessagePumpFuchsia::FileDescriptorWatcher::FileDescriptorWatcher(
    const tracked_objects::Location& from_here)
    : created_from_location_(from_here) {
}

MessagePumpFuchsia::FileDescriptorWatcher::~FileDescriptorWatcher() {
  StopWatchingFileDescriptor();
  if (io_)
    __mxio_release(io_);
  if (was_destroyed_) {
    DCHECK(!*was_destroyed_);
    *was_destroyed_ = true;
  }
}

bool MessagePumpFuchsia::FileDescriptorWatcher::StopWatchingFileDescriptor() {
  uint64_t controller_as_key =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(this));
  return mx_port_cancel(port_, handle_, controller_as_key) == MX_OK;
}

MessagePumpFuchsia::MessagePumpFuchsia() : keep_running_(true) {
  CHECK(mx_port_create(MX_PORT_OPT_V2, &port_) == MX_OK);
}

MessagePumpFuchsia::~MessagePumpFuchsia() {
  mx_status_t status = mx_handle_close(port_);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_handle_close failed: " << status;
  }
}

bool MessagePumpFuchsia::WatchFileDescriptor(int fd,
                                             bool persistent,
                                             int mode,
                                             FileDescriptorWatcher* controller,
                                             Watcher* delegate) {
  DCHECK_GE(fd, 0);
  DCHECK(controller);
  DCHECK(delegate);
  DCHECK(!persistent);  // TODO(fuchsia): Not yet implemented.
  DCHECK(mode == WATCH_READ || mode == WATCH_WRITE || mode == WATCH_READ_WRITE);

  uint32_t events;
  switch (mode) {
    case WATCH_READ:
      events = MXIO_EVT_READABLE;
      break;
    case WATCH_WRITE:
      events = MXIO_EVT_WRITABLE;
      break;
    case WATCH_READ_WRITE:
      events = MXIO_EVT_READABLE | MXIO_EVT_WRITABLE;
      break;
    default:
      DLOG(ERROR) << "unexpected mode: " << mode;
      return false;
  }

  controller->io_ = __mxio_fd_to_io(fd);
  if (!controller->io_)
    return false;

  controller->watcher_ = delegate;
  controller->fd_ = fd;
  controller->desired_events_ = events;

  uint32_t signals;
  __mxio_wait_begin(controller->io_, events, &controller->handle_, &signals);
  if (controller->handle_ == MX_HANDLE_INVALID)
    return false;
  controller->port_ = port_;

  uint64_t controller_as_key =
      static_cast<uint64_t>(reinterpret_cast<uintptr_t>(controller));
  mx_status_t status =
      mx_object_wait_async(controller->handle_, port_, controller_as_key,
                           signals, MX_WAIT_ASYNC_ONCE);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_object_wait_async failed: " << status;
    return false;
  }
  return true;
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

    mx_time_t deadline = delayed_work_time_.is_null()
                             ? MX_TIME_INFINITE
                             : mx_time_get(MX_CLOCK_MONOTONIC) +
                                   delayed_work_time_.ToInternalValue();
    mx_port_packet_t packet;
    const mx_status_t wait_status = mx_port_wait(port_, deadline, &packet, 0);
    if (wait_status != MX_OK && wait_status != MX_ERR_TIMED_OUT) {
      NOTREACHED() << "unexpected wait status: " << wait_status;
      continue;
    }

    if (packet.type == MX_PKT_TYPE_SIGNAL_ONE) {
      // A watched fd caused the wakeup via mx_object_wait_async().
      DCHECK(packet.status == MX_OK);
      FileDescriptorWatcher* controller =
          reinterpret_cast<FileDescriptorWatcher*>(
              static_cast<uintptr_t>(packet.key));

      DCHECK(packet.signal.trigger & packet.signal.observed);

      uint32_t events;
      __mxio_wait_end(controller->io_, packet.signal.observed, &events);
      // .observed can include other spurious things, in particular, that the fd
      // is writable, when we only asked to know when it was readable. In that
      // case, we don't want to call both the CanWrite and CanRead callback,
      // when the caller asked for only, for example, readable callbacks. So,
      // mask with the events that we actually wanted to know about.
      events &= controller->desired_events_;

      if ((events & (MXIO_EVT_READABLE | MXIO_EVT_WRITABLE)) ==
          (MXIO_EVT_READABLE | MXIO_EVT_WRITABLE)) {
        // Both callbacks to be called, must check controller destruction after
        // the first callback is run, which is done by letting the destructor
        // set a bool here (which is located on the stack). If it's set during
        // the first callback, then the controller was destroyed during the
        // first callback so we do not call the second one, as the controller
        // pointer is now invalid.
        bool controller_was_destroyed = false;
        controller->was_destroyed_ = &controller_was_destroyed;
        controller->watcher_->OnFileCanWriteWithoutBlocking(controller->fd_);
        if (!controller_was_destroyed)
          controller->watcher_->OnFileCanReadWithoutBlocking(controller->fd_);
        if (!controller_was_destroyed)
          controller->was_destroyed_ = nullptr;
      } else if (events & MXIO_EVT_WRITABLE) {
        controller->watcher_->OnFileCanWriteWithoutBlocking(controller->fd_);
      } else if (events & MXIO_EVT_READABLE) {
        controller->watcher_->OnFileCanReadWithoutBlocking(controller->fd_);
      }
    } else {
      // Wakeup caused by ScheduleWork().
      DCHECK(packet.type == MX_PKT_TYPE_USER);
    }
  }

  keep_running_ = true;
}

void MessagePumpFuchsia::Quit() {
  keep_running_ = false;
}

void MessagePumpFuchsia::ScheduleWork() {
  // Since this can be called on any thread, we need to ensure that our Run loop
  // wakes up.
  mx_port_packet_t packet = {};
  packet.type = MX_PKT_TYPE_USER;
  mx_status_t status = mx_port_queue(port_, &packet, 0);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_port_queue failed: " << status;
  }
}

void MessagePumpFuchsia::ScheduleDelayedWork(
    const TimeTicks& delayed_work_time) {
  // We know that we can't be blocked right now since this method can only be
  // called on the same thread as Run, so we only need to update our record of
  // how long to sleep when we do sleep.
  delayed_work_time_ = delayed_work_time;
}

}  // namespace base
