// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/message_loop/message_pump_fuchsia.h"

#include <magenta/status.h>
#include <magenta/syscalls.h>

#include "base/auto_reset.h"
#include "base/logging.h"

namespace base {

MessagePumpFuchsia::MxHandleWatchController::MxHandleWatchController(
    const tracked_objects::Location& from_here)
    : created_from_location_(from_here) {}

MessagePumpFuchsia::MxHandleWatchController::~MxHandleWatchController() {
  if (!StopWatchingMxHandle())
    NOTREACHED();
}

bool MessagePumpFuchsia::MxHandleWatchController::StopWatchingMxHandle() {
  if (was_stopped_) {
    DCHECK(!*was_stopped_);
    *was_stopped_ = true;

    // |was_stopped_| points at a value stored on the stack, which will go out
    // of scope. MessagePumpFuchsia::Run() will reset it only if the value is
    // false. So we need to reset this pointer here as well, to make sure it's
    // not used again.
    was_stopped_ = nullptr;
  }

  if (!has_begun_)
    return true;

  has_begun_ = false;

  // If the pump is gone then there is nothing to cancel.
  if (!weak_pump_)
    return true;

  int result = mx_port_cancel(weak_pump_->port_.get(), handle_, wait_key());
  DLOG_IF(ERROR, result != MX_OK)
      << "mx_port_cancel(handle=" << handle_
      << ") failed: " << mx_status_get_string(result);

  return result == MX_OK;
}

void MessagePumpFuchsia::FdWatchController::OnMxHandleSignalled(
    mx_handle_t handle,
    mx_signals_t signals) {
  uint32_t events;
  __mxio_wait_end(io_, signals, &events);

  // Each |watcher_| callback we invoke may stop or delete |this|. The pump has
  // set |was_stopped_| to point to a safe location on the calling stack, so we
  // can use that to detect being stopped mid-callback and avoid doing further
  // work that would touch |this|.
  bool* was_stopped = was_stopped_;
  if (events & MXIO_EVT_WRITABLE)
    watcher_->OnFileCanWriteWithoutBlocking(fd_);
  if (!*was_stopped && (events & MXIO_EVT_READABLE))
    watcher_->OnFileCanReadWithoutBlocking(fd_);

  // Don't add additional work here without checking |*was_stopped_| again.
}

MessagePumpFuchsia::FdWatchController::FdWatchController(
    const tracked_objects::Location& from_here)
    : MxHandleWatchController(from_here) {}

MessagePumpFuchsia::FdWatchController::~FdWatchController() {
  if (!StopWatchingFileDescriptor())
    NOTREACHED();
}

bool MessagePumpFuchsia::FdWatchController::StopWatchingFileDescriptor() {
  bool success = StopWatchingMxHandle();
  if (io_) {
    __mxio_release(io_);
    io_ = nullptr;
  }
  return success;
}

MessagePumpFuchsia::MessagePumpFuchsia() : weak_factory_(this) {
  CHECK_EQ(MX_OK, mx_port_create(0, port_.receive()));
}

bool MessagePumpFuchsia::WatchFileDescriptor(int fd,
                                             bool persistent,
                                             int mode,
                                             FdWatchController* controller,
                                             FdWatcher* delegate) {
  DCHECK_GE(fd, 0);
  DCHECK(controller);
  DCHECK(delegate);

  if (!controller->StopWatchingFileDescriptor())
    NOTREACHED();

  controller->fd_ = fd;
  controller->watcher_ = delegate;

  DCHECK(!controller->io_);
  controller->io_ = __mxio_fd_to_io(fd);
  if (!controller->io_) {
    DLOG(ERROR) << "Failed to get IO for FD";
    return false;
  }

  switch (mode) {
    case WATCH_READ:
      controller->desired_events_ = MXIO_EVT_READABLE;
      break;
    case WATCH_WRITE:
      controller->desired_events_ = MXIO_EVT_WRITABLE;
      break;
    case WATCH_READ_WRITE:
      controller->desired_events_ = MXIO_EVT_READABLE | MXIO_EVT_WRITABLE;
      break;
    default:
      NOTREACHED() << "unexpected mode: " << mode;
      return false;
  }

  // Pass dummy |handle| and |signals| values to WatchMxHandle(). The real
  // values will be populated by FdWatchController::WaitBegin(), before actually
  // starting the wait operation.
  return WatchMxHandle(MX_HANDLE_INVALID, persistent, 1, controller,
                       controller);
}

bool MessagePumpFuchsia::FdWatchController::WaitBegin() {
  // Refresh the |handle_| and |desired_signals_| from the mxio for the fd.
  // Some types of mxio map read/write events to different signals depending on
  // their current state, so we must do this every time we begin to wait.
  __mxio_wait_begin(io_, desired_events_, &handle_, &desired_signals_);
  if (handle_ == MX_HANDLE_INVALID) {
    DLOG(ERROR) << "mxio_wait_begin failed";
    return false;
  }

  return MessagePumpFuchsia::MxHandleWatchController::WaitBegin();
}

bool MessagePumpFuchsia::WatchMxHandle(mx_handle_t handle,
                                       bool persistent,
                                       mx_signals_t signals,
                                       MxHandleWatchController* controller,
                                       MxHandleWatcher* delegate) {
  DCHECK_NE(0u, signals);
  DCHECK(controller);
  DCHECK(delegate);
  DCHECK(handle == MX_HANDLE_INVALID ||
         controller->handle_ == MX_HANDLE_INVALID ||
         handle == controller->handle_);

  if (!controller->StopWatchingMxHandle())
    NOTREACHED();

  controller->handle_ = handle;
  controller->persistent_ = persistent;
  controller->desired_signals_ = signals;
  controller->watcher_ = delegate;

  controller->weak_pump_ = weak_factory_.GetWeakPtr();

  return controller->WaitBegin();
}

bool MessagePumpFuchsia::MxHandleWatchController::WaitBegin() {
  DCHECK(!has_begun_);

  mx_status_t status =
      mx_object_wait_async(handle_, weak_pump_->port_.get(), wait_key(),
                           desired_signals_, MX_WAIT_ASYNC_ONCE);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_object_wait_async failed: "
                << mx_status_get_string(status)
                << " (port=" << weak_pump_->port_.get() << ")";
    return false;
  }

  has_begun_ = true;

  return true;
}

uint32_t MessagePumpFuchsia::MxHandleWatchController::WaitEnd(
    mx_signals_t signals) {
  DCHECK(has_begun_);

  has_begun_ = false;

  // |signals| can include other spurious things, in particular, that an fd
  // is writable, when we only asked to know when it was readable. In that
  // case, we don't want to call both the CanWrite and CanRead callback,
  // when the caller asked for only, for example, readable callbacks. So,
  // mask with the events that we actually wanted to know about.
  signals &= desired_signals_;
  return signals;
}

void MessagePumpFuchsia::Run(Delegate* delegate) {
  AutoReset<bool> auto_reset_keep_running(&keep_running_, true);

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
                             : delayed_work_time_.ToMXTime();
    mx_port_packet_t packet;

    const mx_status_t wait_status =
        mx_port_wait(port_.get(), deadline, &packet, 0);
    if (wait_status != MX_OK) {
      if (wait_status != MX_ERR_TIMED_OUT) {
        NOTREACHED() << "unexpected wait status: "
                     << mx_status_get_string(wait_status);
      }
      continue;
    }

    if (packet.type == MX_PKT_TYPE_SIGNAL_ONE) {
      // A watched fd caused the wakeup via mx_object_wait_async().
      DCHECK_EQ(MX_OK, packet.status);
      MxHandleWatchController* controller =
          reinterpret_cast<MxHandleWatchController*>(
              static_cast<uintptr_t>(packet.key));

      DCHECK_NE(0u, packet.signal.trigger & packet.signal.observed);

      mx_signals_t signals = controller->WaitEnd(packet.signal.observed);

      // In the case of a persistent Watch, the Watch may be stopped and
      // potentially deleted by the caller within the callback, in which case
      // |controller| should not be accessed again, and we mustn't continue the
      // watch. We check for this with a bool on the stack, which the Watch
      // receives a pointer to.
      bool controller_was_stopped = false;
      controller->was_stopped_ = &controller_was_stopped;

      controller->watcher_->OnMxHandleSignalled(controller->handle_, signals);

      if (!controller_was_stopped) {
        controller->was_stopped_ = nullptr;
        if (controller->persistent_)
          controller->WaitBegin();
      }
    } else {
      // Wakeup caused by ScheduleWork().
      DCHECK_EQ(MX_PKT_TYPE_USER, packet.type);
    }
  }
}

void MessagePumpFuchsia::Quit() {
  keep_running_ = false;
}

void MessagePumpFuchsia::ScheduleWork() {
  // Since this can be called on any thread, we need to ensure that our Run loop
  // wakes up.
  mx_port_packet_t packet = {};
  packet.type = MX_PKT_TYPE_USER;
  mx_status_t status = mx_port_queue(port_.get(), &packet, 0);
  DLOG_IF(ERROR, status != MX_OK)
      << "mx_port_queue failed: " << status << " (port=" << port_.get() << ")";
}

void MessagePumpFuchsia::ScheduleDelayedWork(
    const TimeTicks& delayed_work_time) {
  // We know that we can't be blocked right now since this method can only be
  // called on the same thread as Run, so we only need to update our record of
  // how long to sleep when we do sleep.
  delayed_work_time_ = delayed_work_time;
}

}  // namespace base
