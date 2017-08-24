// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_
#define BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_

#include "base/base_export.h"
#include "base/fuchsia/scoped_mx_handle.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/message_loop/message_pump.h"

#include <magenta/syscalls/port.h>
#include <mxio/io.h>
#include <mxio/private.h>

namespace base {

class BASE_EXPORT MessagePumpFuchsia : public MessagePump {
 public:
  // Implemented by callers to receive notifications of handle & fd events.
  class MxHandleWatcher {
   public:
    virtual void OnMxHandleSignalled(mx_handle_t handle,
                                     mx_signals_t signals) = 0;

   protected:
    virtual ~MxHandleWatcher() {}
  };

  class FdWatcher {
   public:
    virtual void OnFileCanReadWithoutBlocking(int fd) = 0;
    virtual void OnFileCanWriteWithoutBlocking(int fd) = 0;
   protected:
    virtual ~FdWatcher() {}
  };

  // Manages an active watch on an mx_handle_t.
  class MxHandleWatchController {
   public:
    explicit MxHandleWatchController(
        const tracked_objects::Location& from_here);
    // Deleting the Controller implicitly calls StopWatchingMxHandle.
    virtual ~MxHandleWatchController();

    // Stop watching the handle, always safe to call.  No-op if there's nothing
    // to do.
    bool StopWatchingMxHandle();

    const tracked_objects::Location& created_from_location() {
      return created_from_location_;
    }

   protected:
    // This bool is used by the pump when invoking the MxHandleWatcher callback,
    // and by the FdHandleWatchController when invoking read & write callbacks,
    // to cope with the possibility of the caller deleting the *Watcher within
    // the callback. The pump sets |was_stopped_| to a location on the stack,
    // and the Watcher writes to it, if set, when deleted, allowing the pump
    // to check the value on the stack to short-cut any post-callback work.
    bool* was_stopped_ = nullptr;

   protected:
    friend class MessagePumpFuchsia;

    // Start watching the handle.
    virtual bool WaitBegin();

    // Called by MessagePumpFuchsia when the handle is signalled. Accepts the
    // set of signals that fired, and returns the intersection with those the
    // caller is interested in.
    mx_signals_t WaitEnd(mx_signals_t observed);

    // Returns the key to use to uniquely identify this object's wait operation.
    uint64_t wait_key() const {
      return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(this));
    }

    const tracked_objects::Location created_from_location_;

    // Set directly from the inputs to WatchFileDescriptor.
    MxHandleWatcher* watcher_ = nullptr;
    mx_handle_t handle_ = MX_HANDLE_INVALID;
    mx_signals_t desired_signals_ = 0;

    // Used to safely access resources owned by the associated message pump.
    WeakPtr<MessagePumpFuchsia> weak_pump_;

    // A watch may be marked as persistent, which means it remains active even
    // after triggering.
    bool persistent_ = false;

    // Used to determine whether an asynchronous wait operation is active on
    // this controller.
    bool has_begun_ = false;

    DISALLOW_COPY_AND_ASSIGN(MxHandleWatchController);
  };

  // Object returned by WatchFileDescriptor to manage further watching.
  class FdWatchController : public MxHandleWatchController,
                            public MxHandleWatcher {
   public:
    explicit FdWatchController(const tracked_objects::Location& from_here);
    ~FdWatchController() override;

    bool StopWatchingFileDescriptor();

   private:
    friend class MessagePumpFuchsia;

    // Determines the desires signals, and begins waiting on the handle.
    bool WaitBegin() override;

    // MxHandleWatcher interface.
    void OnMxHandleSignalled(mx_handle_t handle, mx_signals_t signals) override;

    // Set directly from the inputs to WatchFileDescriptor.
    FdWatcher* watcher_ = nullptr;
    int fd_ = -1;
    uint32_t desired_events_ = 0;

    // Set by WatchFileDescriptor to hold a reference to the descriptor's mxio.
    mxio_t* io_ = nullptr;

    DISALLOW_COPY_AND_ASSIGN(FdWatchController);
  };

  enum Mode {
    WATCH_READ = 1 << 0,
    WATCH_WRITE = 1 << 1,
    WATCH_READ_WRITE = WATCH_READ | WATCH_WRITE
  };

  MessagePumpFuchsia();

  bool WatchMxHandle(mx_handle_t handle,
                     bool persistent,
                     mx_signals_t signals,
                     MxHandleWatchController* controller,
                     MxHandleWatcher* delegate);
  bool WatchFileDescriptor(int fd,
                           bool persistent,
                           int mode,
                           FdWatchController* controller,
                           FdWatcher* delegate);

  // MessagePump implementation:
  void Run(Delegate* delegate) override;
  void Quit() override;
  void ScheduleWork() override;
  void ScheduleDelayedWork(const TimeTicks& delayed_work_time) override;

 private:
  // This flag is set to false when Run should return.
  bool keep_running_ = true;

  ScopedMxHandle port_;

  // The time at which we should call DoDelayedWork.
  TimeTicks delayed_work_time_;

  base::WeakPtrFactory<MessagePumpFuchsia> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(MessagePumpFuchsia);
};

}  // namespace base

#endif  // BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_
