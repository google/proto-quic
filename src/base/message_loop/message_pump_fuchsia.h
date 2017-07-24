// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_
#define BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_

#include "base/base_export.h"
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
  class Watcher {
   public:
    // Called from MessageLoop::Run when an FD can be read from/written to
    // without blocking
    virtual void OnFileCanReadWithoutBlocking(int fd) = 0;
    virtual void OnFileCanWriteWithoutBlocking(int fd) = 0;

   protected:
    virtual ~Watcher() {}
  };

  // Object returned by WatchFileDescriptor to manage further watching.
  class FileDescriptorWatcher {
   public:
    explicit FileDescriptorWatcher(const tracked_objects::Location& from_here);
    ~FileDescriptorWatcher();  // Implicitly calls StopWatchingFileDescriptor.

    // Stop watching the FD, always safe to call.  No-op if there's nothing
    // to do.
    bool StopWatchingFileDescriptor();

    const tracked_objects::Location& created_from_location() {
      return created_from_location_;
    }

   private:
    friend class MessagePumpFuchsia;

    // Start watching the FD.
    bool WaitBegin();

    // Stop watching the FD. Returns the set of events the watcher is interested
    // in based on the observed bits from the underlying packet.
    uint32_t WaitEnd(uint32_t observed);

    // Returns the key to use to uniquely identify this object's wait operation.
    uint64_t wait_key() const {
      return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(this));
    }

    const tracked_objects::Location created_from_location_;

    // Set directly from the inputs to WatchFileDescriptor.
    Watcher* watcher_ = nullptr;
    int fd_ = -1;
    uint32_t desired_events_ = 0;

    // Set by WatchFileDescriptor to hold a reference to the descriptor's mxio.
    mxio_t* io_ = nullptr;

    // Set to the mxio's waitable handle, while a wait is pending (i.e. between
    // WaitBegin and WaitEnd calls), and MX_HANDLE_INVALID otherwise.
    mx_handle_t handle_ = MX_HANDLE_INVALID;

    // Used to safely access resources owned by the associated message pump.
    WeakPtr<MessagePumpFuchsia> weak_pump_;

    // This bool is used during calling |Watcher| callbacks. This object's
    // lifetime is owned by the user of this class. If the message loop is woken
    // up in the case where it needs to call both the readable and writable
    // callbacks, we need to take care not to call the second one if this object
    // is destroyed by the first one. The bool points to the stack, and is set
    // to true in ~FileDescriptorWatcher() to handle this case.
    bool* was_destroyed_ = nullptr;

    // A watch may be marked as persistent, which means it remains active even
    // after triggering.
    bool persistent_ = false;

    DISALLOW_COPY_AND_ASSIGN(FileDescriptorWatcher);
  };

  enum Mode {
    WATCH_READ = 1 << 0,
    WATCH_WRITE = 1 << 1,
    WATCH_READ_WRITE = WATCH_READ | WATCH_WRITE
  };

  MessagePumpFuchsia();
  ~MessagePumpFuchsia() override;

  bool WatchFileDescriptor(int fd,
                           bool persistent,
                           int mode,
                           FileDescriptorWatcher* controller,
                           Watcher* delegate);

  // MessagePump implementation:
  void Run(Delegate* delegate) override;
  void Quit() override;
  void ScheduleWork() override;
  void ScheduleDelayedWork(const TimeTicks& delayed_work_time) override;

 private:
  // This flag is set to false when Run should return.
  bool keep_running_;

  mx_handle_t port_;

  // The time at which we should call DoDelayedWork.
  TimeTicks delayed_work_time_;

  base::WeakPtrFactory<MessagePumpFuchsia> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(MessagePumpFuchsia);
};

}  // namespace base

#endif  // BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_
