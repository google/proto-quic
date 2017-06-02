// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_
#define BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_

#include "base/location.h"
#include "base/macros.h"
#include "base/message_loop/message_pump.h"
#include "base/synchronization/waitable_event.h"

namespace base {

class MessagePumpFuchsia : public MessagePump {
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
    const tracked_objects::Location created_from_location_;

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

  // Used to sleep until there is more work to do.
  WaitableEvent event_;

  // The time at which we should call DoDelayedWork.
  TimeTicks delayed_work_time_;

  DISALLOW_COPY_AND_ASSIGN(MessagePumpFuchsia);
};

}  // namespace base

#endif  // BASE_MESSAGE_LOOP_MESSAGE_PUMP_FUCHSIA_H_
