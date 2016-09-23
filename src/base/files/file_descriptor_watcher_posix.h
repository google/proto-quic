// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_FILES_FILE_DESCRIPTOR_WATCHER_POSIX_H_
#define BASE_FILES_FILE_DESCRIPTOR_WATCHER_POSIX_H_

#include <memory>

#include "base/base_export.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/message_loop/message_loop.h"
#include "base/sequence_checker.h"

namespace base {

class SingleThreadTaskRunner;

// The FileDescriptorWatcher API allows callbacks to be invoked when file
// descriptors are readable or writable without blocking.
class BASE_EXPORT FileDescriptorWatcher {
 public:
  // Instantiated and returned by WatchReadable() or WatchWritable(). The
  // constructor registers a callback to be invoked when a file descriptor is
  // readable or writable without blocking and the destructor unregisters it.
  class Controller {
   public:
    // Unregisters the callback registered by the constructor.
    ~Controller();

   private:
    friend class FileDescriptorWatcher;
    class Watcher;

    // Registers |callback| to be invoked when |fd| is readable or writable
    // without blocking (depending on |mode|).
    Controller(MessageLoopForIO::Mode mode, int fd, const Closure& callback);

    // Starts watching the file descriptor.
    void StartWatching();

    // Runs |callback_|.
    void RunCallback();

    // The callback to run when the watched file descriptor is readable or
    // writable without blocking.
    Closure callback_;

    // TaskRunner associated with the MessageLoopForIO that watches the file
    // descriptor.
    const scoped_refptr<SingleThreadTaskRunner>
        message_loop_for_io_task_runner_;

    // Notified by the MessageLoopForIO associated with
    // |message_loop_for_io_task_runner_| when the watched file descriptor is
    // readable or writable without blocking. Posts a task to run RunCallback()
    // on the sequence on which the Controller was instantiated. When the
    // Controller is deleted, ownership of |watcher_| is transfered to a delete
    // task posted to the MessageLoopForIO. This ensures that |watcher_| isn't
    // deleted while it is being used by the MessageLoopForIO.
    std::unique_ptr<Watcher> watcher_;

    // Validates that the Controller is used on the sequence on which it was
    // instantiated.
    SequenceChecker sequence_checker_;

    WeakPtrFactory<Controller> weak_factory_;

    DISALLOW_COPY_AND_ASSIGN(Controller);
  };

  // Registers |message_loop_for_io| to watch file descriptors for which
  // callbacks are registered from the current thread via WatchReadable() or
  // WatchWritable(). |message_loop_for_io| may run on another thread. The
  // constructed FileDescriptorWatcher must not outlive |message_loop_for_io|.
  FileDescriptorWatcher(MessageLoopForIO* message_loop_for_io);
  ~FileDescriptorWatcher();

  // Registers |callback| to be invoked on the current sequence when |fd| is
  // readable or writable without blocking. |callback| is unregistered when the
  // returned Controller is deleted (deletion must happen on the current
  // sequence). To call these methods, a FileDescriptorWatcher must have been
  // instantiated on the current thread and SequencedTaskRunnerHandle::IsSet()
  // must return true.
  static std::unique_ptr<Controller> WatchReadable(int fd,
                                                   const Closure& callback);
  static std::unique_ptr<Controller> WatchWritable(int fd,
                                                   const Closure& callback);

 private:
  DISALLOW_COPY_AND_ASSIGN(FileDescriptorWatcher);
};

}  // namespace base

#endif  // BASE_FILES_FILE_DESCRIPTOR_WATCHER_POSIX_H_
