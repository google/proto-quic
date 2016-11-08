// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Tool to log the execution of the process (Chrome). Writes logs containing
// time and address of the callback being called for the first time.
//
// For performance reasons logs are buffered. Every thread has its own buffer
// and log file so the contention between threads is minimal. As a side-effect,
// functions called might be mentioned in many thread logs.
//
// A special thread is created in the process to periodically flush logs for all
// threads in case the thread had stopped before flushing its logs.
//
// Also note that the instrumentation code is self-activated. It begins to
// record the log data when it is called first, including the run-time startup.
// Have it in mind when modifying it, in particular do not use global objects
// with constructors as they are called during startup (too late for us).

#ifndef TOOLS_CYGPROFILE_CYGPROFILE_H_
#define TOOLS_CYGPROFILE_CYGPROFILE_H_

#include <sys/time.h>
#include <sys/types.h>

#include <memory>
#include <vector>

#include "base/callback.h"
#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "build/build_config.h"

#if !defined(OS_ANDROID)
// This is only supported on Android thanks to the fact that on Android
// processes (other than the system's zygote) don't fork.
//
// To make cygprofile truly work (i.e. without any deadlock) on Chrome
// platforms that use fork(), cygprofile.cc should be written in a way that
// guarantees that:
// - No lock is acquired by a foreign thread during fork(). In particular this
// means that cygprofile.cc should not perform any heap allocation (since heap
// allocators, including TCMalloc generally use locks).
// - Only cygprofile.cc uses pthread_atfork() in the whole process. Unlike POSIX
// signals, pthread_atfork() doesn't provide a way to install multiple handlers.
// Calling pthread_atfork() in cygprofile.cc would override any handler that
// could have been installed previously.
//
// Chrome happens to violate the first requirement at least once by having its
// process launcher thread fork. However the child process in that case, when
// it's not instrumented with cygprofile, directly calls exec(). This is safe
// since the child process doesn't try to release a lock acquired by another
// thread in the parent process which would lead to a deadlock. This problem was
// actually observed by trying to port the current version of cygprofile.cc to
// Linux.
#error This is only supported on Android.
#endif

// The following is only exposed for testing.
namespace cygprofile {

class Thread;

// Single log entry recorded for each function call.
struct LogEntry {
  LogEntry(const void* address);

  const timespec time;
  const pid_t pid;
  const pid_t tid;
  const void* const address;
};

// Per-thread function calls log.
class ThreadLog {
 public:
  // Callback invoked for flushing that can be provided for testing.
  typedef base::Callback<void (std::vector<LogEntry>*)> FlushCallback;

  ThreadLog();

  // Used for testing.
  ThreadLog(const FlushCallback& flush_callback);

  ~ThreadLog();

  // Must only be called from the thread this ThreadLog instance is watching.
  void AddEntry(void* address);

  // Can be called from any thread.
  void TakeEntries(std::vector<LogEntry>* output);

  // Flushes the provided vector of entries to a file and clears it. Note that
  // this can be called from any thread.
  void Flush(std::vector<LogEntry>* entries) const;

 private:
  // Default implementation (that can be overridden for testing) of the method
  // above.
  void FlushInternal(std::vector<LogEntry>* entries) const;

  // Thread identifier as Linux kernel shows it.  LWP (light-weight process) is
  // a unique ID of the thread in the system, unlike pthread_self() which is the
  // same for fork()-ed threads.
  const pid_t tid_;

  // Current thread is inside the instrumentation routine.
  bool in_use_;

  // Callback used to flush entries.
  const FlushCallback flush_callback_;

  // Keeps track of all functions that have been logged on this thread so we do
  // not record duplicates.
  base::hash_set<void*> called_functions_;

  // A lock that guards |entries_| usage between per-thread instrumentation
  // routine and timer flush callback. So the contention could happen only
  // during the flush, every 15 secs.
  base::Lock lock_;

  std::vector<LogEntry> entries_;

  DISALLOW_COPY_AND_ASSIGN(ThreadLog);
};

// Manages a list of per-thread logs.
class ThreadLogsManager {
 public:
  ThreadLogsManager();

  // Used for testing. The provided callbacks are used for testing to
  // synchronize the internal thread with the unit test running on the main
  // thread.
  ThreadLogsManager(const base::Closure& wait_callback,
                    const base::Closure& notify_callback);

  ~ThreadLogsManager();

  // Can be called from any thread.
  void AddLog(std::unique_ptr<ThreadLog> new_log);

 private:
  void StartInternalFlushThread_Locked();

  // Flush thread's entry point.
  void FlushAllLogsOnFlushThread();

  // Used to make the internal thread sleep before each flush iteration.
  const base::Closure wait_callback_;
  // Used to trigger a notification when a flush happened on the internal
  // thread.
  const base::Closure notify_callback_;

  // Protects the state below.
  base::Lock lock_;
  std::unique_ptr<Thread> flush_thread_;
  std::vector<std::unique_ptr<ThreadLog>> logs_;

  DISALLOW_COPY_AND_ASSIGN(ThreadLogsManager);
};

}  // namespace cygprofile

#endif  // TOOLS_CYGPROFILE_CYGPROFILE_H_
