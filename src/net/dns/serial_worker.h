// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DNS_SERIAL_WORKER_H_
#define NET_DNS_SERIAL_WORKER_H_

#include <string>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"

// Forward declaration
namespace base {
class SingleThreadTaskRunner;
}

namespace net {

// SerialWorker executes a job on WorkerPool serially -- **once at a time**.
// On |WorkNow|, a call to |DoWork| is scheduled on the WorkerPool. Once it
// completes, |OnWorkFinished| is called on the origin thread.
// If |WorkNow| is called (1 or more times) while |DoWork| is already under way,
// |DoWork| will be called once: after current |DoWork| completes, before a
// call to |OnWorkFinished|.
//
// This behavior is designed for updating a result after some trigger, for
// example reading a file once FilePathWatcher indicates it changed.
//
// Derived classes should store results of work done in |DoWork| in dedicated
// fields and read them in |OnWorkFinished| which is executed on the origin
// thread. This avoids the need to template this class.
//
// This implementation avoids locking by using the |state_| member to ensure
// that |DoWork| and |OnWorkFinished| cannot execute in parallel.
//
// TODO(szym): update to WorkerPool::PostTaskAndReply once available.
class NET_EXPORT_PRIVATE SerialWorker
  : NON_EXPORTED_BASE(public base::RefCountedThreadSafe<SerialWorker>) {
 public:
  SerialWorker();

  // Unless already scheduled, post |DoWork| to WorkerPool.
  // Made virtual to allow mocking.
  virtual void WorkNow();

  // Stop scheduling jobs.
  void Cancel();

  bool IsCancelled() const { return state_ == CANCELLED; }

 protected:
  friend class base::RefCountedThreadSafe<SerialWorker>;
  // protected to allow sub-classing, but prevent deleting
  virtual ~SerialWorker();

  // Executed on WorkerPool, at most once at a time.
  virtual void DoWork() = 0;

  // Executed on origin thread after |DoRead| completes.
  virtual void OnWorkFinished() = 0;

  base::SingleThreadTaskRunner* loop() { return task_runner_.get(); }

 private:
  enum State {
    CANCELLED = -1,
    IDLE = 0,
    WORKING,  // |DoWorkJob| posted on WorkerPool, until |OnWorkJobFinished|
    PENDING,  // |WorkNow| while WORKING, must re-do work
    WAITING,  // WorkerPool is busy, |RetryWork| is posted
  };

  // Called on the worker thread, executes |DoWork| and notifies the origin
  // thread.
  void DoWorkJob();

  // Called on the the origin thread after |DoWork| completes.
  void OnWorkJobFinished();

  // Posted to message loop in case WorkerPool is busy. (state == WAITING)
  void RetryWork();

  // Task runner for the thread of origin.
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  State state_;

  DISALLOW_COPY_AND_ASSIGN(SerialWorker);
};

}  // namespace net

#endif  // NET_DNS_SERIAL_WORKER_H_

