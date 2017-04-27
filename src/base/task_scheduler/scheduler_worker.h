// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_WORKER_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_WORKER_H_

#include <memory>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/atomic_flag.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/scheduler_worker_params.h"
#include "base/task_scheduler/sequence.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"

namespace base {
namespace internal {

class TaskTracker;

// A worker that manages a single thread to run Tasks from Sequences returned
// by a delegate.
//
// A SchedulerWorker starts out sleeping. It is woken up by a call to WakeUp().
// After a wake-up, a SchedulerWorker runs Tasks from Sequences returned by the
// GetWork() method of its delegate as long as it doesn't return nullptr. It
// also periodically checks with its TaskTracker whether shutdown has completed
// and exits when it has.
//
// The worker is free to release and reallocate the platform thread with
// guidance from the delegate.
//
// This class is thread-safe.
class BASE_EXPORT SchedulerWorker
    : public RefCountedThreadSafe<SchedulerWorker> {
 public:
  // Delegate interface for SchedulerWorker. The methods are always called from
  // the thread managed by the SchedulerWorker instance.
  class BASE_EXPORT Delegate {
   public:
    virtual ~Delegate() = default;

    // Called by a thread managed by |worker| when it enters its main function.
    // If a thread is recreated after detachment, |detach_duration| is the time
    // elapsed since detachment. Otherwise, if this is the first thread created
    // for |worker|, |detach_duration| is TimeDelta::Max().
    virtual void OnMainEntry(SchedulerWorker* worker) = 0;

    // Called by a thread managed by |worker| to get a Sequence from which to
    // run a Task.
    virtual scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) = 0;

    // Called by the SchedulerWorker after it ran a task.
    virtual void DidRunTask() = 0;

    // Called when |sequence| isn't empty after the SchedulerWorker pops a Task
    // from it. |sequence| is the last Sequence returned by GetWork().
    virtual void ReEnqueueSequence(scoped_refptr<Sequence> sequence) = 0;

    // Called by a thread to determine how long to sleep before the next call to
    // GetWork(). GetWork() may be called before this timeout expires if the
    // worker's WakeUp() method is called.
    virtual TimeDelta GetSleepTimeout() = 0;

    // Called by a thread to wait for work. Override this method if the thread
    // in question needs special handling to go to sleep. |wake_up_event| is a
    // manually resettable event and is signaled on SchedulerWorker::WakeUp()
    virtual void WaitForWork(WaitableEvent* wake_up_event);

    // Called by a thread if it is allowed to detach if the last call to
    // GetWork() returned nullptr.
    //
    // It is the responsibility of the delegate to determine if detachment is
    // safe. If the delegate is responsible for thread-affine work, detachment
    // is generally not safe.
    //
    // When true is returned:
    // - The next WakeUp() could be more costly due to new thread creation.
    // - The worker will take this as a signal that it can detach, but it is not
    //   obligated to do so.
    virtual bool CanDetach(SchedulerWorker* worker) = 0;

    // Called by a thread before it detaches. This method is not allowed to
    // acquire a SchedulerLock because it is called within the scope of another
    // SchedulerLock.
    virtual void OnDetach() = 0;

    // Called by a thread right before the main function exits.
    virtual void OnMainExit() {}
  };

  enum class InitialState { ALIVE, DETACHED };

  // Creates a SchedulerWorker that runs Tasks from Sequences returned by
  // |delegate|. No actual thread will be created for this SchedulerWorker
  // before Start() is called. |priority_hint| is the preferred thread priority;
  // the actual thread priority depends on shutdown state and platform
  // capabilities. |task_tracker| is used to handle shutdown behavior of Tasks.
  // |backward_compatibility| indicates whether backward compatibility is
  // enabled. |initial_state| determines whether the thread is created in
  // Start() or in the first WakeUp() after Start(). Either JoinForTesting() or
  // Cleanup() must be called before releasing the last external reference.
  SchedulerWorker(ThreadPriority priority_hint,
                  std::unique_ptr<Delegate> delegate,
                  TaskTracker* task_tracker,
                  SchedulerBackwardCompatibility backward_compatibility =
                      SchedulerBackwardCompatibility::DISABLED,
                  InitialState initial_state = InitialState::ALIVE);

  // Allows this SchedulerWorker to be backed by a thread. If
  // InitialState::ALIVE was passed to the constructor and Cleanup() wasn't
  // called, a thread is created immediately (in a wait state pending a WakeUp()
  // call). If InitialState::DETACHED was passed to the constructor and
  // Cleanup() wasn't called, creation is delayed until the next WakeUp(). No
  // thread will be created if Cleanup() was called. Returns true on success.
  bool Start();

  // Wakes up this SchedulerWorker if it wasn't already awake. After this is
  // called, this SchedulerWorker will run Tasks from Sequences returned by the
  // GetWork() method of its delegate until it returns nullptr. WakeUp() may
  // fail if the worker is detached and it fails to allocate a new worker. If
  // this happens, there will be no call to GetWork(). No-op if Start() wasn't
  // called.
  void WakeUp();

  SchedulerWorker::Delegate* delegate() { return delegate_.get(); }

  // Joins this SchedulerWorker. If a Task is already running, it will be
  // allowed to complete its execution. This can only be called once.
  //
  // Note: A thread that detaches before JoinForTesting() is called may still be
  // running after JoinForTesting() returns. However, it can't run tasks after
  // JoinForTesting() returns.
  void JoinForTesting();

  // Returns true if the worker is alive.
  bool ThreadAliveForTesting() const;

  // Makes a request to cleanup the worker. This may be called from any thread.
  // The caller is expected to release its reference to this object after
  // calling Cleanup(). Further method calls after Cleanup() returns are
  // undefined.
  //
  // Expected Usage:
  //   scoped_refptr<SchedulerWorker> worker_ = /* Existing Worker */
  //   worker_->Cleanup();
  //   worker_ = nullptr;
  void Cleanup();

 private:
  friend class RefCountedThreadSafe<SchedulerWorker>;
  class Thread;
  enum class DetachNotify {
    // Do not notify any component.
    SILENT,
    // Notify the delegate.
    DELEGATE,
  };

  ~SchedulerWorker();

  // Returns ownership of the thread instance when appropriate so that it can be
  // freed upon termination of the thread. If ownership transfer is not
  // possible, returns nullptr.
  std::unique_ptr<SchedulerWorker::Thread> DetachThreadObject(
      DetachNotify detach_notify);

  void CreateThread();
  bool ShouldExit();

  // Synchronizes access to |thread_| (read+write), |started_| (read+write) and
  // |should_exit_| (write-only). See Cleanup() for details.
  mutable SchedulerLock thread_lock_;

  // The underlying thread for this SchedulerWorker.
  // The thread object will be cleaned up by the running thread unless we join
  // against the thread. Joining requires the thread object to remain alive for
  // the Thread::Join() call.
  std::unique_ptr<Thread> thread_;

  bool started_ = false;
  AtomicFlag should_exit_;

  const ThreadPriority priority_hint_;

  const std::unique_ptr<Delegate> delegate_;
  TaskTracker* const task_tracker_;

#if defined(OS_WIN)
  const SchedulerBackwardCompatibility backward_compatibility_;
#endif

  const InitialState initial_state_;

  // Set once JoinForTesting() has been called.
  AtomicFlag join_called_for_testing_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorker);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_WORKER_H_
