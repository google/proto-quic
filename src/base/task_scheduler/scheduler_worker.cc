// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker.h"

#include <stddef.h>

#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/task_scheduler/task_tracker.h"

#if defined(OS_MACOSX)
#include "base/mac/scoped_nsautorelease_pool.h"
#elif defined(OS_WIN)
#include "base/win/scoped_com_initializer.h"
#endif

namespace base {
namespace internal {

class SchedulerWorker::Thread : public PlatformThread::Delegate {
 public:
  ~Thread() override = default;

  static std::unique_ptr<Thread> Create(scoped_refptr<SchedulerWorker> outer) {
    std::unique_ptr<Thread> thread(new Thread(std::move(outer)));
    thread->Initialize();
    if (thread->thread_handle_.is_null())
      return nullptr;
    return thread;
  }

  // PlatformThread::Delegate.
  void ThreadMain() override {
    // Set if this thread was detached.
    std::unique_ptr<Thread> detached_thread;

    outer_->delegate_->OnMainEntry(outer_.get());

    // A SchedulerWorker starts out waiting for work.
    outer_->delegate_->WaitForWork(&wake_up_event_);

#if defined(OS_WIN)
    std::unique_ptr<win::ScopedCOMInitializer> com_initializer;
    if (outer_->backward_compatibility_ ==
        SchedulerBackwardCompatibility::INIT_COM_STA) {
      com_initializer = MakeUnique<win::ScopedCOMInitializer>();
    }
#endif

    while (!outer_->ShouldExit()) {
      DCHECK(outer_);

#if defined(OS_MACOSX)
      mac::ScopedNSAutoreleasePool autorelease_pool;
#endif

      UpdateThreadPriority(GetDesiredThreadPriority());

      // Get the sequence containing the next task to execute.
      scoped_refptr<Sequence> sequence =
          outer_->delegate_->GetWork(outer_.get());
      if (!sequence) {
        if (outer_->delegate_->CanDetach(outer_.get())) {
          detached_thread = outer_->DetachThreadObject(DetachNotify::DELEGATE);
          if (detached_thread) {
            DCHECK_EQ(detached_thread.get(), this);
            PlatformThread::Detach(thread_handle_);
            break;
          }
        }
        outer_->delegate_->WaitForWork(&wake_up_event_);
        continue;
      }

      if (outer_->task_tracker_->RunTask(sequence->TakeTask(),
                                         sequence->token())) {
        outer_->delegate_->DidRunTask();
      }

      const bool sequence_became_empty = sequence->Pop();

      // If |sequence| isn't empty immediately after the pop, re-enqueue it to
      // maintain the invariant that a non-empty Sequence is always referenced
      // by either a PriorityQueue or a SchedulerWorker. If it is empty
      // and there are live references to it, it will be enqueued when a Task is
      // added to it. Otherwise, it will be destroyed at the end of this scope.
      if (!sequence_became_empty)
        outer_->delegate_->ReEnqueueSequence(std::move(sequence));

      // Calling WakeUp() guarantees that this SchedulerWorker will run
      // Tasks from Sequences returned by the GetWork() method of |delegate_|
      // until it returns nullptr. Resetting |wake_up_event_| here doesn't break
      // this invariant and avoids a useless loop iteration before going to
      // sleep if WakeUp() is called while this SchedulerWorker is awake.
      wake_up_event_.Reset();
    }

    // If a wake up is pending and we successfully detached, somehow |outer_|
    // was able to signal us which means it probably thinks we're still alive.
    // This is bad as it will cause the WakeUp to no-op and |outer_| will be
    // stuck forever.
    DCHECK(!detached_thread || !IsWakeUpPending()) <<
        "This thread was detached and woken up at the same time.";

    // This thread is generally responsible for cleaning itself up except when
    // JoinForTesting() is called.
    // We arrive here in the following cases:
    // Thread Detachment Request:
    //   * |detached_thread| will not be nullptr.
    // ShouldExit() returns true:
    //   * Shutdown: DetachThreadObject() returns the thread object.
    //   * Cleanup: DetachThreadObject() returns the thread object.
    //   * Join: DetachThreadObject() could return either the thread object or
    //           nullptr. JoinForTesting() cleans up if we get nullptr.
    if (!detached_thread)
      detached_thread = outer_->DetachThreadObject(DetachNotify::SILENT);

    outer_->delegate_->OnMainExit();
  }

  void Join() { PlatformThread::Join(thread_handle_); }

  void WakeUp() { wake_up_event_.Signal(); }

  bool IsWakeUpPending() { return wake_up_event_.IsSignaled(); }

 private:
  Thread(scoped_refptr<SchedulerWorker> outer)
      : outer_(std::move(outer)),
        wake_up_event_(WaitableEvent::ResetPolicy::MANUAL,
                       WaitableEvent::InitialState::NOT_SIGNALED),
        current_thread_priority_(GetDesiredThreadPriority()) {
    DCHECK(outer_);
  }

  void Initialize() {
    constexpr size_t kDefaultStackSize = 0;
    PlatformThread::CreateWithPriority(kDefaultStackSize, this, &thread_handle_,
                                       current_thread_priority_);
  }

  // Returns the priority for which the thread should be set based on the
  // priority hint, current shutdown state, and platform capabilities.
  ThreadPriority GetDesiredThreadPriority() {
    DCHECK(outer_);

    // All threads have a NORMAL priority when Lock doesn't handle multiple
    // thread priorities.
    if (!Lock::HandlesMultipleThreadPriorities())
      return ThreadPriority::NORMAL;

    // To avoid shutdown hangs, disallow a priority below NORMAL during
    // shutdown. If thread priority cannot be increased, never allow a priority
    // below NORMAL.
    if (static_cast<int>(outer_->priority_hint_) <
            static_cast<int>(ThreadPriority::NORMAL) &&
        (outer_->task_tracker_->HasShutdownStarted() ||
         !PlatformThread::CanIncreaseCurrentThreadPriority())) {
      return ThreadPriority::NORMAL;
    }

    return outer_->priority_hint_;
  }

  void UpdateThreadPriority(ThreadPriority desired_thread_priority) {
    if (desired_thread_priority == current_thread_priority_)
      return;

    PlatformThread::SetCurrentThreadPriority(desired_thread_priority);
    current_thread_priority_ = desired_thread_priority;
  }

  PlatformThreadHandle thread_handle_;

  scoped_refptr<SchedulerWorker> outer_;

  // Event signaled to wake up this thread.
  WaitableEvent wake_up_event_;

  // Current priority of this thread. May be different from
  // |outer_->priority_hint_|.
  ThreadPriority current_thread_priority_;

  DISALLOW_COPY_AND_ASSIGN(Thread);
};

void SchedulerWorker::Delegate::WaitForWork(WaitableEvent* wake_up_event) {
  DCHECK(wake_up_event);
  const TimeDelta sleep_time = GetSleepTimeout();
  if (sleep_time.is_max()) {
    // Calling TimedWait with TimeDelta::Max is not recommended per
    // http://crbug.com/465948.
    wake_up_event->Wait();
  } else {
    wake_up_event->TimedWait(sleep_time);
  }
  wake_up_event->Reset();
}

SchedulerWorker::SchedulerWorker(
    ThreadPriority priority_hint,
    std::unique_ptr<Delegate> delegate,
    TaskTracker* task_tracker,
    SchedulerBackwardCompatibility backward_compatibility,
    InitialState initial_state)
    : priority_hint_(priority_hint),
      delegate_(std::move(delegate)),
      task_tracker_(task_tracker),
#if defined(OS_WIN)
      backward_compatibility_(backward_compatibility),
#endif
      initial_state_(initial_state) {
  DCHECK(delegate_);
  DCHECK(task_tracker_);
}

bool SchedulerWorker::Start() {
  AutoSchedulerLock auto_lock(thread_lock_);
  DCHECK(!started_);
  DCHECK(!thread_);

  if (should_exit_.IsSet())
    return true;

  started_ = true;

  if (initial_state_ == InitialState::ALIVE) {
    CreateThread();
    return !!thread_;
  }

  return true;
}

void SchedulerWorker::WakeUp() {
  AutoSchedulerLock auto_lock(thread_lock_);

  DCHECK(!join_called_for_testing_.IsSet());

  if (!thread_)
    CreateThread();

  if (thread_)
    thread_->WakeUp();
}

void SchedulerWorker::JoinForTesting() {
  DCHECK(started_);
  DCHECK(!join_called_for_testing_.IsSet());
  join_called_for_testing_.Set();

  std::unique_ptr<Thread> thread;

  {
    AutoSchedulerLock auto_lock(thread_lock_);

    if (thread_) {
      // Make sure the thread is awake. It will see that
      // |join_called_for_testing_| is set and exit shortly after.
      thread_->WakeUp();
      thread = std::move(thread_);
    }
  }

  if (thread)
    thread->Join();
}

bool SchedulerWorker::ThreadAliveForTesting() const {
  AutoSchedulerLock auto_lock(thread_lock_);
  return !!thread_;
}

void SchedulerWorker::Cleanup() {
  // |should_exit_| is synchronized with |thread_| for writes here so that we
  // can maintain access to |thread_| for wakeup. Otherwise, the thread may take
  // away |thread_| for destruction.
  AutoSchedulerLock auto_lock(thread_lock_);
  DCHECK(!should_exit_.IsSet());
  should_exit_.Set();
  if (thread_)
    thread_->WakeUp();
}

SchedulerWorker::~SchedulerWorker() {
  // It is unexpected for |thread_| to be alive and for SchedulerWorker to
  // destroy since SchedulerWorker owns the delegate needed by |thread_|.
  // For testing, this generally means JoinForTesting was not called.
  DCHECK(!thread_);
}

std::unique_ptr<SchedulerWorker::Thread> SchedulerWorker::DetachThreadObject(
    DetachNotify detach_notify) {
  AutoSchedulerLock auto_lock(thread_lock_);

  // Do not detach if the thread is being joined.
  if (!thread_) {
    DCHECK(join_called_for_testing_.IsSet());
    return nullptr;
  }

  // If a wakeup is pending, then a WakeUp() came in while we were deciding to
  // detach. This means we can't go away anymore since we would break the
  // guarantee that we call GetWork() after a successful wakeup.
  if (thread_->IsWakeUpPending())
    return nullptr;

  if (detach_notify == DetachNotify::DELEGATE) {
    // Call OnDetach() within the scope of |thread_lock_| to prevent the
    // delegate from being used concurrently from an old and a new thread.
    delegate_->OnDetach();
  }

  return std::move(thread_);
}

void SchedulerWorker::CreateThread() {
  thread_lock_.AssertAcquired();
  if (started_)
    thread_ = Thread::Create(make_scoped_refptr(this));
}

bool SchedulerWorker::ShouldExit() {
  // The ordering of the checks is important below. This SchedulerWorker may be
  // released and outlive |task_tracker_| in unit tests. However, when the
  // SchedulerWorker is released, |should_exit_| will be set, so check that
  // first.
  return should_exit_.IsSet() || join_called_for_testing_.IsSet() ||
         task_tracker_->IsShutdownComplete();
}

}  // namespace internal
}  // namespace base
