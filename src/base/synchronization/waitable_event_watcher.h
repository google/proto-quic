// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_SYNCHRONIZATION_WAITABLE_EVENT_WATCHER_H_
#define BASE_SYNCHRONIZATION_WAITABLE_EVENT_WATCHER_H_

#include "base/base_export.h"
#include "base/macros.h"
#include "base/sequence_checker.h"
#include "build/build_config.h"

#if defined(OS_WIN)
#include "base/win/object_watcher.h"
#else
#include "base/callback.h"
#include "base/synchronization/waitable_event.h"
#endif

namespace base {

class Flag;
class AsyncWaiter;
class WaitableEvent;

// This class provides a way to wait on a WaitableEvent asynchronously.
//
// Each instance of this object can be waiting on a single WaitableEvent. When
// the waitable event is signaled, a callback is invoked on the sequence that
// called StartWatching(). This callback can be deleted by deleting the waiter.
//
// Typical usage:
//
//   class MyClass {
//    public:
//     void DoStuffWhenSignaled(WaitableEvent *waitable_event) {
//       watcher_.StartWatching(waitable_event,
//           base::Bind(&MyClass::OnWaitableEventSignaled, this);
//     }
//    private:
//     void OnWaitableEventSignaled(WaitableEvent* waitable_event) {
//       // OK, time to do stuff!
//     }
//     base::WaitableEventWatcher watcher_;
//   };
//
// In the above example, MyClass wants to "do stuff" when waitable_event
// becomes signaled. WaitableEventWatcher makes this task easy. When MyClass
// goes out of scope, the watcher_ will be destroyed, and there is no need to
// worry about OnWaitableEventSignaled being called on a deleted MyClass
// pointer.
//
// BEWARE: With automatically reset WaitableEvents, a signal may be lost if it
// occurs just before a WaitableEventWatcher is deleted. There is currently no
// safe way to stop watching an automatic reset WaitableEvent without possibly
// missing a signal.
//
// NOTE: you /are/ allowed to delete the WaitableEvent while still waiting on
// it with a Watcher. It will act as if the event was never signaled.

class BASE_EXPORT WaitableEventWatcher
#if defined(OS_WIN)
    : public win::ObjectWatcher::Delegate
#endif
{
 public:
  typedef Callback<void(WaitableEvent*)> EventCallback;
  WaitableEventWatcher();

#if defined(OS_WIN)
  ~WaitableEventWatcher() override;
#else
  ~WaitableEventWatcher();
#endif

  // When |event| is signaled, |callback| is called on the sequence that called
  // StartWatching().
  bool StartWatching(WaitableEvent* event, const EventCallback& callback);

  // Cancel the current watch. Must be called from the same sequence which
  // started the watch.
  //
  // Does nothing if no event is being watched, nor if the watch has completed.
  // The callback will *not* be called for the current watch after this
  // function returns. Since the callback runs on the same sequence as this
  // function, it cannot be called during this function either.
  void StopWatching();

 private:
#if defined(OS_WIN)
  void OnObjectSignaled(HANDLE h) override;

  win::ObjectWatcher watcher_;
  EventCallback callback_;
  WaitableEvent* event_ = nullptr;
#else
  // Instantiated in StartWatching(). Set before the callback runs. Reset in
  // StopWatching() or StartWatching().
  scoped_refptr<Flag> cancel_flag_;

  // Enqueued in the wait list of the watched WaitableEvent.
  AsyncWaiter* waiter_ = nullptr;

  // Kernel of the watched WaitableEvent.
  scoped_refptr<WaitableEvent::WaitableEventKernel> kernel_;

  // Ensures that StartWatching() and StopWatching() are called on the same
  // sequence.
  SequenceChecker sequence_checker_;
#endif

  DISALLOW_COPY_AND_ASSIGN(WaitableEventWatcher);
};

}  // namespace base

#endif  // BASE_SYNCHRONIZATION_WAITABLE_EVENT_WATCHER_H_
