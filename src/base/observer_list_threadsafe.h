// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_OBSERVER_LIST_THREADSAFE_H_
#define BASE_OBSERVER_LIST_THREADSAFE_H_

#include <algorithm>
#include <map>
#include <memory>
#include <tuple>

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/observer_list.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_task_runner_handle.h"

///////////////////////////////////////////////////////////////////////////////
//
// OVERVIEW:
//
//   A thread-safe container for a list of observers.
//   This is similar to the observer_list (see observer_list.h), but it
//   is more robust for multi-threaded situations.
//
//   The following use cases are supported:
//    * Observers can register for notifications from any thread.
//      Callbacks to the observer will occur on the same thread where
//      the observer initially called AddObserver() from.
//    * Any thread may trigger a notification via Notify().
//    * Observers can remove themselves from the observer list inside
//      of a callback.
//    * If one thread is notifying observers concurrently with an observer
//      removing itself from the observer list, the notifications will
//      be silently dropped.
//
//   The drawback of the threadsafe observer list is that notifications
//   are not as real-time as the non-threadsafe version of this class.
//   Notifications will always be done via PostTask() to another thread,
//   whereas with the non-thread-safe observer_list, notifications happen
//   synchronously and immediately.
//
//   IMPLEMENTATION NOTES
//   The ObserverListThreadSafe maintains an ObserverList for each thread
//   which uses the ThreadSafeObserver.  When Notifying the observers,
//   we simply call PostTask to each registered thread, and then each thread
//   will notify its regular ObserverList.
//
///////////////////////////////////////////////////////////////////////////////

namespace base {
namespace internal {

template <typename ObserverType, typename Method>
struct Dispatcher;

template <typename ObserverType, typename ReceiverType, typename... Params>
struct Dispatcher<ObserverType, void(ReceiverType::*)(Params...)> {
  static void Run(void(ReceiverType::* m)(Params...),
                  Params... params, ObserverType* obj) {
    (obj->*m)(std::forward<Params>(params)...);
  }
};

}  // namespace internal

template <class ObserverType>
class ObserverListThreadSafe
    : public RefCountedThreadSafe<ObserverListThreadSafe<ObserverType>> {
 public:
  using NotificationType =
      typename ObserverList<ObserverType>::NotificationType;

  ObserverListThreadSafe()
      : type_(ObserverListBase<ObserverType>::NOTIFY_ALL) {}
  explicit ObserverListThreadSafe(NotificationType type) : type_(type) {}

  // Add an observer to the list.  An observer should not be added to
  // the same list more than once.
  void AddObserver(ObserverType* obs) {
    // If there is no ThreadTaskRunnerHandle, it is impossible to notify on it,
    // so do not add the observer.
    if (!ThreadTaskRunnerHandle::IsSet())
      return;

    ObserverList<ObserverType>* list = nullptr;
    PlatformThreadId thread_id = PlatformThread::CurrentId();
    {
      AutoLock lock(list_lock_);
      if (observer_lists_.find(thread_id) == observer_lists_.end()) {
        observer_lists_[thread_id] =
            base::MakeUnique<ObserverListContext>(type_);
      }
      list = &(observer_lists_[thread_id]->list);
    }
    list->AddObserver(obs);
  }

  // Remove an observer from the list if it is in the list.
  // If there are pending notifications in-transit to the observer, they will
  // be aborted.
  // If the observer to be removed is in the list, RemoveObserver MUST
  // be called from the same thread which called AddObserver.
  void RemoveObserver(ObserverType* obs) {
    PlatformThreadId thread_id = PlatformThread::CurrentId();
    {
      AutoLock lock(list_lock_);
      auto it = observer_lists_.find(thread_id);
      if (it == observer_lists_.end()) {
        // This will happen if we try to remove an observer on a thread
        // we never added an observer for.
        return;
      }
      ObserverList<ObserverType>& list = it->second->list;

      list.RemoveObserver(obs);

      // If that was the last observer in the list, remove the ObserverList
      // entirely.
      if (list.size() == 0)
        observer_lists_.erase(it);
    }
  }

  // Verifies that the list is currently empty (i.e. there are no observers).
  void AssertEmpty() const {
    AutoLock lock(list_lock_);
    DCHECK(observer_lists_.empty());
  }

  // Notify methods.
  // Make a thread-safe callback to each Observer in the list.
  // Note, these calls are effectively asynchronous.  You cannot assume
  // that at the completion of the Notify call that all Observers have
  // been Notified.  The notification may still be pending delivery.
  template <typename Method, typename... Params>
  void Notify(const tracked_objects::Location& from_here,
              Method m, Params&&... params) {
    Callback<void(ObserverType*)> method =
        Bind(&internal::Dispatcher<ObserverType, Method>::Run,
             m, std::forward<Params>(params)...);

    AutoLock lock(list_lock_);
    for (const auto& entry : observer_lists_) {
      ObserverListContext* context = entry.second.get();
      context->task_runner->PostTask(
          from_here,
          Bind(&ObserverListThreadSafe<ObserverType>::NotifyWrapper,
               this, context, method));
    }
  }

 private:
  friend class RefCountedThreadSafe<ObserverListThreadSafe<ObserverType>>;

  struct ObserverListContext {
    explicit ObserverListContext(NotificationType type)
        : task_runner(ThreadTaskRunnerHandle::Get()), list(type) {}

    scoped_refptr<SingleThreadTaskRunner> task_runner;
    ObserverList<ObserverType> list;

   private:
    DISALLOW_COPY_AND_ASSIGN(ObserverListContext);
  };

  ~ObserverListThreadSafe() {
  }

  // Wrapper which is called to fire the notifications for each thread's
  // ObserverList.  This function MUST be called on the thread which owns
  // the unsafe ObserverList.
  void NotifyWrapper(ObserverListContext* context,
                     const Callback<void(ObserverType*)>& method) {
    // Check that this list still needs notifications.
    {
      AutoLock lock(list_lock_);
      auto it = observer_lists_.find(PlatformThread::CurrentId());

      // The ObserverList could have been removed already.  In fact, it could
      // have been removed and then re-added!  If the master list's loop
      // does not match this one, then we do not need to finish this
      // notification.
      if (it == observer_lists_.end() || it->second.get() != context)
        return;
    }

    for (auto& observer : context->list) {
      method.Run(&observer);
    }

    // If there are no more observers on the list, we can now delete it.
    if (context->list.size() == 0) {
      {
        AutoLock lock(list_lock_);
        // Remove |list| if it's not already removed.
        // This can happen if multiple observers got removed in a notification.
        // See http://crbug.com/55725.
        auto it = observer_lists_.find(PlatformThread::CurrentId());
        if (it != observer_lists_.end() && it->second.get() == context)
          observer_lists_.erase(it);
      }
    }
  }

  mutable Lock list_lock_;  // Protects the observer_lists_.

  // Key by PlatformThreadId because in tests, clients can attempt to remove
  // observers without a SingleThreadTaskRunner. If this were keyed by
  // SingleThreadTaskRunner, that operation would be silently ignored, leaving
  // garbage in the ObserverList.
  std::map<PlatformThreadId, std::unique_ptr<ObserverListContext>>
      observer_lists_;

  const NotificationType type_;

  DISALLOW_COPY_AND_ASSIGN(ObserverListThreadSafe);
};

}  // namespace base

#endif  // BASE_OBSERVER_LIST_THREADSAFE_H_
