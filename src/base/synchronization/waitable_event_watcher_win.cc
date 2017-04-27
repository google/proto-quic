// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/waitable_event_watcher.h"

#include "base/compiler_specific.h"
#include "base/synchronization/waitable_event.h"
#include "base/win/object_watcher.h"

namespace base {

WaitableEventWatcher::WaitableEventWatcher() = default;

WaitableEventWatcher::~WaitableEventWatcher() {
}

bool WaitableEventWatcher::StartWatching(WaitableEvent* event,
                                         EventCallback callback) {
  callback_ = std::move(callback);
  event_ = event;
  return watcher_.StartWatchingOnce(event->handle(), this);
}

void WaitableEventWatcher::StopWatching() {
  callback_.Reset();
  event_ = NULL;
  watcher_.StopWatching();
}

void WaitableEventWatcher::OnObjectSignaled(HANDLE h) {
  WaitableEvent* event = event_;
  EventCallback callback = std::move(callback_);
  event_ = NULL;
  DCHECK(event);

  std::move(callback).Run(event);
}

}  // namespace base
