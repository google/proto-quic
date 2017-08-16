// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/scoped_may_block.h"

#include "base/lazy_instance.h"
#include "base/threading/thread_local.h"

namespace base {

namespace {

LazyInstance<ThreadLocalPointer<internal::BlockingObserver>>::Leaky
    tls_blocking_observer = LAZY_INSTANCE_INITIALIZER;

}  // namespace

namespace internal {

void SetBlockingObserverForCurrentThread(BlockingObserver* blocking_observer) {
  DCHECK(!tls_blocking_observer.Get().Get());
  tls_blocking_observer.Get().Set(blocking_observer);
}

}  // namespace internal

ScopedMayBlock::ScopedMayBlock() {
  internal::BlockingObserver* blocking_observer =
      tls_blocking_observer.Get().Get();
  if (blocking_observer)
    blocking_observer->BlockingScopeEntered();
}

ScopedMayBlock::~ScopedMayBlock() {
  internal::BlockingObserver* blocking_observer =
      tls_blocking_observer.Get().Get();
  if (blocking_observer)
    blocking_observer->BlockingScopeExited();
}

}  // namespace base
