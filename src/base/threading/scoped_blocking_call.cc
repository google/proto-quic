// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/scoped_blocking_call.h"

#include "base/lazy_instance.h"
#include "base/threading/thread_local.h"

namespace base {

namespace {

LazyInstance<ThreadLocalPointer<internal::BlockingObserver>>::Leaky
    tls_blocking_observer = LAZY_INSTANCE_INITIALIZER;

#if DCHECK_IS_ON()
// Ensures the absence of nested ScopedBlockingCall instances.
LazyInstance<ThreadLocalBoolean>::Leaky tls_in_blocked_scope =
    LAZY_INSTANCE_INITIALIZER;
#endif

}  // namespace

namespace internal {

void SetBlockingObserverForCurrentThread(BlockingObserver* blocking_observer) {
  DCHECK(!tls_blocking_observer.Get().Get());
  tls_blocking_observer.Get().Set(blocking_observer);
}

void ClearBlockingObserverForTesting() {
  tls_blocking_observer.Get().Set(nullptr);
}

}  // namespace internal

ScopedBlockingCall::ScopedBlockingCall(BlockingType blocking_type)
    : blocking_type_(blocking_type) {
#if DCHECK_IS_ON()
  DCHECK(!tls_in_blocked_scope.Get().Get());
  tls_in_blocked_scope.Get().Set(true);
#endif

  blocking_observer_ = tls_blocking_observer.Get().Get();
  if (blocking_observer_)
    blocking_observer_->BlockingScopeEntered(blocking_type_);
}

ScopedBlockingCall::~ScopedBlockingCall() {
#if DCHECK_IS_ON()
  DCHECK(tls_in_blocked_scope.Get().Get());
  tls_in_blocked_scope.Get().Set(false);
#endif

  DCHECK_EQ(blocking_observer_, tls_blocking_observer.Get().Get());
  if (blocking_observer_)
    blocking_observer_->BlockingScopeExited(blocking_type_);
}

}  // namespace base
