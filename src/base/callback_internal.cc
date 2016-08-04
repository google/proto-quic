// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/callback_internal.h"

#include "base/logging.h"

namespace base {
namespace internal {

void BindStateBase::AddRef() {
  AtomicRefCountInc(&ref_count_);
}

void BindStateBase::Release() {
  if (!AtomicRefCountDec(&ref_count_))
    destructor_(this);
}

CallbackBase<CopyMode::MoveOnly>::CallbackBase(CallbackBase&& c) = default;

CallbackBase<CopyMode::MoveOnly>&
CallbackBase<CopyMode::MoveOnly>::operator=(CallbackBase&& c) = default;

void CallbackBase<CopyMode::MoveOnly>::Reset() {
  polymorphic_invoke_ = nullptr;
  // NULL the bind_state_ last, since it may be holding the last ref to whatever
  // object owns us, and we may be deleted after that.
  bind_state_ = nullptr;
}

bool CallbackBase<CopyMode::MoveOnly>::EqualsInternal(
    const CallbackBase& other) const {
  // Ignore |polymorphic_invoke_| value in null case.
  if (!bind_state_ || !other.bind_state_)
    return bind_state_ == other.bind_state_;
  return bind_state_ == other.bind_state_ &&
         polymorphic_invoke_ == other.polymorphic_invoke_;
}

CallbackBase<CopyMode::MoveOnly>::CallbackBase(
    BindStateBase* bind_state)
    : bind_state_(bind_state) {
  DCHECK(!bind_state_.get() || bind_state_->ref_count_ == 1);
}

CallbackBase<CopyMode::MoveOnly>::~CallbackBase() {}

CallbackBase<CopyMode::Copyable>::CallbackBase(
    const CallbackBase& c)
    : CallbackBase<CopyMode::MoveOnly>(nullptr) {
  bind_state_ = c.bind_state_;
  polymorphic_invoke_ = c.polymorphic_invoke_;
}

CallbackBase<CopyMode::Copyable>::CallbackBase(CallbackBase&& c) = default;

CallbackBase<CopyMode::Copyable>&
CallbackBase<CopyMode::Copyable>::operator=(const CallbackBase& c) {
  bind_state_ = c.bind_state_;
  polymorphic_invoke_ = c.polymorphic_invoke_;
  return *this;
}

CallbackBase<CopyMode::Copyable>&
CallbackBase<CopyMode::Copyable>::operator=(CallbackBase&& c) = default;

template class CallbackBase<CopyMode::MoveOnly>;
template class CallbackBase<CopyMode::Copyable>;

}  // namespace internal
}  // namespace base
