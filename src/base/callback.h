// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_CALLBACK_H_
#define BASE_CALLBACK_H_

#include "base/callback_forward.h"
#include "base/callback_internal.h"

// NOTE: Header files that do not require the full definition of Callback or
// Closure should #include "base/callback_forward.h" instead of this file.

// -----------------------------------------------------------------------------
// Usage documentation
// -----------------------------------------------------------------------------
//
// See //docs/callback.md for documentation.

namespace base {

template <typename R, typename... Args, internal::CopyMode copy_mode>
class Callback<R(Args...), copy_mode>
    : public internal::CallbackBase<copy_mode> {
 public:
  using PolymorphicInvoke = R (*)(internal::BindStateBase*, Args&&...);

  // MSVC 2013 doesn't support Type Alias of function types.
  // Revisit this after we update it to newer version.
  typedef R RunType(Args...);

  Callback() : internal::CallbackBase<copy_mode>(nullptr) {}

  explicit Callback(internal::BindStateBase* bind_state)
      : internal::CallbackBase<copy_mode>(bind_state) {
  }

  bool Equals(const Callback& other) const {
    return this->EqualsInternal(other);
  }

  // Run() makes an extra copy compared to directly calling the bound function
  // if an argument is passed-by-value and is copyable-but-not-movable:
  // i.e. below copies CopyableNonMovableType twice.
  //   void F(CopyableNonMovableType) {}
  //   Bind(&F).Run(CopyableNonMovableType());
  //
  // We can not fully apply Perfect Forwarding idiom to the callchain from
  // Callback::Run() to the target function. Perfect Forwarding requires
  // knowing how the caller will pass the arguments. However, the signature of
  // InvokerType::Run() needs to be fixed in the callback constructor, so Run()
  // cannot template its arguments based on how it's called.
  R Run(Args... args) const {
    PolymorphicInvoke f =
        reinterpret_cast<PolymorphicInvoke>(this->polymorphic_invoke());
    return f(this->bind_state_.get(), std::forward<Args>(args)...);
  }
};

}  // namespace base

#endif  // BASE_CALLBACK_H_
