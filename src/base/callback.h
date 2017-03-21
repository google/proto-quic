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

namespace internal {

template <typename From, typename To>
struct IsCallbackConvertible : std::false_type {};

template <typename Signature>
struct IsCallbackConvertible<RepeatingCallback<Signature>,
                             OnceCallback<Signature>> : std::true_type {};

}  // namespace internal

template <typename R,
          typename... Args,
          internal::CopyMode copy_mode,
          internal::RepeatMode repeat_mode>
class Callback<R(Args...), copy_mode, repeat_mode>
    : public internal::CallbackBase<copy_mode> {
 public:
  static_assert(repeat_mode != internal::RepeatMode::Once ||
                copy_mode == internal::CopyMode::MoveOnly,
                "OnceCallback must be MoveOnly.");

  using RunType = R(Args...);
  using PolymorphicInvoke = R (*)(internal::BindStateBase*, Args&&...);

  Callback() : internal::CallbackBase<copy_mode>(nullptr) {}

  explicit Callback(internal::BindStateBase* bind_state)
      : internal::CallbackBase<copy_mode>(bind_state) {
  }

  template <typename OtherCallback,
            typename = typename std::enable_if<
                internal::IsCallbackConvertible<OtherCallback, Callback>::value
            >::type>
  Callback(OtherCallback other)
      : internal::CallbackBase<copy_mode>(std::move(other)) {}

  template <typename OtherCallback,
            typename = typename std::enable_if<
                internal::IsCallbackConvertible<OtherCallback, Callback>::value
            >::type>
  Callback& operator=(OtherCallback other) {
    static_cast<internal::CallbackBase<copy_mode>&>(*this) = std::move(other);
    return *this;
  }

  bool Equals(const Callback& other) const {
    return this->EqualsInternal(other);
  }

  R Run(Args... args) const & {
    static_assert(repeat_mode == internal::RepeatMode::Repeating,
                  "OnceCallback::Run() may only be invoked on a non-const "
                  "rvalue, i.e. std::move(callback).Run().");

    PolymorphicInvoke f =
        reinterpret_cast<PolymorphicInvoke>(this->polymorphic_invoke());
    return f(this->bind_state_.get(), std::forward<Args>(args)...);
  }

  R Run(Args... args) && {
    // Move the callback instance into a local variable before the invocation,
    // that ensures the internal state is cleared after the invocation.
    // It's not safe to touch |this| after the invocation, since running the
    // bound function may destroy |this|.
    Callback cb = std::move(*this);
    PolymorphicInvoke f =
        reinterpret_cast<PolymorphicInvoke>(cb.polymorphic_invoke());
    return f(cb.bind_state_.get(), std::forward<Args>(args)...);
  }
};

}  // namespace base

#endif  // BASE_CALLBACK_H_
