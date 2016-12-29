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

template <typename CallbackType>
struct IsOnceCallback : std::false_type {};

template <typename Signature>
struct IsOnceCallback<OnceCallback<Signature>> : std::true_type {};

// RunMixin provides different variants of `Run()` function to `Callback<>`
// based on the type of callback.
template <typename CallbackType>
class RunMixin;

// Specialization for OnceCallback.
template <typename R, typename... Args>
class RunMixin<OnceCallback<R(Args...)>> {
 private:
  using CallbackType = OnceCallback<R(Args...)>;

 public:
  using PolymorphicInvoke = R(*)(internal::BindStateBase*, Args&&...);

  R Run(Args... args) const & {
    // Note: even though this static_assert will trivially always fail, it
    // cannot be simply replaced with static_assert(false, ...) because:
    // - Per [dcl.dcl]/p4, a program is ill-formed if the constant-expression
    //   argument does not evaluate to true.
    // - Per [temp.res]/p8, if no valid specialization can be generated for a
    //   template definition, and that template is not instantiated, the
    //   template definition is ill-formed, no diagnostic required.
    // These two clauses, taken together, would allow a conforming C++ compiler
    // to immediately reject static_assert(false, ...), even inside an
    // uninstantiated template.
    static_assert(!IsOnceCallback<CallbackType>::value,
                  "OnceCallback::Run() may only be invoked on a non-const "
                  "rvalue, i.e. std::move(callback).Run().");
  }

  R Run(Args... args) && {
    // Move the callback instance into a local variable before the invocation,
    // that ensures the internal state is cleared after the invocation.
    // It's not safe to touch |this| after the invocation, since running the
    // bound function may destroy |this|.
    CallbackType cb = static_cast<CallbackType&&>(*this);
    PolymorphicInvoke f =
        reinterpret_cast<PolymorphicInvoke>(cb.polymorphic_invoke());
    return f(cb.bind_state_.get(), std::forward<Args>(args)...);
  }
};

// Specialization for RepeatingCallback.
template <typename R, typename... Args>
class RunMixin<RepeatingCallback<R(Args...)>> {
 private:
  using CallbackType = RepeatingCallback<R(Args...)>;

 public:
  using PolymorphicInvoke = R(*)(internal::BindStateBase*, Args&&...);

  R Run(Args... args) const {
    const CallbackType& cb = static_cast<const CallbackType&>(*this);
    PolymorphicInvoke f =
        reinterpret_cast<PolymorphicInvoke>(cb.polymorphic_invoke());
    return f(cb.bind_state_.get(), std::forward<Args>(args)...);
  }
};

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
    : public internal::CallbackBase<copy_mode>,
      public internal::RunMixin<Callback<R(Args...), copy_mode, repeat_mode>> {
 public:
  static_assert(repeat_mode != internal::RepeatMode::Once ||
                copy_mode == internal::CopyMode::MoveOnly,
                "OnceCallback must be MoveOnly.");

  using RunType = R(Args...);

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

  friend class internal::RunMixin<Callback>;
};

}  // namespace base

#endif  // BASE_CALLBACK_H_
