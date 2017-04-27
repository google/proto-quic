// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

namespace base {
namespace internal {

enum class CopyMode { MoveOnly, Copyable };
enum class RepeatMode { Once, Repeating };

}  // namespace internal

template <typename Signature,
          internal::CopyMode copy_mode = internal::CopyMode::Copyable,
          internal::RepeatMode repeat_mode = internal::RepeatMode::Repeating>
class Callback;

template <typename Signature>
using OnceCallback = Callback<Signature,
                              internal::CopyMode::MoveOnly,
                              internal::RepeatMode::Once>;
template <typename Signature>
using RepeatingCallback = Callback<Signature,
                                   internal::CopyMode::Copyable,
                                   internal::RepeatMode::Repeating>;

using Closure = Callback<void()>;
using OnceClosure = OnceCallback<void()>;
using RepeatingClosure = RepeatingCallback<void()>;

namespace internal {

template <typename From, typename To>
struct IsCallbackConvertible : std::false_type {};

template <typename Signature>
struct IsCallbackConvertible<RepeatingCallback<Signature>,
                             OnceCallback<Signature>> : std::true_type {};

}  // namespace internal

template <typename Signature, internal::CopyMode, internal::RepeatMode>
class Callback {
 public:
  Callback() {}
  Callback(const Callback&) {}
  Callback(Callback&&) {}

  template <typename OtherCallback,
            typename = typename std::enable_if<
                internal::IsCallbackConvertible<OtherCallback,
                                                Callback>::value>::type>
  Callback(OtherCallback other) {}
};

template <typename Functor, typename... Args>
Callback<void()> Bind(Functor, Args&&...) {
  return Callback<void()>();
}

template <typename Functor, typename... Args>
OnceCallback<void()> BindOnce(Functor, Args&&...) {
  return Callback<void()>();
}

}  // namespace base
