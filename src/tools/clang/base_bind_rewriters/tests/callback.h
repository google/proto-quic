// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

namespace base {
namespace internal {

enum class CopyMode { MoveOnly, Copyable };
enum class RepeatMode { Once, Repeating };

}  // namespace internal

template <typename Signature>
class OnceCallback;

template <typename Signature>
class RepeatingCallback;

template <typename Signature>
using Callback = RepeatingCallback<Signature>;

using OnceClosure = OnceCallback<void()>;
using RepeatingClosure = RepeatingCallback<void()>;
using Closure = Callback<void()>;

template <typename Signature>
class OnceCallback {
 public:
  OnceCallback() {}
  OnceCallback(OnceCallback&&) {}
  OnceCallback(RepeatingCallback<Signature> other) {}
};

template <typename Signature>
class RepeatingCallback {
 public:
  RepeatingCallback() {}
  RepeatingCallback(const RepeatingCallback&) {}
  RepeatingCallback(RepeatingCallback&&) {}
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
