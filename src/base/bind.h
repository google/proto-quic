// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_BIND_H_
#define BASE_BIND_H_

#include "base/bind_internal.h"

// -----------------------------------------------------------------------------
// Usage documentation
// -----------------------------------------------------------------------------
//
// See //docs/callback.md for documentation.
//
//
// -----------------------------------------------------------------------------
// Implementation notes
// -----------------------------------------------------------------------------
//
// If you're reading the implementation, before proceeding further, you should
// read the top comment of base/bind_internal.h for a definition of common
// terms and concepts.

namespace base {

namespace internal {

// IsOnceCallback<T> is a std::true_type if |T| is a OnceCallback.
template <typename T>
struct IsOnceCallback : std::false_type {};

template <typename Signature>
struct IsOnceCallback<OnceCallback<Signature>> : std::true_type {};

// Asserts |Param| is constructible from |Unwrapped|. |Arg| is here just to
// show it in the compile error message as a hint to fix the error.
template <size_t i, typename Arg, typename Unwrapped, typename Param>
struct AssertConstructible {
  static_assert(std::is_constructible<Param, Unwrapped>::value,
                "|Param| needs to be constructible from |Unwrapped| type. "
                "The failing argument is passed as the |i|th parameter, whose "
                "type is |Arg|, and delivered as |Unwrapped| into |Param|.");
};

// Takes three same-length TypeLists, and applies AssertConstructible for each
// triples.
template <typename Index,
          typename ArgsList,
          typename UnwrappedTypeList,
          typename ParamsList>
struct AssertBindArgsValidity;

template <size_t... Ns,
          typename... Args,
          typename... Unwrapped,
          typename... Params>
struct AssertBindArgsValidity<IndexSequence<Ns...>,
                              TypeList<Args...>,
                              TypeList<Unwrapped...>,
                              TypeList<Params...>>
    : AssertConstructible<Ns, Args, Unwrapped, Params>... {
  static constexpr bool ok = true;
};

// The implementation of TransformToUnwrappedType below.
template <RepeatMode, typename T>
struct TransformToUnwrappedTypeImpl;

template <typename T>
struct TransformToUnwrappedTypeImpl<RepeatMode::Once, T> {
  using StoredType = typename std::decay<T>::type;
  using ForwardType = StoredType&&;
  using Unwrapped = decltype(Unwrap(std::declval<ForwardType>()));
};

template <typename T>
struct TransformToUnwrappedTypeImpl<RepeatMode::Repeating, T> {
  using StoredType = typename std::decay<T>::type;
  using ForwardType = const StoredType&;
  using Unwrapped = decltype(Unwrap(std::declval<ForwardType>()));
};

// Transform |T| into `Unwrapped` type, which is passed to the target function.
// Example:
//   In repeat_mode == RepeatMode::Once case,
//     `int&&` -> `int&&`,
//     `const int&` -> `int&&`,
//     `OwnedWrapper<int>&` -> `int*&&`.
//   In repeat_mode == RepeatMode::Repeating case,
//     `int&&` -> `const int&`,
//     `const int&` -> `const int&`,
//     `OwnedWrapper<int>&` -> `int* const &`.
template <RepeatMode repeat_mode, typename T>
using TransformToUnwrappedType =
    typename TransformToUnwrappedTypeImpl<repeat_mode, T>::Unwrapped;

// Transforms |Args| into `Unwrapped` types, and packs them into a TypeList.
// If |is_method| is true, tries to dereference the first argument to support
// smart pointers.
template <RepeatMode repeat_mode, bool is_method, typename... Args>
struct MakeUnwrappedTypeListImpl {
  using Type = TypeList<TransformToUnwrappedType<repeat_mode, Args>...>;
};

// Performs special handling for this pointers.
// Example:
//   int* -> int*,
//   std::unique_ptr<int> -> int*.
template <RepeatMode repeat_mode, typename Receiver, typename... Args>
struct MakeUnwrappedTypeListImpl<repeat_mode, true, Receiver, Args...> {
  using UnwrappedReceiver = TransformToUnwrappedType<repeat_mode, Receiver>;
  using Type = TypeList<decltype(&*std::declval<UnwrappedReceiver>()),
                        TransformToUnwrappedType<repeat_mode, Args>...>;
};

template <RepeatMode repeat_mode, bool is_method, typename... Args>
using MakeUnwrappedTypeList =
    typename MakeUnwrappedTypeListImpl<repeat_mode, is_method, Args...>::Type;

}  // namespace internal

// Bind as OnceCallback.
template <typename Functor, typename... Args>
inline OnceCallback<MakeUnboundRunType<Functor, Args...>>
BindOnce(Functor&& functor, Args&&... args) {
  static_assert(
      !internal::IsOnceCallback<typename std::decay<Functor>::type>() ||
          (std::is_rvalue_reference<Functor&&>() &&
           !std::is_const<typename std::remove_reference<Functor>::type>()),
      "BindOnce requires non-const rvalue for OnceCallback binding."
      " I.e.: base::BindOnce(std::move(callback)).");

  // This block checks if each |args| matches to the corresponding params of the
  // target function. This check does not affect the behavior of Bind, but its
  // error message should be more readable.
  using Helper = internal::BindTypeHelper<Functor, Args...>;
  using FunctorTraits = typename Helper::FunctorTraits;
  using BoundArgsList = typename Helper::BoundArgsList;
  using UnwrappedArgsList =
      internal::MakeUnwrappedTypeList<internal::RepeatMode::Once,
                                      FunctorTraits::is_method, Args&&...>;
  using BoundParamsList = typename Helper::BoundParamsList;
  static_assert(
      internal::AssertBindArgsValidity<MakeIndexSequence<Helper::num_bounds>,
                                       BoundArgsList, UnwrappedArgsList,
                                       BoundParamsList>::ok,
      "The bound args need to be convertible to the target params.");

  using BindState = internal::MakeBindStateType<Functor, Args...>;
  using UnboundRunType = MakeUnboundRunType<Functor, Args...>;
  using Invoker = internal::Invoker<BindState, UnboundRunType>;
  using CallbackType = OnceCallback<UnboundRunType>;

  // Store the invoke func into PolymorphicInvoke before casting it to
  // InvokeFuncStorage, so that we can ensure its type matches to
  // PolymorphicInvoke, to which CallbackType will cast back.
  using PolymorphicInvoke = typename CallbackType::PolymorphicInvoke;
  PolymorphicInvoke invoke_func = &Invoker::RunOnce;

  using InvokeFuncStorage = internal::BindStateBase::InvokeFuncStorage;
  return CallbackType(new BindState(
      reinterpret_cast<InvokeFuncStorage>(invoke_func),
      std::forward<Functor>(functor),
      std::forward<Args>(args)...));
}

// Bind as RepeatingCallback.
template <typename Functor, typename... Args>
inline RepeatingCallback<MakeUnboundRunType<Functor, Args...>>
BindRepeating(Functor&& functor, Args&&... args) {
  static_assert(
      !internal::IsOnceCallback<typename std::decay<Functor>::type>(),
      "BindRepeating cannot bind OnceCallback. Use BindOnce with std::move().");

  // This block checks if each |args| matches to the corresponding params of the
  // target function. This check does not affect the behavior of Bind, but its
  // error message should be more readable.
  using Helper = internal::BindTypeHelper<Functor, Args...>;
  using FunctorTraits = typename Helper::FunctorTraits;
  using BoundArgsList = typename Helper::BoundArgsList;
  using UnwrappedArgsList =
      internal::MakeUnwrappedTypeList<internal::RepeatMode::Repeating,
                                      FunctorTraits::is_method, Args&&...>;
  using BoundParamsList = typename Helper::BoundParamsList;
  static_assert(
      internal::AssertBindArgsValidity<MakeIndexSequence<Helper::num_bounds>,
                                       BoundArgsList, UnwrappedArgsList,
                                       BoundParamsList>::ok,
      "The bound args need to be convertible to the target params.");

  using BindState = internal::MakeBindStateType<Functor, Args...>;
  using UnboundRunType = MakeUnboundRunType<Functor, Args...>;
  using Invoker = internal::Invoker<BindState, UnboundRunType>;
  using CallbackType = RepeatingCallback<UnboundRunType>;

  // Store the invoke func into PolymorphicInvoke before casting it to
  // InvokeFuncStorage, so that we can ensure its type matches to
  // PolymorphicInvoke, to which CallbackType will cast back.
  using PolymorphicInvoke = typename CallbackType::PolymorphicInvoke;
  PolymorphicInvoke invoke_func = &Invoker::Run;

  using InvokeFuncStorage = internal::BindStateBase::InvokeFuncStorage;
  return CallbackType(new BindState(
      reinterpret_cast<InvokeFuncStorage>(invoke_func),
      std::forward<Functor>(functor),
      std::forward<Args>(args)...));
}

// Unannotated Bind.
// TODO(tzik): Deprecate this and migrate to OnceCallback and
// RepeatingCallback, once they get ready.
template <typename Functor, typename... Args>
inline Callback<MakeUnboundRunType<Functor, Args...>>
Bind(Functor&& functor, Args&&... args) {
  return BindRepeating(std::forward<Functor>(functor),
                       std::forward<Args>(args)...);
}

}  // namespace base

#endif  // BASE_BIND_H_
