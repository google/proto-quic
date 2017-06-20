// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_SAFE_MATH_SHARED_IMPL_H_
#define BASE_NUMERICS_SAFE_MATH_SHARED_IMPL_H_

#include <stddef.h>
#include <stdint.h>

#include <climits>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <type_traits>

#include "base/numerics/safe_conversions.h"

namespace base {
namespace internal {

// This is used for UnsignedAbs, where we need to support floating-point
// template instantiations even though we don't actually support the operations.
// However, there is no corresponding implementation of e.g. SafeUnsignedAbs,
// so the float versions will not compile.
template <typename Numeric,
          bool IsInteger = std::is_integral<Numeric>::value,
          bool IsFloat = std::is_floating_point<Numeric>::value>
struct UnsignedOrFloatForSize;

template <typename Numeric>
struct UnsignedOrFloatForSize<Numeric, true, false> {
  using type = typename std::make_unsigned<Numeric>::type;
};

template <typename Numeric>
struct UnsignedOrFloatForSize<Numeric, false, true> {
  using type = Numeric;
};

// Wrap the unary operations to allow SFINAE when instantiating integrals versus
// floating points. These don't perform any overflow checking. Rather, they
// exhibit well-defined overflow semantics and rely on the caller to detect
// if an overflow occured.

template <typename T,
          typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
constexpr T NegateWrapper(T value) {
  using UnsignedT = typename std::make_unsigned<T>::type;
  // This will compile to a NEG on Intel, and is normal negation on ARM.
  return static_cast<T>(UnsignedT(0) - static_cast<UnsignedT>(value));
}

template <
    typename T,
    typename std::enable_if<std::is_floating_point<T>::value>::type* = nullptr>
constexpr T NegateWrapper(T value) {
  return -value;
}

template <typename T,
          typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
constexpr typename std::make_unsigned<T>::type InvertWrapper(T value) {
  return ~value;
}

template <typename T,
          typename std::enable_if<std::is_integral<T>::value>::type* = nullptr>
constexpr T AbsWrapper(T value) {
  return static_cast<T>(SafeUnsignedAbs(value));
}

template <
    typename T,
    typename std::enable_if<std::is_floating_point<T>::value>::type* = nullptr>
constexpr T AbsWrapper(T value) {
  return value < 0 ? -value : value;
}

template <template <typename, typename, typename> class M,
          typename L,
          typename R>
struct MathWrapper {
  using math = M<typename UnderlyingType<L>::type,
                 typename UnderlyingType<R>::type,
                 void>;
  using type = typename math::result_type;
};

// These variadic templates work out the return types.
// TODO(jschuh): Rip all this out once we have C++14 non-trailing auto support.
template <template <typename, typename, typename> class M,
          typename L,
          typename R,
          typename... Args>
struct ResultType;

template <template <typename, typename, typename> class M,
          typename L,
          typename R>
struct ResultType<M, L, R> {
  using type = typename MathWrapper<M, L, R>::type;
};

template <template <typename, typename, typename> class M,
          typename L,
          typename R,
          typename... Args>
struct ResultType {
  using type =
      typename ResultType<M, typename ResultType<M, L, R>::type, Args...>::type;
};

// The following macros are just boilerplate for the standard arithmetic
// operator overloads and variadic function templates. A macro isn't the nicest
// solution, but it beats rewriting these over and over again.
#define BASE_NUMERIC_ARITHMETIC_VARIADIC(CLASS, CL_ABBR, OP_NAME)              \
  template <typename L, typename R, typename... Args>                          \
  CLASS##Numeric<typename ResultType<CLASS##OP_NAME##Op, L, R, Args...>::type> \
      CL_ABBR##OP_NAME(const L lhs, const R rhs, const Args... args) {         \
    return ChkMathOp<CLASS##OP_NAME##Op, L, R, Args...>(lhs, rhs, args...);    \
  }

#define BASE_NUMERIC_ARITHMETIC_OPERATORS(CLASS, CL_ABBR, OP_NAME, OP, CMP_OP) \
  /* Binary arithmetic operator for all CheckedNumeric operations. */          \
  template <typename L, typename R,                                            \
            typename std::enable_if<IsCheckedOp<L, R>::value>::type* =         \
                nullptr>                                                       \
  CheckedNumeric<typename MathWrapper<CLASS##OP_NAME##Op, L, R>::type>         \
  operator OP(const L lhs, const R rhs) {                                      \
    return decltype(lhs OP rhs)::template MathOp<CLASS##OP_NAME##Op>(lhs,      \
                                                                     rhs);     \
  }                                                                            \
  /* Assignment arithmetic operator implementation from CheckedNumeric. */     \
  template <typename L>                                                        \
  template <typename R>                                                        \
  CheckedNumeric<L>& CheckedNumeric<L>::operator CMP_OP(const R rhs) {         \
    return MathOp<CLASS##OP_NAME##Op>(rhs);                                    \
  }                                                                            \
  /* Variadic arithmetic functions that return CheckedNumeric. */              \
  BASE_NUMERIC_ARITHMETIC_VARIADIC(CLASS, CL_ABBR, OP_NAME)

}  // namespace internal
}  // namespace base

#endif  // BASE_NUMERICS_SAFE_MATH_SHARED_IMPL_H_
