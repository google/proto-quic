// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_CLAMPED_MATH_IMPL_H_
#define BASE_NUMERICS_CLAMPED_MATH_IMPL_H_

#include <stddef.h>
#include <stdint.h>

#include <climits>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <type_traits>

#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/numerics/safe_math_shared_impl.h"

namespace base {
namespace internal {

// This provides a small optimization that generates more compact code when one
// of the components in an operation is a compile-time constant.
template <typename T>
constexpr bool IsCompileTimeConstant(const T v) {
#if defined(__clang__) || defined(__GNUC__)
  return __builtin_constant_p(v);
#else
  return false;
#endif
}

// This is a wrapper to generate return the max or min for a supplied type.
// If the argument is false, the returned value is the maximum. If true the
// returned value is the minimum.
template <typename T>
constexpr T GetMaxOrMin(bool is_min) {
  // For both signed and unsigned math the bit pattern for minimum is really
  // just one plus the maximum. However, we have to cast to unsigned to ensure
  // we get well-defined overflow semantics.
  return as_unsigned(std::numeric_limits<T>::max()) + is_min;
}

template <typename T, typename U, class Enable = void>
struct ClampedAddOp {};

template <typename T, typename U>
struct ClampedAddOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename MaxExponentPromotion<T, U>::type;
  template <typename V = result_type>
  static V Do(T x, U y) {
    V result;
    return CheckedAddOp<T, U>::Do(x, y, &result)
               ? result
               // Prefer a compile-time constant (if we have one).
               : GetMaxOrMin<V>(IsCompileTimeConstant(x) ? IsValueNegative(x)
                                                         : IsValueNegative(y));
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedSubOp {};

template <typename T, typename U>
struct ClampedSubOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename MaxExponentPromotion<T, U>::type;
  template <typename V = result_type>
  static V Do(T x, U y) {
    V result;
    return CheckedSubOp<T, U>::Do(x, y, &result)
               ? result
               // Prefer a compile-time constant (if we have one).
               : GetMaxOrMin<V>(IsCompileTimeConstant(x) ? IsValueNegative(x)
                                                         : !IsValueNegative(y));
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedMulOp {};

template <typename T, typename U>
struct ClampedMulOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename MaxExponentPromotion<T, U>::type;
  template <typename V = result_type>
  static V Do(T x, U y) {
    V result;
    return CheckedMulOp<T, U>::Do(x, y, &result)
               ? result
               : GetMaxOrMin<V>(IsValueNegative(x) ^ IsValueNegative(y));
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedDivOp {};

template <typename T, typename U>
struct ClampedDivOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename MaxExponentPromotion<T, U>::type;
  template <typename V = result_type>
  static V Do(T x, U y) {
    V result = SaturationDefaultLimits<V>::NaN();
    return !x || CheckedDivOp<T, U>::Do(x, y, &result)
               ? result
               : GetMaxOrMin<V>(IsValueNegative(x) ^ IsValueNegative(y));
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedModOp {};

template <typename T, typename U>
struct ClampedModOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename MaxExponentPromotion<T, U>::type;
  template <typename V = result_type>
  static V Do(T x, U y) {
    V result;
    return CheckedModOp<T, U>::Do(x, y, &result) ? result : x;
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedLshOp {};

// Left shift. Non-zero values saturate in the direction of the sign. A zero
// shifted by any value always results in zero.
// Note: This class template supports left shifting negative values.
template <typename T, typename U>
struct ClampedLshOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = T;
  template <typename V = result_type>
  static V Do(T x, U shift) {
    static_assert(!std::is_signed<U>::value, "Shift value must be unsigned.");
    V result = x;
    return (shift < std::numeric_limits<T>::digits &&
            CheckedMulOp<T, T>::Do(x, T(1) << shift, &result))
               ? result
               : (x ? GetMaxOrMin<V>(IsValueNegative(x)) : 0);
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedRshOp {};

// Right shift. Negative values saturate to -1. Positive or 0 saturates to 0.
template <typename T, typename U>
struct ClampedRshOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = T;
  template <typename V = result_type>
  static V Do(T x, U shift) {
    static_assert(!std::is_signed<U>::value, "Shift value must be unsigned.");
    return shift < IntegerBitsPlusSign<T>::value
               ? saturated_cast<V>(x >> shift)
               // Signed right shift is odd, because it saturates to -1 or 0.
               : as_unsigned(V(0)) - IsValueNegative(x);
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedAndOp {};

template <typename T, typename U>
struct ClampedAndOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename std::make_unsigned<
      typename MaxExponentPromotion<T, U>::type>::type;
  template <typename V>
  static constexpr V Do(T x, U y) {
    return static_cast<result_type>(x) & static_cast<result_type>(y);
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedOrOp {};

// For simplicity we promote to unsigned integers.
template <typename T, typename U>
struct ClampedOrOp<T,
                   U,
                   typename std::enable_if<std::is_integral<T>::value &&
                                           std::is_integral<U>::value>::type> {
  using result_type = typename std::make_unsigned<
      typename MaxExponentPromotion<T, U>::type>::type;
  template <typename V>
  static constexpr V Do(T x, U y) {
    return static_cast<result_type>(x) | static_cast<result_type>(y);
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedXorOp {};

// For simplicity we support only unsigned integers.
template <typename T, typename U>
struct ClampedXorOp<T,
                    U,
                    typename std::enable_if<std::is_integral<T>::value &&
                                            std::is_integral<U>::value>::type> {
  using result_type = typename std::make_unsigned<
      typename MaxExponentPromotion<T, U>::type>::type;
  template <typename V>
  static constexpr V Do(T x, U y) {
    return static_cast<result_type>(x) ^ static_cast<result_type>(y);
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedMaxOp {};

template <typename T, typename U>
struct ClampedMaxOp<
    T,
    U,
    typename std::enable_if<std::is_arithmetic<T>::value &&
                            std::is_arithmetic<U>::value>::type> {
  using result_type = typename MaxExponentPromotion<T, U>::type;
  template <typename V = result_type>
  static constexpr V Do(T x, U y) {
    return IsGreater<T, U>::Test(x, y) ? saturated_cast<V>(x)
                                       : saturated_cast<V>(y);
  }
};

template <typename T, typename U, class Enable = void>
struct ClampedMinOp {};

template <typename T, typename U>
struct ClampedMinOp<
    T,
    U,
    typename std::enable_if<std::is_arithmetic<T>::value &&
                            std::is_arithmetic<U>::value>::type> {
  using result_type = typename LowestValuePromotion<T, U>::type;
  template <typename V = result_type>
  static constexpr V Do(T x, U y) {
    return IsLess<T, U>::Test(x, y) ? saturated_cast<V>(x)
                                    : saturated_cast<V>(y);
  }
};

// This is just boilerplate that wraps the standard floating point arithmetic.
// A macro isn't the nicest solution, but it beats rewriting these repeatedly.
#define BASE_FLOAT_ARITHMETIC_OPS(NAME, OP)                              \
  template <typename T, typename U>                                      \
  struct Clamped##NAME##Op<                                              \
      T, U,                                                              \
      typename std::enable_if<std::is_floating_point<T>::value ||        \
                              std::is_floating_point<U>::value>::type> { \
    using result_type = typename MaxExponentPromotion<T, U>::type;       \
    template <typename V = result_type>                                  \
    static constexpr V Do(T x, U y) {                                    \
      return saturated_cast<V>(x OP y);                                  \
    }                                                                    \
  };

BASE_FLOAT_ARITHMETIC_OPS(Add, +)
BASE_FLOAT_ARITHMETIC_OPS(Sub, -)
BASE_FLOAT_ARITHMETIC_OPS(Mul, *)
BASE_FLOAT_ARITHMETIC_OPS(Div, /)

#undef BASE_FLOAT_ARITHMETIC_OPS

}  // namespace internal
}  // namespace base

#endif  // BASE_NUMERICS_CLAMPED_MATH_IMPL_H_
