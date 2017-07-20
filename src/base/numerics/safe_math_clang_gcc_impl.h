// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_SAFE_MATH_CLANG_GCC_IMPL_H_
#define BASE_NUMERICS_SAFE_MATH_CLANG_GCC_IMPL_H_

#include <cassert>
#include <limits>
#include <type_traits>

#include "base/numerics/safe_conversions.h"

#if !defined(__native_client__) && (defined(__ARMEL__) || defined(__arch64__))
#include "base/numerics/safe_math_arm_impl.h"
#define BASE_HAS_ASSEMBLER_SAFE_MATH (1)
#else
#define BASE_HAS_ASSEMBLER_SAFE_MATH (0)
#endif

namespace base {
namespace internal {

// These are the non-functioning boilerplate implementations of the optimized
// safe math routines.
#if !BASE_HAS_ASSEMBLER_SAFE_MATH
template <typename T, typename U>
struct CheckedMulFastAsmOp {
  static const bool is_supported = false;
  template <typename V>
  static constexpr bool Do(T, U, V*) {
    // Force a compile failure if instantiated.
    return CheckOnFailure::template HandleFailure<bool>();
  }
};

template <typename T, typename U>
struct ClampedAddFastAsmOp {
  static const bool is_supported = false;
  template <typename V>
  static constexpr V Do(T, U) {
    // Force a compile failure if instantiated.
    return CheckOnFailure::template HandleFailure<V>();
  }
};

template <typename T, typename U>
struct ClampedSubFastAsmOp {
  static const bool is_supported = false;
  template <typename V>
  static constexpr V Do(T, U) {
    // Force a compile failure if instantiated.
    return CheckOnFailure::template HandleFailure<V>();
  }
};

template <typename T, typename U>
struct ClampedMulFastAsmOp {
  static const bool is_supported = false;
  template <typename V>
  static constexpr V Do(T, U) {
    // Force a compile failure if instantiated.
    return CheckOnFailure::template HandleFailure<V>();
  }
};
#endif  // BASE_HAS_ASSEMBLER_SAFE_MATH
#undef BASE_HAS_ASSEMBLER_SAFE_MATH

template <typename T, typename U>
struct CheckedAddFastOp {
  static const bool is_supported = true;
  template <typename V>
  __attribute__((always_inline)) static constexpr bool Do(T x, U y, V* result) {
    return !__builtin_add_overflow(x, y, result);
  }
};

template <typename T, typename U>
struct CheckedSubFastOp {
  static const bool is_supported = true;
  template <typename V>
  __attribute__((always_inline)) static constexpr bool Do(T x, U y, V* result) {
    return !__builtin_sub_overflow(x, y, result);
  }
};

template <typename T, typename U>
struct CheckedMulFastOp {
#if defined(__clang__)
  // TODO(jschuh): Get the Clang runtime library issues sorted out so we can
  // support full-width, mixed-sign multiply builtins.
  // https://crbug.com/613003
  // We can support intptr_t, uintptr_t, or a smaller common type.
  static const bool is_supported =
      (IsTypeInRangeForNumericType<intptr_t, T>::value &&
       IsTypeInRangeForNumericType<intptr_t, U>::value) ||
      (IsTypeInRangeForNumericType<uintptr_t, T>::value &&
       IsTypeInRangeForNumericType<uintptr_t, U>::value);
#else
  static const bool is_supported = true;
#endif
  template <typename V>
  __attribute__((always_inline)) static constexpr bool Do(T x, U y, V* result) {
    return (!IsCompileTimeConstant(x) && !IsCompileTimeConstant(y)) &&
                   CheckedMulFastAsmOp<T, U>::is_supported
               ? CheckedMulFastAsmOp<T, U>::Do(x, y, result)
               : !__builtin_mul_overflow(x, y, result);
  }
};

template <typename T, typename U>
struct ClampedAddFastOp {
  static const bool is_supported = true;
  template <typename V>
  static V Do(T x, U y) {
    if ((!IsCompileTimeConstant(x) || !IsCompileTimeConstant(y)) &&
        ClampedAddFastAsmOp<T, U>::is_supported) {
      return ClampedAddFastAsmOp<T, U>::template Do<V>(x, y);
    }

    V result;
    return !__builtin_add_overflow(x, y, &result)
               ? result
               : GetMaxOrMin<V>(IsCompileTimeConstant(x) ? IsValueNegative(x)
                                                         : IsValueNegative(y));
  }
};

// This is the fastest negation on Intel, and a decent fallback on arm.
__attribute__((always_inline)) inline int8_t ClampedNegate(uint8_t value) {
  uint8_t carry;
  return __builtin_subcb(0, value, 0, &carry) + carry;
}

__attribute__((always_inline)) inline int8_t ClampedNegate(int8_t value) {
  return ClampedNegate(static_cast<uint8_t>(value));
}

__attribute__((always_inline)) inline int16_t ClampedNegate(uint16_t value) {
  uint16_t carry;
  return __builtin_subcs(0, value, 0, &carry) + carry;
}

__attribute__((always_inline)) inline int16_t ClampedNegate(int16_t value) {
  return ClampedNegate(static_cast<uint16_t>(value));
}

__attribute__((always_inline)) inline int32_t ClampedNegate(uint32_t value) {
  uint32_t carry;
  return __builtin_subc(0, value, 0, &carry) + carry;
}

__attribute__((always_inline)) inline int32_t ClampedNegate(int32_t value) {
  return ClampedNegate(static_cast<uint32_t>(value));
}

// These are the LP64 platforms minus Mac (because Xcode blows up otherwise).
#if !defined(__APPLE__) && defined(__LP64__) && __LP64__
__attribute__((always_inline)) inline int64_t ClampedNegate(uint64_t value) {
  uint64_t carry;
  return __builtin_subcl(0, value, 0, &carry) + carry;
}
#else  // Mac, Windows, and any IL32 platforms.
__attribute__((always_inline)) inline int64_t ClampedNegate(uint64_t value) {
  uint64_t carry;
  return __builtin_subcll(0, value, 0, &carry) + carry;
}
#endif
__attribute__((always_inline)) inline int64_t ClampedNegate(int64_t value) {
  return ClampedNegate(static_cast<uint64_t>(value));
}

template <typename T, typename U>
struct ClampedSubFastOp {
  static const bool is_supported = true;
  template <typename V>
  static V Do(T x, U y) {
    if ((!IsCompileTimeConstant(x) || !IsCompileTimeConstant(y)) &&
        ClampedSubFastAsmOp<T, U>::is_supported) {
      return ClampedSubFastAsmOp<T, U>::template Do<V>(x, y);
    }

    // Fast path for generic clamped negation.
    if (std::is_same<T, U>::value && std::is_same<U, V>::value &&
        IsCompileTimeConstant(x) && x == 0 && !IsCompileTimeConstant(y)) {
      // We use IntegerForDigitsAndSign<> to convert the type to a uint*_t,
      // otherwise Xcode can't resolve to the standard integral types correctly.
      return ClampedNegate(
          static_cast<typename IntegerForDigitsAndSign<
              IntegerBitsPlusSign<T>::value, std::is_signed<T>::value>::type>(
              y));
    }

    V result;
    return !__builtin_sub_overflow(x, y, &result)
               ? result
               : GetMaxOrMin<V>(IsCompileTimeConstant(x) ? IsValueNegative(x)
                                                         : !IsValueNegative(y));
  }
};

template <typename T, typename U>
struct ClampedMulFastOp {
  static const bool is_supported = CheckedMulFastOp<T, U>::is_supported;
  template <typename V>
  static V Do(T x, U y) {
    if ((!IsCompileTimeConstant(x) && !IsCompileTimeConstant(y)) &&
        ClampedMulFastAsmOp<T, U>::is_supported) {
      return ClampedMulFastAsmOp<T, U>::template Do<V>(x, y);
    }

    V result;
    return CheckedMulFastOp<T, U>::Do(x, y, &result)
               ? result
               : GetMaxOrMin<V>(IsValueNegative(x) ^ IsValueNegative(y));
  }
};

template <typename T>
struct ClampedAbsFastOp {
// The generic code is pretty much optimal on arm, so we use it instead.
#if defined(__ARMEL__) || defined(__arch64__)
  static const bool is_supported = false;
#else
  static const bool is_supported = std::is_signed<T>::value;
#endif
  static T Do(T value) {
    // This variable assignment is necessary to prevent the compiler from
    // emitting longer, ugly, branchy code.
    T negated = ClampedSubFastOp<T, T>::template Do<T>(T(0), value);
    return IsValueNegative(value) ? negated : value;
  }
};

}  // namespace internal
}  // namespace base

#endif  // BASE_NUMERICS_SAFE_MATH_CLANG_GCC_IMPL_H_
