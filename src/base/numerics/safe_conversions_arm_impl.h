// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_SAFE_CONVERSIONS_ARM_IMPL_H_
#define BASE_NUMERICS_SAFE_CONVERSIONS_ARM_IMPL_H_

#include <cassert>
#include <limits>
#include <type_traits>

#include "base/numerics/safe_conversions_impl.h"

namespace base {
namespace internal {

template <typename Dst, typename Src, typename Enable = void>
struct IsValueInRangeFastOp {
  static const bool is_supported = false;
  static constexpr bool Do(Src value) {
    // Force a compile failure if instantiated.
    return CheckOnFailure::template HandleFailure<bool>();
  }
};

// This signed range comparison is faster on arm than the normal boundary
// checking due to the arm instructions for fixed shift operations.
template <typename Dst, typename Src>
struct IsValueInRangeFastOp<
    Src,
    Dst,
    typename std::enable_if<
        std::is_integral<Dst>::value && std::is_integral<Src>::value &&
        std::is_signed<Dst>::value == std::is_signed<Src>::value &&
        !IsTypeInRangeForNumericType<Dst, Src>::value>::type> {
  static const bool is_supported = true;

  __attribute__((always_inline)) static constexpr bool Do(Src value) {
    return (value >> IntegerBitsPlusSign<Dst>::value) ==
           (std::is_signed<Src>::value
                ? (value >> (IntegerBitsPlusSign<Src>::value - 1))
                : Src(0));
  }
};

// Fast saturation to a destination type.
template <typename Dst, typename Src>
struct SaturateFastAsmOp {
  static const bool is_supported =
      std::is_signed<Src>::value && std::is_integral<Dst>::value &&
      std::is_integral<Src>::value &&
      IntegerBitsPlusSign<Src>::value <= IntegerBitsPlusSign<int32_t>::value &&
      IntegerBitsPlusSign<Dst>::value <= IntegerBitsPlusSign<int32_t>::value &&
      !IsTypeInRangeForNumericType<Dst, Src>::value;

  __attribute__((always_inline)) static Dst Do(Src value) {
    int32_t src = value;
    typename std::conditional<std::is_signed<Dst>::value, int32_t,
                              uint32_t>::type result;
    if (std::is_signed<Dst>::value) {
      asm("ssat %[dst], %[shift], %[src]"
          : [dst] "=r"(result)
          : [src] "r"(src), [shift] "n"(IntegerBitsPlusSign<Dst>::value <= 32
                                            ? IntegerBitsPlusSign<Dst>::value
                                            : 32));
    } else {
      asm("usat %[dst], %[shift], %[src]"
          : [dst] "=r"(result)
          : [src] "r"(src), [shift] "n"(IntegerBitsPlusSign<Dst>::value < 32
                                            ? IntegerBitsPlusSign<Dst>::value
                                            : 31));
    }
    return static_cast<Dst>(result);
  }
};

}  // namespace internal
}  // namespace base

#endif  // BASE_NUMERICS_SAFE_CONVERSIONS_ARM_IMPL_H_
