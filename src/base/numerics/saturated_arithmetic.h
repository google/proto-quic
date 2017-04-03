// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_SATURATED_ARITHMETIC_H_
#define BASE_NUMERICS_SATURATED_ARITHMETIC_H_

#include <stdint.h>

#include <limits>

#include "base/compiler_specific.h"

#if defined(ARCH_CPU_ARM_FAMILY) && defined(ARCH_CPU_32_BITS) && \
    defined(COMPILER_GCC) && !defined(OS_NACL) && __OPTIMIZE__

// If we're building ARM 32-bit on GCC we replace the C++ versions with some
// native ARM assembly for speed.
#include "base/numerics/saturated_arithmetic_arm.h"

#else

namespace base {

ALWAYS_INLINE int32_t SaturatedAddition(int32_t a, int32_t b) {
  uint32_t ua = a;
  uint32_t ub = b;
  uint32_t result = ua + ub;

  // Can only overflow if the signed bit of the two values match. If the
  // signed bit of the result and one of the values differ it overflowed.
  // The branch compiles to a CMOVNS instruction on x86.
  if (~(ua ^ ub) & (result ^ ua) & (1 << 31))
    return std::numeric_limits<int>::max() + (ua >> 31);

  return result;
}

ALWAYS_INLINE int32_t SaturatedSubtraction(int32_t a, int32_t b) {
  uint32_t ua = a;
  uint32_t ub = b;
  uint32_t result = ua - ub;

  // Can only overflow if the signed bit of the two input values differ. If
  // the signed bit of the result and the first value differ it overflowed.
  // The branch compiles to a CMOVNS instruction on x86.
  if ((ua ^ ub) & (result ^ ua) & (1 << 31))
    return std::numeric_limits<int>::max() + (ua >> 31);

  return result;
}

ALWAYS_INLINE int32_t SaturatedNegative(int32_t a) {
  if (UNLIKELY(a == std::numeric_limits<int>::min()))
    return std::numeric_limits<int>::max();
  return -a;
}

ALWAYS_INLINE int32_t SaturatedAbsolute(int32_t a) {
  if (a >= 0)
    return a;
  return SaturatedNegative(a);
}

ALWAYS_INLINE int GetMaxSaturatedSetResultForTesting(int fractional_shift) {
  // For C version the set function maxes out to max int, this differs from
  // the ARM asm version, see saturated_arithmetic_arm.h for the equivalent asm
  // version.
  return std::numeric_limits<int>::max();
}

ALWAYS_INLINE int GetMinSaturatedSetResultForTesting(int fractional_shift) {
  return std::numeric_limits<int>::min();
}

template <int fractional_shift>
ALWAYS_INLINE int SaturatedSet(int value) {
  const int kIntMaxForLayoutUnit =
      std::numeric_limits<int>::max() >> fractional_shift;

  const int kIntMinForLayoutUnit =
      std::numeric_limits<int>::min() >> fractional_shift;

  if (value > kIntMaxForLayoutUnit)
    return std::numeric_limits<int>::max();

  if (value < kIntMinForLayoutUnit)
    return std::numeric_limits<int>::min();

  return value << fractional_shift;
}

template <int fractional_shift>
ALWAYS_INLINE int SaturatedSet(unsigned value) {
  const unsigned kIntMaxForLayoutUnit =
      std::numeric_limits<int>::max() >> fractional_shift;

  if (value >= kIntMaxForLayoutUnit)
    return std::numeric_limits<int>::max();

  return value << fractional_shift;
}

}  // namespace base

#endif  // CPU(ARM) && COMPILER(GCC)
#endif  // BASE_NUMERICS_SATURATED_ARITHMETIC_H_
