// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <type_traits>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/numerics/safe_math.h"
#include "base/test/gtest_util.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(COMPILER_MSVC) && defined(ARCH_CPU_32_BITS)
#include <mmintrin.h>
#endif

using std::numeric_limits;
using base::CheckedNumeric;
using base::IsValidForType;
using base::ValueOrDieForType;
using base::ValueOrDefaultForType;
using base::CheckNum;
using base::CheckAdd;
using base::CheckSub;
using base::CheckMul;
using base::CheckDiv;
using base::CheckMod;
using base::CheckLsh;
using base::CheckRsh;
using base::checked_cast;
using base::IsValueInRangeForNumericType;
using base::IsValueNegative;
using base::SizeT;
using base::StrictNumeric;
using base::saturated_cast;
using base::strict_cast;
using base::StrictNumeric;
using base::internal::MaxExponent;
using base::internal::RANGE_VALID;
using base::internal::RANGE_INVALID;
using base::internal::RANGE_OVERFLOW;
using base::internal::RANGE_UNDERFLOW;
using base::internal::SignedIntegerForSize;

// These tests deliberately cause arithmetic boundary errors. If the compiler is
// aggressive enough, it can const detect these errors, so we disable warnings.
#if defined(OS_WIN)
#pragma warning(disable : 4756)  // Arithmetic overflow.
#pragma warning(disable : 4293)  // Invalid shift.
#endif

// This is a helper function for finding the maximum value in Src that can be
// wholy represented as the destination floating-point type.
template <typename Dst, typename Src>
Dst GetMaxConvertibleToFloat() {
  typedef numeric_limits<Dst> DstLimits;
  typedef numeric_limits<Src> SrcLimits;
  static_assert(SrcLimits::is_specialized, "Source must be numeric.");
  static_assert(DstLimits::is_specialized, "Destination must be numeric.");
  CHECK(DstLimits::is_iec559);

  if (SrcLimits::digits <= DstLimits::digits &&
      MaxExponent<Src>::value <= MaxExponent<Dst>::value)
    return SrcLimits::max();
  Src max = SrcLimits::max() / 2 + (SrcLimits::is_integer ? 1 : 0);
  while (max != static_cast<Src>(static_cast<Dst>(max))) {
    max /= 2;
  }
  return static_cast<Dst>(max);
}

namespace base {
namespace internal {
template <typename U>
U GetNumericValueForTest(const CheckedNumeric<U>& src) {
  return src.state_.value();
}
}  // namespace internal.
}  // namespace base.

using base::internal::GetNumericValueForTest;

// Logs the ValueOrDie() failure instead of crashing.
struct LogOnFailure {
  template <typename T>
  static T HandleFailure() {
    LOG(WARNING) << "ValueOrDie() failed unexpectedly.";
    return T();
  }
};

// Helper macros to wrap displaying the conversion types and line numbers.
#define TEST_EXPECTED_VALIDITY(expected, actual)                           \
  EXPECT_EQ(expected, (actual).template Cast<Dst>().IsValid())             \
      << "Result test: Value " << GetNumericValueForTest(actual) << " as " \
      << dst << " on line " << line

#define TEST_EXPECTED_SUCCESS(actual) TEST_EXPECTED_VALIDITY(true, actual)
#define TEST_EXPECTED_FAILURE(actual) TEST_EXPECTED_VALIDITY(false, actual)

#define TEST_EXPECTED_VALUE(expected, actual)                              \
  EXPECT_EQ(static_cast<Dst>(expected),                                    \
            ((actual)                                                      \
                 .template Cast<Dst>()                                     \
                 .template ValueOrDie<Dst, LogOnFailure>()))               \
      << "Result test: Value " << GetNumericValueForTest(actual) << " as " \
      << dst << " on line " << line

// Test the simple pointer arithmetic overrides.
template <typename Dst>
void TestStrictPointerMath() {
  Dst dummy_value = 0;
  Dst* dummy_ptr = &dummy_value;
  static const Dst kDummyOffset = 2;  // Don't want to go too far.
  EXPECT_EQ(dummy_ptr + kDummyOffset,
            dummy_ptr + StrictNumeric<Dst>(kDummyOffset));
  EXPECT_EQ(dummy_ptr - kDummyOffset,
            dummy_ptr - StrictNumeric<Dst>(kDummyOffset));
  EXPECT_NE(dummy_ptr, dummy_ptr + StrictNumeric<Dst>(kDummyOffset));
  EXPECT_NE(dummy_ptr, dummy_ptr - StrictNumeric<Dst>(kDummyOffset));
  EXPECT_DEATH_IF_SUPPORTED(
      dummy_ptr + StrictNumeric<size_t>(std::numeric_limits<size_t>::max()),
      "");
}

// Signed integer arithmetic.
template <typename Dst>
static void TestSpecializedArithmetic(
    const char* dst,
    int line,
    typename std::enable_if<numeric_limits<Dst>::is_integer &&
                                numeric_limits<Dst>::is_signed,
                            int>::type = 0) {
  typedef numeric_limits<Dst> DstLimits;
  TEST_EXPECTED_FAILURE(-CheckedNumeric<Dst>(DstLimits::min()));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()).Abs());
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(-1).Abs());

  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::max()) + -1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) + -1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(-DstLimits::max()) +
                        -DstLimits::max());

  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) - 1);
  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()) - -1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) -
                        -DstLimits::max());
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(-DstLimits::max()) -
                        DstLimits::max());

  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) * 2);

  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) / -1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(-1) / 2);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) * -1);

  // Modulus is legal only for integers.
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>() % 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) % 1);
  TEST_EXPECTED_VALUE(-1, CheckedNumeric<Dst>(-1) % 2);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(-1) % -2);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(DstLimits::min()) % 2);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(DstLimits::max()) % 2);
  // Test all the different modulus combinations.
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) % CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(0, 1 % CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) % 1);
  CheckedNumeric<Dst> checked_dst = 1;
  TEST_EXPECTED_VALUE(0, checked_dst %= 1);
  // Test that div by 0 is avoided but returns invalid result.
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) % 0);
  // Test bit shifts.
  volatile Dst negative_one = -1;
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) << negative_one);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) << (sizeof(Dst) * CHAR_BIT - 1));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(0) << (sizeof(Dst) * CHAR_BIT));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) << 1);
  TEST_EXPECTED_VALUE(static_cast<Dst>(1) << (sizeof(Dst) * CHAR_BIT - 2),
                      CheckedNumeric<Dst>(1) << (sizeof(Dst) * CHAR_BIT - 2));
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(0)
                             << (sizeof(Dst) * CHAR_BIT - 1));
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) << 0);
  TEST_EXPECTED_VALUE(2, CheckedNumeric<Dst>(1) << 1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) >> (sizeof(Dst) * CHAR_BIT));
  TEST_EXPECTED_VALUE(0,
                      CheckedNumeric<Dst>(1) >> (sizeof(Dst) * CHAR_BIT - 1));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) >> negative_one);

  TestStrictPointerMath<Dst>();
}

// Unsigned integer arithmetic.
template <typename Dst>
static void TestSpecializedArithmetic(
    const char* dst,
    int line,
    typename std::enable_if<numeric_limits<Dst>::is_integer &&
                                !numeric_limits<Dst>::is_signed,
                            int>::type = 0) {
  typedef numeric_limits<Dst> DstLimits;
  TEST_EXPECTED_SUCCESS(-CheckedNumeric<Dst>(DstLimits::min()));
  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()).Abs());
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) + -1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::min()) - 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(DstLimits::min()) * 2);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) / 2);
  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()).UnsignedAbs());
  TEST_EXPECTED_SUCCESS(
      CheckedNumeric<typename SignedIntegerForSize<Dst>::type>(
          std::numeric_limits<typename SignedIntegerForSize<Dst>::type>::min())
          .UnsignedAbs());

  // Modulus is legal only for integers.
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>() % 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) % 1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) % 2);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(DstLimits::min()) % 2);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(DstLimits::max()) % 2);
  // Test all the different modulus combinations.
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) % CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(0, 1 % CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) % 1);
  CheckedNumeric<Dst> checked_dst = 1;
  TEST_EXPECTED_VALUE(0, checked_dst %= 1);
  // Test that div by 0 is avoided but returns invalid result.
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) % 0);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) << (sizeof(Dst) * CHAR_BIT));
  // Test bit shifts.
  volatile int negative_one = -1;
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) << negative_one);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) << (sizeof(Dst) * CHAR_BIT));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(0) << (sizeof(Dst) * CHAR_BIT));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) << 1);
  TEST_EXPECTED_VALUE(static_cast<Dst>(1) << (sizeof(Dst) * CHAR_BIT - 1),
                      CheckedNumeric<Dst>(1) << (sizeof(Dst) * CHAR_BIT - 1));
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) << 0);
  TEST_EXPECTED_VALUE(2, CheckedNumeric<Dst>(1) << 1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) >> (sizeof(Dst) * CHAR_BIT));
  TEST_EXPECTED_VALUE(0,
                      CheckedNumeric<Dst>(1) >> (sizeof(Dst) * CHAR_BIT - 1));
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(1) >> negative_one);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) & 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) & 0);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(0) & 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) & 0);
  TEST_EXPECTED_VALUE(std::numeric_limits<Dst>::max(),
                      CheckNum(DstLimits::max()) & -1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) | 1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) | 0);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(0) | 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(0) | 0);
  TEST_EXPECTED_VALUE(std::numeric_limits<Dst>::max(),
                      CheckedNumeric<Dst>(0) | static_cast<Dst>(-1));
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) ^ 1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) ^ 0);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(0) ^ 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(0) ^ 0);
  TEST_EXPECTED_VALUE(std::numeric_limits<Dst>::max(),
                      CheckedNumeric<Dst>(0) ^ static_cast<Dst>(-1));
  TEST_EXPECTED_VALUE(DstLimits::max(), ~CheckedNumeric<Dst>(0));

  TestStrictPointerMath<Dst>();
}

// Floating point arithmetic.
template <typename Dst>
void TestSpecializedArithmetic(
    const char* dst,
    int line,
    typename std::enable_if<numeric_limits<Dst>::is_iec559, int>::type = 0) {
  typedef numeric_limits<Dst> DstLimits;
  TEST_EXPECTED_SUCCESS(-CheckedNumeric<Dst>(DstLimits::min()));

  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()).Abs());
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(-1).Abs());

  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()) + -1);
  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::max()) + 1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(-DstLimits::max()) +
                        -DstLimits::max());

  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) -
                        -DstLimits::max());
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(-DstLimits::max()) -
                        DstLimits::max());

  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()) * 2);

  TEST_EXPECTED_VALUE(-0.5, CheckedNumeric<Dst>(-1.0) / 2);
}

// Generic arithmetic tests.
template <typename Dst>
static void TestArithmetic(const char* dst, int line) {
  typedef numeric_limits<Dst> DstLimits;

  EXPECT_EQ(true, CheckedNumeric<Dst>().IsValid());
  EXPECT_EQ(false,
            CheckedNumeric<Dst>(CheckedNumeric<Dst>(DstLimits::max()) *
                                DstLimits::max()).IsValid());
  EXPECT_EQ(static_cast<Dst>(0), CheckedNumeric<Dst>().ValueOrDie());
  EXPECT_EQ(static_cast<Dst>(0), CheckedNumeric<Dst>().ValueOrDefault(1));
  EXPECT_EQ(static_cast<Dst>(1),
            CheckedNumeric<Dst>(CheckedNumeric<Dst>(DstLimits::max()) *
                                DstLimits::max()).ValueOrDefault(1));

  // Test the operator combinations.
  TEST_EXPECTED_VALUE(2, CheckedNumeric<Dst>(1) + CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) - CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) * CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) / CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(2, 1 + CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(0, 1 - CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(1, 1 * CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(1, 1 / CheckedNumeric<Dst>(1));
  TEST_EXPECTED_VALUE(2, CheckedNumeric<Dst>(1) + 1);
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>(1) - 1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) * 1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) / 1);
  CheckedNumeric<Dst> checked_dst = 1;
  TEST_EXPECTED_VALUE(2, checked_dst += 1);
  checked_dst = 1;
  TEST_EXPECTED_VALUE(0, checked_dst -= 1);
  checked_dst = 1;
  TEST_EXPECTED_VALUE(1, checked_dst *= 1);
  checked_dst = 1;
  TEST_EXPECTED_VALUE(1, checked_dst /= 1);

  // Generic negation.
  if (DstLimits::is_signed) {
    TEST_EXPECTED_VALUE(0, -CheckedNumeric<Dst>());
    TEST_EXPECTED_VALUE(-1, -CheckedNumeric<Dst>(1));
    TEST_EXPECTED_VALUE(1, -CheckedNumeric<Dst>(-1));
    TEST_EXPECTED_VALUE(static_cast<Dst>(DstLimits::max() * -1),
                        -CheckedNumeric<Dst>(DstLimits::max()));
  }

  // Generic absolute value.
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>().Abs());
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1).Abs());
  TEST_EXPECTED_VALUE(DstLimits::max(),
                      CheckedNumeric<Dst>(DstLimits::max()).Abs());

  // Generic addition.
  TEST_EXPECTED_VALUE(1, (CheckedNumeric<Dst>() + 1));
  TEST_EXPECTED_VALUE(2, (CheckedNumeric<Dst>(1) + 1));
  if (numeric_limits<Dst>::is_signed)
    TEST_EXPECTED_VALUE(0, (CheckedNumeric<Dst>(-1) + 1));
  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::min()) + 1);
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) +
                        DstLimits::max());

  // Generic subtraction.
  TEST_EXPECTED_VALUE(0, (CheckedNumeric<Dst>(1) - 1));
  TEST_EXPECTED_SUCCESS(CheckedNumeric<Dst>(DstLimits::max()) - 1);
  if (numeric_limits<Dst>::is_signed) {
    TEST_EXPECTED_VALUE(-1, (CheckedNumeric<Dst>() - 1));
    TEST_EXPECTED_VALUE(-2, (CheckedNumeric<Dst>(-1) - 1));
  } else {
    TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) - -1);
  }

  // Generic multiplication.
  TEST_EXPECTED_VALUE(0, (CheckedNumeric<Dst>() * 1));
  TEST_EXPECTED_VALUE(1, (CheckedNumeric<Dst>(1) * 1));
  TEST_EXPECTED_VALUE(0, (CheckedNumeric<Dst>(0) * 0));
  if (numeric_limits<Dst>::is_signed) {
    TEST_EXPECTED_VALUE(0, (CheckedNumeric<Dst>(-1) * 0));
    TEST_EXPECTED_VALUE(0, (CheckedNumeric<Dst>(0) * -1));
    TEST_EXPECTED_VALUE(-2, (CheckedNumeric<Dst>(-1) * 2));
  } else {
    TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) * -2);
    TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) *
                          CheckedNumeric<uintmax_t>(-2));
  }
  TEST_EXPECTED_FAILURE(CheckedNumeric<Dst>(DstLimits::max()) *
                        DstLimits::max());

  // Generic division.
  TEST_EXPECTED_VALUE(0, CheckedNumeric<Dst>() / 1);
  TEST_EXPECTED_VALUE(1, CheckedNumeric<Dst>(1) / 1);
  TEST_EXPECTED_VALUE(DstLimits::min() / 2,
                      CheckedNumeric<Dst>(DstLimits::min()) / 2);
  TEST_EXPECTED_VALUE(DstLimits::max() / 2,
                      CheckedNumeric<Dst>(DstLimits::max()) / 2);

  TestSpecializedArithmetic<Dst>(dst, line);
}

// Helper macro to wrap displaying the conversion types and line numbers.
#define TEST_ARITHMETIC(Dst) TestArithmetic<Dst>(#Dst, __LINE__)

TEST(SafeNumerics, SignedIntegerMath) {
  TEST_ARITHMETIC(int8_t);
  TEST_ARITHMETIC(int);
  TEST_ARITHMETIC(intptr_t);
  TEST_ARITHMETIC(intmax_t);
}

TEST(SafeNumerics, UnsignedIntegerMath) {
  TEST_ARITHMETIC(uint8_t);
  TEST_ARITHMETIC(unsigned int);
  TEST_ARITHMETIC(uintptr_t);
  TEST_ARITHMETIC(uintmax_t);
}

TEST(SafeNumerics, FloatingPointMath) {
  TEST_ARITHMETIC(float);
  TEST_ARITHMETIC(double);
}

// Enumerates the five different conversions types we need to test.
enum NumericConversionType {
  SIGN_PRESERVING_VALUE_PRESERVING,
  SIGN_PRESERVING_NARROW,
  SIGN_TO_UNSIGN_WIDEN_OR_EQUAL,
  SIGN_TO_UNSIGN_NARROW,
  UNSIGN_TO_SIGN_NARROW_OR_EQUAL,
};

// Template covering the different conversion tests.
template <typename Dst, typename Src, NumericConversionType conversion>
struct TestNumericConversion {};

// EXPECT_EQ wrappers providing specific detail on test failures.
#define TEST_EXPECTED_RANGE(expected, actual)                                  \
  EXPECT_EQ(expected, base::internal::DstRangeRelationToSrcRange<Dst>(actual)) \
      << "Conversion test: " << src << " value " << actual << " to " << dst    \
      << " on line " << line

template <typename Dst, typename Src>
void TestStrictComparison() {
  typedef numeric_limits<Dst> DstLimits;
  typedef numeric_limits<Src> SrcLimits;
  static_assert(StrictNumeric<Src>(SrcLimits::min()) < DstLimits::max(), "");
  static_assert(StrictNumeric<Src>(SrcLimits::min()) < SrcLimits::max(), "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::min()) >= DstLimits::max()),
                "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::min()) >= SrcLimits::max()),
                "");
  static_assert(StrictNumeric<Src>(SrcLimits::min()) <= DstLimits::max(), "");
  static_assert(StrictNumeric<Src>(SrcLimits::min()) <= SrcLimits::max(), "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::min()) > DstLimits::max()), "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::min()) > SrcLimits::max()), "");
  static_assert(StrictNumeric<Src>(SrcLimits::max()) > DstLimits::min(), "");
  static_assert(StrictNumeric<Src>(SrcLimits::max()) > SrcLimits::min(), "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::max()) <= DstLimits::min()),
                "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::max()) <= SrcLimits::min()),
                "");
  static_assert(StrictNumeric<Src>(SrcLimits::max()) >= DstLimits::min(), "");
  static_assert(StrictNumeric<Src>(SrcLimits::max()) >= SrcLimits::min(), "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::max()) < DstLimits::min()), "");
  static_assert(!(StrictNumeric<Src>(SrcLimits::max()) < SrcLimits::min()), "");
  static_assert(StrictNumeric<Src>(static_cast<Src>(1)) == static_cast<Dst>(1),
                "");
  static_assert(StrictNumeric<Src>(static_cast<Src>(1)) != static_cast<Dst>(0),
                "");
  static_assert(StrictNumeric<Src>(SrcLimits::max()) != static_cast<Dst>(0),
                "");
  static_assert(StrictNumeric<Src>(SrcLimits::max()) != DstLimits::min(), "");
  static_assert(
      !(StrictNumeric<Src>(static_cast<Src>(1)) != static_cast<Dst>(1)), "");
  static_assert(
      !(StrictNumeric<Src>(static_cast<Src>(1)) == static_cast<Dst>(0)), "");
}

template <typename Dst, typename Src>
struct TestNumericConversion<Dst, Src, SIGN_PRESERVING_VALUE_PRESERVING> {
  static void Test(const char *dst, const char *src, int line) {
    typedef numeric_limits<Src> SrcLimits;
    typedef numeric_limits<Dst> DstLimits;
                   // Integral to floating.
    static_assert((DstLimits::is_iec559 && SrcLimits::is_integer) ||
                  // Not floating to integral and...
                  (!(DstLimits::is_integer && SrcLimits::is_iec559) &&
                   // Same sign, same numeric, source is narrower or same.
                   ((SrcLimits::is_signed == DstLimits::is_signed &&
                    sizeof(Dst) >= sizeof(Src)) ||
                   // Or signed destination and source is smaller
                    (DstLimits::is_signed && sizeof(Dst) > sizeof(Src)))),
                  "Comparison must be sign preserving and value preserving");

    TestStrictComparison<Dst, Src>();

    const CheckedNumeric<Dst> checked_dst = SrcLimits::max();
    TEST_EXPECTED_SUCCESS(checked_dst);
    if (MaxExponent<Dst>::value > MaxExponent<Src>::value) {
      if (MaxExponent<Dst>::value >= MaxExponent<Src>::value * 2 - 1) {
        // At least twice larger type.
        TEST_EXPECTED_SUCCESS(SrcLimits::max() * checked_dst);

      } else {  // Larger, but not at least twice as large.
        TEST_EXPECTED_FAILURE(SrcLimits::max() * checked_dst);
        TEST_EXPECTED_SUCCESS(checked_dst + 1);
      }
    } else {  // Same width type.
      TEST_EXPECTED_FAILURE(checked_dst + 1);
    }

    TEST_EXPECTED_RANGE(RANGE_VALID, SrcLimits::max());
    TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(1));
    if (SrcLimits::is_iec559) {
      TEST_EXPECTED_RANGE(RANGE_VALID, SrcLimits::max() * static_cast<Src>(-1));
      TEST_EXPECTED_RANGE(RANGE_OVERFLOW, SrcLimits::infinity());
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::infinity() * -1);
      TEST_EXPECTED_RANGE(RANGE_INVALID, SrcLimits::quiet_NaN());
    } else if (numeric_limits<Src>::is_signed) {
      TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(-1));
      TEST_EXPECTED_RANGE(RANGE_VALID, SrcLimits::min());
    }
  }
};

template <typename Dst, typename Src>
struct TestNumericConversion<Dst, Src, SIGN_PRESERVING_NARROW> {
  static void Test(const char *dst, const char *src, int line) {
    typedef numeric_limits<Src> SrcLimits;
    typedef numeric_limits<Dst> DstLimits;
    static_assert(SrcLimits::is_signed == DstLimits::is_signed,
                  "Destination and source sign must be the same");
    static_assert(sizeof(Dst) < sizeof(Src) ||
                   (DstLimits::is_integer && SrcLimits::is_iec559),
                  "Destination must be narrower than source");

    TestStrictComparison<Dst, Src>();

    const CheckedNumeric<Dst> checked_dst;
    TEST_EXPECTED_FAILURE(checked_dst + SrcLimits::max());
    TEST_EXPECTED_VALUE(1, checked_dst + static_cast<Src>(1));
    TEST_EXPECTED_FAILURE(checked_dst - SrcLimits::max());

    TEST_EXPECTED_RANGE(RANGE_OVERFLOW, SrcLimits::max());
    TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(1));
    if (SrcLimits::is_iec559) {
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::max() * -1);
      TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(-1));
      TEST_EXPECTED_RANGE(RANGE_OVERFLOW, SrcLimits::infinity());
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::infinity() * -1);
      TEST_EXPECTED_RANGE(RANGE_INVALID, SrcLimits::quiet_NaN());
      if (DstLimits::is_integer) {
        if (SrcLimits::digits < DstLimits::digits) {
          TEST_EXPECTED_RANGE(RANGE_OVERFLOW,
                              static_cast<Src>(DstLimits::max()));
        } else {
          TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(DstLimits::max()));
        }
        TEST_EXPECTED_RANGE(
            RANGE_VALID,
            static_cast<Src>(GetMaxConvertibleToFloat<Src, Dst>()));
        TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(DstLimits::min()));
      }
    } else if (SrcLimits::is_signed) {
      TEST_EXPECTED_VALUE(-1, checked_dst - static_cast<Src>(1));
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::min());
      TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(-1));
    } else {
      TEST_EXPECTED_FAILURE(checked_dst - static_cast<Src>(1));
      TEST_EXPECTED_RANGE(RANGE_VALID, SrcLimits::min());
    }
  }
};

template <typename Dst, typename Src>
struct TestNumericConversion<Dst, Src, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL> {
  static void Test(const char *dst, const char *src, int line) {
    typedef numeric_limits<Src> SrcLimits;
    typedef numeric_limits<Dst> DstLimits;
    static_assert(sizeof(Dst) >= sizeof(Src),
                  "Destination must be equal or wider than source.");
    static_assert(SrcLimits::is_signed, "Source must be signed");
    static_assert(!DstLimits::is_signed, "Destination must be unsigned");

    TestStrictComparison<Dst, Src>();

    const CheckedNumeric<Dst> checked_dst;
    TEST_EXPECTED_VALUE(SrcLimits::max(), checked_dst + SrcLimits::max());
    TEST_EXPECTED_FAILURE(checked_dst + static_cast<Src>(-1));
    TEST_EXPECTED_FAILURE(checked_dst + -SrcLimits::max());

    TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::min());
    TEST_EXPECTED_RANGE(RANGE_VALID, SrcLimits::max());
    TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(1));
    TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, static_cast<Src>(-1));
  }
};

template <typename Dst, typename Src>
struct TestNumericConversion<Dst, Src, SIGN_TO_UNSIGN_NARROW> {
  static void Test(const char *dst, const char *src, int line) {
    typedef numeric_limits<Src> SrcLimits;
    typedef numeric_limits<Dst> DstLimits;
    static_assert((DstLimits::is_integer && SrcLimits::is_iec559) ||
                   (sizeof(Dst) < sizeof(Src)),
                  "Destination must be narrower than source.");
    static_assert(SrcLimits::is_signed, "Source must be signed.");
    static_assert(!DstLimits::is_signed, "Destination must be unsigned.");

    TestStrictComparison<Dst, Src>();

    const CheckedNumeric<Dst> checked_dst;
    TEST_EXPECTED_VALUE(1, checked_dst + static_cast<Src>(1));
    TEST_EXPECTED_FAILURE(checked_dst + SrcLimits::max());
    TEST_EXPECTED_FAILURE(checked_dst + static_cast<Src>(-1));
    TEST_EXPECTED_FAILURE(checked_dst + -SrcLimits::max());

    TEST_EXPECTED_RANGE(RANGE_OVERFLOW, SrcLimits::max());
    TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(1));
    TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, static_cast<Src>(-1));
    if (SrcLimits::is_iec559) {
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::max() * -1);
      TEST_EXPECTED_RANGE(RANGE_OVERFLOW, SrcLimits::infinity());
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::infinity() * -1);
      TEST_EXPECTED_RANGE(RANGE_INVALID, SrcLimits::quiet_NaN());
      if (DstLimits::is_integer) {
        if (SrcLimits::digits < DstLimits::digits) {
          TEST_EXPECTED_RANGE(RANGE_OVERFLOW,
                              static_cast<Src>(DstLimits::max()));
        } else {
          TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(DstLimits::max()));
        }
        TEST_EXPECTED_RANGE(
            RANGE_VALID,
            static_cast<Src>(GetMaxConvertibleToFloat<Src, Dst>()));
        TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(DstLimits::min()));
      }
    } else {
      TEST_EXPECTED_RANGE(RANGE_UNDERFLOW, SrcLimits::min());
    }
  }
};

template <typename Dst, typename Src>
struct TestNumericConversion<Dst, Src, UNSIGN_TO_SIGN_NARROW_OR_EQUAL> {
  static void Test(const char *dst, const char *src, int line) {
    typedef numeric_limits<Src> SrcLimits;
    typedef numeric_limits<Dst> DstLimits;
    static_assert(sizeof(Dst) <= sizeof(Src),
                  "Destination must be narrower or equal to source.");
    static_assert(!SrcLimits::is_signed, "Source must be unsigned.");
    static_assert(DstLimits::is_signed, "Destination must be signed.");

    TestStrictComparison<Dst, Src>();

    const CheckedNumeric<Dst> checked_dst;
    TEST_EXPECTED_VALUE(1, checked_dst + static_cast<Src>(1));
    TEST_EXPECTED_FAILURE(checked_dst + SrcLimits::max());
    TEST_EXPECTED_VALUE(SrcLimits::min(), checked_dst + SrcLimits::min());

    TEST_EXPECTED_RANGE(RANGE_VALID, SrcLimits::min());
    TEST_EXPECTED_RANGE(RANGE_OVERFLOW, SrcLimits::max());
    TEST_EXPECTED_RANGE(RANGE_VALID, static_cast<Src>(1));
  }
};

// Helper macro to wrap displaying the conversion types and line numbers
#define TEST_NUMERIC_CONVERSION(d, s, t) \
  TestNumericConversion<d, s, t>::Test(#d, #s, __LINE__)

TEST(SafeNumerics, IntMinOperations) {
  TEST_NUMERIC_CONVERSION(int8_t, int8_t, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(uint8_t, uint8_t, SIGN_PRESERVING_VALUE_PRESERVING);

  TEST_NUMERIC_CONVERSION(int8_t, int, SIGN_PRESERVING_NARROW);
  TEST_NUMERIC_CONVERSION(uint8_t, unsigned int, SIGN_PRESERVING_NARROW);
  TEST_NUMERIC_CONVERSION(int8_t, float, SIGN_PRESERVING_NARROW);

  TEST_NUMERIC_CONVERSION(uint8_t, int8_t, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL);

  TEST_NUMERIC_CONVERSION(uint8_t, int, SIGN_TO_UNSIGN_NARROW);
  TEST_NUMERIC_CONVERSION(uint8_t, intmax_t, SIGN_TO_UNSIGN_NARROW);
  TEST_NUMERIC_CONVERSION(uint8_t, float, SIGN_TO_UNSIGN_NARROW);

  TEST_NUMERIC_CONVERSION(int8_t, unsigned int, UNSIGN_TO_SIGN_NARROW_OR_EQUAL);
  TEST_NUMERIC_CONVERSION(int8_t, uintmax_t, UNSIGN_TO_SIGN_NARROW_OR_EQUAL);
}

TEST(SafeNumerics, IntOperations) {
  TEST_NUMERIC_CONVERSION(int, int, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(unsigned int, unsigned int,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(int, int8_t, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(unsigned int, uint8_t,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(int, uint8_t, SIGN_PRESERVING_VALUE_PRESERVING);

  TEST_NUMERIC_CONVERSION(int, intmax_t, SIGN_PRESERVING_NARROW);
  TEST_NUMERIC_CONVERSION(unsigned int, uintmax_t, SIGN_PRESERVING_NARROW);
  TEST_NUMERIC_CONVERSION(int, float, SIGN_PRESERVING_NARROW);
  TEST_NUMERIC_CONVERSION(int, double, SIGN_PRESERVING_NARROW);

  TEST_NUMERIC_CONVERSION(unsigned int, int, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL);
  TEST_NUMERIC_CONVERSION(unsigned int, int8_t, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL);

  TEST_NUMERIC_CONVERSION(unsigned int, intmax_t, SIGN_TO_UNSIGN_NARROW);
  TEST_NUMERIC_CONVERSION(unsigned int, float, SIGN_TO_UNSIGN_NARROW);
  TEST_NUMERIC_CONVERSION(unsigned int, double, SIGN_TO_UNSIGN_NARROW);

  TEST_NUMERIC_CONVERSION(int, unsigned int, UNSIGN_TO_SIGN_NARROW_OR_EQUAL);
  TEST_NUMERIC_CONVERSION(int, uintmax_t, UNSIGN_TO_SIGN_NARROW_OR_EQUAL);
}

TEST(SafeNumerics, IntMaxOperations) {
  TEST_NUMERIC_CONVERSION(intmax_t, intmax_t, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(uintmax_t, uintmax_t,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(intmax_t, int, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(uintmax_t, unsigned int,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(intmax_t, unsigned int,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(intmax_t, uint8_t, SIGN_PRESERVING_VALUE_PRESERVING);

  TEST_NUMERIC_CONVERSION(intmax_t, float, SIGN_PRESERVING_NARROW);
  TEST_NUMERIC_CONVERSION(intmax_t, double, SIGN_PRESERVING_NARROW);

  TEST_NUMERIC_CONVERSION(uintmax_t, int, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL);
  TEST_NUMERIC_CONVERSION(uintmax_t, int8_t, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL);

  TEST_NUMERIC_CONVERSION(uintmax_t, float, SIGN_TO_UNSIGN_NARROW);
  TEST_NUMERIC_CONVERSION(uintmax_t, double, SIGN_TO_UNSIGN_NARROW);

  TEST_NUMERIC_CONVERSION(intmax_t, uintmax_t, UNSIGN_TO_SIGN_NARROW_OR_EQUAL);
}

TEST(SafeNumerics, FloatOperations) {
  TEST_NUMERIC_CONVERSION(float, intmax_t, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(float, uintmax_t,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(float, int, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(float, unsigned int,
                          SIGN_PRESERVING_VALUE_PRESERVING);

  TEST_NUMERIC_CONVERSION(float, double, SIGN_PRESERVING_NARROW);
}

TEST(SafeNumerics, DoubleOperations) {
  TEST_NUMERIC_CONVERSION(double, intmax_t, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(double, uintmax_t,
                          SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(double, int, SIGN_PRESERVING_VALUE_PRESERVING);
  TEST_NUMERIC_CONVERSION(double, unsigned int,
                          SIGN_PRESERVING_VALUE_PRESERVING);
}

TEST(SafeNumerics, SizeTOperations) {
  TEST_NUMERIC_CONVERSION(size_t, int, SIGN_TO_UNSIGN_WIDEN_OR_EQUAL);
  TEST_NUMERIC_CONVERSION(int, size_t, UNSIGN_TO_SIGN_NARROW_OR_EQUAL);
}

// A one-off test to ensure StrictNumeric won't resolve to an incorrect type.
// If this fails we'll just get a compiler error on an ambiguous overload.
int TestOverload(int) {  // Overload fails.
  return 0;
}
uint8_t TestOverload(uint8_t) {  // Overload fails.
  return 0;
}
size_t TestOverload(size_t) {  // Overload succeeds.
  return 0;
}

static_assert(
    std::is_same<decltype(TestOverload(StrictNumeric<int>())), int>::value,
    "");
static_assert(std::is_same<decltype(TestOverload(StrictNumeric<size_t>())),
                           size_t>::value,
              "");

TEST(SafeNumerics, CastTests) {
// MSVC catches and warns that we're forcing saturation in these tests.
// Since that's intentional, we need to shut this warning off.
#if defined(COMPILER_MSVC)
#pragma warning(disable : 4756)
#endif

  int small_positive = 1;
  int small_negative = -1;
  double double_small = 1.0;
  double double_large = numeric_limits<double>::max();
  double double_infinity = numeric_limits<float>::infinity();
  double double_large_int = numeric_limits<int>::max();
  double double_small_int = numeric_limits<int>::min();

  // Just test that the casts compile, since the other tests cover logic.
  EXPECT_EQ(0, checked_cast<int>(static_cast<size_t>(0)));
  EXPECT_EQ(0, strict_cast<int>(static_cast<char>(0)));
  EXPECT_EQ(0, strict_cast<int>(static_cast<unsigned char>(0)));
  EXPECT_EQ(0U, strict_cast<unsigned>(static_cast<unsigned char>(0)));
  EXPECT_EQ(1ULL, static_cast<uint64_t>(StrictNumeric<size_t>(1U)));
  EXPECT_EQ(1ULL, static_cast<uint64_t>(SizeT(1U)));
  EXPECT_EQ(1U, static_cast<size_t>(StrictNumeric<unsigned>(1U)));

  EXPECT_TRUE(CheckedNumeric<uint64_t>(StrictNumeric<unsigned>(1U)).IsValid());
  EXPECT_TRUE(CheckedNumeric<int>(StrictNumeric<unsigned>(1U)).IsValid());
  EXPECT_FALSE(CheckedNumeric<unsigned>(StrictNumeric<int>(-1)).IsValid());

  EXPECT_TRUE(IsValueNegative(-1));
  EXPECT_TRUE(IsValueNegative(numeric_limits<int>::min()));
  EXPECT_FALSE(IsValueNegative(numeric_limits<unsigned>::min()));
  EXPECT_TRUE(IsValueNegative(-numeric_limits<double>::max()));
  EXPECT_FALSE(IsValueNegative(0));
  EXPECT_FALSE(IsValueNegative(1));
  EXPECT_FALSE(IsValueNegative(0u));
  EXPECT_FALSE(IsValueNegative(1u));
  EXPECT_FALSE(IsValueNegative(numeric_limits<int>::max()));
  EXPECT_FALSE(IsValueNegative(numeric_limits<unsigned>::max()));
  EXPECT_FALSE(IsValueNegative(numeric_limits<double>::max()));

  // These casts and coercions will fail to compile:
  // EXPECT_EQ(0, strict_cast<int>(static_cast<size_t>(0)));
  // EXPECT_EQ(0, strict_cast<size_t>(static_cast<int>(0)));
  // EXPECT_EQ(1ULL, StrictNumeric<size_t>(1));
  // EXPECT_EQ(1, StrictNumeric<size_t>(1U));

  // Test various saturation corner cases.
  EXPECT_EQ(saturated_cast<int>(small_negative),
            static_cast<int>(small_negative));
  EXPECT_EQ(saturated_cast<int>(small_positive),
            static_cast<int>(small_positive));
  EXPECT_EQ(saturated_cast<unsigned>(small_negative),
            static_cast<unsigned>(0));
  EXPECT_EQ(saturated_cast<int>(double_small),
            static_cast<int>(double_small));
  EXPECT_EQ(saturated_cast<int>(double_large), numeric_limits<int>::max());
  EXPECT_EQ(saturated_cast<float>(double_large), double_infinity);
  EXPECT_EQ(saturated_cast<float>(-double_large), -double_infinity);
  EXPECT_EQ(numeric_limits<int>::min(), saturated_cast<int>(double_small_int));
  EXPECT_EQ(numeric_limits<int>::max(), saturated_cast<int>(double_large_int));

  float not_a_number = std::numeric_limits<float>::infinity() -
                       std::numeric_limits<float>::infinity();
  EXPECT_TRUE(std::isnan(not_a_number));
  EXPECT_EQ(0, saturated_cast<int>(not_a_number));

  // Test the CheckedNumeric value extractions functions.
  auto int8_min = CheckNum(numeric_limits<int8_t>::min());
  auto int8_max = CheckNum(numeric_limits<int8_t>::max());
  auto double_max = CheckNum(numeric_limits<double>::max());
  static_assert(
      std::is_same<int16_t,
                   decltype(int8_min.ValueOrDie<int16_t>())::type>::value,
      "ValueOrDie returning incorrect type.");
  static_assert(
      std::is_same<int16_t,
                   decltype(int8_min.ValueOrDefault<int16_t>(0))::type>::value,
      "ValueOrDefault returning incorrect type.");
  EXPECT_FALSE(IsValidForType<uint8_t>(int8_min));
  EXPECT_TRUE(IsValidForType<uint8_t>(int8_max));
  EXPECT_EQ(static_cast<int>(numeric_limits<int8_t>::min()),
            ValueOrDieForType<int>(int8_min));
  EXPECT_TRUE(IsValidForType<uint32_t>(int8_max));
  EXPECT_EQ(static_cast<int>(numeric_limits<int8_t>::max()),
            ValueOrDieForType<int>(int8_max));
  EXPECT_EQ(0, ValueOrDefaultForType<int>(double_max, 0));
  uint8_t uint8_dest = 0;
  int16_t int16_dest = 0;
  double double_dest = 0;
  EXPECT_TRUE(int8_max.AssignIfValid(&uint8_dest));
  EXPECT_EQ(static_cast<uint8_t>(numeric_limits<int8_t>::max()), uint8_dest);
  EXPECT_FALSE(int8_min.AssignIfValid(&uint8_dest));
  EXPECT_TRUE(int8_max.AssignIfValid(&int16_dest));
  EXPECT_EQ(static_cast<int16_t>(numeric_limits<int8_t>::max()), int16_dest);
  EXPECT_TRUE(int8_min.AssignIfValid(&int16_dest));
  EXPECT_EQ(static_cast<int16_t>(numeric_limits<int8_t>::min()), int16_dest);
  EXPECT_FALSE(double_max.AssignIfValid(&uint8_dest));
  EXPECT_FALSE(double_max.AssignIfValid(&int16_dest));
  EXPECT_TRUE(double_max.AssignIfValid(&double_dest));
  EXPECT_EQ(numeric_limits<double>::max(), double_dest);
  EXPECT_EQ(1, checked_cast<int>(StrictNumeric<int>(1)));
  EXPECT_EQ(1, saturated_cast<int>(StrictNumeric<int>(1)));
  EXPECT_EQ(1, strict_cast<int>(StrictNumeric<int>(1)));
}

TEST(SafeNumerics, SaturatedCastChecks) {
  float not_a_number = std::numeric_limits<float>::infinity() -
                       std::numeric_limits<float>::infinity();
  EXPECT_TRUE(std::isnan(not_a_number));
  EXPECT_DEATH_IF_SUPPORTED(
      (saturated_cast<int, base::CheckOnFailure>(not_a_number)),
      "");
}

TEST(SafeNumerics, IsValueInRangeForNumericType) {
  EXPECT_TRUE(IsValueInRangeForNumericType<uint32_t>(0));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint32_t>(1));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint32_t>(2));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint32_t>(-1));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint32_t>(0xffffffffu));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint32_t>(UINT64_C(0xffffffff)));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint32_t>(UINT64_C(0x100000000)));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint32_t>(UINT64_C(0x100000001)));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint32_t>(
      std::numeric_limits<int32_t>::min()));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint32_t>(
      std::numeric_limits<int64_t>::min()));

  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(0));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(1));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(2));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(-1));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(0x7fffffff));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(0x7fffffffu));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(0x80000000u));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(0xffffffffu));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(INT64_C(0x80000000)));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(INT64_C(0xffffffff)));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(INT64_C(0x100000000)));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(
      std::numeric_limits<int32_t>::min()));
  EXPECT_TRUE(IsValueInRangeForNumericType<int32_t>(
      static_cast<int64_t>(std::numeric_limits<int32_t>::min())));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(
      static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1));
  EXPECT_FALSE(IsValueInRangeForNumericType<int32_t>(
      std::numeric_limits<int64_t>::min()));

  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(0));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(1));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(2));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint64_t>(-1));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(0xffffffffu));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(UINT64_C(0xffffffff)));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(UINT64_C(0x100000000)));
  EXPECT_TRUE(IsValueInRangeForNumericType<uint64_t>(UINT64_C(0x100000001)));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint64_t>(
      std::numeric_limits<int32_t>::min()));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint64_t>(INT64_C(-1)));
  EXPECT_FALSE(IsValueInRangeForNumericType<uint64_t>(
      std::numeric_limits<int64_t>::min()));

  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(0));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(1));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(2));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(-1));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(0x7fffffff));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(0x7fffffffu));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(0x80000000u));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(0xffffffffu));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(INT64_C(0x80000000)));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(INT64_C(0xffffffff)));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(INT64_C(0x100000000)));
  EXPECT_TRUE(
      IsValueInRangeForNumericType<int64_t>(INT64_C(0x7fffffffffffffff)));
  EXPECT_TRUE(
      IsValueInRangeForNumericType<int64_t>(UINT64_C(0x7fffffffffffffff)));
  EXPECT_FALSE(
      IsValueInRangeForNumericType<int64_t>(UINT64_C(0x8000000000000000)));
  EXPECT_FALSE(
      IsValueInRangeForNumericType<int64_t>(UINT64_C(0xffffffffffffffff)));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(
      std::numeric_limits<int32_t>::min()));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(
      static_cast<int64_t>(std::numeric_limits<int32_t>::min())));
  EXPECT_TRUE(IsValueInRangeForNumericType<int64_t>(
      std::numeric_limits<int64_t>::min()));
}

TEST(SafeNumerics, CompoundNumericOperations) {
  CheckedNumeric<int> a = 1;
  CheckedNumeric<int> b = 2;
  CheckedNumeric<int> c = 3;
  CheckedNumeric<int> d = 4;
  a += b;
  EXPECT_EQ(3, a.ValueOrDie());
  a -= c;
  EXPECT_EQ(0, a.ValueOrDie());
  d /= b;
  EXPECT_EQ(2, d.ValueOrDie());
  d *= d;
  EXPECT_EQ(4, d.ValueOrDie());

  CheckedNumeric<int> too_large = std::numeric_limits<int>::max();
  EXPECT_TRUE(too_large.IsValid());
  too_large += d;
  EXPECT_FALSE(too_large.IsValid());
  too_large -= d;
  EXPECT_FALSE(too_large.IsValid());
  too_large /= d;
  EXPECT_FALSE(too_large.IsValid());
}

TEST(SafeNumerics, VariadicNumericOperations) {
  auto a = CheckAdd(1, 2UL, CheckNum(3LL), 4).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(a)::type>(10), a);
  auto b = CheckSub(CheckNum(20.0), 2UL, 4).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(b)::type>(14.0), b);
  auto c = CheckMul(20.0, CheckNum(1), 5, 3UL).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(c)::type>(300.0), c);
  auto d = CheckDiv(20.0, 2.0, CheckNum(5LL), -4).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(d)::type>(-.5), d);
  auto e = CheckMod(CheckNum(20), 3).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(e)::type>(2), e);
  auto f = CheckLsh(1, CheckNum(2)).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(f)::type>(4), f);
  auto g = CheckRsh(4, CheckNum(2)).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(g)::type>(1), g);
  auto h = CheckRsh(CheckAdd(1, 1, 1, 1), CheckSub(4, 2)).ValueOrDie();
  EXPECT_EQ(static_cast<decltype(h)::type>(1), h);
}
