// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_SAFE_CONVERSIONS_H_
#define BASE_NUMERICS_SAFE_CONVERSIONS_H_

#include <stddef.h>

#include <cassert>
#include <limits>
#include <ostream>
#include <type_traits>

#include "base/numerics/safe_conversions_impl.h"

namespace base {

// The following are helper constexpr template functions and classes for safely
// performing a range of conversions, assignments, and tests:
//
//  checked_cast<> - Analogous to static_cast<> for numeric types, except
//      that it CHECKs that the specified numeric conversion will not overflow
//      or underflow. NaN source will always trigger a CHECK.
//      The default CHECK triggers a crash, but the handler can be overriden.
//  saturated_cast<> - Analogous to static_cast<> for numeric types, except
//      that it returns a saturated result when the specified numeric conversion
//      would otherwise overflow or underflow. An NaN source returns 0 by
//      default, but can be overridden to return a different result.
//  strict_cast<> - Analogous to static_cast<> for numeric types, except that
//      it will cause a compile failure if the destination type is not large
//      enough to contain any value in the source type. It performs no runtime
//      checking and thus introduces no runtime overhead.
//  IsValueInRangeForNumericType<>() - A convenience function that returns true
//      if the type supplied to the template parameter can represent the value
//      passed as an argument to the function.
//  IsValueNegative<>() - A convenience function that will accept any arithmetic
//      type as an argument and will return whether the value is less than zero.
//      Unsigned types always return false.
//  StrictNumeric<> - A wrapper type that performs assignments and copies via
//      the strict_cast<> template, and can perform valid arithmetic comparisons
//      across any range of arithmetic types. StrictNumeric is the return type
//      for values extracted from a CheckedNumeric class instance. The raw
//      arithmetic value is extracted via static_cast to the underlying type.

// Convenience function that returns true if the supplied value is in range
// for the destination type.
template <typename Dst, typename Src>
constexpr bool IsValueInRangeForNumericType(Src value) {
  return internal::DstRangeRelationToSrcRange<Dst>(value) ==
         internal::RANGE_VALID;
}

// Convenience function for determining if a numeric value is negative without
// throwing compiler warnings on: unsigned(value) < 0.
template <typename T>
constexpr typename std::enable_if<std::numeric_limits<T>::is_signed, bool>::type
IsValueNegative(T value) {
  static_assert(std::numeric_limits<T>::is_specialized,
                "Argument must be numeric.");
  return value < 0;
}

template <typename T>
constexpr typename std::enable_if<!std::numeric_limits<T>::is_signed,
                                  bool>::type IsValueNegative(T) {
  static_assert(std::numeric_limits<T>::is_specialized,
                "Argument must be numeric.");
  return false;
}

// Forces a crash, like a CHECK(false). Used for numeric boundary errors.
struct CheckOnFailure {
  template <typename T>
  static T HandleFailure() {
#if defined(__GNUC__) || defined(__clang__)
    __builtin_trap();
#else
    ((void)(*(volatile char*)0 = 0));
#endif
    return T();
  }
};

// checked_cast<> is analogous to static_cast<> for numeric types,
// except that it CHECKs that the specified numeric conversion will not
// overflow or underflow. NaN source will always trigger a CHECK.
template <typename Dst,
          class CheckHandler = CheckOnFailure,
          typename Src>
constexpr Dst checked_cast(Src value) {
  // This throws a compile-time error on evaluating the constexpr if it can be
  // determined at compile-time as failing, otherwise it will CHECK at runtime.
  using SrcType = typename internal::UnderlyingType<Src>::type;
  return IsValueInRangeForNumericType<Dst, SrcType>(value)
             ? static_cast<Dst>(static_cast<SrcType>(value))
             : CheckHandler::template HandleFailure<Dst>();
}

// HandleNaN will return 0 in this case.
struct SaturatedCastNaNBehaviorReturnZero {
  template <typename T>
  static constexpr T HandleFailure() {
    return T();
  }
};

namespace internal {
// This wrapper is used for C++11 constexpr support by avoiding the declaration
// of local variables in the saturated_cast template function.
// TODO(jschuh): convert this back to a switch once we support C++14.
template <typename Dst, class NaNHandler, typename Src>
constexpr Dst saturated_cast_impl(const Src value,
                                  const RangeConstraint constraint) {
  return constraint == RANGE_VALID
             ? static_cast<Dst>(value)
             : (constraint == RANGE_UNDERFLOW
                    ? std::numeric_limits<Dst>::min()
                    : (constraint == RANGE_OVERFLOW
                           ? std::numeric_limits<Dst>::max()
                           : NaNHandler::template HandleFailure<Dst>()));
}

// saturated_cast<> is analogous to static_cast<> for numeric types, except
// that the specified numeric conversion will saturate rather than overflow or
// underflow. NaN assignment to an integral will defer the behavior to a
// specified class. By default, it will return 0.
template <typename Dst,
          class NaNHandler = SaturatedCastNaNBehaviorReturnZero,
          typename Src>
constexpr Dst saturated_cast(Src value) {
  using SrcType = typename UnderlyingType<Src>::type;
  return std::numeric_limits<Dst>::is_iec559
             ? static_cast<Dst>(
                   static_cast<SrcType>(value))  // Floating point optimization.
             : internal::saturated_cast_impl<Dst, NaNHandler>(
                   value,
                   internal::DstRangeRelationToSrcRange<Dst, SrcType>(value));
}

// strict_cast<> is analogous to static_cast<> for numeric types, except that
// it will cause a compile failure if the destination type is not large enough
// to contain any value in the source type. It performs no runtime checking.
template <typename Dst, typename Src>
constexpr Dst strict_cast(Src value) {
  using SrcType = typename UnderlyingType<Src>::type;
  static_assert(UnderlyingType<Src>::is_numeric, "Argument must be numeric.");
  static_assert(std::numeric_limits<Dst>::is_specialized,
                "Result must be numeric.");

  // If you got here from a compiler error, it's because you tried to assign
  // from a source type to a destination type that has insufficient range.
  // The solution may be to change the destination type you're assigning to,
  // and use one large enough to represent the source.
  // Alternatively, you may be better served with the checked_cast<> or
  // saturated_cast<> template functions for your particular use case.
  static_assert(StaticDstRangeRelationToSrcRange<Dst, SrcType>::value ==
                    NUMERIC_RANGE_CONTAINED,
                "The source type is out of range for the destination type. "
                "Please see strict_cast<> comments for more information.");

  return static_cast<Dst>(static_cast<SrcType>(value));
}

// Some wrappers to statically check that a type is in range.
template <typename Dst, typename Src, class Enable = void>
struct IsNumericRangeContained {
  static const bool value = false;
};

template <typename Dst, typename Src>
struct IsNumericRangeContained<
    Dst,
    Src,
    typename std::enable_if<ArithmeticOrUnderlyingEnum<Dst>::value &&
                            ArithmeticOrUnderlyingEnum<Src>::value>::type> {
  static const bool value = StaticDstRangeRelationToSrcRange<Dst, Src>::value ==
                            NUMERIC_RANGE_CONTAINED;
};

// StrictNumeric implements compile time range checking between numeric types by
// wrapping assignment operations in a strict_cast. This class is intended to be
// used for function arguments and return types, to ensure the destination type
// can always contain the source type. This is essentially the same as enforcing
// -Wconversion in gcc and C4302 warnings on MSVC, but it can be applied
// incrementally at API boundaries, making it easier to convert code so that it
// compiles cleanly with truncation warnings enabled.
// This template should introduce no runtime overhead, but it also provides no
// runtime checking of any of the associated mathematical operations. Use
// CheckedNumeric for runtime range checks of the actual value being assigned.
template <typename T>
class StrictNumeric {
 public:
  typedef T type;

  constexpr StrictNumeric() : value_(0) {}

  // Copy constructor.
  template <typename Src>
  constexpr StrictNumeric(const StrictNumeric<Src>& rhs)
      : value_(strict_cast<T>(rhs.value_)) {}

  // This is not an explicit constructor because we implicitly upgrade regular
  // numerics to StrictNumerics to make them easier to use.
  template <typename Src>
  constexpr StrictNumeric(Src value)  // NOLINT(runtime/explicit)
      : value_(strict_cast<T>(value)) {}

  // If you got here from a compiler error, it's because you tried to assign
  // from a source type to a destination type that has insufficient range.
  // The solution may be to change the destination type you're assigning to,
  // and use one large enough to represent the source.
  // If you're assigning from a CheckedNumeric<> class, you may be able to use
  // the AssignIfValid() member function, specify a narrower destination type to
  // the member value functions (e.g. val.template ValueOrDie<Dst>()), use one
  // of the value helper functions (e.g. ValueOrDieForType<Dst>(val)).
  // If you've encountered an _ambiguous overload_ you can use a static_cast<>
  // to explicitly cast the result to the destination type.
  // If none of that works, you may be better served with the checked_cast<> or
  // saturated_cast<> template functions for your particular use case.
  template <typename Dst,
            typename std::enable_if<
                IsNumericRangeContained<Dst, T>::value>::type* = nullptr>
  constexpr operator Dst() const {
    return static_cast<typename ArithmeticOrUnderlyingEnum<Dst>::type>(value_);
  }

 private:
  const T value_;
};

// Overload the ostream output operator to make logging work nicely.
template <typename T>
std::ostream& operator<<(std::ostream& os, const StrictNumeric<T>& value) {
  os << static_cast<T>(value);
  return os;
}

#define STRICT_COMPARISON_OP(NAME, OP)                               \
  template <typename L, typename R,                                  \
            typename std::enable_if<                                 \
                internal::IsStrictOp<L, R>::value>::type* = nullptr> \
  constexpr bool operator OP(const L lhs, const R rhs) {             \
    return SafeCompare<NAME, typename UnderlyingType<L>::type,       \
                       typename UnderlyingType<R>::type>(lhs, rhs);  \
  }

STRICT_COMPARISON_OP(IsLess, <);
STRICT_COMPARISON_OP(IsLessOrEqual, <=);
STRICT_COMPARISON_OP(IsGreater, >);
STRICT_COMPARISON_OP(IsGreaterOrEqual, >=);
STRICT_COMPARISON_OP(IsEqual, ==);
STRICT_COMPARISON_OP(IsNotEqual, !=);

#undef STRICT_COMPARISON_OP
};

using internal::strict_cast;
using internal::saturated_cast;
using internal::StrictNumeric;

// Explicitly make a shorter size_t typedef for convenience.
typedef StrictNumeric<size_t> SizeT;

}  // namespace base

#endif  // BASE_NUMERICS_SAFE_CONVERSIONS_H_
