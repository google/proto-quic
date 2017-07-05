// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_NUMERICS_SAFE_CONVERSIONS_H_
#define BASE_NUMERICS_SAFE_CONVERSIONS_H_

#include <stddef.h>

#include <limits>
#include <ostream>
#include <type_traits>

#include "base/numerics/safe_conversions_impl.h"

namespace base {

// Convenience function that returns true if the supplied value is in range
// for the destination type.
template <typename Dst, typename Src>
constexpr bool IsValueInRangeForNumericType(Src value) {
  return internal::DstRangeRelationToSrcRange<Dst>(value).IsValid();
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

// as_signed<> returns the supplied integral value (or integral castable
// Numeric template) cast as a signed integral of equivalent precision.
// I.e. it's mostly an alias for: static_cast<std::make_signed<T>::type>(t)
template <typename Src>
constexpr typename std::make_signed<
    typename base::internal::UnderlyingType<Src>::type>::type
as_signed(const Src value) {
  static_assert(std::is_integral<decltype(as_signed(value))>::value,
                "Argument must be a signed or unsigned integer type.");
  return static_cast<decltype(as_signed(value))>(value);
}

// as_unsigned<> returns the supplied integral value (or integral castable
// Numeric template) cast as an unsigned integral of equivalent precision.
// I.e. it's mostly an alias for: static_cast<std::make_unsigned<T>::type>(t)
template <typename Src>
constexpr typename std::make_unsigned<
    typename base::internal::UnderlyingType<Src>::type>::type
as_unsigned(const Src value) {
  static_assert(std::is_integral<decltype(as_unsigned(value))>::value,
                "Argument must be a signed or unsigned integer type.");
  return static_cast<decltype(as_unsigned(value))>(value);
}

// Default boundaries for integral/float: max/infinity, lowest/-infinity, 0/NaN.
// You may provide your own limits (e.g. to saturated_cast) so long as you
// implement all of the static constexpr member functions in the class below.
template <typename T>
struct SaturationDefaultLimits : public std::numeric_limits<T> {
  static constexpr T NaN() {
    return std::numeric_limits<T>::has_quiet_NaN
               ? std::numeric_limits<T>::quiet_NaN()
               : T();
  }
  using std::numeric_limits<T>::max;
  static constexpr T Overflow() {
    return std::numeric_limits<T>::has_infinity
               ? std::numeric_limits<T>::infinity()
               : std::numeric_limits<T>::max();
  }
  using std::numeric_limits<T>::lowest;
  static constexpr T Underflow() {
    return std::numeric_limits<T>::has_infinity
               ? std::numeric_limits<T>::infinity() * -1
               : std::numeric_limits<T>::lowest();
  }
};

namespace internal {

template <typename Dst, template <typename> class S, typename Src>
constexpr Dst saturated_cast_impl(Src value, RangeCheck constraint) {
  // For some reason clang generates much better code when the branch is
  // structured exactly this way, rather than a sequence of checks.
  return !constraint.IsOverflowFlagSet()
             ? (!constraint.IsUnderflowFlagSet() ? static_cast<Dst>(value)
                                                 : S<Dst>::Underflow())
             // Skip this check for integral Src, which cannot be NaN.
             : (std::is_integral<Src>::value || !constraint.IsUnderflowFlagSet()
                    ? S<Dst>::Overflow()
                    : S<Dst>::NaN());
}

// saturated_cast<> is analogous to static_cast<> for numeric types, except
// that the specified numeric conversion will saturate by default rather than
// overflow or underflow, and NaN assignment to an integral will return 0.
// All boundary condition behaviors can be overriden with a custom handler.
template <typename Dst,
          template <typename> class SaturationHandler = SaturationDefaultLimits,
          typename Src>
constexpr Dst saturated_cast(Src value) {
  using SrcType = typename UnderlyingType<Src>::type;
  return saturated_cast_impl<Dst, SaturationHandler, SrcType>(
      value,
      DstRangeRelationToSrcRange<Dst, SaturationHandler, SrcType>(value));
}

// strict_cast<> is analogous to static_cast<> for numeric types, except that
// it will cause a compile failure if the destination type is not large enough
// to contain any value in the source type. It performs no runtime checking.
template <typename Dst, typename Src>
constexpr Dst strict_cast(Src value) {
  using SrcType = typename UnderlyingType<Src>::type;
  static_assert(UnderlyingType<Src>::is_numeric, "Argument must be numeric.");
  static_assert(std::is_arithmetic<Dst>::value, "Result must be numeric.");

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
  using type = T;

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

// Convience wrapper returns a StrictNumeric from the provided arithmetic type.
template <typename T>
constexpr StrictNumeric<typename UnderlyingType<T>::type> MakeStrictNum(
    const T value) {
  return value;
}

// Overload the ostream output operator to make logging work nicely.
template <typename T>
std::ostream& operator<<(std::ostream& os, const StrictNumeric<T>& value) {
  os << static_cast<T>(value);
  return os;
}

#define BASE_NUMERIC_COMPARISON_OPERATORS(CLASS, NAME, OP)              \
  template <typename L, typename R,                                     \
            typename std::enable_if<                                    \
                internal::Is##CLASS##Op<L, R>::value>::type* = nullptr> \
  constexpr bool operator OP(const L lhs, const R rhs) {                \
    return SafeCompare<NAME, typename UnderlyingType<L>::type,          \
                       typename UnderlyingType<R>::type>(lhs, rhs);     \
  }

BASE_NUMERIC_COMPARISON_OPERATORS(Strict, IsLess, <);
BASE_NUMERIC_COMPARISON_OPERATORS(Strict, IsLessOrEqual, <=);
BASE_NUMERIC_COMPARISON_OPERATORS(Strict, IsGreater, >);
BASE_NUMERIC_COMPARISON_OPERATORS(Strict, IsGreaterOrEqual, >=);
BASE_NUMERIC_COMPARISON_OPERATORS(Strict, IsEqual, ==);
BASE_NUMERIC_COMPARISON_OPERATORS(Strict, IsNotEqual, !=);

};  // namespace internal

using internal::strict_cast;
using internal::saturated_cast;
using internal::SafeUnsignedAbs;
using internal::StrictNumeric;
using internal::MakeStrictNum;
using internal::IsValueNegative;

// Explicitly make a shorter size_t alias for convenience.
using SizeT = StrictNumeric<size_t>;

}  // namespace base

#endif  // BASE_NUMERICS_SAFE_CONVERSIONS_H_
