# `base/numerics`

This directory contains templates providing well-defined semantics for safely
handling a variety of numeric operations, including most common arithmetic
operations and conversions.

The public API is broken out into the following header files:

*   `checked_math.h` contains the `CheckedNumeric` template class and helper
    functions for performing arithmetic and conversion operations that detect
    errors and boundary conditions (e.g. overflow, truncation, etc.).
*   `clamped_math.h` contains the `ClampedNumeric` template class and
    helper functions for performing fast, clamped (i.e. non-sticky saturating)
    arithmetic operations and conversions.
*   `safe_conversions.h` contains the `StrictNumeric` template class and
    a collection of custom casting templates and helper functions for safely
    converting between a range of numeric types.
*   `safe_math.h` includes all of the previously mentioned headers.

*** aside
**Note:** The `Numeric` template types implicitly convert from C numeric types
and `Numeric` templates that are convertable to an underlying C numeric type.
The conversion priority for `Numeric` type coercions is:

*   `StrictNumeric` coerces to `ClampedNumeric` and `CheckedNumeric`
*   `ClampedNumeric` coerces to `CheckedNumeric` 
***

[TOC]

## Conversion functions and `StrictNumeric<>` in `safe_conversions.h`

This header includes a collection of helper `constexpr` templates for safely
performing a range of conversions, assignments, and tests.

### Safe casting templates

*   `as_signed()` - Returns the supplied integral value as a signed type of
    the same width.
*   `as_unsigned()` - Returns the supplied integral value as an unsigned type
    of the same width.
*   `checked_cast<>()` - Analogous to `static_cast<>` for numeric types, except
    that by default it will trigger a crash on an out-of-bounds conversion (e.g.
    overflow, underflow, NaN to integral) or a compile error if the conversion
    error can be detected at compile time. The crash handler can be overridden
    to perform a behavior other than crashing.
*   `saturated_cast<>()` - Analogous to `static_cast` for numeric types, except
    that it returns a saturated result when the specified numeric conversion
    would otherwise overflow or underflow. An NaN source returns 0 by
    default, but can be overridden to return a different result.
*   `strict_cast<>()` - Analogous to `static_cast` for numeric types, except
    this causes a compile failure if the destination type is not large
    enough to contain any value in the source type. It performs no runtime
    checking and thus introduces no runtime overhead.

### Other helper and conversion functions

*   `IsValueInRangeForNumericType<>()` - A convenience function that returns
    true if the type supplied to the template parameter can represent the value
    passed as an argument to the function.
*   `IsValueNegative()` - A convenience function that will accept any
    arithmetic type as an argument and will return whether the value is less
    than zero. Unsigned types always return false.
*   `SafeUnsignedAbs()` - Returns the absolute value of the supplied integer
    parameter as an unsigned result (thus avoiding an overflow if the value
    is the signed, two's complement minimum).

### `StrictNumeric<>`

`StrictNumeric<>` is a wrapper type that performs assignments and copies via
the `strict_cast` template, and can perform valid arithmetic comparisons
across any range of arithmetic types. `StrictNumeric` is the return type for
values extracted from a `CheckedNumeric` class instance. The raw numeric value
is extracted via `static_cast` to the underlying type or any type with
sufficient range to represent the underlying type.

*   `MakeStrictNum()` - Creates a new `StrictNumeric` from the underlying type
    of the supplied arithmetic or StrictNumeric type.
*   `SizeT` - Alias for `StrictNumeric<size_t>`.

## `CheckedNumeric<>` in `checked_math.h`

`CheckedNumeric<>` implements all the logic and operators for detecting integer
boundary conditions such as overflow, underflow, and invalid conversions.
The `CheckedNumeric` type implicitly converts from floating point and integer
data types, and contains overloads for basic arithmetic operations (i.e.: `+`,
`-`, `*`, `/` for all types and `%`, `<<`, `>>`, `&`, `|`, `^` for integers).
Type promotions are a slightly modified version of the [standard C/C++ numeric
promotions
](http://en.cppreference.com/w/cpp/language/implicit_conversion#Numeric_promotions)
with the two differences being that there is no default promotion to int
and bitwise logical operations always return an unsigned of the wider type.

### Members

The unary negation, increment, and decrement operators are supported, along
with the following unary arithmetic methods, which return a new
`CheckedNumeric` as a result of the operation:

*   `Abs()` - Absolute value.
*   `UnsignedAbs()` - Absolute value as an equal-width unsigned underlying type
    (valid for only integral types).
*   `Max()` - Returns whichever is greater of the current instance or argument.
    The underlying return type is whichever has the greatest magnitude.
*   `Min()` - Returns whichever is lowest of the current instance or argument.
    The underlying return type is whichever has can represent the lowest
    number in the smallest width (e.g. int8_t over unsigned, int over
    int8_t, and float over int).

The following are for converting `CheckedNumeric` instances:

*   `type` - The underlying numeric type.
*   `AssignIfValid()` - Assigns the underlying value to the supplied
    destination pointer if the value is currently valid and within the
    range supported by the destination type. Returns true on success.
*   `Cast<>()` - Instance method returning a `CheckedNumeric` derived from
    casting the current instance to a `CheckedNumeric` of the supplied
    destination type.

*** aside
The following member functions return a `StrictNumeric`, which is valid for
comparison and assignment operations, but will trigger a compile failure on
attempts to assign to a type of insufficient range. The underlying value can
be extracted by an explicit `static_cast` to the underlying type or any type
with sufficient range to represent the underlying type.
***

*   `IsValid()` - Returns true if the underlying numeric value is valid (i.e.
    has not wrapped or saturated and is not the result of an invalid
    conversion).
*   `ValueOrDie()` - Returns the underlying value. If the state is not valid
    this call will trigger a crash by default (but may be overridden by
    supplying an alternate handler to the template).
*   `ValueOrDefault()` - Returns the current value, or the supplied default if
    the state is not valid (but will not crash).

**Comparison operators are explicitly not provided** for `CheckedNumeric`
types because they could result in a crash if the type is not in a valid state.
Patterns like the following should be used instead:

```cpp
CheckedNumeric<size_t> checked_size = untrusted_input_value;
checked_size += HEADER LENGTH;
if (checked_size.IsValid() && checked_size.ValueOrDie() < buffer_size) {
  \\ Do stuff on success...
} else {
  \\ Handle an error...
}
```

### Non-member helper functions

The following variadic convenience functions, which accept standard arithmetic
or `CheckedNumeric` types, perform arithmetic operations, and return a
`CheckedNumeric` result. The supported functions are:

*   `CheckAdd()` - Addition.
*   `CheckSub()` - Subtraction.
*   `CheckMul()` - Multiplication.
*   `CheckDiv()` - Division.
*   `CheckMod()` - Modulus (integer only).
*   `CheckLsh()` - Left integer shift (integer only).
*   `CheckRsh()` - Right integer shift (integer only).
*   `CheckAnd()` - Bitwise AND (integer only with unsigned result).
*   `CheckOr()`  - Bitwise OR (integer only with unsigned result).
*   `CheckXor()` - Bitwise XOR (integer only with unsigned result).
*   `CheckMax()` - Maximum of supplied arguments.
*   `CheckMin()` - Minimum of supplied arguments.

The following wrapper functions can be used to avoid the template
disambiguator syntax when converting a destination type.

*   `IsValidForType<>()` in place of: `a.template IsValid<>()`
*   `ValueOrDieForType<>()` in place of: `a.template ValueOrDie<>()`
*   `ValueOrDefaultForType<>()` in place of: `a.template ValueOrDefault<>()`

The following general utility methods is are useful for converting from
arithmetic types to `CheckedNumeric` types:

*   `MakeCheckedNum()` - Creates a new `CheckedNumeric` from the underlying type
    of the supplied arithmetic or directly convertible type.

## `ClampedNumeric<>` in `clamped_math.h`

`ClampedNumeric<>` implements all the logic and operators for clamped
(non-sticky saturating) arithmetic operations and conversions. The
`ClampedNumeric` type implicitly converts back and forth between floating point
and integer data types, saturating on assignment as appropriate. It contains
overloads for basic arithmetic operations (i.e.: `+`, `-`, `*`, `/` for
all types and `%`, `<<`, `>>`, `&`, `|`, `^` for integers) along with comparison
operators for arithmetic types of any size. Type promotions are a slightly
modified version of the [standard C/C++ numeric promotions
](http://en.cppreference.com/w/cpp/language/implicit_conversion#Numeric_promotions)
with the two differences being that there is no default promotion to int and
bitwise logical operations always return an unsigned of the wider type.

*** aside
Most arithmetic operations saturate normally, to the numeric limit in the
direction of the sign. The potentially unusual cases are:

*   **Division:** Division by zero returns the saturated limit in the direction
    of sign of the dividend (first argument). The one exception is 0/0, which
	returns zero (although logically is NaN).
*   **Modulus:** Division by zero returns the dividend (first argument).
*   **Left shift:** Non-zero values saturate in the direction of the signed
    limit (max/min), even for shifts larger than the bit width. 0 shifted any
    amount results in 0.
*   **Right shift:** Negative values saturate to -1. Positive or 0 saturates
    to 0.
*   **Bitwise operations:** No saturation; bit pattern is identical to
    non-saturated bitwise operations.
***

### Members

The unary negation, increment, and decrement operators are supported, along
with the following unary arithmetic methods, which return a new
`ClampedNumeric` as a result of the operation:

*   `Abs()` - Absolute value.
*   `UnsignedAbs()` - Absolute value as an equal-width unsigned underlying type
    (valid for only integral types).
*   `Max()` - Returns whichever is greater of the current instance or argument.
    The underlying return type is whichever has the greatest magnitude.
*   `Min()` - Returns whichever is lowest of the current instance or argument.
    The underlying return type is whichever has can represent the lowest
    number in the smallest width (e.g. int8_t over unsigned, int over
    int8_t, and float over int).

The following are for converting `ClampedNumeric` instances:

*   `type` - The underlying numeric type.
*   `Cast<>()` - Instance method returning a `ClampedNumeric` derived from
    casting the current instance to a `ClampedNumeric` of the supplied
    destination type.

### Non-member helper functions

The following variadic convenience functions, which accept standard arithmetic
or `ClampedNumeric` types, perform arithmetic operations, and return a
`ClampedNumeric` result. The supported functions are:

*   `ClampAdd()` - Addition.
*   `ClampSub()` - Subtraction.
*   `ClampMul()` - Multiplication.
*   `ClampDiv()` - Division.
*   `ClampMod()` - Modulus (integer only).
*   `ClampLsh()` - Left integer shift (integer only).
*   `ClampRsh()` - Right integer shift (integer only).
*   `ClampAnd()` - Bitwise AND (integer only with unsigned result).
*   `ClampOr()`  - Bitwise OR (integer only with unsigned result).
*   `ClampXor()` - Bitwise XOR (integer only with unsigned result).
*   `ClampMax()` - Maximum of supplied arguments.
*   `ClampMin()` - Minimum of supplied arguments.

The following is a general utility method that is useful for converting
to a `ClampedNumeric` type:

*   `MakeClampedNum()` - Creates a new `ClampedNumeric` from the underlying type
    of the supplied arithmetic or directly convertible type.
