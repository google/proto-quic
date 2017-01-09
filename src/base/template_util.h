// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEMPLATE_UTIL_H_
#define BASE_TEMPLATE_UTIL_H_

#include <stddef.h>
#include <iosfwd>
#include <type_traits>
#include <utility>

#include "build/build_config.h"

// This hacks around libstdc++ 4.6 missing stuff in type_traits, while we need
// to support it.
#define CR_GLIBCXX_4_7_0 20120322
#define CR_GLIBCXX_4_5_4 20120702
#define CR_GLIBCXX_4_6_4 20121127
#if defined(__GLIBCXX__) &&                                               \
    (__GLIBCXX__ < CR_GLIBCXX_4_7_0 || __GLIBCXX__ == CR_GLIBCXX_4_5_4 || \
     __GLIBCXX__ == CR_GLIBCXX_4_6_4)
#define CR_USE_FALLBACKS_FOR_OLD_GLIBCXX
#endif

// Some versions of libstdc++ have partial support for type_traits, but misses
// a smaller subset while removing some of the older non-standard stuff. Assume
// that all versions below 5.0 fall in this category, along with one 5.0
// experimental release. Test for this by consulting compiler major version,
// the only reliable option available, so theoretically this could fail should
// you attempt to mix an earlier version of libstdc++ with >= GCC5. But
// that's unlikely to work out, especially as GCC5 changed ABI.
#define CR_GLIBCXX_5_0_0 20150123
#if (defined(__GNUC__) && __GNUC__ < 5) || \
    (defined(__GLIBCXX__) && __GLIBCXX__ == CR_GLIBCXX_5_0_0)
#define CR_USE_FALLBACKS_FOR_OLD_EXPERIMENTAL_GLIBCXX
#endif

// This hacks around using gcc with libc++ which has some incompatibilies.
// - is_trivially_* doesn't work: https://llvm.org/bugs/show_bug.cgi?id=27538
// TODO(danakj): Remove this when android builders are all using a newer version
// of gcc, or the android ndk is updated to a newer libc++ that works with older
// gcc versions.
#if !defined(__clang__) && defined(_LIBCPP_VERSION)
#define CR_USE_FALLBACKS_FOR_GCC_WITH_LIBCXX
#endif

namespace base {

template <class T> struct is_non_const_reference : std::false_type {};
template <class T> struct is_non_const_reference<T&> : std::true_type {};
template <class T> struct is_non_const_reference<const T&> : std::false_type {};

// is_assignable

namespace internal {

template <typename First, typename Second>
struct SelectSecond {
  using type = Second;
};

struct Any {
  Any(...);
};

// True case: If |Lvalue| can be assigned to from |Rvalue|, then the return
// value is a true_type.
template <class Lvalue, class Rvalue>
typename internal::SelectSecond<
    decltype((std::declval<Lvalue>() = std::declval<Rvalue>())),
    std::true_type>::type
IsAssignableTest(Lvalue&&, Rvalue&&);

// False case: Otherwise the return value is a false_type.
template <class Rvalue>
std::false_type IsAssignableTest(internal::Any, Rvalue&&);

// Default case: Neither Lvalue nor Rvalue is void. Uses IsAssignableTest to
// determine the type of IsAssignableImpl.
template <class Lvalue,
          class Rvalue,
          bool = std::is_void<Lvalue>::value || std::is_void<Rvalue>::value>
struct IsAssignableImpl
    : public std::common_type<decltype(
          internal::IsAssignableTest(std::declval<Lvalue>(),
                                     std::declval<Rvalue>()))>::type {};

// Void case: Either Lvalue or Rvalue is void. Then the type of IsAssignableTest
// is false_type.
template <class Lvalue, class Rvalue>
struct IsAssignableImpl<Lvalue, Rvalue, true> : public std::false_type {};

// Uses expression SFINAE to detect whether using operator<< would work.
template <typename T, typename = void>
struct SupportsOstreamOperator : std::false_type {};
template <typename T>
struct SupportsOstreamOperator<T,
                               decltype(void(std::declval<std::ostream&>()
                                             << std::declval<T>()))>
    : std::true_type {};

}  // namespace internal

// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
template <class Lvalue, class Rvalue>
struct is_assignable : public internal::IsAssignableImpl<Lvalue, Rvalue> {};

// is_copy_assignable is true if a T const& is assignable to a T&.
// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
template <class T>
struct is_copy_assignable
    : public is_assignable<typename std::add_lvalue_reference<T>::type,
                           typename std::add_lvalue_reference<
                               typename std::add_const<T>::type>::type> {};

// is_move_assignable is true if a T&& is assignable to a T&.
// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
template <class T>
struct is_move_assignable
    : public is_assignable<typename std::add_lvalue_reference<T>::type,
                           const typename std::add_rvalue_reference<T>::type> {
};

// underlying_type produces the integer type backing an enum type.
// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
#if defined(CR_USE_FALLBACKS_FOR_OLD_GLIBCXX)
template <typename T>
struct underlying_type {
  using type = __underlying_type(T);
};
#else
template <typename T>
using underlying_type = std::underlying_type<T>;
#endif

// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
#if defined(CR_USE_FALLBACKS_FOR_OLD_GLIBCXX)
template <class T>
using is_trivially_destructible = std::has_trivial_destructor<T>;
#else
template <class T>
using is_trivially_destructible = std::is_trivially_destructible<T>;
#endif

// is_trivially_copyable is especially hard to get right.
// - Older versions of libstdc++ will fail to have it like they do for other
//   type traits. In this case we should provide it based on compiler
//   intrinsics. This is covered by the CR_USE_FALLBACKS_FOR_OLD_GLIBCXX define.
// - An experimental release of gcc includes most of type_traits but misses
//   is_trivially_copyable, so we still have to avoid using libstdc++ in this
//   case, which is covered by CR_USE_FALLBACKS_FOR_OLD_EXPERIMENTAL_GLIBCXX.
// - When compiling libc++ from before r239653, with a gcc compiler, the
//   std::is_trivially_copyable can fail. So we need to work around that by not
//   using the one in libc++ in this case. This is covered by the
//   CR_USE_FALLBACKS_FOR_GCC_WITH_LIBCXX define, and is discussed in
//   https://llvm.org/bugs/show_bug.cgi?id=27538#c1 where they point out that
//   in libc++'s commit r239653 this is fixed by libc++ checking for gcc 5.1.
// - In both of the above cases we are using the gcc compiler. When defining
//   this ourselves on compiler intrinsics, the __is_trivially_copyable()
//   intrinsic is not available on gcc before version 5.1 (see the discussion in
//   https://llvm.org/bugs/show_bug.cgi?id=27538#c1 again), so we must check for
//   that version.
// - When __is_trivially_copyable() is not available because we are on gcc older
//   than 5.1, we need to fall back to something, so we use __has_trivial_copy()
//   instead based on what was done one-off in bit_cast() previously.

// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace and it works with gcc as needed.
#if defined(CR_USE_FALLBACKS_FOR_OLD_GLIBCXX) ||              \
    defined(CR_USE_FALLBACKS_FOR_OLD_EXPERIMENTAL_GLIBCXX) || \
    defined(CR_USE_FALLBACKS_FOR_GCC_WITH_LIBCXX)
template <typename T>
struct is_trivially_copyable {
// TODO(danakj): Remove this when android builders are all using a newer version
// of gcc, or the android ndk is updated to a newer libc++ that does this for
// us.
#if _GNUC_VER >= 501
  static constexpr bool value = __is_trivially_copyable(T);
#else
  static constexpr bool value = __has_trivial_copy(T);
#endif
};
#else
template <class T>
using is_trivially_copyable = std::is_trivially_copyable<T>;
#endif

}  // namespace base

#undef CR_USE_FALLBACKS_FOR_OLD_GLIBCXX
#undef CR_USE_FALLBACKS_FOR_GCC_WITH_LIBCXX
#undef CR_USE_FALLBACKS_FOR_OLD_EXPERIMENTAL_GLIBCXX

#endif  // BASE_TEMPLATE_UTIL_H_
