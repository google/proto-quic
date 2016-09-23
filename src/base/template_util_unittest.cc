// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/template_util.h"

#include <string>

#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace {

enum SimpleEnum { SIMPLE_ENUM };
enum EnumWithExplicitType : uint64_t { ENUM_WITH_EXPLICIT_TYPE };
enum class ScopedEnum { SCOPED_ENUM };
enum class ScopedEnumWithOperator { SCOPED_ENUM_WITH_OPERATOR };
std::ostream& operator<<(std::ostream& os, ScopedEnumWithOperator v) {
  return os;
}
struct SimpleStruct {};
struct StructWithOperator {};
std::ostream& operator<<(std::ostream& os, const StructWithOperator& v) {
  return os;
}

// is_non_const_reference<Type>
static_assert(!is_non_const_reference<int>::value, "IsNonConstReference");
static_assert(!is_non_const_reference<const int&>::value,
              "IsNonConstReference");
static_assert(is_non_const_reference<int&>::value, "IsNonConstReference");

class AssignParent {};
class AssignChild : AssignParent {};

// is_assignable<Type1, Type2>
static_assert(!is_assignable<int, int>::value, "IsAssignable");  // 1 = 1;
static_assert(!is_assignable<int, double>::value, "IsAssignable");
static_assert(is_assignable<int&, int>::value, "IsAssignable");
static_assert(is_assignable<int&, double>::value, "IsAssignable");
static_assert(is_assignable<int&, int&>::value, "IsAssignable");
static_assert(is_assignable<int&, int const&>::value, "IsAssignable");
static_assert(!is_assignable<int const&, int>::value, "IsAssignable");
static_assert(!is_assignable<AssignParent&, AssignChild>::value,
              "IsAssignable");
static_assert(!is_assignable<AssignChild&, AssignParent>::value,
              "IsAssignable");

struct AssignCopy {};
struct AssignNoCopy {
  AssignNoCopy& operator=(AssignNoCopy&&) { return *this; }
  AssignNoCopy& operator=(const AssignNoCopy&) = delete;
};
struct AssignNoMove {
  AssignNoMove& operator=(AssignNoMove&&) = delete;
  AssignNoMove& operator=(const AssignNoMove&) = delete;
};

static_assert(is_copy_assignable<AssignCopy>::value, "IsCopyAssignable");
static_assert(!is_copy_assignable<AssignNoCopy>::value, "IsCopyAssignable");

static_assert(is_move_assignable<AssignCopy>::value, "IsMoveAssignable");
static_assert(is_move_assignable<AssignNoCopy>::value, "IsMoveAssignable");
static_assert(!is_move_assignable<AssignNoMove>::value, "IsMoveAssignable");

// A few standard types that definitely support printing.
static_assert(internal::SupportsOstreamOperator<int>::value,
              "ints should be printable");
static_assert(internal::SupportsOstreamOperator<const char*>::value,
              "C strings should be printable");
static_assert(internal::SupportsOstreamOperator<std::string>::value,
              "std::string should be printable");

// Various kinds of enums operator<< support.
static_assert(internal::SupportsOstreamOperator<SimpleEnum>::value,
              "simple enum should be printable by value");
static_assert(internal::SupportsOstreamOperator<const SimpleEnum&>::value,
              "simple enum should be printable by const ref");
static_assert(internal::SupportsOstreamOperator<EnumWithExplicitType>::value,
              "enum with explicit type should be printable by value");
static_assert(
    internal::SupportsOstreamOperator<const EnumWithExplicitType&>::value,
    "enum with explicit type should be printable by const ref");
static_assert(!internal::SupportsOstreamOperator<ScopedEnum>::value,
              "scoped enum should not be printable by value");
static_assert(!internal::SupportsOstreamOperator<const ScopedEnum&>::value,
              "simple enum should not be printable by const ref");
static_assert(internal::SupportsOstreamOperator<ScopedEnumWithOperator>::value,
              "scoped enum with operator<< should be printable by value");
static_assert(
    internal::SupportsOstreamOperator<const ScopedEnumWithOperator&>::value,
    "scoped enum with operator<< should be printable by const ref");

// operator<< support on structs.
static_assert(!internal::SupportsOstreamOperator<SimpleStruct>::value,
              "simple struct should not be printable by value");
static_assert(!internal::SupportsOstreamOperator<const SimpleStruct&>::value,
              "simple struct should not be printable by const ref");
static_assert(internal::SupportsOstreamOperator<StructWithOperator>::value,
              "struct with operator<< should be printable by value");
static_assert(
    internal::SupportsOstreamOperator<const StructWithOperator&>::value,
    "struct with operator<< should be printable by const ref");

// underlying type of enums
static_assert(std::is_integral<underlying_type<SimpleEnum>::type>::value,
              "simple enum must have some integral type");
static_assert(
    std::is_same<underlying_type<EnumWithExplicitType>::type, uint64_t>::value,
    "explicit type must be detected");
static_assert(std::is_same<underlying_type<ScopedEnum>::type, int>::value,
              "scoped enum defaults to int");

struct TriviallyDestructible {
  int field;
};

class NonTriviallyDestructible {
  ~NonTriviallyDestructible() {}
};

static_assert(is_trivially_destructible<int>::value, "IsTriviallyDestructible");
static_assert(is_trivially_destructible<TriviallyDestructible>::value,
              "IsTriviallyDestructible");
static_assert(!is_trivially_destructible<NonTriviallyDestructible>::value,
              "IsTriviallyDestructible");

}  // namespace
}  // namespace base
