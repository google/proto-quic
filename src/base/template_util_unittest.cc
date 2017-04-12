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

}  // namespace
}  // namespace base
