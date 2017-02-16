// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

class Foo {
 public:
  void foo() {}
};

void f();

int main() {
  int integer;
  Foo foo;

  auto int_copy = integer;
  const auto const_int_copy = integer;
  const auto& const_int_ref = integer;

  auto raw_int_ptr = &integer;
  const auto const_raw_int_ptr = &integer;
  const auto& const_raw_int_ptr_ref = &integer;

  auto* raw_int_ptr_valid = &integer;
  const auto* const_raw_int_ptr_valid = &integer;

  auto raw_foo_ptr = &foo;
  const auto const_raw_foo_ptr = &foo;
  const auto& const_raw_foo_ptr_ref = &foo;

  auto* raw_foo_ptr_valid = &foo;
  const auto* const_raw_foo_ptr_valid = &foo;

  int* int_ptr;

  auto double_ptr_auto = &int_ptr;
  auto* double_ptr_auto_ptr = &int_ptr;
  auto** double_ptr_auto_double_ptr = &int_ptr;

  auto function_ptr = &f;
  auto method_ptr = &Foo::foo;

  int* const* const volatile** const* pointer_awesomeness;
  auto auto_awesome = pointer_awesomeness;

  auto& int_ptr_ref = int_ptr;
  const auto& const_int_ptr_ref = int_ptr;
  auto&& int_ptr_rref = static_cast<int*&&>(int_ptr);
  const auto&& const_int_ptr_rref = static_cast<int*&&>(int_ptr);

  static auto static_ptr = new int;
}
