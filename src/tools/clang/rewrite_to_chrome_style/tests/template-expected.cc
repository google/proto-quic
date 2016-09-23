// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

namespace not_blink {

void function(int x) {}

class Class {
 public:
  void method() {}
  template <typename T>
  void methodTemplate(T) {}
  template <typename T>
  static void staticMethodTemplate(T) {}
};

template <typename T>
void functionTemplate(T x) {}

}  // not_blink

namespace blink {

template <typename T, int number>
void F() {
  // We don't assert on this, and we don't end up considering it a const for
  // now.
  const int maybe_a_const = sizeof(T);
  const int is_a_const = number;
}

template <int number, typename... T>
void F() {
  // We don't assert on this, and we don't end up considering it a const for
  // now.
  const int maybe_a_const = sizeof...(T);
  const int is_a_const = number;
}

namespace test_template_arg_is_function {

void F(int x) {}

template <typename T, void g(T)>
void H(T x) {
  g(x);
}

void Test() {
  // f should be rewritten.
  H<int, F>(0);
  // Non-Blink should stay the same.
  H<int, not_blink::function>(1);
}

}  // namespace test_template_arg_is_function

namespace test_template_arg_is_method {

class Class {
 public:
  void Method() {}
};

template <typename T, void (T::*g)()>
void H(T&& x) {
  (x.*g)();
}

void Test() {
  // method should be rewritten.
  H<Class, &Class::Method>(Class());
  // Non-Blink should stay the same.
  H<not_blink::Class, &not_blink::Class::method>(not_blink::Class());
}

}  // namespace test_template_arg_is_method

namespace test_template_arg_is_function_template {

namespace nested {
template <typename T>
void F(T) {}
}

template <typename T, void g(T)>
void H(T x) {
  g(x);
}

void Test() {
  // f should be rewritten.
  H<int, nested::F>(0);
  // Non-Blink should stay the same.
  H<int, not_blink::functionTemplate>(1);
}

}  // namespace test_template_arg_is_function_template

namespace test_template_arg_is_method_template_in_non_member_context {

struct Class {
  template <typename T>
  static void F(T) {}
};

template <typename T, void g(T)>
void H(T x) {
  g(x);
}

void Test() {
  // f should be rewritten.
  H<int, Class::F>(0);
  // Non-Blink should stay the same.
  H<int, not_blink::Class::staticMethodTemplate>(1);
}

}  // test_template_arg_is_method_template_in_non_member_context

namespace test_template_arg_is_method_template_in_member_context {

struct Class {
  template <typename T>
  static void F(T) {}
};

struct Class2 {
  template <typename T>
  void F(T x) {
    // f should be rewritten.
    Class c;
    c.F(x);
    // Non-Blink should stay the same.
    not_blink::Class c2;
    c2.method(x);
  }
};

}  // namespace test_template_arg_is_method_template_in_member_context

namespace test_unnamed_arg {

template <typename T>
class Class {
 public:
  // Test for https://crbug.com/598141 - shouldn't rewrite
  //    ...int);
  // into
  //    ...intdata_size;
  void F(int);
};

template <typename T>
void Class<T>::F(int data_size){};

void Foo() {
  Class<char>().F(123);
};

}  // namespace test_unnamed_arg

}  // namespace blink
