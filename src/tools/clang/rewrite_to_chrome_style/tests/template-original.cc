// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <type_traits>

namespace not_blink {

void function(int x) {}

class Class {
 public:
  void method() {}
  virtual void virtualMethod() {}
  template <typename T>
  void methodTemplate(T) {}
  template <typename T>
  static void staticMethodTemplate(T) {}
};

template <typename T>
void functionTemplate(T x) {}

template <typename T = Class>
void functionTemplate2() {
  T::staticMethodTemplate(123);
}

template <typename T = Class>
class TemplatedClass {
 public:
  void anotherMethod() { T::staticMethodTemplate(123); }
};

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

void f(int x) {}

template <typename T, void g(T)>
void h(T x) {
  g(x);
}

void test() {
  // f should be rewritten.
  h<int, f>(0);
  // Non-Blink should stay the same.
  h<int, not_blink::function>(1);
}

}  // namespace test_template_arg_is_function

namespace test_template_arg_is_method {

class Class {
 public:
  void method() {}
};

template <typename T, void (T::*g)()>
void h(T&& x) {
  (x.*g)();
}

void test() {
  // method should be rewritten.
  h<Class, &Class::method>(Class());
  // Non-Blink should stay the same.
  h<not_blink::Class, &not_blink::Class::method>(not_blink::Class());
}

}  // namespace test_template_arg_is_method

namespace test_template_arg_is_function_template {

namespace nested {
template <typename T>
void f(T) {}
}

template <typename T, void g(T)>
void h(T x) {
  g(x);
}

void test() {
  // f should be rewritten.
  h<int, nested::f>(0);
  // Non-Blink should stay the same.
  h<int, not_blink::functionTemplate>(1);
}

}  // namespace test_template_arg_is_function_template

namespace test_template_arg_is_method_template_in_non_member_context {

struct Class {
  template <typename T>
  static void f(T) {}
};

template <typename T, void g(T)>
void h(T x) {
  g(x);
}

void test() {
  // f should be rewritten.
  h<int, Class::f>(0);
  // Non-Blink should stay the same.
  h<int, not_blink::Class::staticMethodTemplate>(1);
}

}  // test_template_arg_is_method_template_in_non_member_context

namespace test_inherited_field {

template <typename T>
class BaseClass {
 public:
  unsigned long m_size;
};

template <typename T>
class DerivedClass : protected BaseClass<T> {
 private:
  using Base = BaseClass<T>;
  // https://crbug.com/640016: Need to rewrite |m_size| into |size_|.
  using Base::m_size;
  void method() { m_size = 123; }
};

}  // namespace test_inherited_field

namespace test_template_arg_is_method_template_in_member_context {

struct Class {
  template <typename T>
  static void f(T) {}
};

struct Class2 {
  template <typename T>
  void f(T x) {
    // f should be rewritten.
    Class c;
    c.f(x);
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
  void f(int);
};

template <typename T>
void Class<T>::f(int dataSize){};

void foo() {
  Class<char>().f(123);
};

}  // namespace test_unnamed_arg

namespace cxx_dependent_scope_member_expr_testing {

class PartitionAllocator {
 public:
  static void method() {}
};

template <typename Allocator = PartitionAllocator>
class Vector {
 public:
  // https://crbug.com/582315: |Allocator::method| is a
  // CXXDependentScopeMemberExpr.
  void anotherMethod() {
    if (std::is_class<Allocator>::value)  // Shouldn't rename |value|
      Allocator::method();                // Should rename |method| -> |Method|.
  }
};

template <typename Allocator = PartitionAllocator>
void test() {
  // https://crbug.com/582315: |Allocator::method| is a
  // DependentScopeDeclRefExpr.
  if (std::is_class<Allocator>::value)  // Shouldn't rename |value|.
    Allocator::method();                // Should rename |method|.
}

class InterceptingCanvasBase : public ::not_blink::Class {
 public:
  virtual void virtualMethodInBlink(){};
};

template <typename DerivedCanvas>
class InterceptingCanvas : public InterceptingCanvasBase {
 public:
  void virtualMethod() override {
    this->Class::virtualMethod();  // https://crbug.com/582315#c19
    this->InterceptingCanvasBase::virtualMethodInBlink();
  }
};

template <typename T>
class ThreadSpecific {
 public:
  T* operator->();
  operator T*();
};

template <typename T>
inline ThreadSpecific<T>::operator T*() {
  return nullptr;
}

template <typename T>
inline T* ThreadSpecific<T>::operator->() {
  return operator T*();
}

class Class {
 public:
  virtual void virtualMethodInBlink() {}
};

}  // namespace cxx_dependent_scope_member_expr_testing

}  // namespace blink

namespace not_blink {

namespace cxx_dependent_scope_member_expr_testing {

class Base : public ::blink::cxx_dependent_scope_member_expr_testing::Class {
 public:
  virtual void virtualMethod() {}
};

template <typename T>
class Derived : public Base {
 public:
  void virtualMethod() override {
    this->Class::virtualMethodInBlink();
    this->Base::virtualMethod();
  }
};

}  // namespace cxx_dependent_scope_member_expr_testing

}  // namespace not_blink
