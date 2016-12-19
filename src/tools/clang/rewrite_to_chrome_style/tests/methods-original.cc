// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/thing.h"

namespace v8 {

class InterfaceOutsideOfBlink {
 public:
  virtual void nonBlinkVirtual() = 0;
};

}  // namespace v8

namespace blink {

class InsideOfBlink : public v8::InterfaceOutsideOfBlink {
 public:
  // This function overrides something outside of blink so don't rename it.
  void nonBlinkVirtual() override {}
  // This function is in blink so rename it.
  virtual void blinkVirtual() {}
};

class MyIterator {};
using my_iterator = char*;

class Task {
 public:
  // Already style-compliant methods shouldn't change.
  void OutputDebugString() {}

  // Tests that the declarations for methods are updated.
  void doTheWork();
  // Overload to test using declarations that introduce multiple shadow
  // declarations.
  void doTheWork(int);
  virtual void reallyDoTheWork() = 0;

  // Note: this is purposely copyable and assignable, to make sure the Clang
  // tool doesn't try to emit replacements for things that aren't explicitly
  // written.

  // Overloaded operators should not be rewritten.
  Task& operator++() {
    return *this;
  }

  // Conversion functions should not be rewritten.
  explicit operator int() const {
    return 42;
  }

  // These are special functions that we don't rename so that range-based
  // for loops and STL things work.
  MyIterator begin() {}
  my_iterator end() {}
  my_iterator rbegin() {}
  MyIterator rend() {}
  // The trace() method is used by Oilpan, we shouldn't rename it.
  void trace() {}
  // These are used by std::unique_lock and std::lock_guard.
  void lock() {}
  void unlock() {}
  void try_lock() {}
};

class Other {
  // Static begin/end/trace don't count, and should be renamed.
  static MyIterator begin() {}
  static my_iterator end() {}
  static void trace() {}
  static void lock() {}
};

// Test that the actual method definition is also updated.
void Task::doTheWork() {
  reallyDoTheWork();
}

template <typename T>
class Testable {
 public:
  typedef T Testable::*UnspecifiedBoolType;
  // This method has a reference to a member in a "member context" and a
  // "non-member context" to verify both are rewritten.
  operator UnspecifiedBoolType() { return m_ptr ? &Testable::m_ptr : 0; }

 private:
  int m_ptr;
};

namespace subname {

class SubnameParent {
  virtual void subnameMethod() {}
};

}  // namespace subname

class SubnameChild : public subname::SubnameParent {
  // This subclasses from blink::subname::SubnameParent and should be renamed.
  void subnameMethod() override {}
};

class GenChild : public blink::GenClass {
  // This subclasses from the blink namespace but in the gen directory so it
  // should not be renamed.
  void genMethod() override {}
};

}  // namespace blink

// Test that overrides from outside the Blink namespace are also updated.
class BovineTask : public blink::Task {
 public:
  using Task::doTheWork;
  void reallyDoTheWork() override;
};

class SuperBovineTask : public BovineTask {
 public:
  using BovineTask::reallyDoTheWork;
};

void BovineTask::reallyDoTheWork() {
  doTheWork();
  // Calls via an overridden method should also be updated.
  reallyDoTheWork();
}

// Finally, test that method pointers are also updated.
void F() {
  void (blink::Task::*p1)() = &blink::Task::doTheWork;
  void (blink::Task::*p2)() = &BovineTask::doTheWork;
  void (blink::Task::*p3)() = &blink::Task::reallyDoTheWork;
  void (BovineTask::*p4)() = &BovineTask::reallyDoTheWork;
}

bool G() {
  // Use the Testable class to rewrite the method.
  blink::Testable<int> tt;
  return tt;
}

class SubclassOfInsideOfBlink : public blink::InsideOfBlink {
 public:
  // This function overrides something outside of blink so don't rename it.
  void nonBlinkVirtual() override {}
  // This function overrides something in blink so rename it.
  void blinkVirtual() override {}
};

class TestSubclassInsideOfBlink : public SubclassOfInsideOfBlink {
 public:
 public:
  // This function overrides something outside of blink so don't rename it.
  void nonBlinkVirtual() override {}
  // This function overrides something in blink so rename it.
  void blinkVirtual() override {}
};

namespace blink {

struct StructInBlink {
  // Structs in blink should rename their methods to capitals.
  bool function() { return true; }
};

class BitVector {
 public:
  class OutOfLineBits {};
  enum Foo { Blah };
  struct Bar {};
  class Baz {};
  class FooBar {};

  template <typename T>
  class MyRefPtr {};

  // Naive renaming will break the build, by leaving return type the same
  // as the method name - to avoid this "Get" prefix needs to be prepended
  // as suggested in https://crbug.com/582312#c17.
  const OutOfLineBits* outOfLineBits() const { return nullptr; }
  Foo foo() { return Blah; }
  const Bar& bar() const { return m_bar; }
  MyRefPtr<Baz> baz() { return MyRefPtr<Baz>(); }
  const MyRefPtr<FooBar>& fooBar() { return foobar_; }

 private:
  Bar m_bar;
  MyRefPtr<FooBar> foobar_;
};

namespace get_prefix_vs_inheritance {

// Regression test for https://crbug.com/673031:
// 1. |frame| accessor/method should be renamed in the same way for
//    WebFrameImplBase and WebLocalFrameImpl.
// 2. Need to rename |frame| to |GetFrame| (not to |Frame|) to avoid
//    a conflict with the Frame type.

class Frame {};
class LocalFrame : public Frame {};

class WebFrameImplBase {
 public:
  virtual Frame* frame() const = 0;
};

class WebLocalFrameImpl : public WebFrameImplBase {
 public:
  LocalFrame* frame() const override { return nullptr; }
};

// This is also a regression test for https://crbug.com/673031
// (which can happen in a non-virtual-method case):
class LayoutObject {};
class LayoutBoxModelObject : public LayoutObject {};
class PaintLayerStackingNode {
 public:
  // |layoutObject| should be renamed to |GetLayoutObject|.
  LayoutBoxModelObject* layoutObject() { return nullptr; }
};

}  // namespace get_prefix_vs_inheritance

}  // namespace blink

namespace WTF {

struct StructInWTF {
  // Structs in WTF should rename their methods to capitals.
  bool function() { return true; }
};

}  // namespace WTF

void F2() {
  blink::StructInBlink b;
  b.function();
  WTF::StructInWTF w;
  w.function();
}

namespace blink {

class ClassDeclaredInsideBlink {
 public:
  static void methodDefinedOutsideBlink();
};

namespace internal {

class InternalClass {
 public:
  static void method();
};

}  // namespace internal

}  // namespace blink

// https://crbug.com/640688 - need to rewrite method name below.
void blink::ClassDeclaredInsideBlink::methodDefinedOutsideBlink() {}
void blink::internal::InternalClass::method() {}
