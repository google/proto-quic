// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/bind.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/test/gtest_util.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrictMock;

namespace base {
namespace {

class IncompleteType;

class NoRef {
 public:
  NoRef() {}

  MOCK_METHOD0(VoidMethod0, void());
  MOCK_CONST_METHOD0(VoidConstMethod0, void());

  MOCK_METHOD0(IntMethod0, int());
  MOCK_CONST_METHOD0(IntConstMethod0, int());

  MOCK_METHOD1(VoidMethodWithIntArg, void(int));

 private:
  // Particularly important in this test to ensure no copies are made.
  DISALLOW_COPY_AND_ASSIGN(NoRef);
};

class HasRef : public NoRef {
 public:
  HasRef() {}

  MOCK_CONST_METHOD0(AddRef, void());
  MOCK_CONST_METHOD0(Release, bool());

 private:
  // Particularly important in this test to ensure no copies are made.
  DISALLOW_COPY_AND_ASSIGN(HasRef);
};

class HasRefPrivateDtor : public HasRef {
 private:
  ~HasRefPrivateDtor() {}
};

static const int kParentValue = 1;
static const int kChildValue = 2;

class Parent {
 public:
  void AddRef() const {}
  void Release() const {}
  virtual void VirtualSet() { value = kParentValue; }
  void NonVirtualSet() { value = kParentValue; }
  int value;
};

class Child : public Parent {
 public:
  void VirtualSet() override { value = kChildValue; }
  void NonVirtualSet() { value = kChildValue; }
};

class NoRefParent {
 public:
  virtual void VirtualSet() { value = kParentValue; }
  void NonVirtualSet() { value = kParentValue; }
  int value;
};

class NoRefChild : public NoRefParent {
  void VirtualSet() override { value = kChildValue; }
  void NonVirtualSet() { value = kChildValue; }
};

// Used for probing the number of copies and moves that occur if a type must be
// coerced during argument forwarding in the Run() methods.
struct DerivedCopyMoveCounter {
  DerivedCopyMoveCounter(int* copies,
                         int* assigns,
                         int* move_constructs,
                         int* move_assigns)
      : copies_(copies),
        assigns_(assigns),
        move_constructs_(move_constructs),
        move_assigns_(move_assigns) {}
  int* copies_;
  int* assigns_;
  int* move_constructs_;
  int* move_assigns_;
};

// Used for probing the number of copies and moves in an argument.
class CopyMoveCounter {
 public:
  CopyMoveCounter(int* copies,
                  int* assigns,
                  int* move_constructs,
                  int* move_assigns)
      : copies_(copies),
        assigns_(assigns),
        move_constructs_(move_constructs),
        move_assigns_(move_assigns) {}

  CopyMoveCounter(const CopyMoveCounter& other)
      : copies_(other.copies_),
        assigns_(other.assigns_),
        move_constructs_(other.move_constructs_),
        move_assigns_(other.move_assigns_) {
    (*copies_)++;
  }

  CopyMoveCounter(CopyMoveCounter&& other)
      : copies_(other.copies_),
        assigns_(other.assigns_),
        move_constructs_(other.move_constructs_),
        move_assigns_(other.move_assigns_) {
    (*move_constructs_)++;
  }

  // Probing for copies from coercion.
  explicit CopyMoveCounter(const DerivedCopyMoveCounter& other)
      : copies_(other.copies_),
        assigns_(other.assigns_),
        move_constructs_(other.move_constructs_),
        move_assigns_(other.move_assigns_) {
    (*copies_)++;
  }

  // Probing for moves from coercion.
  explicit CopyMoveCounter(DerivedCopyMoveCounter&& other)
      : copies_(other.copies_),
        assigns_(other.assigns_),
        move_constructs_(other.move_constructs_),
        move_assigns_(other.move_assigns_) {
    (*move_constructs_)++;
  }

  const CopyMoveCounter& operator=(const CopyMoveCounter& rhs) {
    copies_ = rhs.copies_;
    assigns_ = rhs.assigns_;
    move_constructs_ = rhs.move_constructs_;
    move_assigns_ = rhs.move_assigns_;

    (*assigns_)++;

    return *this;
  }

  const CopyMoveCounter& operator=(CopyMoveCounter&& rhs) {
    copies_ = rhs.copies_;
    assigns_ = rhs.assigns_;
    move_constructs_ = rhs.move_constructs_;
    move_assigns_ = rhs.move_assigns_;

    (*move_assigns_)++;

    return *this;
  }

  int copies() const {
    return *copies_;
  }

 private:
  int* copies_;
  int* assigns_;
  int* move_constructs_;
  int* move_assigns_;
};

// Used for probing the number of copies in an argument. The instance is a
// copyable and non-movable type.
class CopyCounter {
 public:
  CopyCounter(int* copies, int* assigns)
      : counter_(copies, assigns, nullptr, nullptr) {}
  CopyCounter(const CopyCounter& other) : counter_(other.counter_) {}
  CopyCounter& operator=(const CopyCounter& other) {
    counter_ = other.counter_;
    return *this;
  }

  explicit CopyCounter(const DerivedCopyMoveCounter& other) : counter_(other) {}

  int copies() const { return counter_.copies(); }

 private:
  CopyMoveCounter counter_;
};

// Used for probing the number of moves in an argument. The instance is a
// non-copyable and movable type.
class MoveCounter {
 public:
  MoveCounter(int* move_constructs, int* move_assigns)
      : counter_(nullptr, nullptr, move_constructs, move_assigns) {}
  MoveCounter(MoveCounter&& other) : counter_(std::move(other.counter_)) {}
  MoveCounter& operator=(MoveCounter&& other) {
    counter_ = std::move(other.counter_);
    return *this;
  }

  explicit MoveCounter(DerivedCopyMoveCounter&& other)
      : counter_(std::move(other)) {}

 private:
  CopyMoveCounter counter_;
};

class DeleteCounter {
 public:
  explicit DeleteCounter(int* deletes)
      : deletes_(deletes) {
  }

  ~DeleteCounter() {
    (*deletes_)++;
  }

  void VoidMethod0() {}

 private:
  int* deletes_;
};

template <typename T>
T PassThru(T scoper) {
  return scoper;
}

// Some test functions that we can Bind to.
template <typename T>
T PolymorphicIdentity(T t) {
  return t;
}

template <typename... Ts>
struct VoidPolymorphic {
  static void Run(Ts... t) {}
};

int Identity(int n) {
  return n;
}

int ArrayGet(const int array[], int n) {
  return array[n];
}

int Sum(int a, int b, int c, int d, int e, int f) {
  return a + b + c + d + e + f;
}

const char* CStringIdentity(const char* s) {
  return s;
}

int GetCopies(const CopyMoveCounter& counter) {
  return counter.copies();
}

int UnwrapNoRefParent(NoRefParent p) {
  return p.value;
}

int UnwrapNoRefParentPtr(NoRefParent* p) {
  return p->value;
}

int UnwrapNoRefParentConstRef(const NoRefParent& p) {
  return p.value;
}

void RefArgSet(int &n) {
  n = 2;
}

void PtrArgSet(int *n) {
  *n = 2;
}

int FunctionWithWeakFirstParam(WeakPtr<NoRef> o, int n) {
  return n;
}

int FunctionWithScopedRefptrFirstParam(const scoped_refptr<HasRef>& o, int n) {
  return n;
}

void TakesACallback(const Closure& callback) {
  callback.Run();
}

class BindTest : public ::testing::Test {
 public:
  BindTest() {
    const_has_ref_ptr_ = &has_ref_;
    const_no_ref_ptr_ = &no_ref_;
    static_func_mock_ptr = &static_func_mock_;
  }

  virtual ~BindTest() {
  }

  static void VoidFunc0() {
    static_func_mock_ptr->VoidMethod0();
  }

  static int IntFunc0() { return static_func_mock_ptr->IntMethod0(); }

 protected:
  StrictMock<NoRef> no_ref_;
  StrictMock<HasRef> has_ref_;
  const HasRef* const_has_ref_ptr_;
  const NoRef* const_no_ref_ptr_;
  StrictMock<NoRef> static_func_mock_;

  // Used by the static functions to perform expectations.
  static StrictMock<NoRef>* static_func_mock_ptr;

 private:
  DISALLOW_COPY_AND_ASSIGN(BindTest);
};

StrictMock<NoRef>* BindTest::static_func_mock_ptr;

TEST_F(BindTest, BasicTest) {
  Callback<int(int, int, int)> cb = Bind(&Sum, 32, 16, 8);
  EXPECT_EQ(92, cb.Run(13, 12, 11));

  Callback<int(int, int, int, int, int, int)> c1 = Bind(&Sum);
  EXPECT_EQ(69, c1.Run(14, 13, 12, 11, 10, 9));

  Callback<int(int, int, int)> c2 = Bind(c1, 32, 16, 8);
  EXPECT_EQ(86, c2.Run(11, 10, 9));

  Callback<int()> c3 = Bind(c2, 4, 2, 1);
  EXPECT_EQ(63, c3.Run());
}

// Test that currying the rvalue result of another Bind() works correctly.
//   - rvalue should be usable as argument to Bind().
//   - multiple runs of resulting Callback remain valid.
TEST_F(BindTest, CurryingRvalueResultOfBind) {
  int n = 0;
  Closure cb = base::Bind(&TakesACallback, base::Bind(&PtrArgSet, &n));

  // If we implement Bind() such that the return value has auto_ptr-like
  // semantics, the second call here will fail because ownership of
  // the internal BindState<> would have been transfered to a *temporary*
  // constructon of a Callback object on the first call.
  cb.Run();
  EXPECT_EQ(2, n);

  n = 0;
  cb.Run();
  EXPECT_EQ(2, n);
}

// Function type support.
//   - Normal function.
//   - Normal function bound with non-refcounted first argument.
//   - Method bound to non-const object.
//   - Method bound to scoped_refptr.
//   - Const method bound to non-const object.
//   - Const method bound to const object.
//   - Derived classes can be used with pointers to non-virtual base functions.
//   - Derived classes can be used with pointers to virtual base functions (and
//     preserve virtual dispatch).
TEST_F(BindTest, FunctionTypeSupport) {
  EXPECT_CALL(static_func_mock_, VoidMethod0());
  EXPECT_CALL(has_ref_, AddRef()).Times(4);
  EXPECT_CALL(has_ref_, Release()).Times(4);
  EXPECT_CALL(has_ref_, VoidMethod0()).Times(2);
  EXPECT_CALL(has_ref_, VoidConstMethod0()).Times(2);

  Closure normal_cb = Bind(&VoidFunc0);
  Callback<NoRef*()> normal_non_refcounted_cb =
      Bind(&PolymorphicIdentity<NoRef*>, &no_ref_);
  normal_cb.Run();
  EXPECT_EQ(&no_ref_, normal_non_refcounted_cb.Run());

  Closure method_cb = Bind(&HasRef::VoidMethod0, &has_ref_);
  Closure method_refptr_cb = Bind(&HasRef::VoidMethod0,
                                  make_scoped_refptr(&has_ref_));
  Closure const_method_nonconst_obj_cb = Bind(&HasRef::VoidConstMethod0,
                                              &has_ref_);
  Closure const_method_const_obj_cb = Bind(&HasRef::VoidConstMethod0,
                                           const_has_ref_ptr_);
  method_cb.Run();
  method_refptr_cb.Run();
  const_method_nonconst_obj_cb.Run();
  const_method_const_obj_cb.Run();

  Child child;
  child.value = 0;
  Closure virtual_set_cb = Bind(&Parent::VirtualSet, &child);
  virtual_set_cb.Run();
  EXPECT_EQ(kChildValue, child.value);

  child.value = 0;
  Closure non_virtual_set_cb = Bind(&Parent::NonVirtualSet, &child);
  non_virtual_set_cb.Run();
  EXPECT_EQ(kParentValue, child.value);
}

// Return value support.
//   - Function with return value.
//   - Method with return value.
//   - Const method with return value.
TEST_F(BindTest, ReturnValues) {
  EXPECT_CALL(static_func_mock_, IntMethod0()).WillOnce(Return(1337));
  EXPECT_CALL(has_ref_, AddRef()).Times(3);
  EXPECT_CALL(has_ref_, Release()).Times(3);
  EXPECT_CALL(has_ref_, IntMethod0()).WillOnce(Return(31337));
  EXPECT_CALL(has_ref_, IntConstMethod0())
      .WillOnce(Return(41337))
      .WillOnce(Return(51337));

  Callback<int()> normal_cb = Bind(&IntFunc0);
  Callback<int()> method_cb = Bind(&HasRef::IntMethod0, &has_ref_);
  Callback<int()> const_method_nonconst_obj_cb =
      Bind(&HasRef::IntConstMethod0, &has_ref_);
  Callback<int()> const_method_const_obj_cb =
      Bind(&HasRef::IntConstMethod0, const_has_ref_ptr_);
  EXPECT_EQ(1337, normal_cb.Run());
  EXPECT_EQ(31337, method_cb.Run());
  EXPECT_EQ(41337, const_method_nonconst_obj_cb.Run());
  EXPECT_EQ(51337, const_method_const_obj_cb.Run());
}

// IgnoreResult adapter test.
//   - Function with return value.
//   - Method with return value.
//   - Const Method with return.
//   - Method with return value bound to WeakPtr<>.
//   - Const Method with return bound to WeakPtr<>.
TEST_F(BindTest, IgnoreResult) {
  EXPECT_CALL(static_func_mock_, IntMethod0()).WillOnce(Return(1337));
  EXPECT_CALL(has_ref_, AddRef()).Times(2);
  EXPECT_CALL(has_ref_, Release()).Times(2);
  EXPECT_CALL(has_ref_, IntMethod0()).WillOnce(Return(10));
  EXPECT_CALL(has_ref_, IntConstMethod0()).WillOnce(Return(11));
  EXPECT_CALL(no_ref_, IntMethod0()).WillOnce(Return(12));
  EXPECT_CALL(no_ref_, IntConstMethod0()).WillOnce(Return(13));

  Closure normal_func_cb = Bind(IgnoreResult(&IntFunc0));
  normal_func_cb.Run();

  Closure non_void_method_cb =
      Bind(IgnoreResult(&HasRef::IntMethod0), &has_ref_);
  non_void_method_cb.Run();

  Closure non_void_const_method_cb =
      Bind(IgnoreResult(&HasRef::IntConstMethod0), &has_ref_);
  non_void_const_method_cb.Run();

  WeakPtrFactory<NoRef> weak_factory(&no_ref_);
  WeakPtrFactory<const NoRef> const_weak_factory(const_no_ref_ptr_);

  Closure non_void_weak_method_cb  =
      Bind(IgnoreResult(&NoRef::IntMethod0), weak_factory.GetWeakPtr());
  non_void_weak_method_cb.Run();

  Closure non_void_weak_const_method_cb =
      Bind(IgnoreResult(&NoRef::IntConstMethod0), weak_factory.GetWeakPtr());
  non_void_weak_const_method_cb.Run();

  weak_factory.InvalidateWeakPtrs();
  non_void_weak_const_method_cb.Run();
  non_void_weak_method_cb.Run();
}

// Argument binding tests.
//   - Argument binding to primitive.
//   - Argument binding to primitive pointer.
//   - Argument binding to a literal integer.
//   - Argument binding to a literal string.
//   - Argument binding with template function.
//   - Argument binding to an object.
//   - Argument binding to pointer to incomplete type.
//   - Argument gets type converted.
//   - Pointer argument gets converted.
//   - Const Reference forces conversion.
TEST_F(BindTest, ArgumentBinding) {
  int n = 2;

  Callback<int()> bind_primitive_cb = Bind(&Identity, n);
  EXPECT_EQ(n, bind_primitive_cb.Run());

  Callback<int*()> bind_primitive_pointer_cb =
      Bind(&PolymorphicIdentity<int*>, &n);
  EXPECT_EQ(&n, bind_primitive_pointer_cb.Run());

  Callback<int()> bind_int_literal_cb = Bind(&Identity, 3);
  EXPECT_EQ(3, bind_int_literal_cb.Run());

  Callback<const char*()> bind_string_literal_cb =
      Bind(&CStringIdentity, "hi");
  EXPECT_STREQ("hi", bind_string_literal_cb.Run());

  Callback<int()> bind_template_function_cb =
      Bind(&PolymorphicIdentity<int>, 4);
  EXPECT_EQ(4, bind_template_function_cb.Run());

  NoRefParent p;
  p.value = 5;
  Callback<int()> bind_object_cb = Bind(&UnwrapNoRefParent, p);
  EXPECT_EQ(5, bind_object_cb.Run());

  IncompleteType* incomplete_ptr = reinterpret_cast<IncompleteType*>(123);
  Callback<IncompleteType*()> bind_incomplete_ptr_cb =
      Bind(&PolymorphicIdentity<IncompleteType*>, incomplete_ptr);
  EXPECT_EQ(incomplete_ptr, bind_incomplete_ptr_cb.Run());

  NoRefChild c;
  c.value = 6;
  Callback<int()> bind_promotes_cb = Bind(&UnwrapNoRefParent, c);
  EXPECT_EQ(6, bind_promotes_cb.Run());

  c.value = 7;
  Callback<int()> bind_pointer_promotes_cb =
      Bind(&UnwrapNoRefParentPtr, &c);
  EXPECT_EQ(7, bind_pointer_promotes_cb.Run());

  c.value = 8;
  Callback<int()> bind_const_reference_promotes_cb =
      Bind(&UnwrapNoRefParentConstRef, c);
  EXPECT_EQ(8, bind_const_reference_promotes_cb.Run());
}

// Unbound argument type support tests.
//   - Unbound value.
//   - Unbound pointer.
//   - Unbound reference.
//   - Unbound const reference.
//   - Unbound unsized array.
//   - Unbound sized array.
//   - Unbound array-of-arrays.
TEST_F(BindTest, UnboundArgumentTypeSupport) {
  Callback<void(int)> unbound_value_cb = Bind(&VoidPolymorphic<int>::Run);
  Callback<void(int*)> unbound_pointer_cb = Bind(&VoidPolymorphic<int*>::Run);
  Callback<void(int&)> unbound_ref_cb = Bind(&VoidPolymorphic<int&>::Run);
  Callback<void(const int&)> unbound_const_ref_cb =
      Bind(&VoidPolymorphic<const int&>::Run);
  Callback<void(int[])> unbound_unsized_array_cb =
      Bind(&VoidPolymorphic<int[]>::Run);
  Callback<void(int[2])> unbound_sized_array_cb =
      Bind(&VoidPolymorphic<int[2]>::Run);
  Callback<void(int[][2])> unbound_array_of_arrays_cb =
      Bind(&VoidPolymorphic<int[][2]>::Run);

  Callback<void(int&)> unbound_ref_with_bound_arg =
      Bind(&VoidPolymorphic<int, int&>::Run, 1);
}

// Function with unbound reference parameter.
//   - Original parameter is modified by callback.
TEST_F(BindTest, UnboundReferenceSupport) {
  int n = 0;
  Callback<void(int&)> unbound_ref_cb = Bind(&RefArgSet);
  unbound_ref_cb.Run(n);
  EXPECT_EQ(2, n);
}

// Functions that take reference parameters.
//  - Forced reference parameter type still stores a copy.
//  - Forced const reference parameter type still stores a copy.
TEST_F(BindTest, ReferenceArgumentBinding) {
  int n = 1;
  int& ref_n = n;
  const int& const_ref_n = n;

  Callback<int()> ref_copies_cb = Bind(&Identity, ref_n);
  EXPECT_EQ(n, ref_copies_cb.Run());
  n++;
  EXPECT_EQ(n - 1, ref_copies_cb.Run());

  Callback<int()> const_ref_copies_cb = Bind(&Identity, const_ref_n);
  EXPECT_EQ(n, const_ref_copies_cb.Run());
  n++;
  EXPECT_EQ(n - 1, const_ref_copies_cb.Run());
}

// Check that we can pass in arrays and have them be stored as a pointer.
//  - Array of values stores a pointer.
//  - Array of const values stores a pointer.
TEST_F(BindTest, ArrayArgumentBinding) {
  int array[4] = {1, 1, 1, 1};
  const int (*const_array_ptr)[4] = &array;

  Callback<int()> array_cb = Bind(&ArrayGet, array, 1);
  EXPECT_EQ(1, array_cb.Run());

  Callback<int()> const_array_cb = Bind(&ArrayGet, *const_array_ptr, 1);
  EXPECT_EQ(1, const_array_cb.Run());

  array[1] = 3;
  EXPECT_EQ(3, array_cb.Run());
  EXPECT_EQ(3, const_array_cb.Run());
}

// Unretained() wrapper support.
//   - Method bound to Unretained() non-const object.
//   - Const method bound to Unretained() non-const object.
//   - Const method bound to Unretained() const object.
TEST_F(BindTest, Unretained) {
  EXPECT_CALL(no_ref_, VoidMethod0());
  EXPECT_CALL(no_ref_, VoidConstMethod0()).Times(2);

  Callback<void()> method_cb =
      Bind(&NoRef::VoidMethod0, Unretained(&no_ref_));
  method_cb.Run();

  Callback<void()> const_method_cb =
      Bind(&NoRef::VoidConstMethod0, Unretained(&no_ref_));
  const_method_cb.Run();

  Callback<void()> const_method_const_ptr_cb =
      Bind(&NoRef::VoidConstMethod0, Unretained(const_no_ref_ptr_));
  const_method_const_ptr_cb.Run();
}

// WeakPtr() support.
//   - Method bound to WeakPtr<> to non-const object.
//   - Const method bound to WeakPtr<> to non-const object.
//   - Const method bound to WeakPtr<> to const object.
//   - Normal Function with WeakPtr<> as P1 can have return type and is
//     not canceled.
TEST_F(BindTest, WeakPtr) {
  EXPECT_CALL(no_ref_, VoidMethod0());
  EXPECT_CALL(no_ref_, VoidConstMethod0()).Times(2);

  WeakPtrFactory<NoRef> weak_factory(&no_ref_);
  WeakPtrFactory<const NoRef> const_weak_factory(const_no_ref_ptr_);

  Closure method_cb =
      Bind(&NoRef::VoidMethod0, weak_factory.GetWeakPtr());
  method_cb.Run();

  Closure const_method_cb =
      Bind(&NoRef::VoidConstMethod0, const_weak_factory.GetWeakPtr());
  const_method_cb.Run();

  Closure const_method_const_ptr_cb =
      Bind(&NoRef::VoidConstMethod0, const_weak_factory.GetWeakPtr());
  const_method_const_ptr_cb.Run();

  Callback<int(int)> normal_func_cb =
      Bind(&FunctionWithWeakFirstParam, weak_factory.GetWeakPtr());
  EXPECT_EQ(1, normal_func_cb.Run(1));

  weak_factory.InvalidateWeakPtrs();
  const_weak_factory.InvalidateWeakPtrs();

  method_cb.Run();
  const_method_cb.Run();
  const_method_const_ptr_cb.Run();

  // Still runs even after the pointers are invalidated.
  EXPECT_EQ(2, normal_func_cb.Run(2));
}

// ConstRef() wrapper support.
//   - Binding w/o ConstRef takes a copy.
//   - Binding a ConstRef takes a reference.
//   - Binding ConstRef to a function ConstRef does not copy on invoke.
TEST_F(BindTest, ConstRef) {
  int n = 1;

  Callback<int()> copy_cb = Bind(&Identity, n);
  Callback<int()> const_ref_cb = Bind(&Identity, ConstRef(n));
  EXPECT_EQ(n, copy_cb.Run());
  EXPECT_EQ(n, const_ref_cb.Run());
  n++;
  EXPECT_EQ(n - 1, copy_cb.Run());
  EXPECT_EQ(n, const_ref_cb.Run());

  int copies = 0;
  int assigns = 0;
  int move_constructs = 0;
  int move_assigns = 0;
  CopyMoveCounter counter(&copies, &assigns, &move_constructs, &move_assigns);
  Callback<int()> all_const_ref_cb =
      Bind(&GetCopies, ConstRef(counter));
  EXPECT_EQ(0, all_const_ref_cb.Run());
  EXPECT_EQ(0, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(0, move_constructs);
  EXPECT_EQ(0, move_assigns);
}

TEST_F(BindTest, ScopedRefptr) {
  EXPECT_CALL(has_ref_, AddRef()).Times(1);
  EXPECT_CALL(has_ref_, Release()).Times(1);

  const scoped_refptr<HasRef> refptr(&has_ref_);
  Callback<int()> scoped_refptr_const_ref_cb =
      Bind(&FunctionWithScopedRefptrFirstParam, base::ConstRef(refptr), 1);
  EXPECT_EQ(1, scoped_refptr_const_ref_cb.Run());
}

// Test Owned() support.
TEST_F(BindTest, Owned) {
  int deletes = 0;
  DeleteCounter* counter = new DeleteCounter(&deletes);

  // If we don't capture, delete happens on Callback destruction/reset.
  // return the same value.
  Callback<DeleteCounter*()> no_capture_cb =
      Bind(&PolymorphicIdentity<DeleteCounter*>, Owned(counter));
  ASSERT_EQ(counter, no_capture_cb.Run());
  ASSERT_EQ(counter, no_capture_cb.Run());
  EXPECT_EQ(0, deletes);
  no_capture_cb.Reset();  // This should trigger a delete.
  EXPECT_EQ(1, deletes);

  deletes = 0;
  counter = new DeleteCounter(&deletes);
  base::Closure own_object_cb =
      Bind(&DeleteCounter::VoidMethod0, Owned(counter));
  own_object_cb.Run();
  EXPECT_EQ(0, deletes);
  own_object_cb.Reset();
  EXPECT_EQ(1, deletes);
}

TEST_F(BindTest, UniquePtrReceiver) {
  std::unique_ptr<StrictMock<NoRef>> no_ref(new StrictMock<NoRef>);
  EXPECT_CALL(*no_ref, VoidMethod0()).Times(1);
  Bind(&NoRef::VoidMethod0, std::move(no_ref)).Run();
}

// Tests for Passed() wrapper support:
//   - Passed() can be constructed from a pointer to scoper.
//   - Passed() can be constructed from a scoper rvalue.
//   - Using Passed() gives Callback Ownership.
//   - Ownership is transferred from Callback to callee on the first Run().
//   - Callback supports unbound arguments.
template <typename T>
class BindMoveOnlyTypeTest : public ::testing::Test {
};

struct CustomDeleter {
  void operator()(DeleteCounter* c) { delete c; }
};

using MoveOnlyTypesToTest =
    ::testing::Types<std::unique_ptr<DeleteCounter>,
                     std::unique_ptr<DeleteCounter, CustomDeleter>>;
TYPED_TEST_CASE(BindMoveOnlyTypeTest, MoveOnlyTypesToTest);

TYPED_TEST(BindMoveOnlyTypeTest, PassedToBoundCallback) {
  int deletes = 0;

  TypeParam ptr(new DeleteCounter(&deletes));
  Callback<TypeParam()> callback = Bind(&PassThru<TypeParam>, Passed(&ptr));
  EXPECT_FALSE(ptr.get());
  EXPECT_EQ(0, deletes);

  // If we never invoke the Callback, it retains ownership and deletes.
  callback.Reset();
  EXPECT_EQ(1, deletes);
}

TYPED_TEST(BindMoveOnlyTypeTest, PassedWithRvalue) {
  int deletes = 0;
  Callback<TypeParam()> callback = Bind(
      &PassThru<TypeParam>, Passed(TypeParam(new DeleteCounter(&deletes))));
  EXPECT_EQ(0, deletes);

  // If we never invoke the Callback, it retains ownership and deletes.
  callback.Reset();
  EXPECT_EQ(1, deletes);
}

// Check that ownership can be transferred back out.
TYPED_TEST(BindMoveOnlyTypeTest, ReturnMoveOnlyType) {
  int deletes = 0;
  DeleteCounter* counter = new DeleteCounter(&deletes);
  Callback<TypeParam()> callback =
      Bind(&PassThru<TypeParam>, Passed(TypeParam(counter)));
  TypeParam result = callback.Run();
  ASSERT_EQ(counter, result.get());
  EXPECT_EQ(0, deletes);

  // Resetting does not delete since ownership was transferred.
  callback.Reset();
  EXPECT_EQ(0, deletes);

  // Ensure that we actually did get ownership.
  result.reset();
  EXPECT_EQ(1, deletes);
}

TYPED_TEST(BindMoveOnlyTypeTest, UnboundForwarding) {
  int deletes = 0;
  TypeParam ptr(new DeleteCounter(&deletes));
  // Test unbound argument forwarding.
  Callback<TypeParam(TypeParam)> cb_unbound = Bind(&PassThru<TypeParam>);
  cb_unbound.Run(std::move(ptr));
  EXPECT_EQ(1, deletes);
}

void VerifyVector(const std::vector<std::unique_ptr<int>>& v) {
  ASSERT_EQ(1u, v.size());
  EXPECT_EQ(12345, *v[0]);
}

std::vector<std::unique_ptr<int>> AcceptAndReturnMoveOnlyVector(
    std::vector<std::unique_ptr<int>> v) {
  VerifyVector(v);
  return v;
}

// Test that a vector containing move-only types can be used with Callback.
TEST_F(BindTest, BindMoveOnlyVector) {
  using MoveOnlyVector = std::vector<std::unique_ptr<int>>;

  MoveOnlyVector v;
  v.push_back(WrapUnique(new int(12345)));

  // Early binding should work:
  base::Callback<MoveOnlyVector()> bound_cb =
      base::Bind(&AcceptAndReturnMoveOnlyVector, Passed(&v));
  MoveOnlyVector intermediate_result = bound_cb.Run();
  VerifyVector(intermediate_result);

  // As should passing it as an argument to Run():
  base::Callback<MoveOnlyVector(MoveOnlyVector)> unbound_cb =
      base::Bind(&AcceptAndReturnMoveOnlyVector);
  MoveOnlyVector final_result = unbound_cb.Run(std::move(intermediate_result));
  VerifyVector(final_result);
}

// Argument copy-constructor usage for non-reference copy-only parameters.
//   - Bound arguments are only copied once.
//   - Forwarded arguments are only copied once.
//   - Forwarded arguments with coercions are only copied twice (once for the
//     coercion, and one for the final dispatch).
TEST_F(BindTest, ArgumentCopies) {
  int copies = 0;
  int assigns = 0;

  CopyCounter counter(&copies, &assigns);
  Bind(&VoidPolymorphic<CopyCounter>::Run, counter);
  EXPECT_EQ(1, copies);
  EXPECT_EQ(0, assigns);

  copies = 0;
  assigns = 0;
  Bind(&VoidPolymorphic<CopyCounter>::Run, CopyCounter(&copies, &assigns));
  EXPECT_EQ(1, copies);
  EXPECT_EQ(0, assigns);

  copies = 0;
  assigns = 0;
  Bind(&VoidPolymorphic<CopyCounter>::Run).Run(counter);
  EXPECT_EQ(2, copies);
  EXPECT_EQ(0, assigns);

  copies = 0;
  assigns = 0;
  Bind(&VoidPolymorphic<CopyCounter>::Run).Run(CopyCounter(&copies, &assigns));
  EXPECT_EQ(1, copies);
  EXPECT_EQ(0, assigns);

  copies = 0;
  assigns = 0;
  DerivedCopyMoveCounter derived(&copies, &assigns, nullptr, nullptr);
  Bind(&VoidPolymorphic<CopyCounter>::Run).Run(CopyCounter(derived));
  EXPECT_EQ(2, copies);
  EXPECT_EQ(0, assigns);

  copies = 0;
  assigns = 0;
  Bind(&VoidPolymorphic<CopyCounter>::Run)
      .Run(CopyCounter(
          DerivedCopyMoveCounter(&copies, &assigns, nullptr, nullptr)));
  EXPECT_EQ(2, copies);
  EXPECT_EQ(0, assigns);
}

// Argument move-constructor usage for move-only parameters.
//   - Bound arguments passed by move are not copied.
TEST_F(BindTest, ArgumentMoves) {
  int move_constructs = 0;
  int move_assigns = 0;

  Bind(&VoidPolymorphic<const MoveCounter&>::Run,
       MoveCounter(&move_constructs, &move_assigns));
  EXPECT_EQ(1, move_constructs);
  EXPECT_EQ(0, move_assigns);

  // TODO(tzik): Support binding move-only type into a non-reference parameter
  // of a variant of Callback.

  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<MoveCounter>::Run)
      .Run(MoveCounter(&move_constructs, &move_assigns));
  EXPECT_EQ(1, move_constructs);
  EXPECT_EQ(0, move_assigns);

  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<MoveCounter>::Run)
      .Run(MoveCounter(DerivedCopyMoveCounter(
          nullptr, nullptr, &move_constructs, &move_assigns)));
  EXPECT_EQ(2, move_constructs);
  EXPECT_EQ(0, move_assigns);
}

// Argument constructor usage for non-reference movable-copyable
// parameters.
//   - Bound arguments passed by move are not copied.
//   - Forwarded arguments are only copied once.
//   - Forwarded arguments with coercions are only copied once and moved once.
TEST_F(BindTest, ArgumentCopiesAndMoves) {
  int copies = 0;
  int assigns = 0;
  int move_constructs = 0;
  int move_assigns = 0;

  CopyMoveCounter counter(&copies, &assigns, &move_constructs, &move_assigns);
  Bind(&VoidPolymorphic<CopyMoveCounter>::Run, counter);
  EXPECT_EQ(1, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(0, move_constructs);
  EXPECT_EQ(0, move_assigns);

  copies = 0;
  assigns = 0;
  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<CopyMoveCounter>::Run,
       CopyMoveCounter(&copies, &assigns, &move_constructs, &move_assigns));
  EXPECT_EQ(0, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(1, move_constructs);
  EXPECT_EQ(0, move_assigns);

  copies = 0;
  assigns = 0;
  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<CopyMoveCounter>::Run).Run(counter);
  EXPECT_EQ(1, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(1, move_constructs);
  EXPECT_EQ(0, move_assigns);

  copies = 0;
  assigns = 0;
  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<CopyMoveCounter>::Run)
      .Run(CopyMoveCounter(&copies, &assigns, &move_constructs, &move_assigns));
  EXPECT_EQ(0, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(1, move_constructs);
  EXPECT_EQ(0, move_assigns);

  DerivedCopyMoveCounter derived_counter(&copies, &assigns, &move_constructs,
                                         &move_assigns);
  copies = 0;
  assigns = 0;
  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<CopyMoveCounter>::Run)
      .Run(CopyMoveCounter(derived_counter));
  EXPECT_EQ(1, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(1, move_constructs);
  EXPECT_EQ(0, move_assigns);

  copies = 0;
  assigns = 0;
  move_constructs = 0;
  move_assigns = 0;
  Bind(&VoidPolymorphic<CopyMoveCounter>::Run)
      .Run(CopyMoveCounter(DerivedCopyMoveCounter(
          &copies, &assigns, &move_constructs, &move_assigns)));
  EXPECT_EQ(0, copies);
  EXPECT_EQ(0, assigns);
  EXPECT_EQ(2, move_constructs);
  EXPECT_EQ(0, move_assigns);
}

TEST_F(BindTest, CapturelessLambda) {
  EXPECT_FALSE(internal::IsConvertibleToRunType<void>::value);
  EXPECT_FALSE(internal::IsConvertibleToRunType<int>::value);
  EXPECT_FALSE(internal::IsConvertibleToRunType<void(*)()>::value);
  EXPECT_FALSE(internal::IsConvertibleToRunType<void(NoRef::*)()>::value);

  auto f = []() {};
  EXPECT_TRUE(internal::IsConvertibleToRunType<decltype(f)>::value);

  int i = 0;
  auto g = [i]() {};
  EXPECT_FALSE(internal::IsConvertibleToRunType<decltype(g)>::value);

  auto h = [](int, double) { return 'k'; };
  EXPECT_TRUE((std::is_same<
      char(int, double),
      internal::ExtractCallableRunType<decltype(h)>>::value));

  EXPECT_EQ(42, Bind([] { return 42; }).Run());
  EXPECT_EQ(42, Bind([](int i) { return i * 7; }, 6).Run());

  int x = 1;
  base::Callback<void(int)> cb =
      Bind([](int* x, int i) { *x *= i; }, Unretained(&x));
  cb.Run(6);
  EXPECT_EQ(6, x);
  cb.Run(7);
  EXPECT_EQ(42, x);
}

TEST_F(BindTest, Cancellation) {
  EXPECT_CALL(no_ref_, VoidMethodWithIntArg(_)).Times(2);

  WeakPtrFactory<NoRef> weak_factory(&no_ref_);
  base::Callback<void(int)> cb =
      Bind(&NoRef::VoidMethodWithIntArg, weak_factory.GetWeakPtr());
  Closure cb2 = Bind(cb, 8);

  EXPECT_FALSE(cb.IsCancelled());
  EXPECT_FALSE(cb2.IsCancelled());

  cb.Run(6);
  cb2.Run();

  weak_factory.InvalidateWeakPtrs();

  EXPECT_TRUE(cb.IsCancelled());
  EXPECT_TRUE(cb2.IsCancelled());

  cb.Run(6);
  cb2.Run();
}

TEST_F(BindTest, OnceCallback) {
  using internal::OnceClosure;
  using internal::RepeatingClosure;
  using internal::BindOnce;
  using internal::BindRepeating;
  using internal::OnceCallback;

  // Check if Callback variants have declarations of conversions as expected.
  // Copy constructor and assignment of RepeatingCallback.
  static_assert(std::is_constructible<
      RepeatingClosure, const RepeatingClosure&>::value,
      "RepeatingClosure should be copyable.");
  static_assert(is_assignable<
      RepeatingClosure, const RepeatingClosure&>::value,
      "RepeatingClosure should be copy-assignable.");

  // Move constructor and assignment of RepeatingCallback.
  static_assert(std::is_constructible<
      RepeatingClosure, RepeatingClosure&&>::value,
      "RepeatingClosure should be movable.");
  static_assert(is_assignable<
      RepeatingClosure, RepeatingClosure&&>::value,
      "RepeatingClosure should be move-assignable");

  // Conversions from OnceCallback to RepeatingCallback.
  static_assert(!std::is_constructible<
      RepeatingClosure, const OnceClosure&>::value,
      "OnceClosure should not be convertible to RepeatingClosure.");
  static_assert(!is_assignable<
      RepeatingClosure, const OnceClosure&>::value,
      "OnceClosure should not be convertible to RepeatingClosure.");

  // Destructive conversions from OnceCallback to RepeatingCallback.
  static_assert(!std::is_constructible<
      RepeatingClosure, OnceClosure&&>::value,
      "OnceClosure should not be convertible to RepeatingClosure.");
  static_assert(!is_assignable<
      RepeatingClosure, OnceClosure&&>::value,
      "OnceClosure should not be convertible to RepeatingClosure.");

  // Copy constructor and assignment of OnceCallback.
  static_assert(!std::is_constructible<
      OnceClosure, const OnceClosure&>::value,
      "OnceClosure should not be copyable.");
  static_assert(!is_assignable<
      OnceClosure, const OnceClosure&>::value,
      "OnceClosure should not be copy-assignable");

  // Move constructor and assignment of OnceCallback.
  static_assert(std::is_constructible<
      OnceClosure, OnceClosure&&>::value,
      "OnceClosure should be movable.");
  static_assert(is_assignable<
      OnceClosure, OnceClosure&&>::value,
      "OnceClosure should be move-assignable.");

  // Conversions from RepeatingCallback to OnceCallback.
  static_assert(std::is_constructible<
      OnceClosure, const RepeatingClosure&>::value,
      "RepeatingClosure should be convertible to OnceClosure.");
  static_assert(is_assignable<
      OnceClosure, const RepeatingClosure&>::value,
      "RepeatingClosure should be convertible to OnceClosure.");

  // Destructive conversions from RepeatingCallback to OnceCallback.
  static_assert(std::is_constructible<
      OnceClosure, RepeatingClosure&&>::value,
      "RepeatingClosure should be convertible to OnceClosure.");
  static_assert(is_assignable<
      OnceClosure, RepeatingClosure&&>::value,
      "RepeatingClosure should be covretible to OnceClosure.");

  OnceClosure cb = BindOnce(&VoidPolymorphic<>::Run);
  std::move(cb).Run();

  // RepeatingCallback should be convertible to OnceCallback.
  OnceClosure cb2 = BindRepeating(&VoidPolymorphic<>::Run);
  std::move(cb2).Run();

  RepeatingClosure cb3 = BindRepeating(&VoidPolymorphic<>::Run);
  cb = cb3;
  std::move(cb).Run();

  cb = std::move(cb2);

  OnceCallback<void(int)> cb4 = BindOnce(
      &VoidPolymorphic<std::unique_ptr<int>, int>::Run, MakeUnique<int>(0));
  BindOnce(std::move(cb4), 1).Run();
}

// Callback construction and assignment tests.
//   - Construction from an InvokerStorageHolder should not cause ref/deref.
//   - Assignment from other callback should only cause one ref
//
// TODO(ajwong): Is there actually a way to test this?

#if defined(OS_WIN)
int __fastcall FastCallFunc(int n) {
  return n;
}

int __stdcall StdCallFunc(int n) {
  return n;
}

// Windows specific calling convention support.
//   - Can bind a __fastcall function.
//   - Can bind a __stdcall function.
TEST_F(BindTest, WindowsCallingConventions) {
  Callback<int()> fastcall_cb = Bind(&FastCallFunc, 1);
  EXPECT_EQ(1, fastcall_cb.Run());

  Callback<int()> stdcall_cb = Bind(&StdCallFunc, 2);
  EXPECT_EQ(2, stdcall_cb.Run());
}
#endif

// Test null callbacks cause a DCHECK.
TEST(BindDeathTest, NullCallback) {
  base::Callback<void(int)> null_cb;
  ASSERT_TRUE(null_cb.is_null());
  EXPECT_DCHECK_DEATH(base::Bind(null_cb, 42));
}

}  // namespace
}  // namespace base
