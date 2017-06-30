// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/ref_counted.h"

#include <utility>

#include "base/test/gtest_util.h"
#include "base/test/opaque_ref_counted.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

class SelfAssign : public base::RefCounted<SelfAssign> {
 protected:
  virtual ~SelfAssign() {}

 private:
  friend class base::RefCounted<SelfAssign>;
};

class Derived : public SelfAssign {
 protected:
  ~Derived() override {}

 private:
  friend class base::RefCounted<Derived>;
};

class CheckDerivedMemberAccess : public scoped_refptr<SelfAssign> {
 public:
  CheckDerivedMemberAccess() {
    // This shouldn't compile if we don't have access to the member variable.
    SelfAssign** pptr = &ptr_;
    EXPECT_EQ(*pptr, ptr_);
  }
};

class ScopedRefPtrToSelf : public base::RefCounted<ScopedRefPtrToSelf> {
 public:
  ScopedRefPtrToSelf() : self_ptr_(this) {}

  static bool was_destroyed() { return was_destroyed_; }

  static void reset_was_destroyed() { was_destroyed_ = false; }

  scoped_refptr<ScopedRefPtrToSelf> self_ptr_;

 private:
  friend class base::RefCounted<ScopedRefPtrToSelf>;
  ~ScopedRefPtrToSelf() { was_destroyed_ = true; }

  static bool was_destroyed_;
};

bool ScopedRefPtrToSelf::was_destroyed_ = false;

class ScopedRefPtrCountBase : public base::RefCounted<ScopedRefPtrCountBase> {
 public:
  ScopedRefPtrCountBase() { ++constructor_count_; }

  static int constructor_count() { return constructor_count_; }

  static int destructor_count() { return destructor_count_; }

  static void reset_count() {
    constructor_count_ = 0;
    destructor_count_ = 0;
  }

 protected:
  virtual ~ScopedRefPtrCountBase() { ++destructor_count_; }

 private:
  friend class base::RefCounted<ScopedRefPtrCountBase>;

  static int constructor_count_;
  static int destructor_count_;
};

int ScopedRefPtrCountBase::constructor_count_ = 0;
int ScopedRefPtrCountBase::destructor_count_ = 0;

class ScopedRefPtrCountDerived : public ScopedRefPtrCountBase {
 public:
  ScopedRefPtrCountDerived() { ++constructor_count_; }

  static int constructor_count() { return constructor_count_; }

  static int destructor_count() { return destructor_count_; }

  static void reset_count() {
    constructor_count_ = 0;
    destructor_count_ = 0;
  }

 protected:
  ~ScopedRefPtrCountDerived() override { ++destructor_count_; }

 private:
  friend class base::RefCounted<ScopedRefPtrCountDerived>;

  static int constructor_count_;
  static int destructor_count_;
};

int ScopedRefPtrCountDerived::constructor_count_ = 0;
int ScopedRefPtrCountDerived::destructor_count_ = 0;

class Other : public base::RefCounted<Other> {
 private:
  friend class base::RefCounted<Other>;

  ~Other() {}
};

scoped_refptr<Other> Overloaded(scoped_refptr<Other> other) {
  return other;
}

scoped_refptr<SelfAssign> Overloaded(scoped_refptr<SelfAssign> self_assign) {
  return self_assign;
}

class InitialRefCountIsOne : public base::RefCounted<InitialRefCountIsOne> {
 public:
  REQUIRE_ADOPTION_FOR_REFCOUNTED_TYPE();

  InitialRefCountIsOne() {}

 private:
  friend class base::RefCounted<InitialRefCountIsOne>;
  ~InitialRefCountIsOne() {}
};

}  // end namespace

TEST(RefCountedUnitTest, TestSelfAssignment) {
  SelfAssign* p = new SelfAssign;
  scoped_refptr<SelfAssign> var(p);
  var = var;
  EXPECT_EQ(var.get(), p);
}

TEST(RefCountedUnitTest, ScopedRefPtrMemberAccess) {
  CheckDerivedMemberAccess check;
}

TEST(RefCountedUnitTest, ScopedRefPtrToSelfPointerAssignment) {
  ScopedRefPtrToSelf::reset_was_destroyed();

  ScopedRefPtrToSelf* check = new ScopedRefPtrToSelf();
  EXPECT_FALSE(ScopedRefPtrToSelf::was_destroyed());
  check->self_ptr_ = nullptr;
  EXPECT_TRUE(ScopedRefPtrToSelf::was_destroyed());
}

TEST(RefCountedUnitTest, ScopedRefPtrToSelfMoveAssignment) {
  ScopedRefPtrToSelf::reset_was_destroyed();

  ScopedRefPtrToSelf* check = new ScopedRefPtrToSelf();
  EXPECT_FALSE(ScopedRefPtrToSelf::was_destroyed());
  // Releasing |check->self_ptr_| will delete |check|.
  // The move assignment operator must assign |check->self_ptr_| first then
  // release |check->self_ptr_|.
  check->self_ptr_ = scoped_refptr<ScopedRefPtrToSelf>();
  EXPECT_TRUE(ScopedRefPtrToSelf::was_destroyed());
}

TEST(RefCountedUnitTest, ScopedRefPtrToOpaque) {
  scoped_refptr<base::OpaqueRefCounted> initial = base::MakeOpaqueRefCounted();
  base::TestOpaqueRefCounted(initial);

  scoped_refptr<base::OpaqueRefCounted> assigned;
  assigned = initial;

  scoped_refptr<base::OpaqueRefCounted> copied(initial);

  scoped_refptr<base::OpaqueRefCounted> moved(std::move(initial));

  scoped_refptr<base::OpaqueRefCounted> move_assigned;
  move_assigned = std::move(moved);
}

TEST(RefCountedUnitTest, ScopedRefPtrToOpaqueThreadSafe) {
  scoped_refptr<base::OpaqueRefCountedThreadSafe> initial =
      base::MakeOpaqueRefCountedThreadSafe();
  base::TestOpaqueRefCountedThreadSafe(initial);

  scoped_refptr<base::OpaqueRefCountedThreadSafe> assigned;
  assigned = initial;

  scoped_refptr<base::OpaqueRefCountedThreadSafe> copied(initial);

  scoped_refptr<base::OpaqueRefCountedThreadSafe> moved(std::move(initial));

  scoped_refptr<base::OpaqueRefCountedThreadSafe> move_assigned;
  move_assigned = std::move(moved);
}

TEST(RefCountedUnitTest, BooleanTesting) {
  scoped_refptr<SelfAssign> ptr_to_an_instance = new SelfAssign;
  EXPECT_TRUE(ptr_to_an_instance);
  EXPECT_FALSE(!ptr_to_an_instance);

  if (ptr_to_an_instance) {
  } else {
    ADD_FAILURE() << "Pointer to an instance should result in true.";
  }

  if (!ptr_to_an_instance) {  // check for operator!().
    ADD_FAILURE() << "Pointer to an instance should result in !x being false.";
  }

  scoped_refptr<SelfAssign> null_ptr;
  EXPECT_FALSE(null_ptr);
  EXPECT_TRUE(!null_ptr);

  if (null_ptr) {
    ADD_FAILURE() << "Null pointer should result in false.";
  }

  if (!null_ptr) {  // check for operator!().
  } else {
    ADD_FAILURE() << "Null pointer should result in !x being true.";
  }
}

TEST(RefCountedUnitTest, Equality) {
  scoped_refptr<SelfAssign> p1(new SelfAssign);
  scoped_refptr<SelfAssign> p2(new SelfAssign);

  EXPECT_EQ(p1, p1);
  EXPECT_EQ(p2, p2);

  EXPECT_NE(p1, p2);
  EXPECT_NE(p2, p1);
}

TEST(RefCountedUnitTest, NullptrEquality) {
  scoped_refptr<SelfAssign> ptr_to_an_instance(new SelfAssign);
  scoped_refptr<SelfAssign> ptr_to_nullptr;

  EXPECT_NE(nullptr, ptr_to_an_instance);
  EXPECT_NE(ptr_to_an_instance, nullptr);
  EXPECT_EQ(nullptr, ptr_to_nullptr);
  EXPECT_EQ(ptr_to_nullptr, nullptr);
}

TEST(RefCountedUnitTest, ConvertibleEquality) {
  scoped_refptr<Derived> p1(new Derived);
  scoped_refptr<SelfAssign> p2;

  EXPECT_NE(p1, p2);
  EXPECT_NE(p2, p1);

  p2 = p1;

  EXPECT_EQ(p1, p2);
  EXPECT_EQ(p2, p1);
}

TEST(RefCountedUnitTest, MoveAssignment1) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase *raw = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1(raw);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    {
      scoped_refptr<ScopedRefPtrCountBase> p2;

      p2 = std::move(p1);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(nullptr, p1.get());
      EXPECT_EQ(raw, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveAssignment2) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase *raw = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1;
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    {
      scoped_refptr<ScopedRefPtrCountBase> p2(raw);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

      p1 = std::move(p2);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(raw, p1.get());
      EXPECT_EQ(nullptr, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveAssignmentSameInstance1) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase *raw = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1(raw);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    {
      scoped_refptr<ScopedRefPtrCountBase> p2(p1);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

      p1 = std::move(p2);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(raw, p1.get());
      EXPECT_EQ(nullptr, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveAssignmentSameInstance2) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase *raw = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1(raw);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    {
      scoped_refptr<ScopedRefPtrCountBase> p2(p1);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

      p2 = std::move(p1);
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(nullptr, p1.get());
      EXPECT_EQ(raw, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveAssignmentDifferentInstances) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase *raw1 = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1(raw1);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    {
      ScopedRefPtrCountBase *raw2 = new ScopedRefPtrCountBase();
      scoped_refptr<ScopedRefPtrCountBase> p2(raw2);
      EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

      p1 = std::move(p2);
      EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(raw2, p1.get());
      EXPECT_EQ(nullptr, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(2, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveAssignmentSelfMove) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase* raw = new ScopedRefPtrCountBase;
    scoped_refptr<ScopedRefPtrCountBase> p1(raw);
    scoped_refptr<ScopedRefPtrCountBase>& p1_ref = p1;

    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    p1 = std::move(p1_ref);

    // |p1| is "valid but unspecified", so don't bother inspecting its
    // contents, just ensure that we don't crash.
  }

  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveAssignmentDerived) {
  ScopedRefPtrCountBase::reset_count();
  ScopedRefPtrCountDerived::reset_count();

  {
    ScopedRefPtrCountBase *raw1 = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1(raw1);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountDerived::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountDerived::destructor_count());

    {
      ScopedRefPtrCountDerived *raw2 = new ScopedRefPtrCountDerived();
      scoped_refptr<ScopedRefPtrCountDerived> p2(raw2);
      EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountDerived::destructor_count());

      p1 = std::move(p2);
      EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountDerived::destructor_count());
      EXPECT_EQ(raw2, p1.get());
      EXPECT_EQ(nullptr, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountDerived::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(2, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(2, ScopedRefPtrCountBase::destructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountDerived::destructor_count());
}

TEST(RefCountedUnitTest, MoveConstructor) {
  ScopedRefPtrCountBase::reset_count();

  {
    ScopedRefPtrCountBase *raw = new ScopedRefPtrCountBase();
    scoped_refptr<ScopedRefPtrCountBase> p1(raw);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());

    {
      scoped_refptr<ScopedRefPtrCountBase> p2(std::move(p1));
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(nullptr, p1.get());
      EXPECT_EQ(raw, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
}

TEST(RefCountedUnitTest, MoveConstructorDerived) {
  ScopedRefPtrCountBase::reset_count();
  ScopedRefPtrCountDerived::reset_count();

  {
    ScopedRefPtrCountDerived *raw1 = new ScopedRefPtrCountDerived();
    scoped_refptr<ScopedRefPtrCountDerived> p1(raw1);
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
    EXPECT_EQ(0, ScopedRefPtrCountDerived::destructor_count());

    {
      scoped_refptr<ScopedRefPtrCountBase> p2(std::move(p1));
      EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountBase::destructor_count());
      EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
      EXPECT_EQ(0, ScopedRefPtrCountDerived::destructor_count());
      EXPECT_EQ(nullptr, p1.get());
      EXPECT_EQ(raw1, p2.get());

      // p2 goes out of scope.
    }
    EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
    EXPECT_EQ(1, ScopedRefPtrCountDerived::destructor_count());

    // p1 goes out of scope.
  }
  EXPECT_EQ(1, ScopedRefPtrCountBase::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountBase::destructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountDerived::constructor_count());
  EXPECT_EQ(1, ScopedRefPtrCountDerived::destructor_count());
}

TEST(RefCountedUnitTest, TestOverloadResolutionCopy) {
  scoped_refptr<Derived> derived(new Derived);
  scoped_refptr<SelfAssign> expected(derived);
  EXPECT_EQ(expected, Overloaded(derived));

  scoped_refptr<Other> other(new Other);
  EXPECT_EQ(other, Overloaded(other));
}

TEST(RefCountedUnitTest, TestOverloadResolutionMove) {
  scoped_refptr<Derived> derived(new Derived);
  scoped_refptr<SelfAssign> expected(derived);
  EXPECT_EQ(expected, Overloaded(std::move(derived)));

  scoped_refptr<Other> other(new Other);
  scoped_refptr<Other> other2(other);
  EXPECT_EQ(other2, Overloaded(std::move(other)));
}

TEST(RefCountedUnitTest, TestInitialRefCountIsOne) {
  scoped_refptr<InitialRefCountIsOne> obj =
      base::MakeRefCounted<InitialRefCountIsOne>();
  EXPECT_TRUE(obj->HasOneRef());
  obj = nullptr;

  scoped_refptr<InitialRefCountIsOne> obj2 =
      base::AdoptRef(new InitialRefCountIsOne);
  EXPECT_TRUE(obj2->HasOneRef());
  obj2 = nullptr;

  scoped_refptr<Other> obj3 = base::MakeRefCounted<Other>();
  EXPECT_TRUE(obj3->HasOneRef());
  obj3 = nullptr;
}

TEST(RefCountedDeathTest, TestAdoptRef) {
  EXPECT_DCHECK_DEATH(make_scoped_refptr(new InitialRefCountIsOne));

  InitialRefCountIsOne* ptr = nullptr;
  EXPECT_DCHECK_DEATH(base::AdoptRef(ptr));

  scoped_refptr<InitialRefCountIsOne> obj =
      base::MakeRefCounted<InitialRefCountIsOne>();
  EXPECT_DCHECK_DEATH(base::AdoptRef(obj.get()));
}
