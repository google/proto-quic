// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/api/quic_reference_counted.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {
namespace {

class Base : public QuicReferenceCounted {
 public:
  explicit Base(bool* destroyed) : destroyed_(destroyed) {
    *destroyed_ = false;
  }

  bool destroyed() const { return *destroyed_; }

 protected:
  ~Base() override { *destroyed_ = true; }

 private:
  bool* destroyed_;
};

class Derived : public Base {
 public:
  explicit Derived(bool* destroyed) : Base(destroyed) {}

 private:
  ~Derived() override {}
};

TEST(QuicReferenceCountedTest, DefaultConstructor) {
  QuicReferenceCountedPointer<Base> a;
  EXPECT_EQ(nullptr, a);
  EXPECT_EQ(nullptr, a.get());
  EXPECT_FALSE(a);
}

TEST(QuicReferenceCountedTest, ConstructFromRawPointer) {
  bool destroyed = false;
  {
    QuicReferenceCountedPointer<Base> a(new Base(&destroyed));
    EXPECT_FALSE(destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, RawPointerAssignment) {
  bool destroyed = false;
  {
    QuicReferenceCountedPointer<Base> a;
    Base* rct = new Base(&destroyed);
    a = rct;
    EXPECT_FALSE(destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerCopy) {
  bool destroyed = false;
  {
    QuicReferenceCountedPointer<Base> a(new Base(&destroyed));
    {
      QuicReferenceCountedPointer<Base> b(a);
      EXPECT_EQ(a, b);
      EXPECT_FALSE(destroyed);
    }
    EXPECT_FALSE(destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerCopyAssignment) {
  bool destroyed = false;
  {
    QuicReferenceCountedPointer<Base> a(new Base(&destroyed));
    {
      QuicReferenceCountedPointer<Base> b = a;
      EXPECT_EQ(a, b);
      EXPECT_FALSE(destroyed);
    }
    EXPECT_FALSE(destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerCopyFromOtherType) {
  bool destroyed = false;
  {
    QuicReferenceCountedPointer<Derived> a(new Derived(&destroyed));
    {
      QuicReferenceCountedPointer<Base> b(a);
      EXPECT_EQ(a.get(), b.get());
      EXPECT_FALSE(destroyed);
    }
    EXPECT_FALSE(destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerCopyAssignmentFromOtherType) {
  bool destroyed = false;
  {
    QuicReferenceCountedPointer<Derived> a(new Derived(&destroyed));
    {
      QuicReferenceCountedPointer<Base> b = a;
      EXPECT_EQ(a.get(), b.get());
      EXPECT_FALSE(destroyed);
    }
    EXPECT_FALSE(destroyed);
  }
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerMove) {
  bool destroyed = false;
  QuicReferenceCountedPointer<Base> a(new Derived(&destroyed));
  EXPECT_FALSE(destroyed);
  QuicReferenceCountedPointer<Base> b(std::move(a));
  EXPECT_FALSE(destroyed);
  EXPECT_NE(nullptr, b);
  EXPECT_EQ(nullptr, a);  // NOLINT

  b = nullptr;
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerMoveAssignment) {
  bool destroyed = false;
  QuicReferenceCountedPointer<Base> a(new Derived(&destroyed));
  EXPECT_FALSE(destroyed);
  QuicReferenceCountedPointer<Base> b = std::move(a);
  EXPECT_FALSE(destroyed);
  EXPECT_NE(nullptr, b);
  EXPECT_EQ(nullptr, a);  // NOLINT

  b = nullptr;
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerMoveFromOtherType) {
  bool destroyed = false;
  QuicReferenceCountedPointer<Derived> a(new Derived(&destroyed));
  EXPECT_FALSE(destroyed);
  QuicReferenceCountedPointer<Base> b(std::move(a));
  EXPECT_FALSE(destroyed);
  EXPECT_NE(nullptr, b);
  EXPECT_EQ(nullptr, a);  // NOLINT

  b = nullptr;
  EXPECT_TRUE(destroyed);
}

TEST(QuicReferenceCountedTest, PointerMoveAssignmentFromOtherType) {
  bool destroyed = false;
  QuicReferenceCountedPointer<Derived> a(new Derived(&destroyed));
  EXPECT_FALSE(destroyed);
  QuicReferenceCountedPointer<Base> b = std::move(a);
  EXPECT_FALSE(destroyed);
  EXPECT_NE(nullptr, b);
  EXPECT_EQ(nullptr, a);  // NOLINT

  b = nullptr;
  EXPECT_TRUE(destroyed);
}

}  // namespace
}  // namespace test
}  // namespace net
