// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_arena_scoped_ptr.h"

#include "net/quic/core/quic_one_block_arena.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

enum class TestParam { kFromHeap, kFromArena };

struct TestObject {
  explicit TestObject(uintptr_t value) : value(value) { buffer.resize(1024); }
  uintptr_t value;

  // Ensure that we have a non-trivial destructor that will leak memory if it's
  // not called.
  std::vector<char> buffer;
};

class QuicArenaScopedPtrParamTest : public ::testing::TestWithParam<TestParam> {
 protected:
  QuicArenaScopedPtr<TestObject> CreateObject(uintptr_t value) {
    QuicArenaScopedPtr<TestObject> ptr;
    switch (GetParam()) {
      case TestParam::kFromHeap:
        ptr = QuicArenaScopedPtr<TestObject>(new TestObject(value));
        CHECK(!ptr.is_from_arena());
        break;
      case TestParam::kFromArena:
        ptr = arena_.New<TestObject>(value);
        CHECK(ptr.is_from_arena());
        break;
    }
    return ptr;
  }

 private:
  QuicOneBlockArena<1024> arena_;
};

INSTANTIATE_TEST_CASE_P(QuicArenaScopedPtrParamTest,
                        QuicArenaScopedPtrParamTest,
                        testing::Values(TestParam::kFromHeap,
                                        TestParam::kFromArena));

TEST(QuicArenaScopedPtrTest, NullObjects) {
  QuicArenaScopedPtr<TestObject> def;
  QuicArenaScopedPtr<TestObject> null(nullptr);
  EXPECT_EQ(def, null);
  EXPECT_EQ(def, nullptr);
  EXPECT_EQ(null, nullptr);
}

TEST(QuicArenaScopedPtrTest, FromArena) {
  QuicOneBlockArena<1024> arena_;
  EXPECT_TRUE(arena_.New<TestObject>(0).is_from_arena());
  EXPECT_FALSE(
      QuicArenaScopedPtr<TestObject>(new TestObject(0)).is_from_arena());
}

TEST_P(QuicArenaScopedPtrParamTest, Assign) {
  QuicArenaScopedPtr<TestObject> ptr = CreateObject(12345);
  ptr = CreateObject(54321);
  EXPECT_EQ(54321u, ptr->value);
}

TEST_P(QuicArenaScopedPtrParamTest, MoveConstruct) {
  QuicArenaScopedPtr<TestObject> ptr1 = CreateObject(12345);
  QuicArenaScopedPtr<TestObject> ptr2(std::move(ptr1));
  EXPECT_EQ(nullptr, ptr1);
  EXPECT_EQ(12345u, ptr2->value);
}

TEST_P(QuicArenaScopedPtrParamTest, Accessors) {
  QuicArenaScopedPtr<TestObject> ptr = CreateObject(12345);
  EXPECT_EQ(12345u, (*ptr).value);
  EXPECT_EQ(12345u, ptr->value);
  // We explicitly want to test that get() returns a valid pointer to the data,
  // but the call looks redundant.
  EXPECT_EQ(12345u, ptr.get()->value);  // NOLINT
}

TEST_P(QuicArenaScopedPtrParamTest, Reset) {
  QuicArenaScopedPtr<TestObject> ptr = CreateObject(12345);
  ptr.reset(new TestObject(54321));
  EXPECT_EQ(54321u, ptr->value);
}

TEST_P(QuicArenaScopedPtrParamTest, Swap) {
  QuicArenaScopedPtr<TestObject> ptr1 = CreateObject(12345);
  QuicArenaScopedPtr<TestObject> ptr2 = CreateObject(54321);
  ptr1.swap(ptr2);
  EXPECT_EQ(12345u, ptr2->value);
  EXPECT_EQ(54321u, ptr1->value);
}

}  // namespace
}  // namespace net
