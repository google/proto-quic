// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_one_block_arena.h"

#include <cstdint>

#include "net/quic/platform/api/quic_containers.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

static const uint32_t kMaxAlign = 8;

struct TestObject {
  uint32_t value;
};

TEST(QuicOneBlockArenaTest, AllocateSuccess) {
  QuicOneBlockArena<1024> arena;
  QuicArenaScopedPtr<TestObject> ptr = arena.New<TestObject>();
  EXPECT_TRUE(ptr.is_from_arena());
}

TEST(QuicOneBlockArenaTest, Exhaust) {
  QuicOneBlockArena<1024> arena;
  for (size_t i = 0; i < 1024 / kMaxAlign; ++i) {
    QuicArenaScopedPtr<TestObject> ptr = arena.New<TestObject>();
    EXPECT_TRUE(ptr.is_from_arena());
  }
  QuicArenaScopedPtr<TestObject> ptr;
  EXPECT_QUIC_BUG(ptr = arena.New<TestObject>(),
                  "Ran out of space in QuicOneBlockArena");
  EXPECT_FALSE(ptr.is_from_arena());
}

TEST(QuicOneBlockArenaTest, NoOverlaps) {
  QuicOneBlockArena<1024> arena;
  std::vector<QuicArenaScopedPtr<TestObject>> objects;
  QuicIntervalSet<uintptr_t> used;
  for (size_t i = 0; i < 1024 / kMaxAlign; ++i) {
    QuicArenaScopedPtr<TestObject> ptr = arena.New<TestObject>();
    EXPECT_TRUE(ptr.is_from_arena());

    uintptr_t begin = reinterpret_cast<uintptr_t>(ptr.get());
    uintptr_t end = begin + sizeof(TestObject);
    EXPECT_FALSE(used.Contains(begin));
    EXPECT_FALSE(used.Contains(end - 1));
    used.Add(begin, end);
  }
}

}  // namespace
}  // namespace net
