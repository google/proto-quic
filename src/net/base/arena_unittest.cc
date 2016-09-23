// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/arena.h"

#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;

namespace net {
namespace {

size_t kDefaultBlockSize = 2048;
const char kTestString[] = "This is a decently long test string.";

TEST(UnsafeArenaTest, Memdup) {
  UnsafeArena arena(kDefaultBlockSize);
  const size_t length = strlen(kTestString);
  char* c = arena.Memdup(kTestString, length);
  EXPECT_NE(nullptr, c);
  EXPECT_NE(c, kTestString);
  EXPECT_EQ(StringPiece(c, length), kTestString);
}

TEST(UnsafeArenaTest, MemdupLargeString) {
  UnsafeArena arena(10 /* block size */);
  const size_t length = strlen(kTestString);
  char* c = arena.Memdup(kTestString, length);
  EXPECT_NE(nullptr, c);
  EXPECT_NE(c, kTestString);
  EXPECT_EQ(StringPiece(c, length), kTestString);
}

TEST(UnsafeArenaTest, MultipleBlocks) {
  UnsafeArena arena(40 /* block size */);
  std::vector<std::string> strings = {
      "One decently long string.", "Another string.",
      "A third string that will surely go in a different block."};
  std::vector<StringPiece> copies;
  for (const std::string& s : strings) {
    StringPiece sp(arena.Memdup(s.data(), s.size()), s.size());
    copies.push_back(sp);
  }
  EXPECT_EQ(strings.size(), copies.size());
  for (size_t i = 0; i < strings.size(); ++i) {
    EXPECT_EQ(copies[i], strings[i]);
  }
}

TEST(UnsafeArenaTest, UseAfterReset) {
  UnsafeArena arena(kDefaultBlockSize);
  const size_t length = strlen(kTestString);
  char* c = arena.Memdup(kTestString, length);
  arena.Reset();
  c = arena.Memdup(kTestString, length);
  EXPECT_NE(nullptr, c);
  EXPECT_NE(c, kTestString);
  EXPECT_EQ(StringPiece(c, length), kTestString);
}

TEST(UnsafeArenaTest, Free) {
  UnsafeArena arena(kDefaultBlockSize);
  const size_t length = strlen(kTestString);
  // Freeing memory not owned by the arena should be a no-op, and freeing
  // before any allocations from the arena should be a no-op.
  arena.Free(const_cast<char*>(kTestString), length);
  char* c1 = arena.Memdup("Foo", 3);
  char* c2 = arena.Memdup(kTestString, length);
  arena.Free(const_cast<char*>(kTestString), length);
  char* c3 = arena.Memdup("Bar", 3);
  char* c4 = arena.Memdup(kTestString, length);
  EXPECT_NE(c1, c2);
  EXPECT_NE(c1, c3);
  EXPECT_NE(c1, c4);
  EXPECT_NE(c2, c3);
  EXPECT_NE(c2, c4);
  EXPECT_NE(c3, c4);
  // Freeing c4 should succeed, since it was the most recent allocation.
  arena.Free(c4, length);
  // Freeing c2 should be a no-op.
  arena.Free(c2, length);
  // c5 should reuse memory that was previously used by c4.
  char* c5 = arena.Memdup("Baz", 3);
  EXPECT_EQ(c4, c5);
}

TEST(UnsafeArenaTest, Alloc) {
  UnsafeArena arena(kDefaultBlockSize);
  const size_t length = strlen(kTestString);
  char* c1 = arena.Alloc(length);
  char* c2 = arena.Alloc(2 * length);
  char* c3 = arena.Alloc(3 * length);
  char* c4 = arena.Memdup(kTestString, length);
  EXPECT_EQ(c1 + length, c2);
  EXPECT_EQ(c2 + 2 * length, c3);
  EXPECT_EQ(c3 + 3 * length, c4);
  EXPECT_EQ(StringPiece(c4, length), kTestString);
}

TEST(UnsafeArenaTest, Realloc) {
  UnsafeArena arena(kDefaultBlockSize);
  const size_t length = strlen(kTestString);
  // Simple realloc that fits in the block.
  char* c1 = arena.Memdup(kTestString, length);
  char* c2 = arena.Realloc(c1, length, 2 * length);
  EXPECT_TRUE(c1);
  EXPECT_EQ(c1, c2);
  EXPECT_EQ(StringPiece(c1, length), kTestString);
  // Multiple reallocs.
  char* c3 = arena.Memdup(kTestString, length);
  EXPECT_EQ(c2 + 2 * length, c3);
  EXPECT_EQ(StringPiece(c3, length), kTestString);
  char* c4 = arena.Realloc(c3, length, 2 * length);
  EXPECT_EQ(c3, c4);
  EXPECT_EQ(StringPiece(c4, length), kTestString);
  char* c5 = arena.Realloc(c4, 2 * length, 3 * length);
  EXPECT_EQ(c4, c5);
  EXPECT_EQ(StringPiece(c5, length), kTestString);
  char* c6 = arena.Memdup(kTestString, length);
  EXPECT_EQ(c5 + 3 * length, c6);
  EXPECT_EQ(StringPiece(c6, length), kTestString);
  // Realloc that does not fit in the remainder of the first block.
  char* c7 = arena.Realloc(c6, length, kDefaultBlockSize);
  EXPECT_EQ(StringPiece(c7, length), kTestString);
  arena.Free(c7, kDefaultBlockSize);
  char* c8 = arena.Memdup(kTestString, length);
  EXPECT_NE(c6, c7);
  EXPECT_EQ(c7, c8);
  EXPECT_EQ(StringPiece(c8, length), kTestString);
}

}  // namespace
}  // namespace net
