// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/containers/flat_map.h"

#include <string>
#include <vector>

#include "base/containers/container_test_utils.h"
#include "base/macros.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

// A flat_map is basically a interface to flat_tree. So several basic
// operations are tested to make sure things are set up properly, but the bulk
// of the tests are in flat_tree_unittests.cc.

using ::testing::ElementsAre;

namespace base {

TEST(FlatMap, IncompleteType) {
  struct A {
    using Map = flat_map<A, A>;
    int data;
    Map set_with_incomplete_type;
    Map::iterator it;
    Map::const_iterator cit;

    // We do not declare operator< because clang complains that it's unused.
  };

  A a;
}

TEST(FlatMap, RangeConstructor) {
  flat_map<int, int>::value_type input_vals[] = {
      {1, 1}, {1, 2}, {1, 3}, {2, 1}, {2, 2}, {2, 3}, {3, 1}, {3, 2}, {3, 3}};

  flat_map<int, int> first(std::begin(input_vals), std::end(input_vals),
                           KEEP_FIRST_OF_DUPES);
  EXPECT_THAT(first, ElementsAre(std::make_pair(1, 1), std::make_pair(2, 1),
                                 std::make_pair(3, 1)));

  flat_map<int, int> last(std::begin(input_vals), std::end(input_vals),
                          KEEP_LAST_OF_DUPES);
  EXPECT_THAT(last, ElementsAre(std::make_pair(1, 3), std::make_pair(2, 3),
                                std::make_pair(3, 3)));
}

TEST(FlatMap, MoveConstructor) {
  using pair = std::pair<MoveOnlyInt, MoveOnlyInt>;

  flat_map<MoveOnlyInt, MoveOnlyInt> original;
  original.insert(pair(MoveOnlyInt(1), MoveOnlyInt(1)));
  original.insert(pair(MoveOnlyInt(2), MoveOnlyInt(2)));
  original.insert(pair(MoveOnlyInt(3), MoveOnlyInt(3)));
  original.insert(pair(MoveOnlyInt(4), MoveOnlyInt(4)));

  flat_map<MoveOnlyInt, MoveOnlyInt> moved(std::move(original));

  EXPECT_EQ(1U, moved.count(MoveOnlyInt(1)));
  EXPECT_EQ(1U, moved.count(MoveOnlyInt(2)));
  EXPECT_EQ(1U, moved.count(MoveOnlyInt(3)));
  EXPECT_EQ(1U, moved.count(MoveOnlyInt(4)));
}

TEST(FlatMap, VectorConstructor) {
  using IntPair = std::pair<int, int>;
  using IntMap = flat_map<int, int>;
  {
    std::vector<IntPair> vect{{1, 1}, {1, 2}, {2, 1}};
    IntMap map(std::move(vect), KEEP_FIRST_OF_DUPES);
    EXPECT_THAT(map, ElementsAre(IntPair(1, 1), IntPair(2, 1)));
  }
  {
    std::vector<IntPair> vect{{1, 1}, {1, 2}, {2, 1}};
    IntMap map(std::move(vect), KEEP_LAST_OF_DUPES);
    EXPECT_THAT(map, ElementsAre(IntPair(1, 2), IntPair(2, 1)));
  }
}

TEST(FlatMap, InitializerListConstructor) {
  {
    flat_map<int, int> cont(
        {{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {1, 2}, {10, 10}, {8, 8}},
        KEEP_FIRST_OF_DUPES);
    EXPECT_THAT(cont, ElementsAre(std::make_pair(1, 1), std::make_pair(2, 2),
                                  std::make_pair(3, 3), std::make_pair(4, 4),
                                  std::make_pair(5, 5), std::make_pair(8, 8),
                                  std::make_pair(10, 10)));
  }
  {
    flat_map<int, int> cont(
        {{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {1, 2}, {10, 10}, {8, 8}},
        KEEP_LAST_OF_DUPES);
    EXPECT_THAT(cont, ElementsAre(std::make_pair(1, 2), std::make_pair(2, 2),
                                  std::make_pair(3, 3), std::make_pair(4, 4),
                                  std::make_pair(5, 5), std::make_pair(8, 8),
                                  std::make_pair(10, 10)));
  }
}

TEST(FlatMap, InsertFindSize) {
  base::flat_map<int, int> s;
  s.insert(std::make_pair(1, 1));
  s.insert(std::make_pair(1, 1));
  s.insert(std::make_pair(2, 2));

  EXPECT_EQ(2u, s.size());
  EXPECT_EQ(std::make_pair(1, 1), *s.find(1));
  EXPECT_EQ(std::make_pair(2, 2), *s.find(2));
  EXPECT_EQ(s.end(), s.find(7));
}

TEST(FlatMap, CopySwap) {
  base::flat_map<int, int> original;
  original.insert({1, 1});
  original.insert({2, 2});
  EXPECT_THAT(original,
              ElementsAre(std::make_pair(1, 1), std::make_pair(2, 2)));

  base::flat_map<int, int> copy(original);
  EXPECT_THAT(copy, ElementsAre(std::make_pair(1, 1), std::make_pair(2, 2)));

  copy.erase(copy.begin());
  copy.insert({10, 10});
  EXPECT_THAT(copy, ElementsAre(std::make_pair(2, 2), std::make_pair(10, 10)));

  original.swap(copy);
  EXPECT_THAT(original,
              ElementsAre(std::make_pair(2, 2), std::make_pair(10, 10)));
  EXPECT_THAT(copy, ElementsAre(std::make_pair(1, 1), std::make_pair(2, 2)));
}

// operator[](const Key&)
TEST(FlatMap, SubscriptConstKey) {
  base::flat_map<std::string, int> m;

  // Default construct elements that don't exist yet.
  int& s = m["a"];
  EXPECT_EQ(0, s);
  EXPECT_EQ(1u, m.size());

  // The returned mapped reference should refer into the map.
  s = 22;
  EXPECT_EQ(22, m["a"]);

  // Overwrite existing elements.
  m["a"] = 44;
  EXPECT_EQ(44, m["a"]);
}

// operator[](Key&&)
TEST(FlatMap, SubscriptMoveOnlyKey) {
  base::flat_map<MoveOnlyInt, int> m;

  // Default construct elements that don't exist yet.
  int& s = m[MoveOnlyInt(1)];
  EXPECT_EQ(0, s);
  EXPECT_EQ(1u, m.size());

  // The returned mapped reference should refer into the map.
  s = 22;
  EXPECT_EQ(22, m[MoveOnlyInt(1)]);

  // Overwrite existing elements.
  m[MoveOnlyInt(1)] = 44;
  EXPECT_EQ(44, m[MoveOnlyInt(1)]);
}

}  // namespace base
