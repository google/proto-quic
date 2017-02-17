// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/containers/flat_set.h"

// Following tests are ported and extended tests from libcpp for std::set.
// They can be found here:
// https://github.com/llvm-mirror/libcxx/tree/master/test/std/containers/associative/set
//
// Not ported tests:
// * No tests with PrivateConstructor and std::less<> changed to std::less<T>
//   These tests have to do with C++14 std::less<>
//   http://en.cppreference.com/w/cpp/utility/functional/less_void
//   and add support for templated versions of lookup functions.
//   Current implementation of flat containers doesn't support it.
// * No tests with TemplateConstructor.
//   Library working group issue: LWG #2059
//   http://www.open-std.org/jtc1/sc22/wg21/docs/lwg-defects.html#2059
//   There is an ambiguity between erase with an iterator and erase with a key,
//   if key has a templated constructor. We have to fix this.
// * No tests for max_size()
//   Has to do with allocator support.
// * No tests with DefaultOnly.
//   Standard containers allocate each element in the separate node on the heap
//   and then manipulate these nodes. Flat containers store their elements in
//   contiguous memory and move them around, type is required to be movable.
// * No tests for N3644.
//   This proposal suggests that all default constructed iterators compare
//   equal. Currently we use std::vector iterators and they don't implement
//   this.
// * No tests with min_allocator and no tests counting allocations.
//   Flat sets currently don't support allocators.
// * No tests for range insertion. Flat sets currently do not support this
//   functionality.

#include <string>
#include <vector>

#include "base/macros.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

class MoveOnly {
 public:
  explicit MoveOnly(int data = 1) : data_(data) {}
  MoveOnly(MoveOnly&& other) : data_(other.data_) { other.data_ = 0; }
  MoveOnly& operator=(MoveOnly&& other) {
    data_ = other.data_;
    other.data_ = 0;
    return *this;
  }

  friend bool operator<(const MoveOnly& lhs, const MoveOnly& rhs) {
    return lhs.data_ < rhs.data_;
  }

  int data() const { return data_; }

 private:
  int data_;

  DISALLOW_COPY_AND_ASSIGN(MoveOnly);
};

template <class It>
class InputIterator {
 public:
  using iterator_category = std::input_iterator_tag;
  using value_type = typename std::iterator_traits<It>::value_type;
  using difference_type = typename std::iterator_traits<It>::difference_type;
  using pointer = It;
  using reference = typename std::iterator_traits<It>::reference;

  InputIterator() : it_() {}
  explicit InputIterator(It it) : it_(it) {}

  reference operator*() const { return *it_; }
  pointer operator->() const { return it_; }

  InputIterator& operator++() {
    ++it_;
    return *this;
  }
  InputIterator operator++(int) {
    InputIterator tmp(*this);
    ++(*this);
    return tmp;
  }

  friend bool operator==(const InputIterator& lhs, const InputIterator& rhs) {
    return lhs.it_ == rhs.it_;
  }
  friend bool operator!=(const InputIterator& lhs, const InputIterator& rhs) {
    return !(lhs == rhs);
  }

 private:
  It it_;
};

template <typename It>
InputIterator<It> MakeInputIterator(It it) {
  return InputIterator<It>(it);
}

class Emplaceable {
 public:
  Emplaceable() : Emplaceable(0, 0.0) {}
  Emplaceable(int i, double d) : int_(i), double_(d) {}
  Emplaceable(Emplaceable&& other) : int_(other.int_), double_(other.double_) {
    other.int_ = 0;
    other.double_ = 0.0;
  }

  Emplaceable& operator=(Emplaceable&& other) {
    int_ = other.int_;
    other.int_ = 0;
    double_ = other.double_;
    other.double_ = 0.0;
    return *this;
  }

  friend bool operator==(const Emplaceable& lhs, const Emplaceable& rhs) {
    return std::tie(lhs.int_, lhs.double_) == std::tie(rhs.int_, rhs.double_);
  }

  friend bool operator<(const Emplaceable& lhs, const Emplaceable& rhs) {
    return std::tie(lhs.int_, lhs.double_) < std::tie(rhs.int_, rhs.double_);
  }

 private:
  int int_;
  double double_;

  DISALLOW_COPY_AND_ASSIGN(Emplaceable);
};

class NonDefaultConstructibleCompare {
 public:
  explicit NonDefaultConstructibleCompare(int) {}

  template <typename T>
  bool operator()(const T& lhs, const T& rhs) {
    return std::less<T>()(lhs, rhs);
  }
};

// Common test sets.
using IntSet = base::flat_set<int>;
using MoveOnlySet = base::flat_set<MoveOnly>;
using EmplaceableSet = base::flat_set<Emplaceable>;
using ReversedSet = base::flat_set<int, std::greater<int>>;

// TODO(dyaroshev): replace less<int> with less<>, once we have it
// crbug.com/682254.
using SetWithLess = base::flat_set<int, std::less<int>>;

using SetWithStrangeCompare =
    base::flat_set<int, NonDefaultConstructibleCompare>;

using ::testing::ElementsAre;

}  // namespace

// ----------------------------------------------------------------------------
// Class.

// Check that base::flat_set and its iterators can be instantiated with an
// incomplete type.

TEST(FlatSet, IncompleteType) {
  struct A {
    using Set = base::flat_set<A>;
    int data;
    Set set_with_incomplete_type;
    Set::iterator it;
    Set::const_iterator cit;

    // We do not declare operator< because clang complains that it's unused.
  };

  A a;
}

TEST(FlatSet, Stability) {
  using Pair = std::pair<int, int>;

  struct LessByFirst {
    bool operator()(const Pair& lhs, const Pair& rhs) {
      return lhs.first < rhs.first;
    }
  };

  using Set = base::flat_set<Pair, LessByFirst>;

  // Constructors are not stable.
  Set cont{{0, 0}, {1, 0}, {0, 1}, {2, 0}, {0, 2}, {1, 1}};

  auto NoneOfSecondsAreTwo = [&cont] {
    return std::none_of(cont.begin(), cont.end(),
                        [](const Pair& elem) { return elem.second == 2; });
  };

  // Should not replace existing.
  cont.insert(Pair(0, 2));
  cont.insert(Pair(1, 2));
  cont.insert(Pair(2, 2));

  EXPECT_TRUE(NoneOfSecondsAreTwo())
      << "insert should be stable with respect to constructor";

  cont.insert(Pair(3, 0));
  cont.insert(Pair(3, 2));

  EXPECT_TRUE(NoneOfSecondsAreTwo())
      << "insert should be stable with respect to previous insert";
}

// ----------------------------------------------------------------------------
// Types.

// key_type
// key_compare
// value_type
// value_compare
// pointer
// const_pointer
// reference
// const_reference
// size_type
// difference_type
// iterator
// const_iterator
// reverse_iterator
// const_reverse_iterator

TEST(FlatSet, Types) {
  // These are guaranteed to be portable.
  static_assert((std::is_same<int, IntSet::key_type>::value), "");
  static_assert((std::is_same<int, IntSet::value_type>::value), "");
  static_assert((std::is_same<std::less<int>, IntSet::key_compare>::value), "");
  static_assert((std::is_same<std::less<int>, IntSet::value_compare>::value),
                "");
  static_assert((std::is_same<int&, IntSet::reference>::value), "");
  static_assert((std::is_same<const int&, IntSet::const_reference>::value), "");
  static_assert((std::is_same<int*, IntSet::pointer>::value), "");
  static_assert((std::is_same<const int*, IntSet::const_pointer>::value), "");
}

// ----------------------------------------------------------------------------
// Lifetime.

// flat_set()
// flat_set(const Compare& comp)

TEST(FlatSet, DefaultConstructor) {
  {
    IntSet cont;
    EXPECT_THAT(cont, ElementsAre());
  }

  {
    SetWithStrangeCompare cont(NonDefaultConstructibleCompare(0));
    EXPECT_THAT(cont, ElementsAre());
  }
}

// flat_set(InputIterator first,
//          InputIterator last,
//          const Compare& comp = Compare())

TEST(FlatSet, RangeConstructor) {
  {
    IntSet::value_type input_vals[] = {1, 1, 1, 2, 2, 2, 3, 3, 3};

    IntSet cont(MakeInputIterator(std::begin(input_vals)),
                MakeInputIterator(std::end(input_vals)));
    EXPECT_THAT(cont, ElementsAre(1, 2, 3));
  }
  {
    SetWithStrangeCompare::value_type input_vals[] = {1, 1, 1, 2, 2,
                                                      2, 3, 3, 3};

    SetWithStrangeCompare cont(MakeInputIterator(std::begin(input_vals)),
                               MakeInputIterator(std::end(input_vals)),
                               NonDefaultConstructibleCompare(0));
    EXPECT_THAT(cont, ElementsAre(1, 2, 3));
  }
}

// flat_set(const flat_set& x)

TEST(FlatSet, CopyConstructor) {
  IntSet original{1, 2, 3, 4};
  IntSet copied(original);

  EXPECT_THAT(copied, ElementsAre(1, 2, 3, 4));

  EXPECT_THAT(copied, ElementsAre(1, 2, 3, 4));
  EXPECT_THAT(original, ElementsAre(1, 2, 3, 4));
  EXPECT_EQ(original, copied);
}

// flat_set(flat_set&& x)

TEST(FlatSet, MoveConstructor) {
  int input_range[] = {1, 2, 3, 4};

  MoveOnlySet original(std::begin(input_range), std::end(input_range));
  MoveOnlySet moved(std::move(original));

  EXPECT_EQ(1U, moved.count(MoveOnly(1)));
  EXPECT_EQ(1U, moved.count(MoveOnly(2)));
  EXPECT_EQ(1U, moved.count(MoveOnly(3)));
  EXPECT_EQ(1U, moved.count(MoveOnly(4)));
}

//  flat_set(std::initializer_list<value_type> ilist,
//           const Compare& comp = Compare())

TEST(FlatSet, InitializerListConstructor) {
  {
    IntSet cont{1, 2, 3, 4, 5, 6, 10, 8};
    EXPECT_THAT(cont, ElementsAre(1, 2, 3, 4, 5, 6, 8, 10));
  }
  {
    SetWithStrangeCompare cont({1, 2, 3, 4, 5, 6, 10, 8},
                               NonDefaultConstructibleCompare(0));
    EXPECT_THAT(cont, ElementsAre(1, 2, 3, 4, 5, 6, 8, 10));
  }
}

// ----------------------------------------------------------------------------
// Assignments.

// flat_set& operator=(const flat_set&)

TEST(FlatSet, CopyAssignable) {
  IntSet original{1, 2, 3, 4};
  IntSet copied;
  copied = original;

  EXPECT_THAT(copied, ElementsAre(1, 2, 3, 4));
  EXPECT_THAT(original, ElementsAre(1, 2, 3, 4));
  EXPECT_EQ(original, copied);
}

// flat_set& operator=(flat_set&&)

TEST(FlatSet, MoveAssignable) {
  int input_range[] = {1, 2, 3, 4};

  MoveOnlySet original(std::begin(input_range), std::end(input_range));
  MoveOnlySet moved;
  moved = std::move(original);

  EXPECT_EQ(1U, moved.count(MoveOnly(1)));
  EXPECT_EQ(1U, moved.count(MoveOnly(2)));
  EXPECT_EQ(1U, moved.count(MoveOnly(3)));
  EXPECT_EQ(1U, moved.count(MoveOnly(4)));
}

// flat_set& operator=(std::initializer_list<value_type> ilist)

TEST(FlatSet, InitializerListAssignable) {
  IntSet cont{0};
  cont = {1, 2, 3, 4, 5, 6, 10, 8};

  EXPECT_EQ(0U, cont.count(0));
  EXPECT_THAT(cont, ElementsAre(1, 2, 3, 4, 5, 6, 8, 10));
}

// --------------------------------------------------------------------------
// Memory management.

// void reserve(size_type new_capacity)

TEST(FlatSet, Reserve) {
  IntSet cont{1, 2, 3};

  cont.reserve(5);
  EXPECT_LE(5U, cont.capacity());
}

// size_type capacity() const

TEST(FlatSet, Capacity) {
  IntSet cont{1, 2, 3};

  EXPECT_LE(cont.size(), cont.capacity());
  cont.reserve(5);
  EXPECT_LE(cont.size(), cont.capacity());
}

// void shrink_to_fit()

TEST(FlatSet, ShrinkToFit) {
  IntSet cont{1, 2, 3};

  IntSet::size_type capacity_before = cont.capacity();
  cont.shrink_to_fit();
  EXPECT_GE(capacity_before, cont.capacity());
}

// ----------------------------------------------------------------------------
// Size management.

// void clear()

TEST(FlatSet, Clear) {
  IntSet cont{1, 2, 3, 4, 5, 6, 7, 8};
  cont.clear();
  EXPECT_THAT(cont, ElementsAre());
}

// size_type size() const

TEST(FlatSet, Size) {
  IntSet cont;

  EXPECT_EQ(0U, cont.size());
  cont.insert(2);
  EXPECT_EQ(1U, cont.size());
  cont.insert(1);
  EXPECT_EQ(2U, cont.size());
  cont.insert(3);
  EXPECT_EQ(3U, cont.size());
  cont.erase(cont.begin());
  EXPECT_EQ(2U, cont.size());
  cont.erase(cont.begin());
  EXPECT_EQ(1U, cont.size());
  cont.erase(cont.begin());
  EXPECT_EQ(0U, cont.size());
}

// bool empty() const

TEST(FlatSet, Empty) {
  IntSet cont;

  EXPECT_TRUE(cont.empty());
  cont.insert(1);
  EXPECT_FALSE(cont.empty());
  cont.clear();
  EXPECT_TRUE(cont.empty());
}

// ----------------------------------------------------------------------------
// Iterators.

// iterator begin()
// const_iterator begin() const
// iterator end()
// const_iterator end() const
//
// reverse_iterator rbegin()
// const_reverse_iterator rbegin() const
// reverse_iterator rend()
// const_reverse_iterator rend() const
//
// const_iterator cbegin() const
// const_iterator cend() const
// const_reverse_iterator crbegin() const
// const_reverse_iterator crend() const

TEST(FlatSet, Iterators) {
  IntSet cont{1, 2, 3, 4, 5, 6, 7, 8};

  auto size = static_cast<IntSet::difference_type>(cont.size());

  EXPECT_EQ(size, std::distance(cont.begin(), cont.end()));
  EXPECT_EQ(size, std::distance(cont.cbegin(), cont.cend()));
  EXPECT_EQ(size, std::distance(cont.rbegin(), cont.rend()));
  EXPECT_EQ(size, std::distance(cont.crbegin(), cont.crend()));

  {
    IntSet::iterator it = cont.begin();
    IntSet::const_iterator c_it = cont.cbegin();
    EXPECT_EQ(it, c_it);
    for (int j = 1; it != cont.end(); ++it, ++c_it, ++j) {
      EXPECT_EQ(j, *it);
      EXPECT_EQ(j, *c_it);
    }
  }
  {
    IntSet::reverse_iterator rit = cont.rbegin();
    IntSet::const_reverse_iterator c_rit = cont.crbegin();
    EXPECT_EQ(rit, c_rit);
    for (int j = static_cast<int>(size); rit != cont.rend();
         ++rit, ++c_rit, --j) {
      EXPECT_EQ(j, *rit);
      EXPECT_EQ(j, *c_rit);
    }
  }
}

// ----------------------------------------------------------------------------
// Insert operations.

// pair<iterator, bool> insert(const value_type& val)

TEST(FlatSet, InsertLValue) {
  IntSet cont;

  int value = 2;
  std::pair<IntSet::iterator, bool> result = cont.insert(value);
  EXPECT_TRUE(result.second);
  EXPECT_EQ(cont.begin(), result.first);
  EXPECT_EQ(1U, cont.size());
  EXPECT_EQ(2, *result.first);

  value = 1;
  result = cont.insert(value);
  EXPECT_TRUE(result.second);
  EXPECT_EQ(cont.begin(), result.first);
  EXPECT_EQ(2U, cont.size());
  EXPECT_EQ(1, *result.first);

  value = 3;
  result = cont.insert(value);
  EXPECT_TRUE(result.second);
  EXPECT_EQ(std::prev(cont.end()), result.first);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, *result.first);

  value = 3;
  result = cont.insert(value);
  EXPECT_FALSE(result.second);
  EXPECT_EQ(std::prev(cont.end()), result.first);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, *result.first);
}

// pair<iterator, bool> insert(value_type&& val)

TEST(FlatSet, InsertRValue) {
  MoveOnlySet cont;

  std::pair<MoveOnlySet::iterator, bool> result = cont.insert(MoveOnly(2));
  EXPECT_TRUE(result.second);
  EXPECT_EQ(cont.begin(), result.first);
  EXPECT_EQ(1U, cont.size());
  EXPECT_EQ(2, result.first->data());

  result = cont.insert(MoveOnly(1));
  EXPECT_TRUE(result.second);
  EXPECT_EQ(cont.begin(), result.first);
  EXPECT_EQ(2U, cont.size());
  EXPECT_EQ(1, result.first->data());

  result = cont.insert(MoveOnly(3));
  EXPECT_TRUE(result.second);
  EXPECT_EQ(std::prev(cont.end()), result.first);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, result.first->data());

  result = cont.insert(MoveOnly(3));
  EXPECT_FALSE(result.second);
  EXPECT_EQ(std::prev(cont.end()), result.first);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, result.first->data());
}

// iterator insert(const_iterator position_hint, const value_type& val)

TEST(FlatSet, InsertPositionLValue) {
  IntSet cont;

  IntSet::iterator result = cont.insert(cont.cend(), 2);
  EXPECT_EQ(cont.begin(), result);
  EXPECT_EQ(1U, cont.size());
  EXPECT_EQ(2, *result);

  result = cont.insert(cont.cend(), 1);
  EXPECT_EQ(cont.begin(), result);
  EXPECT_EQ(2U, cont.size());
  EXPECT_EQ(1, *result);

  result = cont.insert(cont.cend(), 3);
  EXPECT_EQ(std::prev(cont.end()), result);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, *result);

  result = cont.insert(cont.cend(), 3);
  EXPECT_EQ(std::prev(cont.end()), result);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, *result);
}

// iterator insert(const_iterator position_hint, value_type&& val)

TEST(FlatSet, InsertPositionRValue) {
  MoveOnlySet cont;

  MoveOnlySet::iterator result = cont.insert(cont.cend(), MoveOnly(2));
  EXPECT_EQ(cont.begin(), result);
  EXPECT_EQ(1U, cont.size());
  EXPECT_EQ(2, result->data());

  result = cont.insert(cont.cend(), MoveOnly(1));
  EXPECT_EQ(cont.begin(), result);
  EXPECT_EQ(2U, cont.size());
  EXPECT_EQ(1, result->data());

  result = cont.insert(cont.cend(), MoveOnly(3));
  EXPECT_EQ(std::prev(cont.end()), result);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, result->data());

  result = cont.insert(cont.cend(), MoveOnly(3));
  EXPECT_EQ(std::prev(cont.end()), result);
  EXPECT_EQ(3U, cont.size());
  EXPECT_EQ(3, result->data());
}

// template <class... Args>
// pair<iterator, bool> emplace(Args&&... args)

TEST(FlatSet, Emplace) {
  {
    EmplaceableSet cont;

    std::pair<EmplaceableSet::iterator, bool> result = cont.emplace();
    EXPECT_TRUE(result.second);
    EXPECT_EQ(cont.begin(), result.first);
    EXPECT_EQ(1U, cont.size());
    EXPECT_EQ(Emplaceable(), *cont.begin());

    result = cont.emplace(2, 3.5);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(std::next(cont.begin()), result.first);
    EXPECT_EQ(2U, cont.size());
    EXPECT_EQ(Emplaceable(2, 3.5), *result.first);

    result = cont.emplace(2, 3.5);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(std::next(cont.begin()), result.first);
    EXPECT_EQ(2U, cont.size());
    EXPECT_EQ(Emplaceable(2, 3.5), *result.first);
  }
  {
    IntSet cont;

    std::pair<IntSet::iterator, bool> result = cont.emplace(2);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(cont.begin(), result.first);
    EXPECT_EQ(1U, cont.size());
    EXPECT_EQ(2, *result.first);
  }
}

// template <class... Args>
// iterator emplace_hint(const_iterator position_hint, Args&&... args)

TEST(FlatSet, EmplacePosition) {
  {
    EmplaceableSet cont;

    EmplaceableSet::iterator result = cont.emplace_hint(cont.cend());
    EXPECT_EQ(cont.begin(), result);
    EXPECT_EQ(1U, cont.size());
    EXPECT_EQ(Emplaceable(), *cont.begin());

    result = cont.emplace_hint(cont.cend(), 2, 3.5);
    EXPECT_EQ(std::next(cont.begin()), result);
    EXPECT_EQ(2U, cont.size());
    EXPECT_EQ(Emplaceable(2, 3.5), *result);

    result = cont.emplace_hint(cont.cbegin(), 2, 3.5);
    EXPECT_EQ(std::next(cont.begin()), result);
    EXPECT_EQ(2U, cont.size());
    EXPECT_EQ(Emplaceable(2, 3.5), *result);
  }
  {
    IntSet cont;

    IntSet::iterator result = cont.emplace_hint(cont.cend(), 2);
    EXPECT_EQ(cont.begin(), result);
    EXPECT_EQ(1U, cont.size());
    EXPECT_EQ(2, *result);
  }
}

// ----------------------------------------------------------------------------
// Erase operations.

// iterator erase(const_iterator position_hint)

TEST(FlatSet, ErasePosition) {
  IntSet cont{1, 2, 3, 4, 5, 6, 7, 8};

  IntSet::iterator it = cont.erase(std::next(cont.cbegin(), 3));
  EXPECT_EQ(std::next(cont.begin(), 3), it);
  EXPECT_THAT(cont, ElementsAre(1, 2, 3, 5, 6, 7, 8));

  it = cont.erase(std::next(cont.cbegin(), 0));
  EXPECT_EQ(cont.begin(), it);
  EXPECT_THAT(cont, ElementsAre(2, 3, 5, 6, 7, 8));

  it = cont.erase(std::next(cont.cbegin(), 5));
  EXPECT_EQ(cont.end(), it);
  EXPECT_THAT(cont, ElementsAre(2, 3, 5, 6, 7));

  it = cont.erase(std::next(cont.cbegin(), 1));
  EXPECT_EQ(std::next(cont.begin()), it);
  EXPECT_THAT(cont, ElementsAre(2, 5, 6, 7));

  it = cont.erase(std::next(cont.cbegin(), 2));
  EXPECT_EQ(std::next(cont.begin(), 2), it);
  EXPECT_THAT(cont, ElementsAre(2, 5, 7));

  it = cont.erase(std::next(cont.cbegin(), 2));
  EXPECT_EQ(std::next(cont.begin(), 2), it);
  EXPECT_THAT(cont, ElementsAre(2, 5));

  it = cont.erase(std::next(cont.cbegin(), 0));
  EXPECT_EQ(std::next(cont.begin(), 0), it);
  EXPECT_THAT(cont, ElementsAre(5));

  it = cont.erase(cont.cbegin());
  EXPECT_EQ(cont.begin(), it);
  EXPECT_EQ(cont.end(), it);
}

// iterator erase(const_iterator first, const_iterator last)

TEST(FlatSet, EraseRange) {
  IntSet cont{1, 2, 3, 4, 5, 6, 7, 8};

  IntSet::iterator it =
      cont.erase(std::next(cont.cbegin(), 5), std::next(cont.cbegin(), 5));
  EXPECT_EQ(std::next(cont.begin(), 5), it);
  EXPECT_THAT(cont, ElementsAre(1, 2, 3, 4, 5, 6, 7, 8));

  it = cont.erase(std::next(cont.cbegin(), 3), std::next(cont.cbegin(), 4));
  EXPECT_EQ(std::next(cont.begin(), 3), it);
  EXPECT_THAT(cont, ElementsAre(1, 2, 3, 5, 6, 7, 8));

  it = cont.erase(std::next(cont.cbegin(), 2), std::next(cont.cbegin(), 5));
  EXPECT_EQ(std::next(cont.begin(), 2), it);
  EXPECT_THAT(cont, ElementsAre(1, 2, 7, 8));

  it = cont.erase(std::next(cont.cbegin(), 0), std::next(cont.cbegin(), 2));
  EXPECT_EQ(std::next(cont.begin(), 0), it);
  EXPECT_THAT(cont, ElementsAre(7, 8));

  it = cont.erase(cont.cbegin(), cont.cend());
  EXPECT_EQ(cont.begin(), it);
  EXPECT_EQ(cont.end(), it);
}

// size_type erase(const key_type& key)

TEST(FlatSet, EraseKey) {
  IntSet cont{1, 2, 3, 4, 5, 6, 7, 8};

  EXPECT_EQ(0U, cont.erase(9));
  EXPECT_THAT(cont, ElementsAre(1, 2, 3, 4, 5, 6, 7, 8));

  EXPECT_EQ(1U, cont.erase(4));
  EXPECT_THAT(cont, ElementsAre(1, 2, 3, 5, 6, 7, 8));

  EXPECT_EQ(1U, cont.erase(1));
  EXPECT_THAT(cont, ElementsAre(2, 3, 5, 6, 7, 8));

  EXPECT_EQ(1U, cont.erase(8));
  EXPECT_THAT(cont, ElementsAre(2, 3, 5, 6, 7));

  EXPECT_EQ(1U, cont.erase(3));
  EXPECT_THAT(cont, ElementsAre(2, 5, 6, 7));

  EXPECT_EQ(1U, cont.erase(6));
  EXPECT_THAT(cont, ElementsAre(2, 5, 7));

  EXPECT_EQ(1U, cont.erase(7));
  EXPECT_THAT(cont, ElementsAre(2, 5));

  EXPECT_EQ(1U, cont.erase(2));
  EXPECT_THAT(cont, ElementsAre(5));

  EXPECT_EQ(1U, cont.erase(5));
  EXPECT_THAT(cont, ElementsAre());
}

// ----------------------------------------------------------------------------
// Comparators.

// key_compare key_comp() const

TEST(FlatSet, KeyComp) {
  ReversedSet cont{1, 2, 3, 4, 5};

  EXPECT_TRUE(std::is_sorted(cont.begin(), cont.end(), cont.key_comp()));
  int new_elements[] = {6, 7, 8, 9, 10};
  std::copy(std::begin(new_elements), std::end(new_elements),
            std::inserter(cont, cont.end()));
  EXPECT_TRUE(std::is_sorted(cont.begin(), cont.end(), cont.key_comp()));
}

// value_compare value_comp() const

TEST(FlatSet, ValueComp) {
  ReversedSet cont{1, 2, 3, 4, 5};

  EXPECT_TRUE(std::is_sorted(cont.begin(), cont.end(), cont.value_comp()));
  int new_elements[] = {6, 7, 8, 9, 10};
  std::copy(std::begin(new_elements), std::end(new_elements),
            std::inserter(cont, cont.end()));
  EXPECT_TRUE(std::is_sorted(cont.begin(), cont.end(), cont.value_comp()));
}

// ----------------------------------------------------------------------------
// Search operations.

// size_type count(const key_type& key) const

TEST(FlatSet, Count) {
  {
    const IntSet cont{5, 6, 7, 8, 9, 10, 11, 12};

    EXPECT_EQ(1U, cont.count(5));
    EXPECT_EQ(1U, cont.count(6));
    EXPECT_EQ(1U, cont.count(7));
    EXPECT_EQ(1U, cont.count(8));
    EXPECT_EQ(1U, cont.count(9));
    EXPECT_EQ(1U, cont.count(10));
    EXPECT_EQ(1U, cont.count(11));
    EXPECT_EQ(1U, cont.count(12));
    EXPECT_EQ(0U, cont.count(4));
  }
  {
    const SetWithLess cont{5, 6, 7, 8, 9, 10, 11, 12};

    EXPECT_EQ(1U, cont.count(5));
    EXPECT_EQ(1U, cont.count(6));
    EXPECT_EQ(1U, cont.count(7));
    EXPECT_EQ(1U, cont.count(8));
    EXPECT_EQ(1U, cont.count(9));
    EXPECT_EQ(1U, cont.count(10));
    EXPECT_EQ(1U, cont.count(11));
    EXPECT_EQ(1U, cont.count(12));
    EXPECT_EQ(0U, cont.count(4));
  }
}

// iterator find(const key_type& key)
// const_iterator find(const key_type& key) const

TEST(FlatSet, Find) {
  {
    IntSet cont{5, 6, 7, 8, 9, 10, 11, 12};

    EXPECT_EQ(cont.begin(), cont.find(5));
    EXPECT_EQ(std::next(cont.begin()), cont.find(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.find(7));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.find(8));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.find(9));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.find(10));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.find(11));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.find(12));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.find(4));
  }
  {
    const IntSet cont{5, 6, 7, 8, 9, 10, 11, 12};

    EXPECT_EQ(cont.begin(), cont.find(5));
    EXPECT_EQ(std::next(cont.begin()), cont.find(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.find(7));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.find(8));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.find(9));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.find(10));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.find(11));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.find(12));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.find(4));
  }
  {
    SetWithLess cont{5, 6, 7, 8, 9, 10, 11, 12};

    EXPECT_EQ(cont.begin(), cont.find(5));
    EXPECT_EQ(std::next(cont.begin()), cont.find(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.find(7));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.find(8));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.find(9));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.find(10));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.find(11));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.find(12));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.find(4));
  }
}

// pair<iterator, iterator> equal_range(const key_type& key)
// pair<const_iterator, const_iterator> equal_range(const key_type& key) const

TEST(FlatSet, EqualRange) {
  {
    IntSet cont{5, 7, 9, 11, 13, 15, 17, 19};

    std::pair<IntSet::iterator, IntSet::iterator> result = cont.equal_range(5);
    EXPECT_EQ(std::next(cont.begin(), 0), result.first);
    EXPECT_EQ(std::next(cont.begin(), 1), result.second);
    result = cont.equal_range(7);
    EXPECT_EQ(std::next(cont.begin(), 1), result.first);
    EXPECT_EQ(std::next(cont.begin(), 2), result.second);
    result = cont.equal_range(9);
    EXPECT_EQ(std::next(cont.begin(), 2), result.first);
    EXPECT_EQ(std::next(cont.begin(), 3), result.second);
    result = cont.equal_range(11);
    EXPECT_EQ(std::next(cont.begin(), 3), result.first);
    EXPECT_EQ(std::next(cont.begin(), 4), result.second);
    result = cont.equal_range(13);
    EXPECT_EQ(std::next(cont.begin(), 4), result.first);
    EXPECT_EQ(std::next(cont.begin(), 5), result.second);
    result = cont.equal_range(15);
    EXPECT_EQ(std::next(cont.begin(), 5), result.first);
    EXPECT_EQ(std::next(cont.begin(), 6), result.second);
    result = cont.equal_range(17);
    EXPECT_EQ(std::next(cont.begin(), 6), result.first);
    EXPECT_EQ(std::next(cont.begin(), 7), result.second);
    result = cont.equal_range(19);
    EXPECT_EQ(std::next(cont.begin(), 7), result.first);
    EXPECT_EQ(std::next(cont.begin(), 8), result.second);
    result = cont.equal_range(4);
    EXPECT_EQ(std::next(cont.begin(), 0), result.first);
    EXPECT_EQ(std::next(cont.begin(), 0), result.second);
    result = cont.equal_range(6);
    EXPECT_EQ(std::next(cont.begin(), 1), result.first);
    EXPECT_EQ(std::next(cont.begin(), 1), result.second);
    result = cont.equal_range(8);
    EXPECT_EQ(std::next(cont.begin(), 2), result.first);
    EXPECT_EQ(std::next(cont.begin(), 2), result.second);
    result = cont.equal_range(10);
    EXPECT_EQ(std::next(cont.begin(), 3), result.first);
    EXPECT_EQ(std::next(cont.begin(), 3), result.second);
    result = cont.equal_range(12);
    EXPECT_EQ(std::next(cont.begin(), 4), result.first);
    EXPECT_EQ(std::next(cont.begin(), 4), result.second);
    result = cont.equal_range(14);
    EXPECT_EQ(std::next(cont.begin(), 5), result.first);
    EXPECT_EQ(std::next(cont.begin(), 5), result.second);
    result = cont.equal_range(16);
    EXPECT_EQ(std::next(cont.begin(), 6), result.first);
    EXPECT_EQ(std::next(cont.begin(), 6), result.second);
    result = cont.equal_range(18);
    EXPECT_EQ(std::next(cont.begin(), 7), result.first);
    EXPECT_EQ(std::next(cont.begin(), 7), result.second);
    result = cont.equal_range(20);
    EXPECT_EQ(std::next(cont.begin(), 8), result.first);
    EXPECT_EQ(std::next(cont.begin(), 8), result.second);
  }
  {
    const IntSet cont{5, 7, 9, 11, 13, 15, 17, 19};

    std::pair<IntSet::const_iterator, IntSet::const_iterator> result =
        cont.equal_range(5);
    EXPECT_EQ(std::next(cont.begin(), 0), result.first);
    EXPECT_EQ(std::next(cont.begin(), 1), result.second);
    result = cont.equal_range(7);
    EXPECT_EQ(std::next(cont.begin(), 1), result.first);
    EXPECT_EQ(std::next(cont.begin(), 2), result.second);
    result = cont.equal_range(9);
    EXPECT_EQ(std::next(cont.begin(), 2), result.first);
    EXPECT_EQ(std::next(cont.begin(), 3), result.second);
    result = cont.equal_range(11);
    EXPECT_EQ(std::next(cont.begin(), 3), result.first);
    EXPECT_EQ(std::next(cont.begin(), 4), result.second);
    result = cont.equal_range(13);
    EXPECT_EQ(std::next(cont.begin(), 4), result.first);
    EXPECT_EQ(std::next(cont.begin(), 5), result.second);
    result = cont.equal_range(15);
    EXPECT_EQ(std::next(cont.begin(), 5), result.first);
    EXPECT_EQ(std::next(cont.begin(), 6), result.second);
    result = cont.equal_range(17);
    EXPECT_EQ(std::next(cont.begin(), 6), result.first);
    EXPECT_EQ(std::next(cont.begin(), 7), result.second);
    result = cont.equal_range(19);
    EXPECT_EQ(std::next(cont.begin(), 7), result.first);
    EXPECT_EQ(std::next(cont.begin(), 8), result.second);
    result = cont.equal_range(4);
    EXPECT_EQ(std::next(cont.begin(), 0), result.first);
    EXPECT_EQ(std::next(cont.begin(), 0), result.second);
    result = cont.equal_range(6);
    EXPECT_EQ(std::next(cont.begin(), 1), result.first);
    EXPECT_EQ(std::next(cont.begin(), 1), result.second);
    result = cont.equal_range(8);
    EXPECT_EQ(std::next(cont.begin(), 2), result.first);
    EXPECT_EQ(std::next(cont.begin(), 2), result.second);
    result = cont.equal_range(10);
    EXPECT_EQ(std::next(cont.begin(), 3), result.first);
    EXPECT_EQ(std::next(cont.begin(), 3), result.second);
    result = cont.equal_range(12);
    EXPECT_EQ(std::next(cont.begin(), 4), result.first);
    EXPECT_EQ(std::next(cont.begin(), 4), result.second);
    result = cont.equal_range(14);
    EXPECT_EQ(std::next(cont.begin(), 5), result.first);
    EXPECT_EQ(std::next(cont.begin(), 5), result.second);
    result = cont.equal_range(16);
    EXPECT_EQ(std::next(cont.begin(), 6), result.first);
    EXPECT_EQ(std::next(cont.begin(), 6), result.second);
    result = cont.equal_range(18);
    EXPECT_EQ(std::next(cont.begin(), 7), result.first);
    EXPECT_EQ(std::next(cont.begin(), 7), result.second);
    result = cont.equal_range(20);
    EXPECT_EQ(std::next(cont.begin(), 8), result.first);
    EXPECT_EQ(std::next(cont.begin(), 8), result.second);
  }
  {
    SetWithLess cont{5, 7, 9, 11, 13, 15, 17, 19};

    std::pair<SetWithLess::iterator, SetWithLess::iterator> result =
        cont.equal_range(5);
    EXPECT_EQ(std::next(cont.begin(), 0), result.first);
    EXPECT_EQ(std::next(cont.begin(), 1), result.second);
    result = cont.equal_range(7);
    EXPECT_EQ(std::next(cont.begin(), 1), result.first);
    EXPECT_EQ(std::next(cont.begin(), 2), result.second);
    result = cont.equal_range(9);
    EXPECT_EQ(std::next(cont.begin(), 2), result.first);
    EXPECT_EQ(std::next(cont.begin(), 3), result.second);
    result = cont.equal_range(11);
    EXPECT_EQ(std::next(cont.begin(), 3), result.first);
    EXPECT_EQ(std::next(cont.begin(), 4), result.second);
    result = cont.equal_range(13);
    EXPECT_EQ(std::next(cont.begin(), 4), result.first);
    EXPECT_EQ(std::next(cont.begin(), 5), result.second);
    result = cont.equal_range(15);
    EXPECT_EQ(std::next(cont.begin(), 5), result.first);
    EXPECT_EQ(std::next(cont.begin(), 6), result.second);
    result = cont.equal_range(17);
    EXPECT_EQ(std::next(cont.begin(), 6), result.first);
    EXPECT_EQ(std::next(cont.begin(), 7), result.second);
    result = cont.equal_range(19);
    EXPECT_EQ(std::next(cont.begin(), 7), result.first);
    EXPECT_EQ(std::next(cont.begin(), 8), result.second);
    result = cont.equal_range(4);
    EXPECT_EQ(std::next(cont.begin(), 0), result.first);
    EXPECT_EQ(std::next(cont.begin(), 0), result.second);
    result = cont.equal_range(6);
    EXPECT_EQ(std::next(cont.begin(), 1), result.first);
    EXPECT_EQ(std::next(cont.begin(), 1), result.second);
    result = cont.equal_range(8);
    EXPECT_EQ(std::next(cont.begin(), 2), result.first);
    EXPECT_EQ(std::next(cont.begin(), 2), result.second);
    result = cont.equal_range(10);
    EXPECT_EQ(std::next(cont.begin(), 3), result.first);
    EXPECT_EQ(std::next(cont.begin(), 3), result.second);
    result = cont.equal_range(12);
    EXPECT_EQ(std::next(cont.begin(), 4), result.first);
    EXPECT_EQ(std::next(cont.begin(), 4), result.second);
    result = cont.equal_range(14);
    EXPECT_EQ(std::next(cont.begin(), 5), result.first);
    EXPECT_EQ(std::next(cont.begin(), 5), result.second);
    result = cont.equal_range(16);
    EXPECT_EQ(std::next(cont.begin(), 6), result.first);
    EXPECT_EQ(std::next(cont.begin(), 6), result.second);
    result = cont.equal_range(18);
    EXPECT_EQ(std::next(cont.begin(), 7), result.first);
    EXPECT_EQ(std::next(cont.begin(), 7), result.second);
    result = cont.equal_range(20);
    EXPECT_EQ(std::next(cont.begin(), 8), result.first);
    EXPECT_EQ(std::next(cont.begin(), 8), result.second);
  }
}

//       iterator lower_bound(const key_type& key);
// const_iterator lower_bound(const key_type& key) const;

TEST(FlatSet, LowerBound) {
  {
    IntSet cont{5, 7, 9, 11, 13, 15, 17, 19};

    EXPECT_EQ(cont.begin(), cont.lower_bound(5));
    EXPECT_EQ(std::next(cont.begin()), cont.lower_bound(7));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.lower_bound(9));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.lower_bound(11));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.lower_bound(13));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.lower_bound(15));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.lower_bound(17));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.lower_bound(19));
    EXPECT_EQ(std::next(cont.begin(), 0), cont.lower_bound(4));
    EXPECT_EQ(std::next(cont.begin(), 1), cont.lower_bound(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.lower_bound(8));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.lower_bound(10));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.lower_bound(12));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.lower_bound(14));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.lower_bound(16));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.lower_bound(18));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.lower_bound(20));
  }
  {
    const IntSet cont{5, 7, 9, 11, 13, 15, 17, 19};

    EXPECT_EQ(cont.begin(), cont.lower_bound(5));
    EXPECT_EQ(std::next(cont.begin()), cont.lower_bound(7));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.lower_bound(9));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.lower_bound(11));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.lower_bound(13));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.lower_bound(15));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.lower_bound(17));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.lower_bound(19));
    EXPECT_EQ(std::next(cont.begin(), 0), cont.lower_bound(4));
    EXPECT_EQ(std::next(cont.begin(), 1), cont.lower_bound(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.lower_bound(8));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.lower_bound(10));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.lower_bound(12));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.lower_bound(14));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.lower_bound(16));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.lower_bound(18));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.lower_bound(20));
  }
  {
    SetWithLess cont{5, 7, 9, 11, 13, 15, 17, 19};

    EXPECT_EQ(cont.begin(), cont.lower_bound(5));
    EXPECT_EQ(std::next(cont.begin()), cont.lower_bound(7));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.lower_bound(9));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.lower_bound(11));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.lower_bound(13));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.lower_bound(15));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.lower_bound(17));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.lower_bound(19));
    EXPECT_EQ(std::next(cont.begin(), 0), cont.lower_bound(4));
    EXPECT_EQ(std::next(cont.begin(), 1), cont.lower_bound(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.lower_bound(8));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.lower_bound(10));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.lower_bound(12));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.lower_bound(14));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.lower_bound(16));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.lower_bound(18));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.lower_bound(20));
  }
}

// iterator upper_bound(const key_type& key)
// const_iterator upper_bound(const key_type& key) const

TEST(FlatSet, UpperBound) {
  {
    IntSet cont{5, 7, 9, 11, 13, 15, 17, 19};

    EXPECT_EQ(std::next(cont.begin(), 1), cont.upper_bound(5));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.upper_bound(7));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.upper_bound(9));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.upper_bound(11));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.upper_bound(13));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.upper_bound(15));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.upper_bound(17));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.upper_bound(19));
    EXPECT_EQ(std::next(cont.begin(), 0), cont.upper_bound(4));
    EXPECT_EQ(std::next(cont.begin(), 1), cont.upper_bound(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.upper_bound(8));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.upper_bound(10));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.upper_bound(12));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.upper_bound(14));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.upper_bound(16));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.upper_bound(18));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.upper_bound(20));
  }
  {
    const IntSet cont{5, 7, 9, 11, 13, 15, 17, 19};

    EXPECT_EQ(std::next(cont.begin(), 1), cont.upper_bound(5));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.upper_bound(7));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.upper_bound(9));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.upper_bound(11));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.upper_bound(13));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.upper_bound(15));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.upper_bound(17));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.upper_bound(19));
    EXPECT_EQ(std::next(cont.begin(), 0), cont.upper_bound(4));
    EXPECT_EQ(std::next(cont.begin(), 1), cont.upper_bound(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.upper_bound(8));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.upper_bound(10));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.upper_bound(12));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.upper_bound(14));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.upper_bound(16));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.upper_bound(18));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.upper_bound(20));
  }
  {
    SetWithLess cont{5, 7, 9, 11, 13, 15, 17, 19};

    EXPECT_EQ(std::next(cont.begin(), 1), cont.upper_bound(5));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.upper_bound(7));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.upper_bound(9));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.upper_bound(11));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.upper_bound(13));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.upper_bound(15));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.upper_bound(17));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.upper_bound(19));
    EXPECT_EQ(std::next(cont.begin(), 0), cont.upper_bound(4));
    EXPECT_EQ(std::next(cont.begin(), 1), cont.upper_bound(6));
    EXPECT_EQ(std::next(cont.begin(), 2), cont.upper_bound(8));
    EXPECT_EQ(std::next(cont.begin(), 3), cont.upper_bound(10));
    EXPECT_EQ(std::next(cont.begin(), 4), cont.upper_bound(12));
    EXPECT_EQ(std::next(cont.begin(), 5), cont.upper_bound(14));
    EXPECT_EQ(std::next(cont.begin(), 6), cont.upper_bound(16));
    EXPECT_EQ(std::next(cont.begin(), 7), cont.upper_bound(18));
    EXPECT_EQ(std::next(cont.begin(), 8), cont.upper_bound(20));
  }
}

// ----------------------------------------------------------------------------
// General operations.

// void swap(flat_set& other)
// void swap(flat_set& lhs, flat_set& rhs)

TEST(FlatSetOurs, Swap) {
  IntSet x{1, 2, 3};
  IntSet y{4};
  swap(x, y);
  EXPECT_THAT(x, ElementsAre(4));
  EXPECT_THAT(y, ElementsAre(1, 2, 3));

  y.swap(x);
  EXPECT_THAT(x, ElementsAre(1, 2, 3));
  EXPECT_THAT(y, ElementsAre(4));
}

// bool operator==(const flat_set& lhs, const flat_set& rhs)
// bool operator!=(const flat_set& lhs, const flat_set& rhs)
// bool operator<(const flat_set& lhs, const flat_set& rhs)
// bool operator>(const flat_set& lhs, const flat_set& rhs)
// bool operator<=(const flat_set& lhs, const flat_set& rhs)
// bool operator>=(const flat_set& lhs, const flat_set& rhs)

TEST(FlatSet, Comparison) {
  // Provided comparator does not participate in comparison.
  ReversedSet biggest{3};
  ReversedSet smallest{1};
  ReversedSet middle{1, 2};

  EXPECT_EQ(biggest, biggest);
  EXPECT_NE(biggest, smallest);
  EXPECT_LT(smallest, middle);
  EXPECT_LE(smallest, middle);
  EXPECT_LE(middle, middle);
  EXPECT_GT(biggest, middle);
  EXPECT_GE(biggest, middle);
  EXPECT_GE(biggest, biggest);
}
