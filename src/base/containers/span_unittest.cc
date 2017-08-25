// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/containers/span.h"

#include <vector>

#include "base/macros.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;

namespace base {

// TODO(dcheng): Add tests for initializer list, containers, etc.

TEST(SpanTest, ConstructFromDataAndSize) {
  std::vector<int> vector = {1, 1, 2, 3, 5, 8};

  Span<int> span(vector.data(), vector.size());
  EXPECT_EQ(vector.data(), span.data());
  EXPECT_EQ(vector.size(), span.size());

  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(vector[i], span[i]);
}

TEST(SpanTest, ConstructFromConstexprArray) {
  static constexpr int kArray[] = {5, 4, 3, 2, 1};

  constexpr Span<const int> span(kArray);
  EXPECT_EQ(kArray, span.data());
  EXPECT_EQ(arraysize(kArray), span.size());

  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(kArray[i], span[i]);
}

TEST(SpanTest, ConstructFromArray) {
  int array[] = {5, 4, 3, 2, 1};

  Span<const int> const_span(array);
  EXPECT_EQ(array, const_span.data());
  EXPECT_EQ(arraysize(array), const_span.size());
  for (size_t i = 0; i < const_span.size(); ++i)
    EXPECT_EQ(array[i], const_span[i]);

  Span<int> span(array);
  EXPECT_EQ(array, span.data());
  EXPECT_EQ(arraysize(array), span.size());
  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(array[i], span[i]);
}

TEST(SpanTest, Subspan) {
  int array[] = {1, 2, 3};
  Span<int> span(array);

  {
    auto subspan = span.subspan(0, 0);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(0u, subspan.size());
  }

  {
    auto subspan = span.subspan(1, 0);
    EXPECT_EQ(span.data() + 1, subspan.data());
    EXPECT_EQ(0u, subspan.size());
  }

  {
    auto subspan = span.subspan(2, 0);
    EXPECT_EQ(span.data() + 2, subspan.data());
    EXPECT_EQ(0u, subspan.size());
  }

  {
    auto subspan = span.subspan(0, 1);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(1u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
  }

  {
    auto subspan = span.subspan(1, 1);
    EXPECT_EQ(span.data() + 1, subspan.data());
    EXPECT_EQ(1u, subspan.size());
    EXPECT_EQ(2, subspan[0]);
  }

  {
    auto subspan = span.subspan(2, 1);
    EXPECT_EQ(span.data() + 2, subspan.data());
    EXPECT_EQ(1u, subspan.size());
    EXPECT_EQ(3, subspan[0]);
  }

  {
    auto subspan = span.subspan(0, 2);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(2u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
    EXPECT_EQ(2, subspan[1]);
  }

  {
    auto subspan = span.subspan(1, 2);
    EXPECT_EQ(span.data() + 1, subspan.data());
    EXPECT_EQ(2u, subspan.size());
    EXPECT_EQ(2, subspan[0]);
    EXPECT_EQ(3, subspan[1]);
  }

  {
    auto subspan = span.subspan(0, 3);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(span.size(), subspan.size());
    EXPECT_EQ(1, subspan[0]);
    EXPECT_EQ(2, subspan[1]);
    EXPECT_EQ(3, subspan[2]);
  }
}

TEST(SpanTest, Iterator) {
  static constexpr int kArray[] = {1, 6, 1, 8, 0};
  constexpr Span<const int> span(kArray);

  std::vector<int> results;
  for (int i : span)
    results.emplace_back(i);
  EXPECT_THAT(results, ElementsAre(1, 6, 1, 8, 0));
}

TEST(SpanTest, Equality) {
  static constexpr int kArray1[] = {3, 1, 4, 1, 5};
  static constexpr int kArray2[] = {3, 1, 4, 1, 5};
  constexpr Span<const int> span1(kArray1);
  constexpr Span<const int> span2(kArray2);

  EXPECT_EQ(span1, span2);

  static constexpr int kArray3[] = {2, 7, 1, 8, 3};
  constexpr Span<const int> span3(kArray3);

  EXPECT_FALSE(span1 == span3);
}

TEST(SpanTest, Inequality) {
  static constexpr int kArray1[] = {2, 3, 5, 7, 11};
  static constexpr int kArray2[] = {1, 4, 6, 8, 9};
  constexpr Span<const int> span1(kArray1);
  constexpr Span<const int> span2(kArray2);

  EXPECT_NE(span1, span2);

  static constexpr int kArray3[] = {2, 3, 5, 7, 11};
  constexpr Span<const int> span3(kArray3);

  EXPECT_FALSE(span1 != span3);
}

TEST(SpanTest, MakeSpanFromDataAndSize) {
  std::vector<int> vector = {1, 1, 2, 3, 5, 8};
  Span<int> span(vector.data(), vector.size());
  EXPECT_EQ(span, MakeSpan(vector.data(), vector.size()));
}

TEST(SpanTest, MakeSpanFromConstexprArray) {
  static constexpr int kArray[] = {1, 2, 3, 4, 5};
  constexpr Span<const int> span(kArray);
  EXPECT_EQ(span, MakeSpan(kArray));
}

}  // namespace base
