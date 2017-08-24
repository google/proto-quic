// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/containers/span.h"

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/macros.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::Pointwise;

namespace base {

TEST(SpanTest, ConstructFromNullptr) {
  span<int> span(nullptr);
  EXPECT_EQ(nullptr, span.data());
  EXPECT_EQ(0u, span.size());
}

TEST(SpanTest, ConstructFromDataAndSize) {
  std::vector<int> vector = {1, 1, 2, 3, 5, 8};

  span<int> span(vector.data(), vector.size());
  EXPECT_EQ(vector.data(), span.data());
  EXPECT_EQ(vector.size(), span.size());

  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(vector[i], span[i]);
}

TEST(SpanTest, ConstructFromConstexprArray) {
  static constexpr int kArray[] = {5, 4, 3, 2, 1};

  constexpr span<const int> span(kArray);
  EXPECT_EQ(kArray, span.data());
  EXPECT_EQ(arraysize(kArray), span.size());

  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(kArray[i], span[i]);
}

TEST(SpanTest, ConstructFromArray) {
  int array[] = {5, 4, 3, 2, 1};

  span<const int> const_span(array);
  EXPECT_EQ(array, const_span.data());
  EXPECT_EQ(arraysize(array), const_span.size());
  for (size_t i = 0; i < const_span.size(); ++i)
    EXPECT_EQ(array[i], const_span[i]);

  span<int> span(array);
  EXPECT_EQ(array, span.data());
  EXPECT_EQ(arraysize(array), span.size());
  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(array[i], span[i]);
}

TEST(SpanTest, ConstructFromConstContainer) {
  const std::vector<int> vector = {1, 1, 2, 3, 5, 8};

  span<const int> const_span(vector);
  EXPECT_EQ(vector.data(), const_span.data());
  EXPECT_EQ(vector.size(), const_span.size());

  for (size_t i = 0; i < const_span.size(); ++i)
    EXPECT_EQ(vector[i], const_span[i]);
}

TEST(SpanTest, ConstructFromContainer) {
  std::vector<int> vector = {1, 1, 2, 3, 5, 8};

  span<const int> const_span(vector);
  EXPECT_EQ(vector.data(), const_span.data());
  EXPECT_EQ(vector.size(), const_span.size());

  for (size_t i = 0; i < const_span.size(); ++i)
    EXPECT_EQ(vector[i], const_span[i]);

  span<int> span(vector);
  EXPECT_EQ(vector.data(), span.data());
  EXPECT_EQ(vector.size(), span.size());

  for (size_t i = 0; i < span.size(); ++i)
    EXPECT_EQ(vector[i], span[i]);
}

TEST(SpanTest, ConvertNonConstIntegralToConst) {
  std::vector<int> vector = {1, 1, 2, 3, 5, 8};

  span<int> int_span(vector.data(), vector.size());
  span<const int> const_span(int_span);
  EXPECT_THAT(const_span, Pointwise(Eq(), int_span));
}

TEST(SpanTest, ConvertNonConstPointerToConst) {
  auto a = std::make_unique<int>(11);
  auto b = std::make_unique<int>(22);
  auto c = std::make_unique<int>(33);
  std::vector<int*> vector = {a.get(), b.get(), c.get()};

  span<int*> non_const_pointer_span(vector);
  EXPECT_THAT(non_const_pointer_span, Pointwise(Eq(), vector));
  span<int* const> const_pointer_span(non_const_pointer_span);
  EXPECT_THAT(const_pointer_span, Pointwise(Eq(), non_const_pointer_span));
  // Note: no test for conversion from span<int> to span<const int*>, since that
  // would imply a conversion from int** to const int**, which is unsafe.
  span<const int* const> const_pointer_to_const_data_span(
      non_const_pointer_span);
  EXPECT_THAT(const_pointer_to_const_data_span,
              Pointwise(Eq(), non_const_pointer_span));
}

TEST(SpanTest, ConvertBetweenEquivalentTypes) {
  std::vector<int32_t> vector = {2, 4, 8, 16, 32};

  span<int32_t> int32_t_span(vector);
  span<int> converted_span(int32_t_span);
  EXPECT_EQ(int32_t_span, converted_span);
}

TEST(SpanTest, First) {
  int array[] = {1, 2, 3};
  span<int> span(array);

  {
    auto subspan = span.first(0);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(0u, subspan.size());
  }

  {
    auto subspan = span.first(1);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(1u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
  }

  {
    auto subspan = span.first(2);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(2u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
    EXPECT_EQ(2, subspan[1]);
  }

  {
    auto subspan = span.first(3);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(3u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
    EXPECT_EQ(2, subspan[1]);
    EXPECT_EQ(3, subspan[2]);
  }
}

TEST(SpanTest, Last) {
  int array[] = {1, 2, 3};
  span<int> span(array);

  {
    auto subspan = span.last(0);
    EXPECT_EQ(span.data() + 3, subspan.data());
    EXPECT_EQ(0u, subspan.size());
  }

  {
    auto subspan = span.last(1);
    EXPECT_EQ(span.data() + 2, subspan.data());
    EXPECT_EQ(1u, subspan.size());
    EXPECT_EQ(3, subspan[0]);
  }

  {
    auto subspan = span.last(2);
    EXPECT_EQ(span.data() + 1, subspan.data());
    EXPECT_EQ(2u, subspan.size());
    EXPECT_EQ(2, subspan[0]);
    EXPECT_EQ(3, subspan[1]);
  }

  {
    auto subspan = span.last(3);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(3u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
    EXPECT_EQ(2, subspan[1]);
    EXPECT_EQ(3, subspan[2]);
  }
}

TEST(SpanTest, Subspan) {
  int array[] = {1, 2, 3};
  span<int> span(array);

  {
    auto subspan = span.subspan(0);
    EXPECT_EQ(span.data(), subspan.data());
    EXPECT_EQ(3u, subspan.size());
    EXPECT_EQ(1, subspan[0]);
    EXPECT_EQ(2, subspan[1]);
    EXPECT_EQ(3, subspan[2]);
  }

  {
    auto subspan = span.subspan(1);
    EXPECT_EQ(span.data() + 1, subspan.data());
    EXPECT_EQ(2u, subspan.size());
    EXPECT_EQ(2, subspan[0]);
    EXPECT_EQ(3, subspan[1]);
  }

  {
    auto subspan = span.subspan(2);
    EXPECT_EQ(span.data() + 2, subspan.data());
    EXPECT_EQ(1u, subspan.size());
    EXPECT_EQ(3, subspan[0]);
  }

  {
    auto subspan = span.subspan(3);
    EXPECT_EQ(span.data() + 3, subspan.data());
    EXPECT_EQ(0u, subspan.size());
  }

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

TEST(SpanTest, Length) {
  {
    span<int> span;
    EXPECT_EQ(0u, span.length());
  }

  {
    int array[] = {1, 2, 3};
    span<int> span(array);
    EXPECT_EQ(3u, span.length());
  }
}

TEST(SpanTest, Size) {
  {
    span<int> span;
    EXPECT_EQ(0u, span.size());
  }

  {
    int array[] = {1, 2, 3};
    span<int> span(array);
    EXPECT_EQ(3u, span.size());
  }
}

TEST(SpanTest, Empty) {
  {
    span<int> span;
    EXPECT_TRUE(span.empty());
  }

  {
    int array[] = {1, 2, 3};
    span<int> span(array);
    EXPECT_FALSE(span.empty());
  }
}

TEST(SpanTest, Iterator) {
  static constexpr int kArray[] = {1, 6, 1, 8, 0};
  constexpr span<const int> span(kArray);

  std::vector<int> results;
  for (int i : span)
    results.emplace_back(i);
  EXPECT_THAT(results, ElementsAre(1, 6, 1, 8, 0));
}

TEST(SpanTest, ReverseIterator) {
  static constexpr int kArray[] = {1, 6, 1, 8, 0};
  constexpr span<const int> span(kArray);

  EXPECT_TRUE(std::equal(std::rbegin(kArray), std::rend(kArray), span.rbegin(),
                         span.rend()));
  EXPECT_TRUE(std::equal(std::crbegin(kArray), std::crend(kArray),
                         span.crbegin(), span.crend()));
}

TEST(SpanTest, Equality) {
  static constexpr int kArray1[] = {3, 1, 4, 1, 5};
  static constexpr int kArray2[] = {3, 1, 4, 1, 5};
  constexpr span<const int> span1(kArray1);
  constexpr span<const int> span2(kArray2);

  EXPECT_EQ(span1, span2);

  static constexpr int kArray3[] = {2, 7, 1, 8, 3};
  constexpr span<const int> span3(kArray3);

  EXPECT_FALSE(span1 == span3);
}

TEST(SpanTest, Inequality) {
  static constexpr int kArray1[] = {2, 3, 5, 7, 11};
  static constexpr int kArray2[] = {1, 4, 6, 8, 9};
  constexpr span<const int> span1(kArray1);
  constexpr span<const int> span2(kArray2);

  EXPECT_NE(span1, span2);

  static constexpr int kArray3[] = {2, 3, 5, 7, 11};
  constexpr span<const int> span3(kArray3);

  EXPECT_FALSE(span1 != span3);
}

TEST(SpanTest, LessThan) {
  static constexpr int kArray1[] = {2, 3, 5, 7, 11};
  static constexpr int kArray2[] = {2, 3, 5, 7, 11, 13};
  constexpr span<const int> span1(kArray1);
  constexpr span<const int> span2(kArray2);

  EXPECT_LT(span1, span2);

  static constexpr int kArray3[] = {2, 3, 5, 7, 11};
  constexpr span<const int> span3(kArray3);

  EXPECT_FALSE(span1 < span3);
}

TEST(SpanTest, LessEqual) {
  static constexpr int kArray1[] = {2, 3, 5, 7, 11};
  static constexpr int kArray2[] = {2, 3, 5, 7, 11, 13};
  constexpr span<const int> span1(kArray1);
  constexpr span<const int> span2(kArray2);

  EXPECT_LE(span1, span1);
  EXPECT_LE(span1, span2);

  static constexpr int kArray3[] = {2, 3, 5, 7, 10};
  constexpr span<const int> span3(kArray3);

  EXPECT_FALSE(span1 <= span3);
}

TEST(SpanTest, GreaterThan) {
  static constexpr int kArray1[] = {2, 3, 5, 7, 11, 13};
  static constexpr int kArray2[] = {2, 3, 5, 7, 11};
  constexpr span<const int> span1(kArray1);
  constexpr span<const int> span2(kArray2);

  EXPECT_GT(span1, span2);

  static constexpr int kArray3[] = {2, 3, 5, 7, 11, 13};
  constexpr span<const int> span3(kArray3);

  EXPECT_FALSE(span1 > span3);
}

TEST(SpanTest, GreaterEqual) {
  static constexpr int kArray1[] = {2, 3, 5, 7, 11, 13};
  static constexpr int kArray2[] = {2, 3, 5, 7, 11};
  constexpr span<const int> span1(kArray1);
  constexpr span<const int> span2(kArray2);

  EXPECT_GE(span1, span1);
  EXPECT_GE(span1, span2);

  static constexpr int kArray3[] = {2, 3, 5, 7, 12};
  constexpr span<const int> span3(kArray3);

  EXPECT_FALSE(span1 >= span3);
}

TEST(SpanTest, MakeSpanFromDataAndSize) {
  std::vector<int> vector = {1, 1, 2, 3, 5, 8};
  span<int> span(vector.data(), vector.size());
  EXPECT_EQ(span, make_span(vector.data(), vector.size()));
}

TEST(SpanTest, MakeSpanFromConstexprArray) {
  static constexpr int kArray[] = {1, 2, 3, 4, 5};
  constexpr span<const int> span(kArray);
  EXPECT_EQ(span, make_span(kArray));
}

TEST(SpanTest, MakeSpanFromConstContainer) {
  const std::vector<int> vector = {-1, -2, -3, -4, -5};
  span<const int> span(vector);
  EXPECT_EQ(span, make_span(vector));
}

TEST(SpanTest, MakeSpanFromContainer) {
  std::vector<int> vector = {-1, -2, -3, -4, -5};
  span<int> span(vector);
  EXPECT_EQ(span, make_span(vector));
}

}  // namespace base
