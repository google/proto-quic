// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/unguessable_token.h"

#include <sstream>
#include <type_traits>

#include "testing/gtest/include/gtest/gtest.h"

namespace base {

void TestSmallerThanOperator(const UnguessableToken& a,
                             const UnguessableToken& b) {
  EXPECT_TRUE(a < b);
  EXPECT_FALSE(b < a);
}

TEST(UnguessableTokenTest, VerifyEqualityOperators) {
  // Deserialize is used for testing purposes.
  // Use UnguessableToken::Create() in production code instead.
  UnguessableToken token = UnguessableToken::Deserialize(1, 2);
  UnguessableToken same_token = UnguessableToken::Deserialize(1, 2);
  UnguessableToken diff_token = UnguessableToken::Deserialize(1, 3);

  EXPECT_TRUE(token == token);
  EXPECT_FALSE(token != token);

  EXPECT_TRUE(token == same_token);
  EXPECT_FALSE(token != same_token);

  EXPECT_FALSE(token == diff_token);
  EXPECT_FALSE(diff_token == token);
  EXPECT_TRUE(token != diff_token);
  EXPECT_TRUE(diff_token != token);
}

TEST(UnguessableTokenTest, VerifyConstructors) {
  UnguessableToken token = UnguessableToken::Create();
  EXPECT_FALSE(token.is_empty());
  EXPECT_TRUE(token);

  UnguessableToken copied_token(token);
  EXPECT_TRUE(copied_token);
  EXPECT_EQ(token, copied_token);

  UnguessableToken uninitialized;
  EXPECT_TRUE(uninitialized.is_empty());
  EXPECT_FALSE(uninitialized);

  EXPECT_TRUE(UnguessableToken().is_empty());
  EXPECT_FALSE(UnguessableToken());
}

TEST(UnguessableTokenTest, VerifySerialization) {
  UnguessableToken token = UnguessableToken::Create();

  uint64_t high = token.GetHighForSerialization();
  uint64_t low = token.GetLowForSerialization();

  EXPECT_TRUE(high);
  EXPECT_TRUE(low);

  UnguessableToken Deserialized = UnguessableToken::Deserialize(high, low);
  EXPECT_EQ(token, Deserialized);
}

TEST(UnguessableTokenTest, VerifyToString) {
  UnguessableToken token = UnguessableToken::Deserialize(0x123, 0xABC);
  std::string expected = "(0000012300000ABC)";

  EXPECT_EQ(expected, token.ToString());

  std::stringstream stream;
  stream << token;
  EXPECT_EQ(expected, stream.str());
}

TEST(UnguessableTokenTest, VerifySmallerThanOperator) {
  // Deserialize is used for testing purposes.
  // Use UnguessableToken::Create() in production code instead.
  {
    SCOPED_TRACE("a.low < b.low and a.high == b.high.");
    TestSmallerThanOperator(UnguessableToken::Deserialize(0, 1),
                            UnguessableToken::Deserialize(0, 5));
  }
  {
    SCOPED_TRACE("a.low == b.low and a.high < b.high.");
    TestSmallerThanOperator(UnguessableToken::Deserialize(1, 0),
                            UnguessableToken::Deserialize(5, 0));
  }
  {
    SCOPED_TRACE("a.low < b.low and a.high < b.high.");
    TestSmallerThanOperator(UnguessableToken::Deserialize(1, 1),
                            UnguessableToken::Deserialize(5, 5));
  }
  {
    SCOPED_TRACE("a.low > b.low and a.high < b.high.");
    TestSmallerThanOperator(UnguessableToken::Deserialize(1, 10),
                            UnguessableToken::Deserialize(10, 1));
  }
}

TEST(UnguessableTokenTest, VerifyHash) {
  UnguessableToken token = UnguessableToken::Create();

  EXPECT_EQ(base::HashInts64(token.GetHighForSerialization(),
                             token.GetLowForSerialization()),
            UnguessableTokenHash()(token));
}

TEST(UnguessableTokenTest, VerifyBasicUniqueness) {
  EXPECT_NE(UnguessableToken::Create(), UnguessableToken::Create());

  UnguessableToken token = UnguessableToken::Create();
  EXPECT_NE(token.GetHighForSerialization(), token.GetLowForSerialization());
}
}
