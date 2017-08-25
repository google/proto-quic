// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/battor_agent/serial_utils.h"

#include "testing/gtest/include/gtest/gtest.h"

using namespace testing;

namespace battor {

TEST(SerialUtilsTest, CharVectorToStringLengthZero) {
  EXPECT_EQ("", CharVectorToString(std::vector<char>()));
}

TEST(SerialUtilsTest, CharVectorToStringLengthOne) {
  EXPECT_EQ("0x41", CharVectorToString(std::vector<char>({'A'})));
}

TEST(SerialUtilsTest, CharVectorToStringLengthTwo) {
  EXPECT_EQ("0x41 0x4a",
            CharVectorToString(std::vector<char>({'A', 'J'})));
}

TEST(SerialUtilsTest, CharArrayToStringLengthOne) {
  const char arr[] = {'A'};
  EXPECT_EQ("0x41", CharArrayToString(arr, sizeof(arr)));
}

TEST(SerialUtilsTest, CharArrayToStringLengthTwo) {
  const char arr[] = {'A', 'J'};
  EXPECT_EQ("0x41 0x4a", CharArrayToString(arr, sizeof(arr)));
}

}  // namespace battor
