// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "net/der/input.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace der {
namespace test {

const uint8_t kInput[] = {'t', 'e', 's', 't'};
const uint8_t kInput2[] = {'t', 'e', 'a', 'l'};

TEST(InputTest, Equals) {
  Input test(kInput);
  Input test2(kInput);
  EXPECT_EQ(test, test2);

  uint8_t input_copy[arraysize(kInput)] = {0};
  memcpy(input_copy, kInput, arraysize(kInput));
  Input test_copy(input_copy);
  EXPECT_EQ(test, test_copy);

  Input test_truncated(kInput, arraysize(kInput) - 1);
  EXPECT_NE(test, test_truncated);
  EXPECT_NE(test_truncated, test);
}

TEST(InputTest, LessThan) {
  Input test(kInput);
  EXPECT_FALSE(test < test);

  Input test2(kInput2);
  EXPECT_FALSE(test < test2);
  EXPECT_TRUE(test2 < test);

  Input test_truncated(kInput, arraysize(kInput) - 1);
  EXPECT_FALSE(test < test_truncated);
  EXPECT_TRUE(test_truncated < test);
}

TEST(InputTest, AsString) {
  Input input(kInput);
  std::string expected_string(reinterpret_cast<const char*>(kInput),
                              arraysize(kInput));
  EXPECT_EQ(expected_string, input.AsString());
}

TEST(InputTest, StaticArray) {
  Input input(kInput);
  EXPECT_EQ(arraysize(kInput), input.Length());

  Input input2(kInput);
  EXPECT_EQ(input, input2);
}

TEST(ByteReaderTest, NoReadPastEnd) {
  ByteReader reader(Input(nullptr, 0));
  uint8_t data;
  EXPECT_FALSE(reader.ReadByte(&data));
}

TEST(ByteReaderTest, ReadToEnd) {
  uint8_t out;
  ByteReader reader((Input(kInput)));
  for (size_t i = 0; i < arraysize(kInput); ++i) {
    ASSERT_TRUE(reader.ReadByte(&out));
    ASSERT_EQ(kInput[i], out);
  }
  EXPECT_FALSE(reader.ReadByte(&out));
}

TEST(ByteReaderTest, PartialReadFails) {
  Input out;
  ByteReader reader((Input(kInput)));
  EXPECT_FALSE(reader.ReadBytes(5, &out));
}

TEST(ByteReaderTest, HasMore) {
  Input out;
  ByteReader reader((Input(kInput)));

  ASSERT_TRUE(reader.HasMore());
  ASSERT_TRUE(reader.ReadBytes(arraysize(kInput), &out));
  ASSERT_FALSE(reader.HasMore());
}

}  // namespace test
}  // namespace der
}  // namespace net
