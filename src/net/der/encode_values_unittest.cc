// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/der/encode_values.h"

#include "base/time/time.h"
#include "net/der/parse_values.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace der {
namespace test {

TEST(EncodeValuesTest, EncodeTimeAsGeneralizedTime) {
  // Fri, 24 Jun 2016 17:04:54 GMT
  base::Time time =
      base::Time::UnixEpoch() + base::TimeDelta::FromSeconds(1466787894);
  GeneralizedTime generalized_time;
  ASSERT_TRUE(EncodeTimeAsGeneralizedTime(time, &generalized_time));
  EXPECT_EQ(2016, generalized_time.year);
  EXPECT_EQ(6, generalized_time.month);
  EXPECT_EQ(24, generalized_time.day);
  EXPECT_EQ(17, generalized_time.hours);
  EXPECT_EQ(4, generalized_time.minutes);
  EXPECT_EQ(54, generalized_time.seconds);
}

// ASN.1 GeneralizedTime can represent dates from year 0000 to 9999, and
// although base::Time can represent times from before the Windows epoch and
// after the 32-bit time_t maximum, the conversion between base::Time and
// der::GeneralizedTime goes through the time representation of the underlying
// platform, which might not be able to handle the full GeneralizedTime date
// range. Out-of-range times should not be converted to der::GeneralizedTime. In
// tests, possibly-out-of-range test times are specified as a
// base::Time::Exploded, and then converted to a base::Time. If the conversion
// fails, this signals the underlying platform cannot handle the time, and the
// test aborts early. If the underlying platform can represent the time, then
// the conversion is successful, and the encoded GeneralizedTime can should
// match the test time.
//
// Thu, 1 Jan 1570 00:00:00 GMT. This time is unrepresentable by the Windows
// native time libraries.
TEST(EncodeValuesTest, EncodeTimeFromBeforeWindowsEpoch) {
  base::Time::Exploded exploded;
  exploded.year = 1570;
  exploded.month = 1;
  exploded.day_of_week = 5;
  exploded.day_of_month = 1;
  exploded.hour = 0;
  exploded.minute = 0;
  exploded.second = 0;
  exploded.millisecond = 0;

  base::Time time;
  if (!base::Time::FromUTCExploded(exploded, &time))
    return;

  GeneralizedTime generalized_time;
  ASSERT_TRUE(EncodeTimeAsGeneralizedTime(time, &generalized_time));
  EXPECT_EQ(1570, generalized_time.year);
  EXPECT_EQ(1, generalized_time.month);
  EXPECT_EQ(1, generalized_time.day);
  EXPECT_EQ(0, generalized_time.hours);
  EXPECT_EQ(0, generalized_time.minutes);
  EXPECT_EQ(0, generalized_time.seconds);
}

// Sat, 1 Jan 2039 00:00:00 GMT. See above comment. This time may be
// unrepresentable on 32-bit systems.
TEST(EncodeValuesTest, EncodeTimeAfterTimeTMax) {
  base::Time::Exploded exploded;
  exploded.year = 2039;
  exploded.month = 1;
  exploded.day_of_week = 7;
  exploded.day_of_month = 1;
  exploded.hour = 0;
  exploded.minute = 0;
  exploded.second = 0;
  exploded.millisecond = 0;

  base::Time time;
  if (!base::Time::FromUTCExploded(exploded, &time))
    return;

  GeneralizedTime generalized_time;
  ASSERT_TRUE(EncodeTimeAsGeneralizedTime(time, &generalized_time));
  EXPECT_EQ(2039, generalized_time.year);
  EXPECT_EQ(1, generalized_time.month);
  EXPECT_EQ(1, generalized_time.day);
  EXPECT_EQ(0, generalized_time.hours);
  EXPECT_EQ(0, generalized_time.minutes);
  EXPECT_EQ(0, generalized_time.seconds);
}

}  // namespace test

}  // namespace der

}  // namespace net
