// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/build_time.h"
#include "base/generated_build_date.h"
#include "base/time/time.h"

#include "testing/gtest/include/gtest/gtest.h"

TEST(BuildTime, DateLooksValid) {
  char build_date[] = BUILD_DATE;

  EXPECT_EQ(20u, strlen(build_date));
  EXPECT_EQ(' ', build_date[3]);
  EXPECT_EQ(' ', build_date[6]);
  EXPECT_EQ(' ', build_date[11]);
  EXPECT_EQ('0', build_date[12]);
  EXPECT_EQ('5', build_date[13]);
  EXPECT_EQ(':', build_date[14]);
  EXPECT_EQ('0', build_date[15]);
  EXPECT_EQ('0', build_date[16]);
  EXPECT_EQ(':', build_date[17]);
  EXPECT_EQ('0', build_date[18]);
  EXPECT_EQ('0', build_date[19]);
}

TEST(BuildTime, InThePast) {
  EXPECT_LT(base::GetBuildTime(), base::Time::Now());
  EXPECT_LT(base::GetBuildTime(), base::Time::NowFromSystemTime());
}

TEST(BuildTime, NotTooFar) {
  // BuildTime must be less than 45 days old.
  base::Time cutoff(base::Time::Now() - base::TimeDelta::FromDays(45));
  EXPECT_GT(base::GetBuildTime(), cutoff);
}
