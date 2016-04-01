// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_clock.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

TEST(QuicClockTest, Now) {
  QuicClock clock;

  QuicTime start(base::TimeTicks::Now());
  QuicTime now = clock.ApproximateNow();
  QuicTime end(base::TimeTicks::Now());

  EXPECT_LE(start, now);
  EXPECT_LE(now, end);
}

TEST(QuicClockTest, WallNow) {
  QuicClock clock;

  base::Time start = base::Time::Now();
  QuicWallTime now = clock.WallNow();
  base::Time end = base::Time::Now();

  // If end > start, then we can check now is between start and end.
  if (end > start) {
    EXPECT_LE(static_cast<uint64_t>(start.ToTimeT()), now.ToUNIXSeconds());
    EXPECT_LE(now.ToUNIXSeconds(), static_cast<uint64_t>(end.ToTimeT()));
  }
}

}  // namespace test
}  // namespace net
