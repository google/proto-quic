// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/impl/quic_chromium_clock.h"

#include "base/time/time.h"

namespace net {

QuicChromiumClock::QuicChromiumClock() {}

QuicChromiumClock::~QuicChromiumClock() {}

QuicTime QuicChromiumClock::ApproximateNow() const {
  // At the moment, Chrome does not have a distinct notion of ApproximateNow().
  // We should consider implementing this using MessageLoop::recent_time_.
  return Now();
}

QuicTime QuicChromiumClock::Now() const {
  return QuicTime(base::TimeTicks::Now());
}

QuicWallTime QuicChromiumClock::WallNow() const {
  return QuicWallTime::FromUNIXMicroseconds(base::Time::Now().ToJavaTime() *
                                            1000);
}

}  // namespace net
