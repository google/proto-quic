// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/impl/quic_chromium_clock.h"

#if defined(OS_IOS)
#include <time.h>

#include "base/ios/ios_util.h"
#endif

#include "base/memory/singleton.h"
#include "base/time/time.h"

namespace net {

QuicChromiumClock* QuicChromiumClock::GetInstance() {
  return base::Singleton<QuicChromiumClock>::get();
}
QuicChromiumClock::QuicChromiumClock() {}

QuicChromiumClock::~QuicChromiumClock() {}

QuicTime QuicChromiumClock::ApproximateNow() const {
  // At the moment, Chrome does not have a distinct notion of ApproximateNow().
  // We should consider implementing this using MessageLoop::recent_time_.
  return Now();
}

QuicTime QuicChromiumClock::Now() const {
#if defined(OS_IOS)
  if (base::ios::IsRunningOnIOS10OrLater()) {
    struct timespec tp;
    if (clock_gettime(CLOCK_MONOTONIC, &tp) == 0) {
      return CreateTimeFromMicroseconds(tp.tv_sec * 1000000 +
                                        tp.tv_nsec / 1000);
    }
  }
#endif
  return CreateTimeFromMicroseconds(base::TimeTicks::Now().ToInternalValue());
}

QuicWallTime QuicChromiumClock::WallNow() const {
  return QuicWallTime::FromUNIXMicroseconds(base::Time::Now().ToJavaTime() *
                                            1000);
}

}  // namespace net
