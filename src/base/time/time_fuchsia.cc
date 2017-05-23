// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/time/time.h"

#include <magenta/syscalls.h>

#include "base/compiler_specific.h"

namespace base {

namespace {

// Helper function to map an unsigned integer with nanosecond timebase to a
// signed integer with microsecond timebase.
ALWAYS_INLINE int64_t MxTimeToMicroseconds(mx_time_t nanos) {
  const mx_time_t micros =
      nanos / static_cast<mx_time_t>(base::Time::kNanosecondsPerMicrosecond);
  return static_cast<int64_t>(micros);
}

}  // namespace

// Time -----------------------------------------------------------------------

// static
Time Time::Now() {
  const mx_time_t nanos_since_unix_epoch = mx_time_get(MX_CLOCK_UTC);
  CHECK(nanos_since_unix_epoch != 0);
  // The following expression will overflow in the year 289938 A.D.:
  return Time(MxTimeToMicroseconds(nanos_since_unix_epoch) +
              kTimeTToMicrosecondsOffset);
}

// static
Time Time::NowFromSystemTime() {
  return Now();
}

// TimeTicks ------------------------------------------------------------------

// static
TimeTicks TimeTicks::Now() {
  const mx_time_t nanos_since_boot = mx_time_get(MX_CLOCK_MONOTONIC);
  CHECK(nanos_since_boot != 0);
  return TimeTicks(MxTimeToMicroseconds(nanos_since_boot));
}

// static
TimeTicks::Clock TimeTicks::GetClock() {
  return Clock::FUCHSIA_MX_CLOCK_MONOTONIC;
}

// static
bool TimeTicks::IsHighResolution() {
  return true;
}

// static
bool TimeTicks::IsConsistentAcrossProcesses() {
  return true;
}

// static
TimeTicks TimeTicks::FromMXTime(mx_time_t nanos_since_boot) {
  return TimeTicks(MxTimeToMicroseconds(nanos_since_boot));
}

// static
ThreadTicks ThreadTicks::Now() {
  const mx_time_t nanos_since_thread_started = mx_time_get(MX_CLOCK_THREAD);
  CHECK(nanos_since_thread_started != 0);
  return ThreadTicks(MxTimeToMicroseconds(nanos_since_thread_started));
}

}  // namespace base
