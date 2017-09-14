// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/cygprofile/cygprofile.h"

#include <cstdint>
#include <vector>

#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/perf/perf_test.h"

namespace cygprofile {

namespace {

void AddEntryCost(int iterations, int addresses_count) {
  // This is intentionally leaky. ThreadLog() destructor would call abort(),
  // limiting us to a single test. Leaking ThreadLog is fine as long as we clean
  // up the entries.
  auto* thread_log = new ThreadLog();

  auto tick = base::TimeTicks::Now();
  for (int i = 0; i < iterations; i++) {
    for (int address = 0; address < addresses_count; address++) {
      thread_log->AddEntry(reinterpret_cast<void*>(address));
    }
  }
  auto tock = base::TimeTicks::Now();
  double nanos = static_cast<double>((tock - tick).InNanoseconds());
  auto ns_per_call =
      nanos / (iterations * static_cast<double>(addresses_count));
  auto modifier = base::StringPrintf("_%d_%d", iterations, addresses_count);
  perf_test::PrintResult("AddEntryCostPerCall", modifier, "", ns_per_call, "ns",
                         true);

  // Entries cleanup, see comment at the beginning of the function.
  std::vector<LogEntry> entries;
  thread_log->TakeEntries(&entries);
}
}  // namespace

TEST(CygprofilePerfTest, CreateEntries_10_10000) {
  AddEntryCost(10, 10000);
}

TEST(CygprofilePerfTest, CreateEntries_100_10000) {
  AddEntryCost(100, 10000);
}

TEST(CygprofilePerfTest, CreateEntries_10_100000) {
  AddEntryCost(10, 100000);
}

TEST(CygprofilePerfTest, CreateEntries_100_1000000) {
  AddEntryCost(100, 100000);
}

}  // namespace cygprofile

// Custom runner implementation since base's one requires JNI on Android.
int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
