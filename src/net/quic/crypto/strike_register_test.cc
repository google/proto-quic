// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/strike_register.h"

#include <set>
#include <string>

#include "base/rand_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

using std::min;
using std::pair;
using std::set;
using std::string;

const uint8_t kOrbit[8] = {1, 2, 3, 4, 5, 6, 7, 8};

// StrikeRegisterTests don't look at the random bytes so this function can
// simply set the random bytes to 0.
void SetNonce(uint8_t nonce[32], unsigned time, const uint8_t orbit[8]) {
  nonce[0] = time >> 24;
  nonce[1] = time >> 16;
  nonce[2] = time >> 8;
  nonce[3] = time;
  memcpy(nonce + 4, orbit, 8);
  memset(nonce + 12, 0, 20);
}

TEST(StrikeRegisterTest, SimpleHorizon) {
  // The set must reject values created on or before its own creation time.
  StrikeRegister set(10 /* max size */, 1000 /* current time */,
                     100 /* window secs */, kOrbit,
                     StrikeRegister::DENY_REQUESTS_AT_STARTUP);
  uint8_t nonce[32];
  SetNonce(nonce, 999, kOrbit);
  EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce, 1000));
  SetNonce(nonce, 1000, kOrbit);
  EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce, 1000));

  EXPECT_EQ(0u, set.GetCurrentValidWindowSecs(1000 /* current time */));
  EXPECT_EQ(0u, set.GetCurrentValidWindowSecs(1100 /* current time */));
  EXPECT_EQ(1u, set.GetCurrentValidWindowSecs(1101 /* current time */));
  EXPECT_EQ(50u, set.GetCurrentValidWindowSecs(1150 /* current time */));
  EXPECT_EQ(100u, set.GetCurrentValidWindowSecs(1200 /* current time */));
  EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1300 /* current time */));
}

TEST(StrikeRegisterTest, NoStartupMode) {
  // Check that a strike register works immediately if NO_STARTUP_PERIOD_NEEDED
  // is specified.
  StrikeRegister set(10 /* max size */, 1000 /* current time */,
                     100 /* window secs */, kOrbit,
                     StrikeRegister::NO_STARTUP_PERIOD_NEEDED);
  uint8_t nonce[32];
  SetNonce(nonce, 1000, kOrbit);
  EXPECT_EQ(NONCE_OK, set.Insert(nonce, 1000));
  EXPECT_EQ(NONCE_NOT_UNIQUE_FAILURE, set.Insert(nonce, 1000));

  EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1000 /* current time */));
  EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1050 /* current time */));
  EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1100 /* current time */));
  EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1200 /* current time */));
  EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1300 /* current time */));
}

TEST(StrikeRegisterTest, WindowFuture) {
  // The set must reject values outside the window.
  StrikeRegister set(10 /* max size */, 1000 /* current time */,
                     100 /* window secs */, kOrbit,
                     StrikeRegister::DENY_REQUESTS_AT_STARTUP);
  uint8_t nonce[32];
  SetNonce(nonce, 1101, kOrbit);
  EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce, 1000));
  SetNonce(nonce, 999, kOrbit);
  EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce, 1100));
}

TEST(StrikeRegisterTest, BadOrbit) {
  // The set must reject values with the wrong orbit
  StrikeRegister set(10 /* max size */, 1000 /* current time */,
                     100 /* window secs */, kOrbit,
                     StrikeRegister::DENY_REQUESTS_AT_STARTUP);
  uint8_t nonce[32];
  static const uint8_t kBadOrbit[8] = {0, 0, 0, 0, 1, 1, 1, 1};
  SetNonce(nonce, 1101, kBadOrbit);
  EXPECT_EQ(NONCE_INVALID_ORBIT_FAILURE, set.Insert(nonce, 1100));
}

TEST(StrikeRegisterTest, OneValue) {
  StrikeRegister set(10 /* max size */, 1000 /* current time */,
                     100 /* window secs */, kOrbit,
                     StrikeRegister::DENY_REQUESTS_AT_STARTUP);
  uint8_t nonce[32];
  SetNonce(nonce, 1101, kOrbit);
  EXPECT_EQ(NONCE_OK, set.Insert(nonce, 1101));
}

TEST(StrikeRegisterTest, RejectDuplicate) {
  // The set must reject values with the wrong orbit
  StrikeRegister set(10 /* max size */, 1000 /* current time */,
                     100 /* window secs */, kOrbit,
                     StrikeRegister::DENY_REQUESTS_AT_STARTUP);
  uint8_t nonce[32];
  SetNonce(nonce, 1101, kOrbit);
  EXPECT_EQ(NONCE_OK, set.Insert(nonce, 1101));
  EXPECT_EQ(NONCE_NOT_UNIQUE_FAILURE, set.Insert(nonce, 1101));
}

TEST(StrikeRegisterTest, HorizonUpdating) {
  StrikeRegister::StartupType startup_types[] = {
      StrikeRegister::DENY_REQUESTS_AT_STARTUP,
      StrikeRegister::NO_STARTUP_PERIOD_NEEDED};

  for (size_t type_idx = 0; type_idx < arraysize(startup_types); ++type_idx) {
    StrikeRegister set(5 /* max size */, 500 /* current time */,
                       100 /* window secs */, kOrbit, startup_types[type_idx]);
    uint8_t nonce[6][32];
    for (unsigned i = 0; i < 5; i++) {
      SetNonce(nonce[i], 1101 + i, kOrbit);
      nonce[i][31] = i;
      EXPECT_EQ(NONCE_OK, set.Insert(nonce[i], 1100));
    }

    // Valid window is still equal to |window_secs + 1|.
    EXPECT_EQ(101u, set.GetCurrentValidWindowSecs(1100));

    // This should push the oldest value out and force the horizon to
    // be updated.
    SetNonce(nonce[5], 1110, kOrbit);
    EXPECT_EQ(NONCE_OK, set.Insert(nonce[5], 1110));
    // Effective horizon is computed based on the timestamp of the
    // value that was pushed out.
    EXPECT_EQ(9u, set.GetCurrentValidWindowSecs(1110));

    SetNonce(nonce[5], 1111, kOrbit);
    EXPECT_EQ(NONCE_OK, set.Insert(nonce[5], 1110));
    EXPECT_EQ(8u, set.GetCurrentValidWindowSecs(1110));

    // This should be behind the horizon now:
    SetNonce(nonce[5], 1101, kOrbit);
    nonce[5][31] = 10;
    EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce[5], 1110));

    // Insert beyond the valid range.
    SetNonce(nonce[5], 1117, kOrbit);
    nonce[5][31] = 2;
    EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce[5], 1110));

    // Insert at the upper valid range.
    SetNonce(nonce[5], 1116, kOrbit);
    nonce[5][31] = 1;
    EXPECT_EQ(NONCE_OK, set.Insert(nonce[5], 1110));

    // This should be beyond the upper valid range now:
    SetNonce(nonce[5], 1116, kOrbit);
    nonce[5][31] = 2;
    EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce[5], 1110));
  }
}

TEST(StrikeRegisterTest, InsertMany) {
  StrikeRegister set(5000 /* max size */, 1000 /* current time */,
                     500 /* window secs */, kOrbit,
                     StrikeRegister::DENY_REQUESTS_AT_STARTUP);

  uint8_t nonce[32];
  SetNonce(nonce, 1101, kOrbit);
  for (unsigned i = 0; i < 100000; i++) {
    SetNonce(nonce, 1101 + i / 500, kOrbit);
    memcpy(nonce + 12, &i, sizeof(i));
    EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, set.Insert(nonce, 1100));
  }
}

// For the following test we create a slow, but simple, version of a
// StrikeRegister. The behaviour of this object is much easier to understand
// than the fully fledged version. We then create a test to show, empirically,
// that the two objects have identical behaviour.

// A SlowStrikeRegister has the same public interface as a StrikeRegister, but
// is much slower. Hopefully it is also more obviously correct and we can
// empirically test that their behaviours are identical.
class SlowStrikeRegister {
 public:
  SlowStrikeRegister(unsigned max_entries,
                     uint32_t current_time,
                     uint32_t window_secs,
                     const uint8_t orbit[8])
      : max_entries_(max_entries),
        window_secs_(window_secs),
        creation_time_(current_time),
        horizon_(ExternalTimeToInternal(current_time + window_secs) + 1) {
    memcpy(orbit_, orbit, sizeof(orbit_));
  }

  InsertStatus Insert(const uint8_t nonce_bytes[32],
                      const uint32_t nonce_time_external,
                      const uint32_t current_time_external) {
    if (nonces_.size() == max_entries_) {
      DropOldestEntry();
    }

    const uint32_t current_time = ExternalTimeToInternal(current_time_external);

    // Check to see if the orbit is correct.
    if (memcmp(nonce_bytes + 4, orbit_, sizeof(orbit_))) {
      return NONCE_INVALID_ORBIT_FAILURE;
    }
    const uint32_t nonce_time =
        ExternalTimeToInternal(TimeFromBytes(nonce_bytes));
    EXPECT_EQ(ExternalTimeToInternal(nonce_time_external), nonce_time);
    // We have dropped one or more nonces with a time value of |horizon_ - 1|,
    // so we have to reject anything with a timestamp less than or
    // equal to that.
    if (nonce_time < horizon_) {
      return NONCE_INVALID_TIME_FAILURE;
    }

    // Check that the timestamp is in the current window.
    if ((current_time > window_secs_ &&
         nonce_time < (current_time - window_secs_)) ||
        nonce_time > (current_time + window_secs_)) {
      return NONCE_INVALID_TIME_FAILURE;
    }

    pair<uint32_t, string> nonce = std::make_pair(
        nonce_time, string(reinterpret_cast<const char*>(nonce_bytes), 32));

    set<pair<uint32_t, string>>::const_iterator it = nonces_.find(nonce);
    if (it != nonces_.end()) {
      return NONCE_NOT_UNIQUE_FAILURE;
    }

    nonces_.insert(nonce);
    return NONCE_OK;
  }

  uint32_t GetCurrentValidWindowSecs(
      const uint32_t current_time_external) const {
    const uint32_t current_time = ExternalTimeToInternal(current_time_external);
    if (horizon_ > current_time) {
      return 0;
    }
    return 1 + min(current_time - horizon_, window_secs_);
  }

 private:
  // TimeFromBytes returns a big-endian uint32_t from |d|.
  static uint32_t TimeFromBytes(const uint8_t d[4]) {
    return static_cast<uint32_t>(d[0]) << 24 |
           static_cast<uint32_t>(d[1]) << 16 |
           static_cast<uint32_t>(d[2]) << 8 | static_cast<uint32_t>(d[3]);
  }

  uint32_t ExternalTimeToInternal(uint32_t external_time) const {
    static const uint32_t kCreationTimeFromInternalEpoch = 63115200.0;
    uint32_t internal_epoch = 0;
    if (creation_time_ > kCreationTimeFromInternalEpoch) {
      internal_epoch = creation_time_ - kCreationTimeFromInternalEpoch;
    }

    return external_time - internal_epoch;
  }

  void DropOldestEntry() {
    set<pair<uint32_t, string>>::iterator oldest = nonces_.begin();
    horizon_ = oldest->first + 1;
    nonces_.erase(oldest);
  }

  const unsigned max_entries_;
  const unsigned window_secs_;
  const uint32_t creation_time_;
  uint8_t orbit_[8];
  uint32_t horizon_;

  set<pair<uint32_t, string>> nonces_;
};

class StrikeRegisterStressTest : public ::testing::Test {};

TEST_F(StrikeRegisterStressTest, InOrderInsertion) {
  // Fixed seed gives reproducibility for this test.
  srand(42);

  unsigned max_entries = 64;
  uint32_t current_time = 10000, window = 200;
  scoped_ptr<StrikeRegister> s1(
      new StrikeRegister(max_entries, current_time, window, kOrbit,
                         StrikeRegister::DENY_REQUESTS_AT_STARTUP));
  scoped_ptr<SlowStrikeRegister> s2(
      new SlowStrikeRegister(max_entries, current_time, window, kOrbit));

  uint64_t i;
  const uint64_t kMaxIterations = 10000;
  for (i = 0; i < kMaxIterations; i++) {
    const uint32_t time = current_time + i;

    uint8_t nonce[32];
    SetNonce(nonce, time, kOrbit);

    // There are 2048 possible nonce values:
    const uint32_t v = rand() % 2048;
    nonce[30] = v >> 8;
    nonce[31] = v;

    const InsertStatus nonce_error2 = s2->Insert(nonce, time, time);
    const InsertStatus nonce_error1 = s1->Insert(nonce, time);
    EXPECT_EQ(nonce_error1, nonce_error2);

    // Inserts succeed after the startup period.
    if (time > current_time + window) {
      EXPECT_EQ(NONCE_OK, nonce_error1);
    } else {
      EXPECT_EQ(NONCE_INVALID_TIME_FAILURE, nonce_error1);
    }
    EXPECT_EQ(s1->GetCurrentValidWindowSecs(time),
              s2->GetCurrentValidWindowSecs(time));

    if (i % 10 == 0) {
      s1->Validate();
    }

    if (HasFailure()) {
      break;
    }
  }

  if (i != kMaxIterations) {
    FAIL() << "Failed after " << i << " iterations";
  }
}

TEST_F(StrikeRegisterStressTest, Stress) {
  // Fixed seed gives reproducibility for this test.
  srand(42);
  unsigned max_entries = 64;
  uint32_t current_time = 10000, window = 200;
  scoped_ptr<StrikeRegister> s1(
      new StrikeRegister(max_entries, current_time, window, kOrbit,
                         StrikeRegister::DENY_REQUESTS_AT_STARTUP));
  scoped_ptr<SlowStrikeRegister> s2(
      new SlowStrikeRegister(max_entries, current_time, window, kOrbit));
  uint64_t i;

  // When making changes it's worth removing the limit on this test and running
  // it for a while. For the initial development an opt binary was left running
  // for 10 minutes.
  const uint64_t kMaxIterations = 10000;
  for (i = 0; i < kMaxIterations; i++) {
    if (rand() % 1000 == 0) {
      // 0.1% chance of resetting the sets.
      max_entries = rand() % 300 + 2;
      current_time = rand() % 10000;
      window = rand() % 500;
      s1.reset(new StrikeRegister(max_entries, current_time, window, kOrbit,
                                  StrikeRegister::DENY_REQUESTS_AT_STARTUP));
      s2.reset(
          new SlowStrikeRegister(max_entries, current_time, window, kOrbit));
    }

    int32_t time_delta = rand() % (window * 4);
    time_delta -= window * 2;
    const uint32_t time = current_time + time_delta;
    if (time_delta < 0 && time > current_time) {
      continue;  // overflow
    }

    uint8_t nonce[32];
    SetNonce(nonce, time, kOrbit);

    // There are 2048 possible nonce values:
    const uint32_t v = rand() % 2048;
    nonce[30] = v >> 8;
    nonce[31] = v;

    const InsertStatus nonce_error2 = s2->Insert(nonce, time, time);
    const InsertStatus nonce_error1 = s1->Insert(nonce, time);
    EXPECT_EQ(nonce_error1, nonce_error2);
    EXPECT_EQ(s1->GetCurrentValidWindowSecs(time),
              s2->GetCurrentValidWindowSecs(time));

    if (i % 10 == 0) {
      s1->Validate();
    }

    if (HasFailure()) {
      break;
    }
  }

  if (i != kMaxIterations) {
    FAIL() << "Failed after " << i << " iterations";
  }
}

}  // namespace

}  // namespace net
