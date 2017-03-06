// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_throttle_manager_impl.h"

#include <memory>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/callback_helpers.h"
#include "base/run_loop.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/test_message_loop.h"
#include "net/base/request_priority.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

#include "testing/gtest/include/gtest/gtest.h"

const int kInitialAgeHorizonForUncountedRequests =
    (NetworkThrottleManagerImpl::kInitialMedianInMs *
     NetworkThrottleManagerImpl::kMedianLifetimeMultiple);

// Must be greater than the corresponding fudge factor in
// network_throttle_manager_impl.cc.
const int kAgeHorizonFudgeFactor = 20;

// Test fixture for throttle manager tests.

// Note that the manager owned and managed by this fixture has a clock
// that is set to base::TimeTicks::Now() (which value is also exposed
// via an accessor) on creation but does not change without
// intervention by tests (to make the tests more predictable).
//
// HOWEVER, also note that that manager uses the base::Timer class, which
// uses the system clock, which isn't affected by the setting of the
// test fixture clock.  So test should be written to a) avoid situations
// in which the manager's timer will actually go off based on the system
// clock, and b) call ConditionallyTriggerTimerForTesting() (which does
// evaluate the manager's clock) when timer based tests are necessary.
class NetworkThrottleManagerTest : public testing::Test,
                                   NetworkThrottleManager::ThrottleDelegate {
 public:
  NetworkThrottleManagerTest()
      : clock_(new base::SimpleTestTickClock),
        now_(base::TimeTicks::Now()),
        throttle_state_change_count_(0),
        last_throttle_to_change_state_(nullptr),
        throttle_manager_(new NetworkThrottleManagerImpl) {
    clock_->SetNowTicks(now_);
    throttle_manager_->SetTickClockForTesting(
        std::unique_ptr<base::TickClock>(clock_));
  }

 protected:
  enum ExpectedThrottleBlockState { BLOCKED, UNBLOCKED };

  base::TimeTicks now() { return now_; }
  NetworkThrottleManagerImpl* throttle_manager() {
    return throttle_manager_.get();
  }

  // Set the offset of the test clock from now_.
  void SetClockDelta(base::TimeDelta time_delta) {
    clock_->SetNowTicks(now_ + time_delta);
  }

  // Throttle creation
  std::unique_ptr<NetworkThrottleManager::Throttle> CreateThrottle(
      net::RequestPriority priority,
      ExpectedThrottleBlockState throttle_state) {
    std::unique_ptr<NetworkThrottleManager::Throttle> throttle(
        throttle_manager_->CreateThrottle(this, priority, false));
    EXPECT_EQ(throttle_state == BLOCKED, throttle->IsBlocked());
    return throttle;
  }
  std::unique_ptr<NetworkThrottleManager::Throttle>
  CreateThrottleIgnoringLimits(net::RequestPriority priority) {
    std::unique_ptr<NetworkThrottleManager::Throttle> throttle(
        throttle_manager_->CreateThrottle(this, priority, true));
    EXPECT_FALSE(throttle->IsBlocked());
    return throttle;
  }

  // Throttle state change information.
  int throttle_state_change_count() { return throttle_state_change_count_; }
  NetworkThrottleManager::Throttle* last_throttle_to_change_state() {
    return last_throttle_to_change_state_;
  }

  // Setting a callback to be invoked when a throttle's state changes.
  void SetThrottleStateChangedCallback(const base::Closure& callback) {
    throttle_state_changed_callback_ = callback;
  }

 private:
  // NetworkThrottleManager::Delegate
  void OnThrottleUnblocked(
      NetworkThrottleManager::Throttle* throttle) override {
    ++throttle_state_change_count_;
    last_throttle_to_change_state_ = throttle;
    if (!throttle_state_changed_callback_.is_null())
      base::ResetAndReturn(&throttle_state_changed_callback_).Run();
  }

  base::SimpleTestTickClock* clock_;
  base::TimeTicks now_;
  int throttle_state_change_count_;
  NetworkThrottleManager::Throttle* last_throttle_to_change_state_;
  std::unique_ptr<NetworkThrottleManagerImpl> throttle_manager_;
  base::Closure throttle_state_changed_callback_;

  DISALLOW_COPY_AND_ASSIGN(NetworkThrottleManagerTest);
};

// Check to confirm that all created throttles at priorities other than
// THROTTLED start unblocked.
TEST_F(NetworkThrottleManagerTest, AllUnthrottled) {
  for (int i = MINIMUM_PRIORITY; i <= MAXIMUM_PRIORITY; ++i) {
    if (i == THROTTLED)
      continue;
    CreateThrottle(static_cast<RequestPriority>(i), UNBLOCKED);
  }
}

// Check for basic semantics around the new THROTTLED level.
TEST_F(NetworkThrottleManagerTest, ThrottledBlocking) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(THROTTLED, BLOCKED));

  EXPECT_EQ(0, throttle_state_change_count());

  throttle1.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle3.get(), last_throttle_to_change_state());

  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_TRUE(throttle4->IsBlocked());
  EXPECT_TRUE(throttle5->IsBlocked());

  throttle2.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(2, throttle_state_change_count());
  EXPECT_EQ(throttle4.get(), last_throttle_to_change_state());

  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_FALSE(throttle4->IsBlocked());
  EXPECT_TRUE(throttle5->IsBlocked());
}

// Check that THROTTLED semantics are dependent on all outstanding requests.
TEST_F(NetworkThrottleManagerTest, ThrottledBlockingMultiPriority) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(HIGHEST, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(LOW, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(THROTTLED, BLOCKED));

  EXPECT_EQ(0, throttle_state_change_count());

  throttle1.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(0, throttle_state_change_count());
  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_TRUE(throttle4->IsBlocked());
  EXPECT_TRUE(throttle5->IsBlocked());

  throttle2.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle4.get(), last_throttle_to_change_state());

  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_FALSE(throttle4->IsBlocked());
  EXPECT_TRUE(throttle5->IsBlocked());

  throttle3.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(2, throttle_state_change_count());
  EXPECT_EQ(throttle5.get(), last_throttle_to_change_state());

  EXPECT_FALSE(throttle4->IsBlocked());
  EXPECT_FALSE(throttle5->IsBlocked());
}

// Check that a SetPriority() away from THROTTLED results in unblocking
// and an upcall.
TEST_F(NetworkThrottleManagerTest, ThrottledSetPriority) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));

  EXPECT_EQ(0, throttle_state_change_count());

  throttle3->SetPriority(LOW);
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle3.get(), last_throttle_to_change_state());
  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_TRUE(throttle4->IsBlocked());
}

void ResetThrottles(
    bool* function_called,
    std::vector<std::unique_ptr<NetworkThrottleManager::Throttle>> throttles) {
  *function_called = true;
  // All pointers in the vector should be deleted on exit.
}

// Check that tearing down all elements in the NTM on a SetPriority
// upcall doesn't create any problems.
TEST_F(NetworkThrottleManagerTest, ThrottleTeardown) {
  std::vector<std::unique_ptr<NetworkThrottleManager::Throttle>> throttles;

  throttles.push_back(CreateThrottle(THROTTLED, UNBLOCKED));
  throttles.push_back(CreateThrottle(THROTTLED, UNBLOCKED));

  // Note that if there is more than one throttle blocked, then the
  // number of throttle state changes is dependent on destruction order.
  // So only one blocked throttle is created.
  auto throttle_temporary = CreateThrottle(THROTTLED, BLOCKED);
  NetworkThrottleManager::Throttle* throttle3 = throttle_temporary.get();
  throttles.push_back(std::move(throttle_temporary));

  bool callback_called(false);
  SetThrottleStateChangedCallback(
      base::Bind(&ResetThrottles, &callback_called, base::Passed(&throttles)));

  EXPECT_EQ(0, throttle_state_change_count());

  throttle3->SetPriority(LOW);

  // If the test is functioning as expected, throttle3 now points to
  // a deleted object and can no longer be indirected through.

  EXPECT_TRUE(callback_called);
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle3, last_throttle_to_change_state());
}

// Note that this routine is dependent on priority setting *not* resulting in
// destruction of any throttle and should only be used in tests where that is
// true.
void SetAllToPriority(
    RequestPriority priority,
    std::vector<NetworkThrottleManager::Throttle*> throttles) {
  for (size_t i = 0; i < throttles.size(); ++i)
    throttles[i]->SetPriority(priority);
}

// Check that modifying all the priorities of the allocated throttles in
// the callback works properly.
TEST_F(NetworkThrottleManagerTest, ThrottlePriorityReset) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));

  std::vector<NetworkThrottleManager::Throttle*> throttles;
  throttles.push_back(throttle1.get());
  throttles.push_back(throttle2.get());
  throttles.push_back(throttle3.get());

  SetThrottleStateChangedCallback(
      base::Bind(&SetAllToPriority, MEDIUM, base::Passed(&throttles)));

  EXPECT_EQ(0, throttle_state_change_count());
  throttle3->SetPriority(HIGHEST);

  // Expected result: throttles 1-3 @ medium priority (the callback should
  // have overridden the priority setting above), only throttle 4 blocked
  // (throttle3 should have been unblocked by either of the priority changes),
  // and one state changes (the unblocking).
  EXPECT_EQ(MEDIUM, throttle1->Priority());
  EXPECT_EQ(MEDIUM, throttle2->Priority());
  EXPECT_EQ(MEDIUM, throttle3->Priority());
  EXPECT_EQ(THROTTLED, throttle4->Priority());
  EXPECT_FALSE(throttle1->IsBlocked());
  EXPECT_FALSE(throttle2->IsBlocked());
  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_TRUE(throttle4->IsBlocked());
  EXPECT_EQ(1, throttle_state_change_count());
}

// Check that modifying the priority of a request from a non-THROTTLED
// value to THROTTLED causes no change in behavior.
TEST_F(NetworkThrottleManagerTest, ThrottlePriorityResetToThrottled) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(THROTTLED, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(LOW, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));

  EXPECT_EQ(0, throttle_state_change_count());
  throttle3->SetPriority(THROTTLED);
  EXPECT_EQ(0, throttle_state_change_count());

  EXPECT_FALSE(throttle1->IsBlocked());
  EXPECT_FALSE(throttle2->IsBlocked());
  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_TRUE(throttle4->IsBlocked());

  EXPECT_EQ(THROTTLED, throttle1->Priority());
  EXPECT_EQ(THROTTLED, throttle2->Priority());
  EXPECT_EQ(THROTTLED, throttle3->Priority());
  EXPECT_EQ(THROTTLED, throttle4->Priority());
}

// Confirm that old requests don't count against the limit.
TEST_F(NetworkThrottleManagerTest, DontCountAgedRequests) {
  const int age_in_days_of_old_throttles = 4;

  // Confirm default median and timing means that 4 days is long enough ago
  // to be aged out.
  EXPECT_GT(age_in_days_of_old_throttles * 24 * 60 * 60 * 1000,
            kInitialAgeHorizonForUncountedRequests);

  SetClockDelta(-base::TimeDelta::FromDays(age_in_days_of_old_throttles));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(IDLE, UNBLOCKED));

  SetClockDelta(base::TimeDelta());
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(LOW, UNBLOCKED));

  // First throttled request should not be blocked.
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, UNBLOCKED));

  // Second should be.
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(THROTTLED, BLOCKED));

  // Destroying the old requests should not result in any upcalls.
  EXPECT_EQ(0, throttle_state_change_count());
  throttle1.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(0, throttle_state_change_count());
  throttle2.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(0, throttle_state_change_count());

  // But destroying a new request should result in a state change.
  throttle3.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle5.get(), last_throttle_to_change_state());
}

// Confirm that a slew of throttles of a specific age will shift the
// median for determining "aged requests" to that age.
TEST_F(NetworkThrottleManagerTest, ShiftMedian) {
  // Setup two throttles of age *just short* of aging out; confirm
  // they result in blocked THROTTLED requests.
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(IDLE, UNBLOCKED));
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      kInitialAgeHorizonForUncountedRequests - 1));
  EXPECT_FALSE(throttle_manager()->ConditionallyTriggerTimerForTesting());

  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));

  throttle1.reset();
  throttle2.reset();
  throttle3.reset();
  base::RunLoop().RunUntilIdle();  // Allow posttasks to run.

  // Create 100 throttles and destroy them, effectively with lifetime zero.
  // This should substantially decrease the median age estimate.
  SetClockDelta(base::TimeDelta());
  for (int i = 0; i < 100; ++i) {
    std::unique_ptr<NetworkThrottleManager::Throttle> tmp(
        CreateThrottle(IDLE, UNBLOCKED));
  }

  // Clear out any possible leftover timer by setting the clock to a point
  // in the future at which it will definitely go off, and triggering it.
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      2 * kInitialAgeHorizonForUncountedRequests + kAgeHorizonFudgeFactor));
  throttle_manager()->ConditionallyTriggerTimerForTesting();

  // The identical test above should no longer result in blocked throttles.
  SetClockDelta(base::TimeDelta());
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle6(
      CreateThrottle(IDLE, UNBLOCKED));
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      kInitialAgeHorizonForUncountedRequests - 1));
  EXPECT_TRUE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle7(
      CreateThrottle(THROTTLED, UNBLOCKED));
}

// Confirm that just "aging out" requests will result in unblocking
// blocked requests.
TEST_F(NetworkThrottleManagerTest, AgeInvalidThrottles) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));

  EXPECT_EQ(0, throttle_state_change_count());
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      kInitialAgeHorizonForUncountedRequests + kAgeHorizonFudgeFactor));
  EXPECT_TRUE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle3.get(), last_throttle_to_change_state());
  EXPECT_FALSE(throttle3->IsBlocked());
}

// Confirm that if throttles are unblocked and made active by all
// existing outstanding throttles aging out, they will also eventually
// age out and let new throttles through.
TEST_F(NetworkThrottleManagerTest, NewlyUnblockedThrottlesAlsoAge) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle6(
      CreateThrottle(THROTTLED, BLOCKED));

  // Age the first two throttles out of the outstanding, which should
  // result in the next two throttles becoming unblocked (and in the
  // oustanding list).  (The internal implementation will zero out
  // the outstanding queue and then add in the two new unblocked throttles.)
  EXPECT_EQ(0, throttle_state_change_count());
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      kInitialAgeHorizonForUncountedRequests + kAgeHorizonFudgeFactor));
  EXPECT_TRUE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  EXPECT_EQ(2, throttle_state_change_count());
  EXPECT_FALSE(throttle3->IsBlocked());
  EXPECT_FALSE(throttle4->IsBlocked());

  // Age the next two throttles out of the outstanding queue, which
  // should result in the next two throttles becoming unblocked (and
  // in the oustanding list).  This will only happen if a timer was properly
  // set in the above age process as the oustanding queue went through
  // the empty state.
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      2 * (kInitialAgeHorizonForUncountedRequests + kAgeHorizonFudgeFactor)));
  EXPECT_TRUE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  EXPECT_EQ(4, throttle_state_change_count());
  EXPECT_FALSE(throttle5->IsBlocked());
  EXPECT_FALSE(throttle6->IsBlocked());
}

// Confirm that throttles that are blocked for a while and then
// unblocked don't "age out".
TEST_F(NetworkThrottleManagerTest, AgeBlockedThrottles) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(THROTTLED, BLOCKED));

  EXPECT_EQ(0, throttle_state_change_count());
  SetClockDelta(base::TimeDelta::FromMilliseconds(
      kInitialAgeHorizonForUncountedRequests + kAgeHorizonFudgeFactor));
  EXPECT_TRUE(throttle_manager()->ConditionallyTriggerTimerForTesting());

  // If blocked throttles aged out, all three throttles should have been
  // unblocked.  If not, only the two replacing the IDLE throttles should
  // have.
  EXPECT_EQ(2, throttle_state_change_count());
}

// Confirm that deleting old throttles before they age out doesn't
// interfere with the aging out of more recent throttles.
TEST_F(NetworkThrottleManagerTest, DeletionAgingInterference) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(THROTTLED, BLOCKED));
  EXPECT_EQ(0, throttle_state_change_count());

  SetClockDelta(base::TimeDelta::FromMilliseconds(
      kInitialAgeHorizonForUncountedRequests / 2));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottle(IDLE, UNBLOCKED));
  EXPECT_FALSE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  EXPECT_EQ(0, throttle_state_change_count());

  throttle1.reset();
  throttle2.reset();
  EXPECT_FALSE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  EXPECT_EQ(0, throttle_state_change_count());

  SetClockDelta(base::TimeDelta::FromMilliseconds(
      (3 * kInitialAgeHorizonForUncountedRequests / 2 +
       2 * kAgeHorizonFudgeFactor)));
  EXPECT_TRUE(throttle_manager()->ConditionallyTriggerTimerForTesting());
  EXPECT_EQ(1, throttle_state_change_count());
  EXPECT_EQ(throttle3.get(), last_throttle_to_change_state());
  EXPECT_FALSE(throttle3->IsBlocked());
}

// Confirm that "ignore_limits" boolean is respected.
TEST_F(NetworkThrottleManagerTest, IgnoreLimits) {
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle1(
      CreateThrottle(HIGHEST, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle2(
      CreateThrottle(LOW, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle3(
      CreateThrottle(IDLE, UNBLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle4(
      CreateThrottle(THROTTLED, BLOCKED));
  std::unique_ptr<NetworkThrottleManager::Throttle> throttle5(
      CreateThrottleIgnoringLimits(THROTTLED));
}

}  // namespace

}  // namespace net
