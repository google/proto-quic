// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_epoll_connection_helper.h"

#include "net/quic/crypto/quic_random.h"
#include "net/tools/quic/test_tools/mock_epoll_server.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::MockEpollServer;

namespace net {
namespace test {
namespace {

class TestDelegate : public QuicAlarm::Delegate {
 public:
  TestDelegate() : fired_(false) {}

  void OnAlarm() override { fired_ = true; }

  bool fired() const { return fired_; }

 private:
  bool fired_;
};

class QuicEpollConnectionHelperTest : public ::testing::Test {
 protected:
  QuicEpollConnectionHelperTest() : helper_(&epoll_server_) {}

  MockEpollServer epoll_server_;
  QuicEpollConnectionHelper helper_;
};

TEST_F(QuicEpollConnectionHelperTest, GetClock) {
  const QuicClock* clock = helper_.GetClock();
  QuicTime start = clock->Now();

  QuicTime::Delta delta = QuicTime::Delta::FromMilliseconds(5);
  epoll_server_.AdvanceBy(delta.ToMicroseconds());

  EXPECT_EQ(start.Add(delta), clock->Now());
}

TEST_F(QuicEpollConnectionHelperTest, GetRandomGenerator) {
  QuicRandom* random = helper_.GetRandomGenerator();
  EXPECT_EQ(QuicRandom::GetInstance(), random);
}

// The boolean parameter denotes whether or not to use an arena.
class QuicEpollConnectionHelperAlarmTest
    : public QuicEpollConnectionHelperTest,
      public ::testing::WithParamInterface<bool> {
 protected:
  QuicConnectionArena* GetArenaParam() {
    return GetParam() ? &arena_ : nullptr;
  }

 private:
  QuicConnectionArena arena_;
};

INSTANTIATE_TEST_CASE_P(QuicEpollConnectionHelperAlarmTest,
                        QuicEpollConnectionHelperAlarmTest,
                        ::testing::Bool());

TEST_P(QuicEpollConnectionHelperAlarmTest, CreateAlarm) {
  QuicArenaScopedPtr<TestDelegate> delegate =
      QuicArenaScopedPtr<TestDelegate>(new TestDelegate());
  QuicArenaScopedPtr<QuicAlarm> alarm(
      helper_.CreateAlarm(std::move(delegate), GetArenaParam()));

  const QuicClock* clock = helper_.GetClock();
  QuicTime start = clock->Now();
  QuicTime::Delta delta = QuicTime::Delta::FromMicroseconds(1);
  alarm->Set(start.Add(delta));

  epoll_server_.AdvanceByAndWaitForEventsAndExecuteCallbacks(
      delta.ToMicroseconds());
  EXPECT_EQ(start.Add(delta), clock->Now());
}

TEST_P(QuicEpollConnectionHelperAlarmTest, CreateAlarmAndCancel) {
  QuicArenaScopedPtr<TestDelegate> delegate =
      QuicArenaScopedPtr<TestDelegate>(new TestDelegate());
  TestDelegate* unowned_delegate = delegate.get();
  QuicArenaScopedPtr<QuicAlarm> alarm(
      helper_.CreateAlarm(std::move(delegate), GetArenaParam()));

  const QuicClock* clock = helper_.GetClock();
  QuicTime start = clock->Now();
  QuicTime::Delta delta = QuicTime::Delta::FromMicroseconds(1);
  alarm->Set(start.Add(delta));
  alarm->Cancel();

  epoll_server_.AdvanceByExactlyAndCallCallbacks(delta.ToMicroseconds());
  EXPECT_EQ(start.Add(delta), clock->Now());
  EXPECT_FALSE(unowned_delegate->fired());
}

TEST_P(QuicEpollConnectionHelperAlarmTest, CreateAlarmAndReset) {
  QuicArenaScopedPtr<TestDelegate> delegate =
      QuicArenaScopedPtr<TestDelegate>(new TestDelegate());
  TestDelegate* unowned_delegate = delegate.get();
  QuicArenaScopedPtr<QuicAlarm> alarm(
      helper_.CreateAlarm(std::move(delegate), GetArenaParam()));

  const QuicClock* clock = helper_.GetClock();
  QuicTime start = clock->Now();
  QuicTime::Delta delta = QuicTime::Delta::FromMicroseconds(1);
  alarm->Set(clock->Now().Add(delta));
  alarm->Cancel();
  QuicTime::Delta new_delta = QuicTime::Delta::FromMicroseconds(3);
  alarm->Set(clock->Now().Add(new_delta));

  epoll_server_.AdvanceByExactlyAndCallCallbacks(delta.ToMicroseconds());
  EXPECT_EQ(start.Add(delta), clock->Now());
  EXPECT_FALSE(unowned_delegate->fired());

  epoll_server_.AdvanceByExactlyAndCallCallbacks(
      new_delta.Subtract(delta).ToMicroseconds());
  EXPECT_EQ(start.Add(new_delta), clock->Now());
  EXPECT_TRUE(unowned_delegate->fired());
}

TEST_P(QuicEpollConnectionHelperAlarmTest, CreateAlarmAndUpdate) {
  QuicArenaScopedPtr<TestDelegate> delegate =
      QuicArenaScopedPtr<TestDelegate>(new TestDelegate());
  TestDelegate* unowned_delegate = delegate.get();
  QuicArenaScopedPtr<QuicAlarm> alarm(
      helper_.CreateAlarm(std::move(delegate), GetArenaParam()));

  const QuicClock* clock = helper_.GetClock();
  QuicTime start = clock->Now();
  QuicTime::Delta delta = QuicTime::Delta::FromMicroseconds(1);
  alarm->Set(clock->Now().Add(delta));
  QuicTime::Delta new_delta = QuicTime::Delta::FromMicroseconds(3);
  alarm->Update(clock->Now().Add(new_delta),
                QuicTime::Delta::FromMicroseconds(1));

  epoll_server_.AdvanceByExactlyAndCallCallbacks(delta.ToMicroseconds());
  EXPECT_EQ(start.Add(delta), clock->Now());
  EXPECT_FALSE(unowned_delegate->fired());

  // Move the alarm forward 1us and ensure it doesn't move forward.
  alarm->Update(clock->Now().Add(new_delta),
                QuicTime::Delta::FromMicroseconds(2));

  epoll_server_.AdvanceByExactlyAndCallCallbacks(
      new_delta.Subtract(delta).ToMicroseconds());
  EXPECT_EQ(start.Add(new_delta), clock->Now());
  EXPECT_TRUE(unowned_delegate->fired());

  // Set the alarm via an update call.
  new_delta = QuicTime::Delta::FromMicroseconds(5);
  alarm->Update(clock->Now().Add(new_delta),
                QuicTime::Delta::FromMicroseconds(1));
  EXPECT_TRUE(alarm->IsSet());

  // Update it with an uninitialized time and ensure it's cancelled.
  alarm->Update(QuicTime::Zero(), QuicTime::Delta::FromMicroseconds(1));
  EXPECT_FALSE(alarm->IsSet());
}

}  // namespace
}  // namespace test
}  // namespace net
