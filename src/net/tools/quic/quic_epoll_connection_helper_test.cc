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
  QuicEpollConnectionHelperTest()
      : helper_(&epoll_server_, QuicAllocator::BUFFER_POOL) {}

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

}  // namespace
}  // namespace test
}  // namespace net
