// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/lifo_write_scheduler.h"

#include "net/spdy/core/spdy_protocol.h"
#include "net/spdy/core/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace test {

template <typename StreamIdType>
class LifoWriteSchedulerPeer {
 public:
  explicit LifoWriteSchedulerPeer(LifoWriteScheduler<StreamIdType>* scheduler)
      : scheduler_(scheduler) {}

  size_t NumRegisteredListStreams() const {
    return scheduler_->registered_streams_.size();
  }

  std::set<StreamIdType>* GetReadyList() const {
    return &scheduler_->ready_streams_;
  }

 private:
  LifoWriteScheduler<StreamIdType>* scheduler_;
};

// Test add and remove from ready list.
TEST(LifoWriteSchedulerTest, ReadyListTest) {
  LifoWriteScheduler<SpdyStreamId> lifo;
  LifoWriteSchedulerPeer<SpdyStreamId> peer(&lifo);

  EXPECT_SPDY_BUG(
      EXPECT_EQ((uint32_t)0,
                std::get<0>(lifo.PopNextReadyStreamAndPrecedence())),
      "No ready streams available");
  EXPECT_SPDY_BUG(EXPECT_EQ((uint32_t)0, lifo.PopNextReadyStream()),
                  "No ready streams available");
  EXPECT_FALSE(lifo.HasReadyStreams());
  EXPECT_SPDY_BUG(lifo.MarkStreamReady(9, true), "Stream 9 is not registered");
  SpdyStreamPrecedence precedence(1);
  lifo.RegisterStream(3, precedence);
  lifo.RegisterStream(7, precedence);
  lifo.RegisterStream(9, precedence);
  lifo.RegisterStream(11, precedence);
  lifo.RegisterStream(13, precedence);
  lifo.RegisterStream(15, precedence);
  lifo.RegisterStream(17, precedence);
  lifo.MarkStreamReady(9, true);
  lifo.MarkStreamReady(15, true);
  lifo.MarkStreamReady(7, true);
  lifo.MarkStreamReady(13, true);
  lifo.MarkStreamReady(11, true);
  lifo.MarkStreamReady(3, true);
  lifo.MarkStreamReady(17, true);
  EXPECT_TRUE(lifo.HasReadyStreams());
  EXPECT_EQ((uint32_t)7, lifo.NumReadyStreams());

  EXPECT_SPDY_BUG(lifo.MarkStreamReady(11, true),
                  "Stream already exists in the list");
  EXPECT_SPDY_BUG(lifo.MarkStreamNotReady(5),
                  "Try to remove a stream that is not on list");
  EXPECT_SPDY_BUG(lifo.MarkStreamNotReady(21),
                  "Try to remove a stream that is not on list");

  EXPECT_EQ((uint32_t)17, lifo.PopNextReadyStream());
  EXPECT_EQ((uint32_t)15, std::get<0>(lifo.PopNextReadyStreamAndPrecedence()));
  EXPECT_TRUE(lifo.ShouldYield(9));
  EXPECT_FALSE(lifo.ShouldYield(13));
  EXPECT_FALSE(lifo.ShouldYield(15));

  lifo.MarkStreamNotReady(3);
  EXPECT_TRUE(peer.GetReadyList()->find(3) == peer.GetReadyList()->end());
  lifo.MarkStreamNotReady(13);
  EXPECT_TRUE(peer.GetReadyList()->find(13) == peer.GetReadyList()->end());
  lifo.MarkStreamNotReady(7);
  EXPECT_TRUE(peer.GetReadyList()->find(7) == peer.GetReadyList()->end());
  EXPECT_EQ((uint32_t)2, lifo.NumReadyStreams());
}

// Test add and remove from registered list.
TEST(LifoWriteSchedulerTest, RegisterListTest) {
  LifoWriteScheduler<SpdyStreamId> lifo;
  LifoWriteSchedulerPeer<SpdyStreamId> peer(&lifo);
  SpdyStreamPrecedence precedence(1);
  lifo.RegisterStream(3, precedence);
  lifo.RegisterStream(5, precedence);
  lifo.RegisterStream(7, precedence);
  lifo.RegisterStream(9, precedence);
  lifo.RegisterStream(11, precedence);

  EXPECT_TRUE(lifo.StreamRegistered(3));
  EXPECT_TRUE(lifo.StreamRegistered(5));
  EXPECT_TRUE(lifo.StreamRegistered(7));
  EXPECT_TRUE(lifo.StreamRegistered(9));
  EXPECT_TRUE(lifo.StreamRegistered(11));
  EXPECT_SPDY_BUG(lifo.RegisterStream(11, precedence),
                  "Stream 11 already registered");
  EXPECT_EQ((uint32_t)5, peer.NumRegisteredListStreams());

  lifo.UnregisterStream(3);
  EXPECT_FALSE(lifo.StreamRegistered(3));
  EXPECT_SPDY_BUG(lifo.UnregisterStream(3), "Stream 3 is not registered");
  EXPECT_SPDY_BUG(lifo.UnregisterStream(13), "Stream 13 is not registered");
  lifo.UnregisterStream(11);
  EXPECT_FALSE(lifo.StreamRegistered(11));
  lifo.UnregisterStream(7);
  EXPECT_FALSE(lifo.StreamRegistered(7));
  EXPECT_TRUE(lifo.StreamRegistered(5));
  EXPECT_TRUE(lifo.StreamRegistered(9));
}

// Test mark latest event time.
TEST(LifoWriteSchedulerTest, GetLatestEventTest) {
  LifoWriteScheduler<SpdyStreamId> lifo;
  LifoWriteSchedulerPeer<SpdyStreamId> peer(&lifo);
  SpdyStreamPrecedence precedence(1);
  lifo.RegisterStream(1, precedence);
  lifo.RegisterStream(3, precedence);
  lifo.RegisterStream(5, precedence);
  lifo.RegisterStream(7, precedence);
  lifo.RegisterStream(9, precedence);
  lifo.RecordStreamEventTime(1, 1);
  lifo.RecordStreamEventTime(3, 8);
  lifo.RecordStreamEventTime(5, 4);
  lifo.RecordStreamEventTime(7, 2);
  lifo.RecordStreamEventTime(9, 3);
  EXPECT_SPDY_BUG(lifo.RecordStreamEventTime(11, 1),
                  "Stream 11 is not registered");
  EXPECT_EQ(0, lifo.GetLatestEventWithPrecedence(9));
  EXPECT_EQ(3, lifo.GetLatestEventWithPrecedence(7));
  EXPECT_EQ(3, lifo.GetLatestEventWithPrecedence(5));
  EXPECT_EQ(4, lifo.GetLatestEventWithPrecedence(3));
  EXPECT_EQ(8, lifo.GetLatestEventWithPrecedence(1));
  EXPECT_SPDY_BUG(lifo.GetLatestEventWithPrecedence(11),
                  "Stream 11 is not registered");
}

}  // namespace test

}  // namespace net
