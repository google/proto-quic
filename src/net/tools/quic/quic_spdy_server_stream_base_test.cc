// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_spdy_server_stream_base.h"

#include "base/memory/ptr_util.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;

namespace net {
namespace test {
namespace {

class TestQuicSpdyServerStream : public QuicSpdyServerStreamBase {
 public:
  TestQuicSpdyServerStream(QuicStreamId id, QuicSpdySession* session)
      : QuicSpdyServerStreamBase(id, session) {}

  void OnDataAvailable() override {}
};

class QuicSpdyServerStreamBaseTest : public ::testing::Test {
 protected:
  QuicSpdyServerStreamBaseTest()
      : session_(new MockQuicConnection(&helper_,
                                        &alarm_factory_,
                                        Perspective::IS_SERVER)) {
    stream_ = new TestQuicSpdyServerStream(kClientDataStreamId1, &session_);
    session_.ActivateStream(base::WrapUnique(stream_));
  }

  QuicSpdyServerStreamBase* stream_ = nullptr;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicSpdySession session_;
};

TEST_F(QuicSpdyServerStreamBaseTest,
       SendQuicRstStreamNoErrorWithEarlyResponse) {
  stream_->StopReading();
  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(1);
  stream_->set_fin_sent(true);
  stream_->CloseWriteSide();
}

TEST_F(QuicSpdyServerStreamBaseTest,
       DoNotSendQuicRstStreamNoErrorWithRstReceived) {
  EXPECT_FALSE(stream_->reading_stopped());

  EXPECT_CALL(session_, SendRstStream(_, QUIC_STREAM_NO_ERROR, _)).Times(0);
  EXPECT_CALL(session_, SendRstStream(_, QUIC_RST_ACKNOWLEDGEMENT, _)).Times(1);
  QuicRstStreamFrame rst_frame(stream_->id(), QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);

  EXPECT_TRUE(stream_->reading_stopped());
  EXPECT_TRUE(stream_->write_side_closed());
}

}  // namespace
}  // namespace test
}  // namespace net
