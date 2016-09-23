// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_MOCK_SPDY_FRAMER_VISITOR_H_
#define NET_SPDY_MOCK_SPDY_FRAMER_VISITOR_H_

#include <stddef.h>
#include <stdint.h>

#include "base/strings/string_piece.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace net {

namespace test {

class MockSpdyFramerVisitor : public SpdyFramerVisitorInterface {
 public:
  MockSpdyFramerVisitor();
  virtual ~MockSpdyFramerVisitor();
  MOCK_METHOD1(OnError, void(SpdyFramer* framer));
  MOCK_METHOD3(OnDataFrameHeader, void(SpdyStreamId stream_id,
                                       size_t length,
                                       bool fin));
  MOCK_METHOD3(OnStreamFrameData,
               void(SpdyStreamId stream_id, const char* data, size_t len));
  MOCK_METHOD1(OnStreamEnd, void(SpdyStreamId stream_id));
  MOCK_METHOD2(OnStreamPadding, void(SpdyStreamId stream_id, size_t len));
  MOCK_METHOD1(OnHeaderFrameStart,
               SpdyHeadersHandlerInterface*(SpdyStreamId stream_id));
  MOCK_METHOD2(OnHeaderFrameEnd, void(SpdyStreamId stream_id, bool end));
  MOCK_METHOD3(OnControlFrameHeaderData, bool(SpdyStreamId stream_id,
                                              const char* header_data,
                                              size_t len));
  MOCK_METHOD5(OnSynStream, void(SpdyStreamId stream_id,
                                 SpdyStreamId associated_stream_id,
                                 SpdyPriority priority,
                                 bool fin,
                                 bool unidirectional));
  MOCK_METHOD2(OnSynReply, void(SpdyStreamId stream_id, bool fin));
  MOCK_METHOD2(OnRstStream, void(SpdyStreamId stream_id,
                                 SpdyRstStreamStatus status));
  MOCK_METHOD1(OnSettings, void(bool clear_persisted));
  MOCK_METHOD3(OnSetting,
               void(SpdySettingsIds id, uint8_t flags, uint32_t value));
  MOCK_METHOD2(OnPing, void(SpdyPingId unique_id, bool is_ack));
  MOCK_METHOD0(OnSettingsEnd, void());
  MOCK_METHOD2(OnGoAway, void(SpdyStreamId last_accepted_stream_id,
                              SpdyGoAwayStatus status));

  MOCK_METHOD7(OnHeaders,
               void(SpdyStreamId stream_id,
                    bool has_priority,
                    int weight,
                    SpdyStreamId parent_stream_id,
                    bool exclusive,
                    bool fin,
                    bool end));
  MOCK_METHOD2(OnWindowUpdate,
               void(SpdyStreamId stream_id, int delta_window_size));
  MOCK_METHOD1(OnBlocked, void(SpdyStreamId stream_id));
  MOCK_METHOD3(OnPushPromise, void(SpdyStreamId stream_id,
                                   SpdyStreamId promised_stream_id,
                                   bool end));
  MOCK_METHOD2(OnContinuation, void(SpdyStreamId stream_id, bool end));
  MOCK_METHOD3(OnAltSvc,
               void(SpdyStreamId stream_id,
                    base::StringPiece origin,
                    const SpdyAltSvcWireFormat::AlternativeServiceVector&
                        altsvc_vector));
  MOCK_METHOD4(OnPriority,
               void(SpdyStreamId stream_id,
                    SpdyStreamId parent_stream_id,
                    int weight,
                    bool exclusive));
  MOCK_METHOD2(OnUnknownFrame, bool(SpdyStreamId stream_id, int frame_type));

  void DelegateNewHeaderHandling() {
    ON_CALL(*this, OnHeaderFrameStart(testing::_))
        .WillByDefault(testing::Invoke(
            this, &MockSpdyFramerVisitor::ReturnTestHeadersHandler));
    ON_CALL(*this, OnHeaderFrameEnd(testing::_, testing::_))
        .WillByDefault(testing::Invoke(
            this, &MockSpdyFramerVisitor::ResetTestHeadersHandler));
  }

  SpdyHeadersHandlerInterface* ReturnTestHeadersHandler(
      SpdyStreamId /* stream_id */) {
    if (headers_handler_ == nullptr) {
      headers_handler_.reset(new TestHeadersHandler);
    }
    return headers_handler_.get();
  }

  void ResetTestHeadersHandler(SpdyStreamId /* stream_id */, bool end) {
    if (end) {
      headers_handler_.reset();
    }
  }

  std::unique_ptr<SpdyHeadersHandlerInterface> headers_handler_;
};

}  // namespace test

}  // namespace net

#endif  // NET_SPDY_MOCK_SPDY_FRAMER_VISITOR_H_
