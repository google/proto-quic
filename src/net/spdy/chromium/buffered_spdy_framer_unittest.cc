// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/chromium/buffered_spdy_framer.h"

#include <algorithm>
#include <utility>

#include "base/logging.h"
#include "net/log/net_log_with_source.h"
#include "net/spdy/chromium/spdy_test_util_common.h"
#include "testing/platform_test.h"

namespace net {

namespace {

class TestBufferedSpdyVisitor : public BufferedSpdyFramerVisitorInterface {
 public:
  TestBufferedSpdyVisitor()
      : buffered_spdy_framer_(NetLogWithSource()),
        error_count_(0),
        setting_count_(0),
        headers_frame_count_(0),
        push_promise_frame_count_(0),
        goaway_count_(0),
        altsvc_count_(0),
        header_stream_id_(static_cast<SpdyStreamId>(-1)),
        promised_stream_id_(static_cast<SpdyStreamId>(-1)) {}

  void OnError(SpdyFramer::SpdyFramerError spdy_framer_error) override {
    VLOG(1) << "SpdyFramer Error: " << spdy_framer_error;
    error_count_++;
  }

  void OnStreamError(SpdyStreamId stream_id,
                     const SpdyString& description) override {
    VLOG(1) << "SpdyFramer Error on stream: " << stream_id << " "
            << description;
    error_count_++;
  }

  void OnHeaders(SpdyStreamId stream_id,
                 bool has_priority,
                 int weight,
                 SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 SpdyHeaderBlock headers) override {
    header_stream_id_ = stream_id;
    EXPECT_NE(header_stream_id_, SpdyFramer::kInvalidStream);
    headers_frame_count_++;
    headers_ = std::move(headers);
  }

  void OnDataFrameHeader(SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override {
    ADD_FAILURE() << "Unexpected OnDataFrameHeader call.";
  }

  void OnStreamFrameData(SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override {
    LOG(FATAL) << "Unexpected OnStreamFrameData call.";
  }

  void OnStreamEnd(SpdyStreamId stream_id) override {
    LOG(FATAL) << "Unexpected OnStreamEnd call.";
  }

  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override {
    LOG(FATAL) << "Unexpected OnStreamPadding call.";
  }

  void OnSettings() override {}

  void OnSetting(SpdySettingsIds id, uint32_t value) override {
    setting_count_++;
  }

  void OnPing(SpdyPingId unique_id, bool is_ack) override {}

  void OnRstStream(SpdyStreamId stream_id, SpdyErrorCode error_code) override {}

  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyErrorCode error_code,
                SpdyStringPiece debug_data) override {
    goaway_count_++;
    goaway_last_accepted_stream_id_ = last_accepted_stream_id;
    goaway_error_code_ = error_code;
    goaway_debug_data_.assign(debug_data.data(), debug_data.size());
  }

  void OnDataFrameHeader(const SpdySerializedFrame* frame) {
    LOG(FATAL) << "Unexpected OnDataFrameHeader call.";
  }

  void OnRstStream(const SpdySerializedFrame& frame) {}
  void OnGoAway(const SpdySerializedFrame& frame) {}
  void OnPing(const SpdySerializedFrame& frame) {}
  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override {}

  void OnPushPromise(SpdyStreamId stream_id,
                     SpdyStreamId promised_stream_id,
                     SpdyHeaderBlock headers) override {
    header_stream_id_ = stream_id;
    EXPECT_NE(header_stream_id_, SpdyFramer::kInvalidStream);
    push_promise_frame_count_++;
    promised_stream_id_ = promised_stream_id;
    EXPECT_NE(promised_stream_id_, SpdyFramer::kInvalidStream);
    headers_ = std::move(headers);
  }

  void OnAltSvc(SpdyStreamId stream_id,
                SpdyStringPiece origin,
                const SpdyAltSvcWireFormat::AlternativeServiceVector&
                    altsvc_vector) override {
    altsvc_count_++;
    altsvc_stream_id_ = stream_id;
    origin.CopyToString(&altsvc_origin_);
    altsvc_vector_ = altsvc_vector;
  }

  bool OnUnknownFrame(SpdyStreamId stream_id, uint8_t frame_type) override {
    return true;
  }

  // Convenience function which runs a framer simulation with particular input.
  void SimulateInFramer(const SpdySerializedFrame& frame) {
    const char* input_ptr = frame.data();
    size_t input_remaining = frame.size();
    buffered_spdy_framer_.set_visitor(this);
    while (input_remaining > 0 &&
           buffered_spdy_framer_.spdy_framer_error() ==
               SpdyFramer::SPDY_NO_ERROR) {
      // To make the tests more interesting, we feed random (amd small) chunks
      // into the framer.  This simulates getting strange-sized reads from
      // the socket.
      const size_t kMaxReadSize = 32;
      size_t bytes_read =
          (rand() % std::min(input_remaining, kMaxReadSize)) + 1;
      size_t bytes_processed =
          buffered_spdy_framer_.ProcessInput(input_ptr, bytes_read);
      input_remaining -= bytes_processed;
      input_ptr += bytes_processed;
    }
  }

  BufferedSpdyFramer buffered_spdy_framer_;

  // Counters from the visitor callbacks.
  int error_count_;
  int setting_count_;
  int headers_frame_count_;
  int push_promise_frame_count_;
  int goaway_count_;
  int altsvc_count_;

  // Header block streaming state:
  SpdyStreamId header_stream_id_;
  SpdyStreamId promised_stream_id_;

  // Headers from OnHeaders and OnPushPromise for verification.
  SpdyHeaderBlock headers_;

  // OnGoAway parameters.
  SpdyStreamId goaway_last_accepted_stream_id_;
  SpdyErrorCode goaway_error_code_;
  SpdyString goaway_debug_data_;

  // OnAltSvc parameters.
  SpdyStreamId altsvc_stream_id_;
  SpdyString altsvc_origin_;
  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector_;
};

}  // namespace

class BufferedSpdyFramerTest : public PlatformTest {};

TEST_F(BufferedSpdyFramerTest, OnSetting) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);
  SpdySettingsIR settings_ir;
  settings_ir.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, 2);
  settings_ir.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, 3);
  SpdySerializedFrame control_frame(framer.SerializeSettings(settings_ir));
  TestBufferedSpdyVisitor visitor;

  visitor.SimulateInFramer(control_frame);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(2, visitor.setting_count_);
}

TEST_F(BufferedSpdyFramerTest, HeaderListTooLarge) {
  SpdyHeaderBlock headers;
  SpdyString long_header_value(256 * 1024, 'x');
  headers["foo"] = long_header_value;
  SpdyHeadersIR headers_ir(/*stream_id=*/1, std::move(headers));

  NetLogWithSource net_log;
  BufferedSpdyFramer framer(net_log);
  SpdySerializedFrame control_frame = framer.SerializeFrame(headers_ir);

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(control_frame);

  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(0, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.push_promise_frame_count_);
  EXPECT_EQ(SpdyHeaderBlock(), visitor.headers_);
}

TEST_F(BufferedSpdyFramerTest, ValidHeadersAfterInvalidHeaders) {
  SpdyHeaderBlock headers;
  headers["invalid"] = "\r\n\r\n";

  SpdyHeaderBlock headers2;
  headers["alpha"] = "beta";

  SpdyTestUtil spdy_test_util;
  SpdySerializedFrame headers_frame(
      spdy_test_util.ConstructSpdyReply(1, std::move(headers)));
  SpdySerializedFrame headers_frame2(
      spdy_test_util.ConstructSpdyReply(2, std::move(headers2)));

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(headers_frame);
  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(0, visitor.headers_frame_count_);

  visitor.SimulateInFramer(headers_frame2);
  EXPECT_EQ(1, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
}

TEST_F(BufferedSpdyFramerTest, ReadHeadersHeaderBlock) {
  SpdyHeaderBlock headers;
  headers["alpha"] = "beta";
  headers["gamma"] = "delta";
  SpdyHeadersIR headers_ir(/*stream_id=*/1, headers.Clone());

  NetLogWithSource net_log;
  BufferedSpdyFramer framer(net_log);
  SpdySerializedFrame control_frame = framer.SerializeFrame(headers_ir);

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(control_frame);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.headers_frame_count_);
  EXPECT_EQ(0, visitor.push_promise_frame_count_);
  EXPECT_EQ(headers, visitor.headers_);
}

TEST_F(BufferedSpdyFramerTest, ReadPushPromiseHeaderBlock) {
  SpdyHeaderBlock headers;
  headers["alpha"] = "beta";
  headers["gamma"] = "delta";
  NetLogWithSource net_log;
  BufferedSpdyFramer framer(net_log);
  SpdyPushPromiseIR push_promise_ir(/*stream_id=*/1, /*promised_stream_id=*/2,
                                    headers.Clone());
  SpdySerializedFrame control_frame = framer.SerializeFrame(push_promise_ir);

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(control_frame);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(0, visitor.headers_frame_count_);
  EXPECT_EQ(1, visitor.push_promise_frame_count_);
  EXPECT_EQ(headers, visitor.headers_);
  EXPECT_EQ(1u, visitor.header_stream_id_);
  EXPECT_EQ(2u, visitor.promised_stream_id_);
}

TEST_F(BufferedSpdyFramerTest, GoAwayDebugData) {
  SpdyGoAwayIR go_ir(/*last_accepted_stream_id=*/2, ERROR_CODE_FRAME_SIZE_ERROR,
                     "foo");
  NetLogWithSource net_log;
  BufferedSpdyFramer framer(net_log);
  SpdySerializedFrame goaway_frame = framer.SerializeFrame(go_ir);

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(goaway_frame);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.goaway_count_);
  EXPECT_EQ(2u, visitor.goaway_last_accepted_stream_id_);
  EXPECT_EQ(ERROR_CODE_FRAME_SIZE_ERROR, visitor.goaway_error_code_);
  EXPECT_EQ("foo", visitor.goaway_debug_data_);
}

// ALTSVC frame on stream 0 must have an origin.
TEST_F(BufferedSpdyFramerTest, OnAltSvcOnStreamZero) {
  const SpdyStreamId altsvc_stream_id(0);
  SpdyAltSvcIR altsvc_ir(altsvc_stream_id);
  SpdyAltSvcWireFormat::AlternativeService alternative_service(
      "quic", "alternative.example.org", 443, 86400,
      SpdyAltSvcWireFormat::VersionVector());
  altsvc_ir.add_altsvc(alternative_service);
  const char altsvc_origin[] = "https://www.example.org";
  altsvc_ir.set_origin(altsvc_origin);
  NetLogWithSource net_log;
  BufferedSpdyFramer framer(net_log);
  SpdySerializedFrame altsvc_frame(framer.SerializeFrame(altsvc_ir));

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(altsvc_frame);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.altsvc_count_);
  EXPECT_EQ(altsvc_stream_id, visitor.altsvc_stream_id_);
  EXPECT_EQ(altsvc_origin, visitor.altsvc_origin_);
  ASSERT_EQ(1u, visitor.altsvc_vector_.size());
  EXPECT_EQ(alternative_service, visitor.altsvc_vector_[0]);
}

// ALTSVC frame on a non-zero stream must not have an origin.
TEST_F(BufferedSpdyFramerTest, OnAltSvcOnNonzeroStream) {
  const SpdyStreamId altsvc_stream_id(1);
  SpdyAltSvcIR altsvc_ir(altsvc_stream_id);
  SpdyAltSvcWireFormat::AlternativeService alternative_service(
      "quic", "alternative.example.org", 443, 86400,
      SpdyAltSvcWireFormat::VersionVector());
  altsvc_ir.add_altsvc(alternative_service);
  NetLogWithSource net_log;
  BufferedSpdyFramer framer(net_log);
  SpdySerializedFrame altsvc_frame(framer.SerializeFrame(altsvc_ir));

  TestBufferedSpdyVisitor visitor;
  visitor.SimulateInFramer(altsvc_frame);
  EXPECT_EQ(0, visitor.error_count_);
  EXPECT_EQ(1, visitor.altsvc_count_);
  EXPECT_EQ(altsvc_stream_id, visitor.altsvc_stream_id_);
  EXPECT_TRUE(visitor.altsvc_origin_.empty());
  ASSERT_EQ(1u, visitor.altsvc_vector_.size());
  EXPECT_EQ(alternative_service, visitor.altsvc_vector_[0]);
}

}  // namespace net
