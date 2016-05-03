// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_headers_stream.h"

#include "net/quic/quic_utils.h"
#include "net/quic/spdy_utils.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_spdy_session_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/reliable_quic_stream_peer.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_protocol.h"
#include "net/spdy/spdy_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::ostream;
using std::string;
using std::vector;
using testing::ElementsAre;
using testing::InSequence;
using testing::Invoke;
using testing::StrictMock;
using testing::WithArgs;
using testing::_;

namespace net {
namespace test {
namespace {

// TODO(ckrasic):  this workaround is due to absence of std::initializer_list
const bool kFins[] = {false, true};

class MockVisitor : public SpdyFramerVisitorInterface {
 public:
  MOCK_METHOD1(OnError, void(SpdyFramer* framer));
  MOCK_METHOD3(OnDataFrameHeader,
               void(SpdyStreamId stream_id, size_t length, bool fin));
  MOCK_METHOD4(
      OnStreamFrameData,
      void(SpdyStreamId stream_id, const char* data, size_t len, bool fin));
  MOCK_METHOD1(OnStreamEnd, void(SpdyStreamId stream_id));
  MOCK_METHOD2(OnStreamPadding, void(SpdyStreamId stream_id, size_t len));
  MOCK_METHOD1(OnHeaderFrameStart,
               SpdyHeadersHandlerInterface*(SpdyStreamId stream_id));
  MOCK_METHOD2(OnHeaderFrameEnd, void(SpdyStreamId stream_id, bool end));
  MOCK_METHOD3(OnControlFrameHeaderData,
               bool(SpdyStreamId stream_id,
                    const char* header_data,
                    size_t len));
  MOCK_METHOD5(OnSynStream,
               void(SpdyStreamId stream_id,
                    SpdyStreamId associated_stream_id,
                    SpdyPriority priority,
                    bool fin,
                    bool unidirectional));
  MOCK_METHOD2(OnSynReply, void(SpdyStreamId stream_id, bool fin));
  MOCK_METHOD2(OnRstStream,
               void(SpdyStreamId stream_id, SpdyRstStreamStatus status));
  MOCK_METHOD1(OnSettings, void(bool clear_persisted));
  MOCK_METHOD3(OnSetting,
               void(SpdySettingsIds id, uint8_t flags, uint32_t value));
  MOCK_METHOD0(OnSettingsAck, void());
  MOCK_METHOD0(OnSettingsEnd, void());
  MOCK_METHOD2(OnPing, void(SpdyPingId unique_id, bool is_ack));
  MOCK_METHOD2(OnGoAway,
               void(SpdyStreamId last_accepted_stream_id,
                    SpdyGoAwayStatus status));
  MOCK_METHOD7(OnHeaders,
               void(SpdyStreamId stream_id,
                    bool has_priority,
                    SpdyPriority priority,
                    SpdyStreamId parent_stream_id,
                    bool exclusive,
                    bool fin,
                    bool end));
  MOCK_METHOD2(OnWindowUpdate,
               void(SpdyStreamId stream_id, int delta_window_size));
  MOCK_METHOD1(OnBlocked, void(SpdyStreamId stream_id));
  MOCK_METHOD3(OnPushPromise,
               void(SpdyStreamId stream_id,
                    SpdyStreamId promised_stream_id,
                    bool end));
  MOCK_METHOD2(OnContinuation, void(SpdyStreamId stream_id, bool end));
  MOCK_METHOD3(OnAltSvc,
               void(SpdyStreamId stream_id,
                    StringPiece origin,
                    const SpdyAltSvcWireFormat::AlternativeServiceVector&
                        altsvc_vector));
  MOCK_METHOD2(OnUnknownFrame, bool(SpdyStreamId stream_id, int frame_type));
};

// Run all tests with each version, perspective (client or server),
// and relevant flag options (false or true)
struct TestParams {
  TestParams(QuicVersion version, Perspective perspective)
      : version(version), perspective(perspective) {}

  friend ostream& operator<<(ostream& os, const TestParams& p) {
    os << "{ version: " << QuicVersionToString(p.version);
    os << ", perspective: " << p.perspective << " }";
    return os;
  }

  QuicVersion version;
  Perspective perspective;
};

// Constructs various test permutations.
vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  QuicVersionVector all_supported_versions = QuicSupportedVersions();
  for (const QuicVersion version : all_supported_versions) {
    params.push_back(TestParams(version, Perspective::IS_CLIENT));
    params.push_back(TestParams(version, Perspective::IS_SERVER));
  }
  FLAGS_quic_supports_push_promise = true;
  return params;
}

class QuicHeadersStreamTest : public ::testing::TestWithParam<TestParams> {
 public:
  QuicHeadersStreamTest()
      : connection_(new StrictMock<MockConnection>(&helper_,
                                                   &alarm_factory_,
                                                   perspective(),
                                                   GetVersion())),
        session_(connection_),
        headers_stream_(QuicSpdySessionPeer::GetHeadersStream(&session_)),
        body_("hello world"),
        stream_frame_(kHeadersStreamId, /*fin=*/false, /*offset=*/0, ""),
        next_promised_stream_id_(2) {
    FLAGS_quic_always_log_bugs_for_tests = true;
    headers_[":version"] = "HTTP/1.1";
    headers_[":status"] = "200 Ok";
    headers_["content-length"] = "11";
    framer_ = std::unique_ptr<SpdyFramer>(new SpdyFramer(HTTP2));
    framer_->set_visitor(&visitor_);
    EXPECT_EQ(version(), session_.connection()->version());
    EXPECT_TRUE(headers_stream_ != nullptr);
    VLOG(1) << GetParam();
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  }

  QuicConsumedData SaveIov(const QuicIOVector& data) {
    const iovec* iov = data.iov;
    int count = data.iov_count;
    for (int i = 0; i < count; ++i) {
      saved_data_.append(static_cast<char*>(iov[i].iov_base), iov[i].iov_len);
    }
    return QuicConsumedData(saved_data_.length(), false);
  }

  bool SaveHeaderData(const char* data, int len) {
    saved_header_data_.append(data, len);
    return true;
  }

  void SaveHeaderDataStringPiece(StringPiece data) {
    saved_header_data_.append(data.data(), data.length());
  }

  void WriteHeadersAndExpectSynStream(QuicStreamId stream_id,
                                      bool fin,
                                      SpdyPriority priority) {
    WriteHeadersAndCheckData(stream_id, fin, priority, SYN_STREAM);
  }

  void WriteHeadersAndExpectSynReply(QuicStreamId stream_id, bool fin) {
    WriteHeadersAndCheckData(stream_id, fin, 0, SYN_REPLY);
  }

  void WriteHeadersAndCheckData(QuicStreamId stream_id,
                                bool fin,
                                SpdyPriority priority,
                                SpdyFrameType type) {
    // Write the headers and capture the outgoing data
    EXPECT_CALL(session_, WritevData(kHeadersStreamId, _, _, false, nullptr))
        .WillOnce(WithArgs<1>(Invoke(this, &QuicHeadersStreamTest::SaveIov)));
    headers_stream_->WriteHeaders(stream_id, headers_, fin, priority, nullptr);

    // Parse the outgoing data and check that it matches was was written.
    if (type == SYN_STREAM) {
      EXPECT_CALL(visitor_,
                  OnHeaders(stream_id, kHasPriority, priority,
                            /*parent_stream_id=*/0,
                            /*exclusive=*/false, fin, kFrameComplete));
    } else {
      EXPECT_CALL(visitor_,
                  OnHeaders(stream_id, !kHasPriority,
                            /*priority=*/0,
                            /*parent_stream_id=*/0,
                            /*exclusive=*/false, fin, kFrameComplete));
    }
    EXPECT_CALL(visitor_, OnControlFrameHeaderData(stream_id, _, _))
        .WillRepeatedly(WithArgs<1, 2>(
            Invoke(this, &QuicHeadersStreamTest::SaveHeaderData)));
    if (fin) {
      EXPECT_CALL(visitor_, OnStreamEnd(stream_id));
    }
    framer_->ProcessInput(saved_data_.data(), saved_data_.length());
    EXPECT_FALSE(framer_->HasError())
        << SpdyFramer::ErrorCodeToString(framer_->error_code());

    CheckHeaders();
    saved_data_.clear();
  }

  void CheckHeaders() {
    SpdyHeaderBlock headers;
    EXPECT_TRUE(framer_->ParseHeaderBlockInBuffer(
        saved_header_data_.data(), saved_header_data_.length(), &headers));
    EXPECT_EQ(headers_, headers);
    saved_header_data_.clear();
  }

  Perspective perspective() { return GetParam().perspective; }

  QuicVersion version() { return GetParam().version; }

  QuicVersionVector GetVersion() {
    QuicVersionVector versions;
    versions.push_back(version());
    return versions;
  }

  void TearDownLocalConnectionState() {
    QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  }

  QuicStreamId NextPromisedStreamId() { return next_promised_stream_id_ += 2; }

  static const bool kFrameComplete = true;
  static const bool kHasPriority = true;

  MockConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockConnection>* connection_;
  StrictMock<MockQuicSpdySession> session_;
  QuicHeadersStream* headers_stream_;
  SpdyHeaderBlock headers_;
  string body_;
  string saved_data_;
  string saved_header_data_;
  std::unique_ptr<SpdyFramer> framer_;
  StrictMock<MockVisitor> visitor_;
  QuicStreamFrame stream_frame_;
  QuicStreamId next_promised_stream_id_;
};

INSTANTIATE_TEST_CASE_P(Tests,
                        QuicHeadersStreamTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicHeadersStreamTest, StreamId) {
  EXPECT_EQ(3u, headers_stream_->id());
}

TEST_P(QuicHeadersStreamTest, WriteHeaders) {
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : kFins) {
      if (perspective() == Perspective::IS_SERVER) {
        WriteHeadersAndExpectSynReply(stream_id, fin);
      } else {
        for (SpdyPriority priority = 0; priority < 7; ++priority) {
          // TODO(rch): implement priorities correctly.
          WriteHeadersAndExpectSynStream(stream_id, fin, 0);
        }
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, WritePushPromises) {
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    QuicStreamId promised_stream_id = NextPromisedStreamId();
    if (perspective() == Perspective::IS_SERVER) {
      // Write the headers and capture the outgoing data
      EXPECT_CALL(session_, WritevData(kHeadersStreamId, _, _, false, nullptr))
          .WillOnce(WithArgs<1>(Invoke(this, &QuicHeadersStreamTest::SaveIov)));
      headers_stream_->WritePushPromise(stream_id, promised_stream_id, headers_,
                                        nullptr);

      // Parse the outgoing data and check that it matches was was written.
      EXPECT_CALL(visitor_,
                  OnPushPromise(stream_id, promised_stream_id, kFrameComplete));
      EXPECT_CALL(visitor_, OnControlFrameHeaderData(stream_id, _, _))
          .WillRepeatedly(WithArgs<1, 2>(
              Invoke(this, &QuicHeadersStreamTest::SaveHeaderData)));
      framer_->ProcessInput(saved_data_.data(), saved_data_.length());
      EXPECT_FALSE(framer_->HasError())
          << SpdyFramer::ErrorCodeToString(framer_->error_code());
      CheckHeaders();
      saved_data_.clear();
    } else {
      EXPECT_DFATAL(headers_stream_->WritePushPromise(
                        stream_id, promised_stream_id, headers_, nullptr),
                    "Client shouldn't send PUSH_PROMISE");
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessRawData) {
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id);
          headers_frame.set_header_block(headers_);
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
        } else {
          SpdyHeadersIR headers_frame(stream_id);
          headers_frame.set_header_block(headers_);
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_, OnStreamHeaders(stream_id, _))
            .WillRepeatedly(WithArgs<1>(Invoke(
                this, &QuicHeadersStreamTest::SaveHeaderDataStringPiece)));
        EXPECT_CALL(session_,
                    OnStreamHeadersComplete(stream_id, fin, frame.size()));
        stream_frame_.frame_buffer = frame.data();
        stream_frame_.frame_length = frame.size();
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessPushPromise) {
  if (perspective() == Perspective::IS_SERVER)
    return;
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    QuicStreamId promised_stream_id = NextPromisedStreamId();
    SpdyPushPromiseIR push_promise(stream_id, promised_stream_id);
    push_promise.set_header_block(headers_);
    SpdySerializedFrame frame(framer_->SerializeFrame(push_promise));
    if (perspective() == Perspective::IS_SERVER) {
      EXPECT_CALL(*connection_,
                  CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                  "PUSH_PROMISE not supported.", _))
          .WillRepeatedly(InvokeWithoutArgs(
              this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
    } else {
      EXPECT_CALL(session_, OnPromiseHeaders(stream_id, _))
          .WillRepeatedly(WithArgs<1>(
              Invoke(this, &QuicHeadersStreamTest::SaveHeaderDataStringPiece)));
      EXPECT_CALL(session_, OnPromiseHeadersComplete(
                                stream_id, promised_stream_id, frame.size()));
    }
    stream_frame_.frame_buffer = frame.data();
    stream_frame_.frame_length = frame.size();
    headers_stream_->OnStreamFrame(stream_frame_);
    if (perspective() == Perspective::IS_CLIENT) {
      stream_frame_.offset += frame.size();
      CheckHeaders();
    }
  }
}

TEST_P(QuicHeadersStreamTest, EmptyHeaderHOLBlockedTime) {
  EXPECT_CALL(session_, OnHeadersHeadOfLineBlocking(_)).Times(0);
  testing::InSequence seq;
  bool fin = true;
  for (int stream_num = 0; stream_num < 10; stream_num++) {
    QuicStreamId stream_id = QuicClientDataStreamId(stream_num);
    // Replace with "WriteHeadersAndSaveData"
    SpdySerializedFrame frame;
    if (perspective() == Perspective::IS_SERVER) {
      SpdyHeadersIR headers_frame(stream_id);
      headers_frame.set_header_block(headers_);
      headers_frame.set_fin(fin);
      headers_frame.set_has_priority(true);
      frame = framer_->SerializeFrame(headers_frame);
      EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
    } else {
      SpdyHeadersIR headers_frame(stream_id);
      headers_frame.set_header_block(headers_);
      headers_frame.set_fin(fin);
      frame = framer_->SerializeFrame(headers_frame);
    }
    EXPECT_CALL(session_, OnStreamHeaders(stream_id, _));
    EXPECT_CALL(session_,
                OnStreamHeadersComplete(stream_id, fin, frame.size()));
    stream_frame_.frame_buffer = frame.data();
    stream_frame_.frame_length = frame.size();
    headers_stream_->OnStreamFrame(stream_frame_);
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
    stream_frame_.offset += frame.size();
  }
}

TEST_P(QuicHeadersStreamTest, NonEmptyHeaderHOLBlockedTime) {
  QuicStreamId stream_id;
  bool fin = true;
  QuicStreamFrame stream_frames[10];
  SpdySerializedFrame frames[10];
  // First create all the frames in order
  {
    InSequence seq;
    for (int stream_num = 0; stream_num < 10; ++stream_num) {
      stream_id = QuicClientDataStreamId(stream_num);
      if (perspective() == Perspective::IS_SERVER) {
        SpdyHeadersIR headers_frame(stream_id);
        headers_frame.set_header_block(headers_);
        headers_frame.set_fin(fin);
        headers_frame.set_has_priority(true);
        frames[stream_num] = framer_->SerializeFrame(headers_frame);
        EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0)).Times(1);
      } else {
        SpdyHeadersIR headers_frame(stream_id);
        headers_frame.set_header_block(headers_);
        headers_frame.set_fin(fin);
        frames[stream_num] = framer_->SerializeFrame(headers_frame);
      }
      stream_frames[stream_num].stream_id = stream_frame_.stream_id;
      stream_frames[stream_num].offset = stream_frame_.offset;
      stream_frames[stream_num].frame_buffer = frames[stream_num].data();
      stream_frames[stream_num].frame_length = frames[stream_num].size();
      DVLOG(1) << "make frame for stream " << stream_num << " offset "
               << stream_frames[stream_num].offset;
      stream_frame_.offset += frames[stream_num].size();
      EXPECT_CALL(session_, OnStreamHeaders(stream_id, _)).Times(1);
      EXPECT_CALL(session_, OnStreamHeadersComplete(stream_id, fin, _))
          .Times(1);
    }
  }

  // Actually writing the frames in reverse order will cause HOL blocking.
  EXPECT_CALL(session_, OnHeadersHeadOfLineBlocking(_)).Times(9);

  for (int stream_num = 9; stream_num >= 0; --stream_num) {
    DVLOG(1) << "OnStreamFrame for stream " << stream_num << " offset "
             << stream_frames[stream_num].offset;
    headers_stream_->OnStreamFrame(stream_frames[stream_num]);
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  }
}

TEST_P(QuicHeadersStreamTest, ProcessLargeRawData) {
  // We want to create a frame that is more than the SPDY Framer's max control
  // frame size, which is 16K, but less than the HPACK decoders max decode
  // buffer size, which is 32K.
  headers_["key0"] = string(1 << 13, '.');
  headers_["key1"] = string(1 << 13, '.');
  headers_["key2"] = string(1 << 13, '.');
  for (QuicStreamId stream_id = kClientDataStreamId1;
       stream_id < kClientDataStreamId3; stream_id += 2) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id);
          headers_frame.set_header_block(headers_);
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(stream_id, 0));
        } else {
          SpdyHeadersIR headers_frame(stream_id);
          headers_frame.set_header_block(headers_);
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_, OnStreamHeaders(stream_id, _))
            .WillRepeatedly(WithArgs<1>(Invoke(
                this, &QuicHeadersStreamTest::SaveHeaderDataStringPiece)));
        EXPECT_CALL(session_,
                    OnStreamHeadersComplete(stream_id, fin, frame.size()));
        stream_frame_.frame_buffer = frame.data();
        stream_frame_.frame_length = frame.size();
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessBadData) {
  const char kBadData[] = "blah blah blah";
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA, _, _))
      .Times(::testing::AnyNumber());
  stream_frame_.frame_buffer = kBadData;
  stream_frame_.frame_length = strlen(kBadData);
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyDataFrame) {
  SpdyDataIR data(2, "");
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY DATA frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.frame_buffer = frame.data();
  stream_frame_.frame_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyRstStreamFrame) {
  SpdyRstStreamIR data(2, RST_STREAM_PROTOCOL_ERROR);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "SPDY RST_STREAM frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.frame_buffer = frame.data();
  stream_frame_.frame_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdySettingsFrame) {
  SpdySettingsIR data;
  data.AddSetting(SETTINGS_HEADER_TABLE_SIZE, true, true, 0);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY SETTINGS frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.frame_buffer = frame.data();
  stream_frame_.frame_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyPingFrame) {
  SpdyPingIR data(1);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY PING frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.frame_buffer = frame.data();
  stream_frame_.frame_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyGoAwayFrame) {
  SpdyGoAwayIR data(1, GOAWAY_PROTOCOL_ERROR, "go away");
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY GOAWAY frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.frame_buffer = frame.data();
  stream_frame_.frame_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyWindowUpdateFrame) {
  SpdyWindowUpdateIR data(1, 1);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "SPDY WINDOW_UPDATE frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.frame_buffer = frame.data();
  stream_frame_.frame_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, NoConnectionLevelFlowControl) {
  EXPECT_FALSE(ReliableQuicStreamPeer::StreamContributesToConnectionFlowControl(
      headers_stream_));
}

}  // namespace
}  // namespace test
}  // namespace net
