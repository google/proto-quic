// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_packet_generator.h"

#include <cstdint>
#include <memory>
#include <string>

#include "base/macros.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_simple_buffer_allocator.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/test_tools/quic_packet_creator_peer.h"
#include "net/quic/test_tools/quic_packet_generator_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simple_quic_framer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;
using testing::InSequence;
using testing::Return;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {
namespace {

class MockDelegate : public QuicPacketGenerator::DelegateInterface {
 public:
  MockDelegate() {}
  ~MockDelegate() override {}

  MOCK_METHOD2(ShouldGeneratePacket,
               bool(HasRetransmittableData retransmittable,
                    IsHandshake handshake));
  MOCK_METHOD0(GetUpdatedAckFrame, const QuicFrame());
  MOCK_METHOD1(PopulateStopWaitingFrame, void(QuicStopWaitingFrame*));
  MOCK_METHOD1(OnSerializedPacket, void(SerializedPacket* packet));
  MOCK_METHOD3(OnUnrecoverableError,
               void(QuicErrorCode, const string&, ConnectionCloseSource));

  void SetCanWriteAnything() {
    EXPECT_CALL(*this, ShouldGeneratePacket(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*this, ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, _))
        .WillRepeatedly(Return(true));
  }

  void SetCanNotWrite() {
    EXPECT_CALL(*this, ShouldGeneratePacket(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*this, ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, _))
        .WillRepeatedly(Return(false));
  }

  // Use this when only ack frames should be allowed to be written.
  void SetCanWriteOnlyNonRetransmittable() {
    EXPECT_CALL(*this, ShouldGeneratePacket(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*this, ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, _))
        .WillRepeatedly(Return(true));
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockDelegate);
};

// Simple struct for describing the contents of a packet.
// Useful in conjunction with a SimpleQuicFrame for validating that a packet
// contains the expected frames.
struct PacketContents {
  PacketContents()
      : num_ack_frames(0),
        num_connection_close_frames(0),
        num_goaway_frames(0),
        num_rst_stream_frames(0),
        num_stop_waiting_frames(0),
        num_stream_frames(0),
        num_ping_frames(0),
        num_mtu_discovery_frames(0) {}

  size_t num_ack_frames;
  size_t num_connection_close_frames;
  size_t num_goaway_frames;
  size_t num_rst_stream_frames;
  size_t num_stop_waiting_frames;
  size_t num_stream_frames;
  size_t num_ping_frames;
  size_t num_mtu_discovery_frames;
};

}  // namespace

class QuicPacketGeneratorTest : public ::testing::Test {
 public:
  QuicPacketGeneratorTest()
      : framer_(AllSupportedVersions(),
                QuicTime::Zero(),
                Perspective::IS_CLIENT),
        generator_(42, &framer_, &buffer_allocator_, &delegate_),
        creator_(QuicPacketGeneratorPeer::GetPacketCreator(&generator_)) {
    creator_->SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           new NullEncrypter(Perspective::IS_CLIENT));
    creator_->set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  }

  ~QuicPacketGeneratorTest() override {
    for (SerializedPacket& packet : packets_) {
      delete[] packet.encrypted_buffer;
      ClearSerializedPacket(&packet);
    }
  }

  void SavePacket(SerializedPacket* packet) {
    packet->encrypted_buffer = CopyBuffer(*packet);
    packets_.push_back(*packet);
    packet->encrypted_buffer = nullptr;
    packet->retransmittable_frames.clear();
  }

 protected:
  QuicRstStreamFrame* CreateRstStreamFrame() {
    return new QuicRstStreamFrame(1, QUIC_STREAM_NO_ERROR, 0);
  }

  QuicGoAwayFrame* CreateGoAwayFrame() {
    return new QuicGoAwayFrame(QUIC_NO_ERROR, 1, string());
  }

  void CheckPacketContains(const PacketContents& contents,
                           size_t packet_index) {
    ASSERT_GT(packets_.size(), packet_index);
    const SerializedPacket& packet = packets_[packet_index];
    size_t num_retransmittable_frames =
        contents.num_connection_close_frames + contents.num_goaway_frames +
        contents.num_rst_stream_frames + contents.num_stream_frames +
        contents.num_ping_frames;
    size_t num_frames =
        contents.num_ack_frames + contents.num_stop_waiting_frames +
        contents.num_mtu_discovery_frames + num_retransmittable_frames;

    if (num_retransmittable_frames == 0) {
      ASSERT_TRUE(packet.retransmittable_frames.empty());
    } else {
      ASSERT_FALSE(packet.retransmittable_frames.empty());
      EXPECT_EQ(num_retransmittable_frames,
                packet.retransmittable_frames.size());
    }

    ASSERT_TRUE(packet.encrypted_buffer != nullptr);
    ASSERT_TRUE(simple_framer_.ProcessPacket(
        QuicEncryptedPacket(packet.encrypted_buffer, packet.encrypted_length)));
    EXPECT_EQ(num_frames, simple_framer_.num_frames());
    EXPECT_EQ(contents.num_ack_frames, simple_framer_.ack_frames().size());
    EXPECT_EQ(contents.num_connection_close_frames,
              simple_framer_.connection_close_frames().size());
    EXPECT_EQ(contents.num_goaway_frames,
              simple_framer_.goaway_frames().size());
    EXPECT_EQ(contents.num_rst_stream_frames,
              simple_framer_.rst_stream_frames().size());
    EXPECT_EQ(contents.num_stream_frames,
              simple_framer_.stream_frames().size());
    EXPECT_EQ(contents.num_stop_waiting_frames,
              simple_framer_.stop_waiting_frames().size());

    // From the receiver's perspective, MTU discovery frames are ping frames.
    EXPECT_EQ(contents.num_ping_frames + contents.num_mtu_discovery_frames,
              simple_framer_.ping_frames().size());
  }

  void CheckPacketHasSingleStreamFrame(size_t packet_index) {
    ASSERT_GT(packets_.size(), packet_index);
    const SerializedPacket& packet = packets_[packet_index];
    ASSERT_FALSE(packet.retransmittable_frames.empty());
    EXPECT_EQ(1u, packet.retransmittable_frames.size());
    ASSERT_TRUE(packet.encrypted_buffer != nullptr);
    ASSERT_TRUE(simple_framer_.ProcessPacket(
        QuicEncryptedPacket(packet.encrypted_buffer, packet.encrypted_length)));
    EXPECT_EQ(1u, simple_framer_.num_frames());
    EXPECT_EQ(1u, simple_framer_.stream_frames().size());
  }

  void CheckAllPacketsHaveSingleStreamFrame() {
    for (size_t i = 0; i < packets_.size(); i++) {
      CheckPacketHasSingleStreamFrame(i);
    }
  }

  QuicIOVector CreateData(size_t len) {
    data_array_.reset(new char[len]);
    memset(data_array_.get(), '?', len);
    iov_.iov_base = data_array_.get();
    iov_.iov_len = len;
    return QuicIOVector(&iov_, 1, len);
  }

  QuicIOVector MakeIOVectorFromStringPiece(StringPiece s) {
    return MakeIOVector(s, &iov_);
  }

  QuicFramer framer_;
  SimpleBufferAllocator buffer_allocator_;
  StrictMock<MockDelegate> delegate_;
  QuicPacketGenerator generator_;
  QuicPacketCreator* creator_;
  SimpleQuicFramer simple_framer_;
  std::vector<SerializedPacket> packets_;
  QuicAckFrame ack_frame_;

 private:
  std::unique_ptr<char[]> data_array_;
  struct iovec iov_;
};

class MockDebugDelegate : public QuicPacketCreator::DebugDelegate {
 public:
  MOCK_METHOD1(OnFrameAddedToPacket, void(const QuicFrame&));
};

TEST_F(QuicPacketGeneratorTest, ShouldSendAck_NotWritable) {
  delegate_.SetCanNotWrite();

  generator_.SetShouldSendAck(false);
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, ShouldSendAck_WritableAndShouldNotFlush) {
  StrictMock<MockDebugDelegate> debug_delegate;

  generator_.set_debug_delegate(&debug_delegate);
  delegate_.SetCanWriteOnlyNonRetransmittable();
  generator_.StartBatchOperations();

  EXPECT_CALL(delegate_, GetUpdatedAckFrame())
      .WillOnce(Return(QuicFrame(&ack_frame_)));
  EXPECT_CALL(debug_delegate, OnFrameAddedToPacket(_)).Times(1);

  generator_.SetShouldSendAck(false);
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, ShouldSendAck_WritableAndShouldFlush) {
  delegate_.SetCanWriteOnlyNonRetransmittable();

  EXPECT_CALL(delegate_, GetUpdatedAckFrame())
      .WillOnce(Return(QuicFrame(&ack_frame_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  generator_.SetShouldSendAck(false);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_ack_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketGeneratorTest, ShouldSendAck_MultipleCalls) {
  // Make sure that calling SetShouldSendAck multiple times does not result in a
  // crash. Previously this would result in multiple QuicFrames queued in the
  // packet generator, with all but the last with internal pointers to freed
  // memory.
  delegate_.SetCanWriteAnything();

  // Only one AckFrame should be created.
  EXPECT_CALL(delegate_, GetUpdatedAckFrame())
      .WillOnce(Return(QuicFrame(&ack_frame_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(1)
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  generator_.StartBatchOperations();
  generator_.SetShouldSendAck(false);
  generator_.SetShouldSendAck(false);
  generator_.FinishBatchOperations();
}

TEST_F(QuicPacketGeneratorTest, AddControlFrame_NotWritable) {
  delegate_.SetCanNotWrite();

  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, AddControlFrame_OnlyAckWritable) {
  delegate_.SetCanWriteOnlyNonRetransmittable();

  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, AddControlFrame_WritableAndShouldNotFlush) {
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, AddControlFrame_NotWritableBatchThenFlush) {
  delegate_.SetCanNotWrite();
  generator_.StartBatchOperations();

  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_TRUE(generator_.HasQueuedFrames());
  generator_.FinishBatchOperations();
  EXPECT_TRUE(generator_.HasQueuedFrames());

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  generator_.FlushAllQueuedFrames();
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_rst_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketGeneratorTest, AddControlFrame_WritableAndShouldFlush) {
  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_rst_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketGeneratorTest, ConsumeData_NotWritable) {
  delegate_.SetCanNotWrite();

  QuicConsumedData consumed = generator_.ConsumeData(
      kHeadersStreamId, MakeIOVectorFromStringPiece("foo"), 2, true, nullptr);
  EXPECT_EQ(0u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, ConsumeData_WritableAndShouldNotFlush) {
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  QuicConsumedData consumed = generator_.ConsumeData(
      kHeadersStreamId, MakeIOVectorFromStringPiece("foo"), 2, true, nullptr);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, ConsumeData_WritableAndShouldFlush) {
  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  QuicConsumedData consumed = generator_.ConsumeData(
      kHeadersStreamId, MakeIOVectorFromStringPiece("foo"), 2, true, nullptr);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

// Test the behavior of ConsumeData when the data consumed is for the crypto
// handshake stream.  Ensure that the packet is always sent and padded even if
// the generator operates in batch mode.
TEST_F(QuicPacketGeneratorTest, ConsumeData_Handshake) {
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  QuicConsumedData consumed = generator_.ConsumeData(
      kCryptoStreamId, MakeIOVectorFromStringPiece("foo"), 0, false, nullptr);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);

  ASSERT_EQ(1u, packets_.size());
  ASSERT_EQ(kDefaultMaxPacketSize, generator_.GetCurrentMaxPacketLength());
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[0].encrypted_length);
}

TEST_F(QuicPacketGeneratorTest, ConsumeData_EmptyData) {
  EXPECT_QUIC_BUG(
      generator_.ConsumeData(kHeadersStreamId, MakeIOVectorFromStringPiece(""),
                             0, false, nullptr),
      "Attempt to consume empty data without FIN.");
}

TEST_F(QuicPacketGeneratorTest,
       ConsumeDataMultipleTimes_WritableAndShouldNotFlush) {
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  generator_.ConsumeData(kHeadersStreamId, MakeIOVectorFromStringPiece("foo"),
                         2, true, nullptr);
  QuicConsumedData consumed = generator_.ConsumeData(
      3, MakeIOVectorFromStringPiece("quux"), 7, false, nullptr);
  EXPECT_EQ(4u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

TEST_F(QuicPacketGeneratorTest, ConsumeData_BatchOperations) {
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  generator_.ConsumeData(kHeadersStreamId, MakeIOVectorFromStringPiece("foo"),
                         2, true, nullptr);
  QuicConsumedData consumed = generator_.ConsumeData(
      3, MakeIOVectorFromStringPiece("quux"), 7, false, nullptr);
  EXPECT_EQ(4u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());

  // Now both frames will be flushed out.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  generator_.FinishBatchOperations();
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_stream_frames = 2;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketGeneratorTest, ConsumeData_FramesPreviouslyQueued) {
  // Set the packet size be enough for two stream frames with 0 stream offset,
  // but not enough for a stream frame of 0 offset and one with non-zero offset.
  size_t length =
      NullEncrypter(Perspective::IS_CLIENT).GetCiphertextSize(0) +
      GetPacketHeaderSize(
          framer_.version(), creator_->connection_id_length(), kIncludeVersion,
          !kIncludeDiversificationNonce,
          QuicPacketCreatorPeer::GetPacketNumberLength(creator_)) +
      // Add an extra 3 bytes for the payload and 1 byte so BytesFree is larger
      // than the GetMinStreamFrameSize.
      QuicFramer::GetMinStreamFrameSize(1, 0, false) + 3 +
      QuicFramer::GetMinStreamFrameSize(1, 0, true) + 1;
  generator_.SetMaxPacketLength(length);
  delegate_.SetCanWriteAnything();
  {
    InSequence dummy;
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  }
  generator_.StartBatchOperations();
  // Queue enough data to prevent a stream frame with a non-zero offset from
  // fitting.
  QuicConsumedData consumed = generator_.ConsumeData(
      kHeadersStreamId, MakeIOVectorFromStringPiece("foo"), 0, false, nullptr);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());

  // This frame will not fit with the existing frame, causing the queued frame
  // to be serialized, and it will be added to a new open packet.
  consumed = generator_.ConsumeData(
      kHeadersStreamId, MakeIOVectorFromStringPiece("bar"), 3, true, nullptr);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());

  creator_->Flush();
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
  CheckPacketContains(contents, 1);
}

TEST_F(QuicPacketGeneratorTest, ConsumeDataFastPath) {
  delegate_.SetCanWriteAnything();

  // Create a 10000 byte IOVector.
  QuicIOVector iov(CreateData(10000));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  QuicConsumedData consumed =
      generator_.ConsumeDataFastPath(kHeadersStreamId, iov, 0, true, nullptr);
  EXPECT_EQ(10000u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketGeneratorTest, NotWritableThenBatchOperations) {
  delegate_.SetCanNotWrite();

  generator_.SetShouldSendAck(false);
  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_TRUE(generator_.HasQueuedFrames());

  delegate_.SetCanWriteAnything();

  generator_.StartBatchOperations();

  // When the first write operation is invoked, the ack frame will be returned.
  EXPECT_CALL(delegate_, GetUpdatedAckFrame())
      .WillOnce(Return(QuicFrame(&ack_frame_)));

  // Send some data and a control frame
  generator_.ConsumeData(3, MakeIOVectorFromStringPiece("quux"), 7, false,
                         nullptr);
  generator_.AddControlFrame(QuicFrame(CreateGoAwayFrame()));

  // All five frames will be flushed out in a single packet.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  generator_.FinishBatchOperations();
  EXPECT_FALSE(generator_.HasQueuedFrames());

  PacketContents contents;
  contents.num_ack_frames = 1;
  contents.num_goaway_frames = 1;
  contents.num_rst_stream_frames = 1;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketGeneratorTest, NotWritableThenBatchOperations2) {
  delegate_.SetCanNotWrite();

  generator_.SetShouldSendAck(false);
  generator_.AddControlFrame(QuicFrame(CreateRstStreamFrame()));
  EXPECT_TRUE(generator_.HasQueuedFrames());

  delegate_.SetCanWriteAnything();

  generator_.StartBatchOperations();

  // When the first write operation is invoked, the ack frame will be returned.
  EXPECT_CALL(delegate_, GetUpdatedAckFrame())
      .WillOnce(Return(QuicFrame(&ack_frame_)));

  {
    InSequence dummy;
    // All five frames will be flushed out in a single packet
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  }

  // Send enough data to exceed one packet
  size_t data_len = kDefaultMaxPacketSize + 100;
  QuicConsumedData consumed =
      generator_.ConsumeData(3, CreateData(data_len), 0, true, nullptr);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  generator_.AddControlFrame(QuicFrame(CreateGoAwayFrame()));

  generator_.FinishBatchOperations();
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // The first packet should have the queued data and part of the stream data.
  PacketContents contents;
  contents.num_ack_frames = 1;
  contents.num_rst_stream_frames = 1;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);

  // The second should have the remainder of the stream data.
  PacketContents contents2;
  contents2.num_goaway_frames = 1;
  contents2.num_stream_frames = 1;
  CheckPacketContains(contents2, 1);
}

TEST_F(QuicPacketGeneratorTest, TestConnectionIdLength) {
  generator_.SetConnectionIdLength(0);
  EXPECT_EQ(PACKET_0BYTE_CONNECTION_ID, creator_->connection_id_length());

  for (size_t i = 1; i < 10; i++) {
    generator_.SetConnectionIdLength(i);
    EXPECT_EQ(PACKET_8BYTE_CONNECTION_ID, creator_->connection_id_length());
  }
}

// Test whether SetMaxPacketLength() works in the situation when the queue is
// empty, and we send three packets worth of data.
TEST_F(QuicPacketGeneratorTest, SetMaxPacketLength_Initial) {
  delegate_.SetCanWriteAnything();

  // Send enough data for three packets.
  size_t data_len = 3 * kDefaultMaxPacketSize + 1;
  size_t packet_len = kDefaultMaxPacketSize + 100;
  ASSERT_LE(packet_len, kMaxPacketSize);
  generator_.SetMaxPacketLength(packet_len);
  EXPECT_EQ(packet_len, generator_.GetCurrentMaxPacketLength());

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(3)
      .WillRepeatedly(Invoke(this, &QuicPacketGeneratorTest::SavePacket));
  QuicConsumedData consumed =
      generator_.ConsumeData(kHeadersStreamId, CreateData(data_len),
                             /*offset=*/2,
                             /*fin=*/true, nullptr);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // We expect three packets, and first two of them have to be of packet_len
  // size.  We check multiple packets (instead of just one) because we want to
  // ensure that |max_packet_length_| does not get changed incorrectly by the
  // generator after first packet is serialized.
  ASSERT_EQ(3u, packets_.size());
  EXPECT_EQ(packet_len, packets_[0].encrypted_length);
  EXPECT_EQ(packet_len, packets_[1].encrypted_length);
  CheckAllPacketsHaveSingleStreamFrame();
}

// Test whether SetMaxPacketLength() works in the situation when we first write
// data, then change packet size, then write data again.
TEST_F(QuicPacketGeneratorTest, SetMaxPacketLength_Middle) {
  delegate_.SetCanWriteAnything();

  // We send enough data to overflow default packet length, but not the altered
  // one.
  size_t data_len = kDefaultMaxPacketSize;
  size_t packet_len = kDefaultMaxPacketSize + 100;
  ASSERT_LE(packet_len, kMaxPacketSize);

  // We expect to see three packets in total.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(3)
      .WillRepeatedly(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  // Send two packets before packet size change.
  QuicConsumedData consumed =
      generator_.ConsumeData(kHeadersStreamId, CreateData(data_len),
                             /*offset=*/2,
                             /*fin=*/false, nullptr);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // Make sure we already have two packets.
  ASSERT_EQ(2u, packets_.size());

  // Increase packet size.
  generator_.SetMaxPacketLength(packet_len);
  EXPECT_EQ(packet_len, generator_.GetCurrentMaxPacketLength());

  // Send a packet after packet size change.
  consumed = generator_.ConsumeData(kHeadersStreamId, CreateData(data_len),
                                    2 + data_len,
                                    /*fin=*/true, nullptr);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // We expect first data chunk to get fragmented, but the second one to fit
  // into a single packet.
  ASSERT_EQ(3u, packets_.size());
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[0].encrypted_length);
  EXPECT_LE(kDefaultMaxPacketSize, packets_[2].encrypted_length);
  CheckAllPacketsHaveSingleStreamFrame();
}

// Test whether SetMaxPacketLength() works correctly when we force the change of
// the packet size in the middle of the batched packet.
TEST_F(QuicPacketGeneratorTest, SetMaxPacketLength_MidpacketFlush) {
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  size_t first_write_len = kDefaultMaxPacketSize / 2;
  size_t packet_len = kDefaultMaxPacketSize + 100;
  size_t second_write_len = packet_len + 1;
  ASSERT_LE(packet_len, kMaxPacketSize);

  // First send half of the packet worth of data.  We are in the batch mode, so
  // should not cause packet serialization.
  QuicConsumedData consumed =
      generator_.ConsumeData(kHeadersStreamId, CreateData(first_write_len),
                             /*offset=*/2,
                             /*fin=*/false, nullptr);
  EXPECT_EQ(first_write_len, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());

  // Make sure we have no packets so far.
  ASSERT_EQ(0u, packets_.size());

  // Expect a packet to be flushed.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  // Increase packet size after flushing all frames.
  // Ensure it's immediately enacted.
  generator_.FlushAllQueuedFrames();
  generator_.SetMaxPacketLength(packet_len);
  EXPECT_EQ(packet_len, generator_.GetCurrentMaxPacketLength());
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // We expect to see exactly one packet serialized after that, because we send
  // a value somewhat exceeding new max packet size, and the tail data does not
  // get serialized because we are still in the batch mode.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  // Send a more than a packet worth of data to the same stream.  This should
  // trigger serialization of one packet, and queue another one.
  consumed =
      generator_.ConsumeData(kHeadersStreamId, CreateData(second_write_len),
                             /*offset=*/2 + first_write_len,
                             /*fin=*/true, nullptr);
  EXPECT_EQ(second_write_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(generator_.HasQueuedFrames());

  // We expect the first packet to be underfilled, and the second packet be up
  // to the new max packet size.
  ASSERT_EQ(2u, packets_.size());
  EXPECT_GT(kDefaultMaxPacketSize, packets_[0].encrypted_length);
  EXPECT_EQ(packet_len, packets_[1].encrypted_length);

  CheckAllPacketsHaveSingleStreamFrame();
}

// Test sending an MTU probe, without any surrounding data.
TEST_F(QuicPacketGeneratorTest, GenerateMtuDiscoveryPacket_Simple) {
  delegate_.SetCanWriteAnything();

  const size_t target_mtu = kDefaultMaxPacketSize + 100;
  static_assert(target_mtu < kMaxPacketSize,
                "The MTU probe used by the test exceeds maximum packet size");

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  generator_.GenerateMtuDiscoveryPacket(target_mtu, nullptr);

  EXPECT_FALSE(generator_.HasQueuedFrames());
  ASSERT_EQ(1u, packets_.size());
  EXPECT_EQ(target_mtu, packets_[0].encrypted_length);

  PacketContents contents;
  contents.num_mtu_discovery_frames = 1;
  CheckPacketContains(contents, 0);
}

// Test sending an MTU probe.  Surround it with data, to ensure that it resets
// the MTU to the value before the probe was sent.
TEST_F(QuicPacketGeneratorTest, GenerateMtuDiscoveryPacket_SurroundedByData) {
  delegate_.SetCanWriteAnything();

  const size_t target_mtu = kDefaultMaxPacketSize + 100;
  static_assert(target_mtu < kMaxPacketSize,
                "The MTU probe used by the test exceeds maximum packet size");

  // Send enough data so it would always cause two packets to be sent.
  const size_t data_len = target_mtu + 1;

  // Send a total of five packets: two packets before the probe, the probe
  // itself, and two packets after the probe.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(5)
      .WillRepeatedly(Invoke(this, &QuicPacketGeneratorTest::SavePacket));

  // Send data before the MTU probe.
  QuicConsumedData consumed =
      generator_.ConsumeData(kHeadersStreamId, CreateData(data_len),
                             /*offset=*/2,
                             /*fin=*/false, nullptr);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // Send the MTU probe.
  generator_.GenerateMtuDiscoveryPacket(target_mtu, nullptr);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  // Send data after the MTU probe.
  consumed = generator_.ConsumeData(kHeadersStreamId, CreateData(data_len),
                                    /*offset=*/2 + data_len,
                                    /*fin=*/true, nullptr);
  EXPECT_EQ(data_len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(generator_.HasQueuedFrames());

  ASSERT_EQ(5u, packets_.size());
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[0].encrypted_length);
  EXPECT_EQ(target_mtu, packets_[2].encrypted_length);
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[3].encrypted_length);

  PacketContents probe_contents;
  probe_contents.num_mtu_discovery_frames = 1;

  CheckPacketHasSingleStreamFrame(0);
  CheckPacketHasSingleStreamFrame(1);
  CheckPacketContains(probe_contents, 2);
  CheckPacketHasSingleStreamFrame(3);
  CheckPacketHasSingleStreamFrame(4);
}

TEST_F(QuicPacketGeneratorTest, DontCrashOnInvalidStopWaiting) {
  // Test added to ensure the generator does not crash when an invalid frame is
  // added.  Because this is an indication of internal programming errors,
  // DFATALs are expected.
  // A 1 byte packet number length can't encode a gap of 1000.
  QuicPacketCreatorPeer::SetPacketNumber(creator_, 1000);

  delegate_.SetCanNotWrite();
  generator_.SetShouldSendAck(true);
  delegate_.SetCanWriteAnything();
  generator_.StartBatchOperations();

  // Set up frames to write into the creator when control frames are written.
  EXPECT_CALL(delegate_, GetUpdatedAckFrame())
      .WillOnce(Return(QuicFrame(&ack_frame_)));
  EXPECT_CALL(delegate_, PopulateStopWaitingFrame(_));
  // Generator should have queued control frames, and creator should be empty.
  EXPECT_TRUE(generator_.HasQueuedFrames());
  EXPECT_FALSE(creator_->HasPendingFrames());

  // This will not serialize any packets, because of the invalid frame.
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET, _,
                                   ConnectionCloseSource::FROM_SELF));
  EXPECT_QUIC_BUG(generator_.FinishBatchOperations(),
                  "packet_number_length 1 is too small "
                  "for least_unacked_delta: 1001");
}

// Regression test for b/31486443.
TEST_F(QuicPacketGeneratorTest, ConnectionCloseFrameLargerThanPacketSize) {
  delegate_.SetCanWriteAnything();
  QuicConnectionCloseFrame* frame = new QuicConnectionCloseFrame();
  frame->error_code = QUIC_PACKET_WRITE_ERROR;
  char buf[2000];
  StringPiece error_details(buf, 2000);
  frame->error_details = error_details.as_string();
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET,
                                   "Single frame cannot fit into a packet", _));
  EXPECT_QUIC_BUG(generator_.AddControlFrame(QuicFrame(frame)), "");
  EXPECT_TRUE(generator_.HasQueuedFrames());
}

}  // namespace test
}  // namespace net
