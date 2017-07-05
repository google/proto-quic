// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_packet_creator.h"

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>

#include "base/macros.h"
#include "net/quic/core/crypto/null_encrypter.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_data_writer.h"
#include "net/quic/core/quic_pending_retransmission.h"
#include "net/quic/core/quic_simple_buffer_allocator.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_test.h"
#include "net/quic/test_tools/quic_framer_peer.h"
#include "net/quic/test_tools/quic_packet_creator_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"

using std::string;
using testing::DoAll;
using testing::InSequence;
using testing::Return;
using testing::SaveArg;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {
namespace {

const QuicStreamId kGetNthClientInitiatedStreamId1 = kHeadersStreamId + 2;

// Run tests with combinations of {QuicVersion, ToggleVersionSerialization}.
struct TestParams {
  TestParams(QuicVersion version,
             bool version_serialization,
             QuicConnectionIdLength length,
             bool delegate_saves_data)
      : version(version),
        connection_id_length(length),
        version_serialization(version_serialization),
        delegate_saves_data(delegate_saves_data) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ client_version: " << QuicVersionToString(p.version)
       << " connection id length: " << p.connection_id_length
       << " include version: " << p.version_serialization
       << " delegate_saves_data: " << p.delegate_saves_data << " }";
    return os;
  }

  QuicVersion version;
  QuicConnectionIdLength connection_id_length;
  bool version_serialization;
  bool delegate_saves_data;
};

// Constructs various test permutations.
std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  constexpr QuicConnectionIdLength kMax = PACKET_8BYTE_CONNECTION_ID;
  QuicVersionVector all_supported_versions = AllSupportedVersions();
  for (bool delegate_saves_data : {true, false}) {
    for (size_t i = 0; i < all_supported_versions.size(); ++i) {
      params.push_back(TestParams(all_supported_versions[i], true, kMax,
                                  delegate_saves_data));
      params.push_back(TestParams(all_supported_versions[i], false, kMax,
                                  delegate_saves_data));
    }
    params.push_back(TestParams(all_supported_versions[0], true,
                                PACKET_0BYTE_CONNECTION_ID,
                                delegate_saves_data));
    params.push_back(
        TestParams(all_supported_versions[0], true, kMax, delegate_saves_data));
  }
  return params;
}

class QuicPacketCreatorTest : public QuicTestWithParam<TestParams> {
 public:
  void ClearSerializedPacketForTests(SerializedPacket* serialized_packet) {
    if (serialized_packet == nullptr) {
      return;
    }
    ClearSerializedPacket(serialized_packet);
  }

  void SaveSerializedPacket(SerializedPacket* serialized_packet) {
    if (serialized_packet == nullptr) {
      return;
    }
    delete[] serialized_packet_.encrypted_buffer;
    serialized_packet_ = *serialized_packet;
    serialized_packet_.encrypted_buffer = CopyBuffer(*serialized_packet);
    serialized_packet->retransmittable_frames.clear();
  }

  void DeleteSerializedPacket() {
    delete[] serialized_packet_.encrypted_buffer;
    serialized_packet_.encrypted_buffer = nullptr;
    ClearSerializedPacket(&serialized_packet_);
  }

 protected:
  QuicPacketCreatorTest()
      : server_framer_(SupportedVersions(GetParam().version),
                       QuicTime::Zero(),
                       Perspective::IS_SERVER),
        client_framer_(SupportedVersions(GetParam().version),
                       QuicTime::Zero(),
                       Perspective::IS_CLIENT),
        connection_id_(2),
        data_("foo"),
        creator_(connection_id_,
                 &client_framer_,
                 &buffer_allocator_,
                 &delegate_),
        serialized_packet_(creator_.NoPacket()) {
    creator_.set_connection_id_length(GetParam().connection_id_length);

    creator_.SetEncrypter(ENCRYPTION_INITIAL,
                          new NullEncrypter(Perspective::IS_CLIENT));
    creator_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                          new NullEncrypter(Perspective::IS_CLIENT));
    client_framer_.set_visitor(&framer_visitor_);
    server_framer_.set_visitor(&framer_visitor_);
    if (GetParam().delegate_saves_data) {
      creator_.set_delegate_saves_data(true);
    }
  }

  ~QuicPacketCreatorTest() override {
    delete[] serialized_packet_.encrypted_buffer;
    ClearSerializedPacket(&serialized_packet_);
  }

  SerializedPacket SerializeAllFrames(const QuicFrames& frames) {
    SerializedPacket packet = QuicPacketCreatorPeer::SerializeAllFrames(
        &creator_, frames, buffer_, kMaxPacketSize);
    EXPECT_EQ(QuicPacketCreatorPeer::GetEncryptionLevel(&creator_),
              packet.encryption_level);
    return packet;
  }

  void ProcessPacket(const SerializedPacket& packet) {
    QuicEncryptedPacket encrypted_packet(packet.encrypted_buffer,
                                         packet.encrypted_length);
    server_framer_.ProcessPacket(encrypted_packet);
  }

  void CheckStreamFrame(const QuicFrame& frame,
                        QuicStreamId stream_id,
                        const string& data,
                        QuicStreamOffset offset,
                        bool fin) {
    EXPECT_EQ(STREAM_FRAME, frame.type);
    ASSERT_TRUE(frame.stream_frame);
    EXPECT_EQ(stream_id, frame.stream_frame->stream_id);
    if (GetParam().delegate_saves_data) {
      char buf[kMaxPacketSize];
      QuicDataWriter writer(kMaxPacketSize, buf, Perspective::IS_CLIENT,
                            HOST_BYTE_ORDER);
      if (frame.stream_frame->data_length > 0) {
        delegate_.WriteStreamData(stream_id, frame.stream_frame->offset,
                                  frame.stream_frame->data_length, &writer);
      }
      EXPECT_EQ(data, QuicStringPiece(buf, frame.stream_frame->data_length));
    } else {
      EXPECT_EQ(data, QuicStringPiece(frame.stream_frame->data_buffer,
                                      frame.stream_frame->data_length));
    }
    EXPECT_EQ(offset, frame.stream_frame->offset);
    EXPECT_EQ(fin, frame.stream_frame->fin);
  }

  // Returns the number of bytes consumed by the header of packet, including
  // the version.
  size_t GetPacketHeaderOverhead(QuicVersion version) {
    return GetPacketHeaderSize(
        version, creator_.connection_id_length(), kIncludeVersion,
        !kIncludeDiversificationNonce,
        QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
  }

  // Returns the number of bytes of overhead that will be added to a packet
  // of maximum length.
  size_t GetEncryptionOverhead() {
    return creator_.max_packet_length() -
           client_framer_.GetMaxPlaintextSize(creator_.max_packet_length());
  }

  // Returns the number of bytes consumed by the non-data fields of a stream
  // frame, assuming it is the last frame in the packet
  size_t GetStreamFrameOverhead() {
    return QuicFramer::GetMinStreamFrameSize(kGetNthClientInitiatedStreamId1,
                                             kOffset, true);
  }

  QuicIOVector MakeIOVectorFromStringPiece(QuicStringPiece s) {
    return MakeIOVector(s, &iov_);
  }

  QuicPendingRetransmission CreateRetransmission(
      const QuicFrames& retransmittable_frames,
      bool has_crypto_handshake,
      int num_padding_bytes,
      EncryptionLevel encryption_level,
      QuicPacketNumberLength packet_number_length) {
    return QuicPendingRetransmission(
        1u, NOT_RETRANSMISSION, retransmittable_frames, has_crypto_handshake,
        num_padding_bytes, encryption_level, packet_number_length);
  }

  static const QuicStreamOffset kOffset = 1u;

  char buffer_[kMaxPacketSize];
  QuicFrames frames_;
  QuicFramer server_framer_;
  QuicFramer client_framer_;
  StrictMock<MockFramerVisitor> framer_visitor_;
  StrictMock<MockPacketCreatorDelegate> delegate_;
  QuicConnectionId connection_id_;
  string data_;
  struct iovec iov_;
  SimpleBufferAllocator buffer_allocator_;
  QuicPacketCreator creator_;
  SerializedPacket serialized_packet_;
};

// Run all packet creator tests with all supported versions of QUIC, and with
// and without version in the packet header, as well as doing a run for each
// length of truncated connection id.
INSTANTIATE_TEST_CASE_P(QuicPacketCreatorTests,
                        QuicPacketCreatorTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicPacketCreatorTest, SerializeFrames) {
  for (int i = ENCRYPTION_NONE; i < NUM_ENCRYPTION_LEVELS; ++i) {
    EncryptionLevel level = static_cast<EncryptionLevel>(i);
    creator_.set_encryption_level(level);
    frames_.push_back(QuicFrame(new QuicAckFrame(MakeAckFrame(0u))));
    frames_.push_back(QuicFrame(
        new QuicStreamFrame(kCryptoStreamId, false, 0u, QuicStringPiece())));
    frames_.push_back(QuicFrame(
        new QuicStreamFrame(kCryptoStreamId, true, 0u, QuicStringPiece())));
    SerializedPacket serialized = SerializeAllFrames(frames_);
    EXPECT_EQ(level, serialized.encryption_level);
    delete frames_[0].ack_frame;
    delete frames_[1].stream_frame;
    delete frames_[2].stream_frame;
    frames_.clear();

    {
      InSequence s;
      EXPECT_CALL(framer_visitor_, OnPacket());
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
      EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
      EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
      EXPECT_CALL(framer_visitor_, OnAckFrame(_));
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
      EXPECT_CALL(framer_visitor_, OnPacketComplete());
    }
    ProcessPacket(serialized);
  }
}

TEST_P(QuicPacketCreatorTest, ReserializeFramesWithSequenceNumberLength) {
  // If the original packet number length, the current packet number
  // length, and the configured send packet number length are different, the
  // retransmit must sent with the original length and the others do not change.
  QuicPacketCreatorPeer::SetPacketNumberLength(&creator_,
                                               PACKET_2BYTE_PACKET_NUMBER);
  QuicStreamFrame* stream_frame = new QuicStreamFrame(
      kCryptoStreamId, /*fin=*/false, 0u, QuicStringPiece());
  QuicFrames frames;
  frames.push_back(QuicFrame(stream_frame));
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(CreateRetransmission(
      frames, true /* has_crypto_handshake */, -1 /* needs full padding */,
      ENCRYPTION_NONE, PACKET_1BYTE_PACKET_NUMBER));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
  // The packet number length is updated after every packet is sent,
  // so there is no need to restore the old length after sending.
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            serialized_packet_.packet_number_length);

  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized_packet_);
  delete stream_frame;
}

TEST_P(QuicPacketCreatorTest, ReserializeCryptoFrameWithForwardSecurity) {
  QuicStreamFrame* stream_frame = new QuicStreamFrame(
      kCryptoStreamId, /*fin=*/false, 0u, QuicStringPiece());
  QuicFrames frames;
  frames.push_back(QuicFrame(stream_frame));
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(CreateRetransmission(
      frames, true /* has_crypto_handshake */, -1 /* needs full padding */,
      ENCRYPTION_NONE,
      QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
  EXPECT_EQ(ENCRYPTION_NONE, serialized_packet_.encryption_level);
  delete stream_frame;
}

TEST_P(QuicPacketCreatorTest, ReserializeFrameWithForwardSecurity) {
  QuicStreamFrame* stream_frame =
      new QuicStreamFrame(0u, /*fin=*/false, 0u, QuicStringPiece());
  QuicFrames frames;
  frames.push_back(QuicFrame(stream_frame));
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(CreateRetransmission(
      frames, false /* has_crypto_handshake */, 0 /* no padding */,
      ENCRYPTION_NONE,
      QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, serialized_packet_.encryption_level);
  delete stream_frame;
}

TEST_P(QuicPacketCreatorTest, ReserializeFramesWithFullPadding) {
  QuicFrame frame;
  QuicIOVector io_vector(
      MakeIOVectorFromStringPiece("fake handshake message data"));
  QuicPacketCreatorPeer::CreateStreamFrame(&creator_, kCryptoStreamId,
                                           io_vector, 0u, 0u, false, &frame);
  QuicFrames frames;
  frames.push_back(frame);
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(CreateRetransmission(
      frames, true /* has_crypto_handshake */, -1 /* needs full padding */,
      ENCRYPTION_NONE,
      QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
  EXPECT_EQ(kDefaultMaxPacketSize, serialized_packet_.encrypted_length);
  delete frame.stream_frame;
}

TEST_P(QuicPacketCreatorTest, DoNotRetransmitPendingPadding) {
  QuicFrame frame;
  QuicIOVector io_vector(MakeIOVectorFromStringPiece("fake message data"));
  QuicPacketCreatorPeer::CreateStreamFrame(&creator_, kCryptoStreamId,
                                           io_vector, 0u, 0u, false, &frame);

  const int kNumPaddingBytes1 = 4;
  int packet_size = 0;
  {
    QuicFrames frames;
    frames.push_back(frame);
    char buffer[kMaxPacketSize];
    QuicPendingRetransmission retransmission(CreateRetransmission(
        frames, false /* has_crypto_handshake */,
        kNumPaddingBytes1 /* padding bytes */, ENCRYPTION_NONE,
        QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
    creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
    packet_size = serialized_packet_.encrypted_length;
  }

  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    // Pending paddings are not retransmitted.
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_)).Times(0);
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized_packet_);

  const int kNumPaddingBytes2 = 44;
  QuicFrames frames;
  frames.push_back(frame);
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(CreateRetransmission(
      frames, false /* has_crypto_handshake */,
      kNumPaddingBytes2 /* padding bytes */, ENCRYPTION_NONE,
      QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);

  EXPECT_EQ(packet_size, serialized_packet_.encrypted_length);
  delete frame.stream_frame;
}

TEST_P(QuicPacketCreatorTest, ReserializeFramesWithFullPacketAndPadding) {
  const size_t overhead = GetPacketHeaderOverhead(client_framer_.version()) +
                          GetEncryptionOverhead() + GetStreamFrameOverhead();
  size_t capacity = kDefaultMaxPacketSize - overhead;
  for (int delta = -5; delta <= 0; ++delta) {
    string data(capacity + delta, 'A');
    size_t bytes_free = 0 - delta;

    QuicFrame frame;
    QuicIOVector io_vector(MakeIOVectorFromStringPiece(data));
    QuicPacketCreatorPeer::CreateStreamFrame(
        &creator_, kCryptoStreamId, io_vector, 0, kOffset, false, &frame);
    QuicFrames frames;
    frames.push_back(frame);
    char buffer[kMaxPacketSize];
    QuicPendingRetransmission retransmission(CreateRetransmission(
        frames, true /* has_crypto_handshake */, -1 /* needs full padding */,
        ENCRYPTION_NONE,
        QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
    creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);

    // If there is not enough space in the packet to fit a padding frame
    // (1 byte) and to expand the stream frame (another 2 bytes) the packet
    // will not be padded.
    if (bytes_free < 3) {
      EXPECT_EQ(kDefaultMaxPacketSize - bytes_free,
                serialized_packet_.encrypted_length);
    } else {
      EXPECT_EQ(kDefaultMaxPacketSize, serialized_packet_.encrypted_length);
    }

    delete frame.stream_frame;
    frames_.clear();
  }
}

TEST_P(QuicPacketCreatorTest, SerializeConnectionClose) {
  QuicConnectionCloseFrame frame;
  frame.error_code = QUIC_NO_ERROR;
  frame.error_details = "error";

  QuicFrames frames;
  frames.push_back(QuicFrame(&frame));
  SerializedPacket serialized = SerializeAllFrames(frames);
  EXPECT_EQ(ENCRYPTION_NONE, serialized.encryption_level);
  ASSERT_EQ(1u, serialized.packet_number);
  ASSERT_EQ(1u, creator_.packet_number());

  InSequence s;
  EXPECT_CALL(framer_visitor_, OnPacket());
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
  EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
  EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
  EXPECT_CALL(framer_visitor_, OnConnectionCloseFrame(_));
  EXPECT_CALL(framer_visitor_, OnPacketComplete());

  ProcessPacket(serialized);
}

TEST_P(QuicPacketCreatorTest, ConsumeData) {
  QuicFrame frame;
  QuicIOVector io_vector(MakeIOVectorFromStringPiece("test"));
  ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 0u, false,
                                   false, &frame));
  ASSERT_TRUE(frame.stream_frame);
  size_t consumed = frame.stream_frame->data_length;
  EXPECT_EQ(4u, consumed);
  CheckStreamFrame(frame, 1u, "test", 0u, false);
  EXPECT_TRUE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, ConsumeDataFin) {
  QuicFrame frame;
  QuicIOVector io_vector(MakeIOVectorFromStringPiece("test"));
  ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 10u, true,
                                   false, &frame));
  ASSERT_TRUE(frame.stream_frame);
  size_t consumed = frame.stream_frame->data_length;
  EXPECT_EQ(4u, consumed);
  CheckStreamFrame(frame, 1u, "test", 10u, true);
  EXPECT_TRUE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, ConsumeDataFinOnly) {
  QuicFrame frame;
  QuicIOVector io_vector(nullptr, 0, 0);
  ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 0u, true,
                                   false, &frame));
  ASSERT_TRUE(frame.stream_frame);
  size_t consumed = frame.stream_frame->data_length;
  EXPECT_EQ(0u, consumed);
  CheckStreamFrame(frame, 1u, string(), 0u, true);
  EXPECT_TRUE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, CreateAllFreeBytesForStreamFrames) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  const size_t overhead = GetPacketHeaderOverhead(client_framer_.version()) +
                          GetEncryptionOverhead();
  for (size_t i = overhead; i < overhead + 100; ++i) {
    creator_.SetMaxPacketLength(i);
    const bool should_have_room = i > overhead + GetStreamFrameOverhead();
    ASSERT_EQ(should_have_room, creator_.HasRoomForStreamFrame(
                                    kGetNthClientInitiatedStreamId1, kOffset));
    if (should_have_room) {
      QuicFrame frame;
      QuicIOVector io_vector(MakeIOVectorFromStringPiece("testdata"));
      EXPECT_CALL(delegate_, OnSerializedPacket(_))
          .WillRepeatedly(Invoke(
              this, &QuicPacketCreatorTest::ClearSerializedPacketForTests));
      ASSERT_TRUE(creator_.ConsumeData(kGetNthClientInitiatedStreamId1,
                                       io_vector, 0u, kOffset, false, false,
                                       &frame));
      ASSERT_TRUE(frame.stream_frame);
      size_t bytes_consumed = frame.stream_frame->data_length;
      EXPECT_LT(0u, bytes_consumed);
      creator_.Flush();
    }
  }
}

TEST_P(QuicPacketCreatorTest, StreamFrameConsumption) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  // Compute the total overhead for a single frame in packet.
  const size_t overhead = GetPacketHeaderOverhead(client_framer_.version()) +
                          GetEncryptionOverhead() + GetStreamFrameOverhead();
  size_t capacity = kDefaultMaxPacketSize - overhead;
  // Now, test various sizes around this size.
  for (int delta = -5; delta <= 5; ++delta) {
    string data(capacity + delta, 'A');
    size_t bytes_free = delta > 0 ? 0 : 0 - delta;
    QuicFrame frame;
    QuicIOVector io_vector(MakeIOVectorFromStringPiece(data));
    ASSERT_TRUE(creator_.ConsumeData(kGetNthClientInitiatedStreamId1, io_vector,
                                     0u, kOffset, false, false, &frame));
    ASSERT_TRUE(frame.stream_frame);

    // BytesFree() returns bytes available for the next frame, which will
    // be two bytes smaller since the stream frame would need to be grown.
    EXPECT_EQ(2u, creator_.ExpansionOnNewFrame());
    size_t expected_bytes_free = bytes_free < 3 ? 0 : bytes_free - 2;
    EXPECT_EQ(expected_bytes_free, creator_.BytesFree()) << "delta: " << delta;
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
    creator_.Flush();
    ASSERT_TRUE(serialized_packet_.encrypted_buffer);
    DeleteSerializedPacket();
  }
}

TEST_P(QuicPacketCreatorTest, CryptoStreamFramePacketPadding) {
  // Compute the total overhead for a single frame in packet.
  const size_t overhead = GetPacketHeaderOverhead(client_framer_.version()) +
                          GetEncryptionOverhead() + GetStreamFrameOverhead();
  ASSERT_GT(kMaxPacketSize, overhead);
  size_t capacity = kDefaultMaxPacketSize - overhead;
  // Now, test various sizes around this size.
  for (int delta = -5; delta <= 5; ++delta) {
    string data(capacity + delta, 'A');
    size_t bytes_free = delta > 0 ? 0 : 0 - delta;

    QuicFrame frame;
    QuicIOVector io_vector(MakeIOVectorFromStringPiece(data));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillRepeatedly(
            Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
    ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, kOffset,
                                     false, true, &frame));
    ASSERT_TRUE(frame.stream_frame);
    size_t bytes_consumed = frame.stream_frame->data_length;
    EXPECT_LT(0u, bytes_consumed);
    creator_.Flush();
    ASSERT_TRUE(serialized_packet_.encrypted_buffer);
    // If there is not enough space in the packet to fit a padding frame
    // (1 byte) and to expand the stream frame (another 2 bytes) the packet
    // will not be padded.
    if (bytes_free < 3) {
      EXPECT_EQ(kDefaultMaxPacketSize - bytes_free,
                serialized_packet_.encrypted_length);
    } else {
      EXPECT_EQ(kDefaultMaxPacketSize, serialized_packet_.encrypted_length);
    }
    DeleteSerializedPacket();
  }
}

TEST_P(QuicPacketCreatorTest, NonCryptoStreamFramePacketNonPadding) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  // Compute the total overhead for a single frame in packet.
  const size_t overhead = GetPacketHeaderOverhead(client_framer_.version()) +
                          GetEncryptionOverhead() + GetStreamFrameOverhead();
  ASSERT_GT(kDefaultMaxPacketSize, overhead);
  size_t capacity = kDefaultMaxPacketSize - overhead;
  // Now, test various sizes around this size.
  for (int delta = -5; delta <= 5; ++delta) {
    string data(capacity + delta, 'A');
    size_t bytes_free = delta > 0 ? 0 : 0 - delta;

    QuicFrame frame;
    QuicIOVector io_vector(MakeIOVectorFromStringPiece(data));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
    ASSERT_TRUE(creator_.ConsumeData(kGetNthClientInitiatedStreamId1, io_vector,
                                     0u, kOffset, false, false, &frame));
    ASSERT_TRUE(frame.stream_frame);
    size_t bytes_consumed = frame.stream_frame->data_length;
    EXPECT_LT(0u, bytes_consumed);
    creator_.Flush();
    ASSERT_TRUE(serialized_packet_.encrypted_buffer);
    if (bytes_free > 0) {
      EXPECT_EQ(kDefaultMaxPacketSize - bytes_free,
                serialized_packet_.encrypted_length);
    } else {
      EXPECT_EQ(kDefaultMaxPacketSize, serialized_packet_.encrypted_length);
    }
    DeleteSerializedPacket();
  }
}

TEST_P(QuicPacketCreatorTest, SerializeVersionNegotiationPacket) {
  QuicFramerPeer::SetPerspective(&client_framer_, Perspective::IS_SERVER);
  QuicVersionVector versions;
  versions.push_back(test::QuicVersionMax());
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      creator_.SerializeVersionNegotiationPacket(versions));

  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnVersionNegotiationPacket(_));
  }
  QuicFramerPeer::SetPerspective(&client_framer_, Perspective::IS_CLIENT);
  client_framer_.ProcessPacket(*encrypted);
}

TEST_P(QuicPacketCreatorTest, UpdatePacketSequenceNumberLengthLeastAwaiting) {
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 64);
  creator_.UpdatePacketNumberLength(2, 10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 64 * 256);
  creator_.UpdatePacketNumberLength(2, 10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 64 * 256 * 256);
  creator_.UpdatePacketNumberLength(2, 10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_,
                                         UINT64_C(64) * 256 * 256 * 256 * 256);
  creator_.UpdatePacketNumberLength(2, 10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_6BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
}

TEST_P(QuicPacketCreatorTest, UpdatePacketSequenceNumberLengthCwnd) {
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(1, 10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(1, 10000 * 256 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(1,
                                    10000 * 256 * 256 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(
      1, UINT64_C(1000) * 256 * 256 * 256 * 256 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_6BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
}

TEST_P(QuicPacketCreatorTest, SerializeFrame) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  frames_.push_back(QuicFrame(
      new QuicStreamFrame(kCryptoStreamId, false, 0u, QuicStringPiece())));
  SerializedPacket serialized = SerializeAllFrames(frames_);
  delete frames_[0].stream_frame;

  QuicPacketHeader header;
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_))
        .WillOnce(DoAll(SaveArg<0>(&header), Return(true)));
    EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized);
  EXPECT_EQ(GetParam().version_serialization,
            header.public_header.version_flag);
}

TEST_P(QuicPacketCreatorTest, ConsumeDataLargerThanOneStreamFrame) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  // A string larger than fits into a frame.
  size_t payload_length;
  creator_.SetMaxPacketLength(GetPacketLengthForOneStream(
      client_framer_.version(),
      QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
      !kIncludeDiversificationNonce, creator_.connection_id_length(),
      PACKET_1BYTE_PACKET_NUMBER, &payload_length));
  QuicFrame frame;
  const string too_long_payload(payload_length * 2, 'a');
  QuicIOVector io_vector(MakeIOVectorFromStringPiece(too_long_payload));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 0u, true,
                                   false, &frame));
  ASSERT_TRUE(frame.stream_frame);
  size_t consumed = frame.stream_frame->data_length;
  EXPECT_EQ(payload_length, consumed);
  const string payload(payload_length, 'a');
  CheckStreamFrame(frame, 1u, payload, 0u, false);
  creator_.Flush();
  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest, AddFrameAndFlush) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  const size_t max_plaintext_size =
      client_framer_.GetMaxPlaintextSize(creator_.max_packet_length());
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_EQ(max_plaintext_size -
                GetPacketHeaderSize(
                    client_framer_.version(), creator_.connection_id_length(),
                    QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
                    !kIncludeDiversificationNonce, PACKET_1BYTE_PACKET_NUMBER),
            creator_.BytesFree());

  // Add a variety of frame types and then a padding frame.
  QuicAckFrame ack_frame(MakeAckFrame(10u));
  EXPECT_TRUE(creator_.AddSavedFrame(QuicFrame(&ack_frame)));
  EXPECT_TRUE(creator_.HasPendingFrames());

  QuicFrame frame;
  QuicIOVector io_vector(MakeIOVectorFromStringPiece("test"));
  ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 0u, false,
                                   false, &frame));
  ASSERT_TRUE(frame.stream_frame);
  size_t consumed = frame.stream_frame->data_length;
  EXPECT_EQ(4u, consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());

  QuicPaddingFrame padding_frame;
  EXPECT_TRUE(creator_.AddSavedFrame(QuicFrame(padding_frame)));
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_EQ(0u, creator_.BytesFree());

  // Packet is full. Creator will flush.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  EXPECT_FALSE(creator_.AddSavedFrame(QuicFrame(&ack_frame)));

  // Ensure the packet is successfully created.
  ASSERT_TRUE(serialized_packet_.encrypted_buffer);
  ASSERT_FALSE(serialized_packet_.retransmittable_frames.empty());
  const QuicFrames& retransmittable = serialized_packet_.retransmittable_frames;
  ASSERT_EQ(1u, retransmittable.size());
  EXPECT_EQ(STREAM_FRAME, retransmittable[0].type);
  ASSERT_TRUE(retransmittable[0].stream_frame);
  EXPECT_TRUE(serialized_packet_.has_ack);
  if (FLAGS_quic_reloadable_flag_quic_no_stop_waiting_frames) {
    EXPECT_EQ(10u, serialized_packet_.largest_acked);
  }
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_EQ(max_plaintext_size -
                GetPacketHeaderSize(
                    client_framer_.version(), creator_.connection_id_length(),
                    QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
                    !kIncludeDiversificationNonce, PACKET_1BYTE_PACKET_NUMBER),
            creator_.BytesFree());
}

TEST_P(QuicPacketCreatorTest, SerializeAndSendStreamFrame) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  EXPECT_FALSE(creator_.HasPendingFrames());

  QuicIOVector iov(MakeIOVectorFromStringPiece("test"));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  creator_.CreateAndSerializeStreamFrame(kHeadersStreamId, iov, 0, 0, true,
                                         nullptr, &num_bytes_consumed);
  EXPECT_EQ(4u, num_bytes_consumed);

  // Ensure the packet is successfully created.
  ASSERT_TRUE(serialized_packet_.encrypted_buffer);
  ASSERT_FALSE(serialized_packet_.retransmittable_frames.empty());
  const QuicFrames& retransmittable = serialized_packet_.retransmittable_frames;
  ASSERT_EQ(1u, retransmittable.size());
  EXPECT_EQ(STREAM_FRAME, retransmittable[0].type);
  ASSERT_TRUE(retransmittable[0].stream_frame);
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, AddUnencryptedStreamDataClosesConnection) {
  creator_.set_encryption_level(ENCRYPTION_NONE);
  EXPECT_CALL(delegate_, OnUnrecoverableError(_, _, _));
  QuicStreamFrame stream_frame(kHeadersStreamId, /*fin=*/false, 0u,
                               QuicStringPiece());
  EXPECT_QUIC_BUG(creator_.AddSavedFrame(QuicFrame(&stream_frame)),
                  "Cannot send stream data without encryption.");
}

TEST_P(QuicPacketCreatorTest, ChloTooLarge) {
  CryptoHandshakeMessage message;
  message.set_tag(kCHLO);
  message.set_minimum_size(kMaxPacketSize);
  CryptoFramer framer;
  std::unique_ptr<QuicData> message_data;
  message_data.reset(
      framer.ConstructHandshakeMessage(message, Perspective::IS_CLIENT));

  struct iovec iov;
  QuicIOVector data_iovec(MakeIOVector(
      QuicStringPiece(message_data->data(), message_data->length()), &iov));
  QuicFrame frame;
  EXPECT_CALL(delegate_,
              OnUnrecoverableError(QUIC_CRYPTO_CHLO_TOO_LARGE, _, _));
  EXPECT_QUIC_BUG(creator_.ConsumeData(kCryptoStreamId, data_iovec, 0u, 0u,
                                       false, false, &frame),
                  "Client hello won't fit in a single packet.");
}

TEST_P(QuicPacketCreatorTest, PendingPadding) {
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes * 10);
  EXPECT_EQ(kMaxNumRandomPaddingBytes * 10, creator_.pending_padding_bytes());

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  // Flush all paddings.
  while (creator_.pending_padding_bytes() > 0) {
    creator_.Flush();
    {
      InSequence s;
      EXPECT_CALL(framer_visitor_, OnPacket());
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
      EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
      EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
      EXPECT_CALL(framer_visitor_, OnPacketComplete());
    }
    // Packet only contains padding.
    ProcessPacket(serialized_packet_);
  }
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, FullPaddingDoesNotConsumePendingPadding) {
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  QuicFrame frame;
  QuicIOVector io_vector(MakeIOVectorFromStringPiece("test"));
  ASSERT_TRUE(creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 0u, false,
                                   /*needs_full_padding=*/true, &frame));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.Flush();
  EXPECT_EQ(kMaxNumRandomPaddingBytes, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, SendPendingPaddingInRetransmission) {
  QuicStreamFrame* stream_frame = new QuicStreamFrame(
      kCryptoStreamId, /*fin=*/false, 0u, QuicStringPiece());
  QuicFrames frames;
  frames.push_back(QuicFrame(stream_frame));
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(
      CreateRetransmission(frames, true, /*num_padding_bytes=*/0,
                           ENCRYPTION_NONE, PACKET_1BYTE_PACKET_NUMBER));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized_packet_);
  delete stream_frame;
}

TEST_P(QuicPacketCreatorTest, SendPacketAfterFullPaddingRetransmission) {
  // Making sure needs_full_padding gets reset after a full padding
  // retransmission.
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
  QuicFrame frame;
  QuicIOVector io_vector(
      MakeIOVectorFromStringPiece("fake handshake message data"));
  QuicPacketCreatorPeer::CreateStreamFrame(&creator_, kCryptoStreamId,
                                           io_vector, 0u, 0u, false, &frame);
  QuicFrames frames;
  frames.push_back(frame);
  char buffer[kMaxPacketSize];
  QuicPendingRetransmission retransmission(CreateRetransmission(
      frames, true, /*num_padding_bytes=*/-1, ENCRYPTION_NONE,
      QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.ReserializeAllFrames(retransmission, buffer, kMaxPacketSize);
  EXPECT_EQ(kDefaultMaxPacketSize, serialized_packet_.encrypted_length);
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    // Full padding.
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized_packet_);
  delete frame.stream_frame;

  creator_.ConsumeData(kCryptoStreamId, io_vector, 0u, 0u, false, false,
                       &frame);
  creator_.Flush();
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    // needs_full_padding gets reset.
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_)).Times(0);
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized_packet_);
}

TEST_P(QuicPacketCreatorTest, ConsumeDataAndRandomPadding) {
  const QuicByteCount kStreamFramePayloadSize = 100u;
  // Set the packet size be enough for one stream frame with 0 stream offset +
  // 1.
  size_t length = GetPacketHeaderOverhead(client_framer_.version()) +
                  GetEncryptionOverhead() +
                  QuicFramer::GetMinStreamFrameSize(
                      kCryptoStreamId, 0, /*last_frame_in_packet=*/false) +
                  kStreamFramePayloadSize + 1;
  creator_.SetMaxPacketLength(length);
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  QuicByteCount pending_padding_bytes = creator_.pending_padding_bytes();
  QuicFrame frame;
  char buf[kStreamFramePayloadSize + 1] = {};
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  // Send stream frame of size kStreamFramePayloadSize.
  creator_.ConsumeData(kCryptoStreamId,
                       MakeIOVectorFromStringPiece(
                           QuicStringPiece(buf, kStreamFramePayloadSize)),
                       0u, 0u, false, false, &frame);
  creator_.Flush();
  delete frame.stream_frame;
  // 1 byte padding is sent.
  EXPECT_EQ(pending_padding_bytes - 1, creator_.pending_padding_bytes());
  // Send stream frame of size kStreamFramePayloadSize + 1.
  creator_.ConsumeData(kCryptoStreamId,
                       MakeIOVectorFromStringPiece(
                           QuicStringPiece(buf, kStreamFramePayloadSize + 1)),
                       0u, 0u, false, false, &frame);
  // No padding is sent.
  creator_.Flush();
  delete frame.stream_frame;
  EXPECT_EQ(pending_padding_bytes - 1, creator_.pending_padding_bytes());
  // Flush all paddings.
  while (creator_.pending_padding_bytes() > 0) {
    creator_.Flush();
  }
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
}

}  // namespace
}  // namespace test
}  // namespace net
