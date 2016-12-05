// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_framer.h"

#include <string.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "net/quic/core/crypto/null_decrypter.h"
#include "net/quic/core/crypto/quic_decrypter.h"
#include "net/quic/core/crypto/quic_encrypter.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/quic_framer_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"

using base::StringPiece;
using std::string;
using testing::Return;
using testing::Truly;
using testing::_;

namespace net {
namespace test {

const QuicPacketNumber kEpoch = UINT64_C(1) << 48;
const QuicPacketNumber kMask = kEpoch - 1;

// Use fields in which each byte is distinct to ensure that every byte is
// framed correctly. The values are otherwise arbitrary.
const QuicConnectionId kConnectionId = UINT64_C(0xFEDCBA9876543210);
const QuicPathId kPathId = 0x42;
const QuicPacketNumber kPacketNumber = UINT64_C(0x123456789ABC);
const QuicPacketNumber kSmallLargestObserved = UINT16_C(0x1234);
const QuicPacketNumber kSmallMissingPacket = UINT16_C(0x1233);
const QuicPacketNumber kLeastUnacked = UINT64_C(0x0123456789AA0);
const QuicStreamId kStreamId = UINT64_C(0x01020304);
const QuicStreamOffset kStreamOffset = UINT64_C(0xBA98FEDC32107654);
const QuicPublicResetNonceProof kNonceProof = UINT64_C(0xABCDEF0123456789);

// Index into the connection_id offset in the header.
const size_t kConnectionIdOffset = kPublicFlagsSize;
// Index into the version string in the header. (if present).
const size_t kVersionOffset = kConnectionIdOffset + PACKET_8BYTE_CONNECTION_ID;

// Size in bytes of the stream frame fields for an arbitrary StreamID and
// offset and the last frame in a packet.
size_t GetMinStreamFrameSize() {
  return kQuicFrameTypeSize + kQuicMaxStreamIdSize + kQuicMaxStreamOffsetSize;
}

// Index into the path id offset in the header (if present).
size_t GetPathIdOffset(QuicConnectionIdLength connection_id_length,
                       bool include_version) {
  return kConnectionIdOffset + connection_id_length +
         (include_version ? kQuicVersionSize : 0);
}

// Index into the packet number offset in the header.
size_t GetPacketNumberOffset(QuicConnectionIdLength connection_id_length,
                             bool include_version,
                             bool include_path_id) {
  return kConnectionIdOffset + connection_id_length +
         (include_version ? kQuicVersionSize : 0) +
         (include_path_id ? kQuicPathIdSize : 0);
}

size_t GetPacketNumberOffset(bool include_version, bool include_path_id) {
  return GetPacketNumberOffset(PACKET_8BYTE_CONNECTION_ID, include_version,
                               include_path_id);
}

// Index into the private flags offset in the data packet header.
size_t GetPrivateFlagsOffset(QuicConnectionIdLength connection_id_length,
                             bool include_version,
                             bool include_path_id) {
  return GetPacketNumberOffset(connection_id_length, include_version,
                               include_path_id) +
         PACKET_6BYTE_PACKET_NUMBER;
}

size_t GetPrivateFlagsOffset(bool include_version, bool include_path_id) {
  return GetPrivateFlagsOffset(PACKET_8BYTE_CONNECTION_ID, include_version,
                               include_path_id);
}

size_t GetPrivateFlagsOffset(bool include_version,
                             bool include_path_id,
                             QuicPacketNumberLength packet_number_length) {
  return GetPacketNumberOffset(PACKET_8BYTE_CONNECTION_ID, include_version,
                               include_path_id) +
         packet_number_length;
}

// Index into the message tag of the public reset packet.
// Public resets always have full connection_ids.
const size_t kPublicResetPacketMessageTagOffset =
    kConnectionIdOffset + PACKET_8BYTE_CONNECTION_ID;

class TestEncrypter : public QuicEncrypter {
 public:
  ~TestEncrypter() override {}
  bool SetKey(StringPiece key) override { return true; }
  bool SetNoncePrefix(StringPiece nonce_prefix) override { return true; }
  bool EncryptPacket(QuicPathId path_id,
                     QuicPacketNumber packet_number,
                     StringPiece associated_data,
                     StringPiece plaintext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override {
    path_id_ = path_id;
    packet_number_ = packet_number;
    associated_data_ = associated_data.as_string();
    plaintext_ = plaintext.as_string();
    memcpy(output, plaintext.data(), plaintext.length());
    *output_length = plaintext.length();
    return true;
  }
  size_t GetKeySize() const override { return 0; }
  size_t GetNoncePrefixSize() const override { return 0; }
  size_t GetMaxPlaintextSize(size_t ciphertext_size) const override {
    return ciphertext_size;
  }
  size_t GetCiphertextSize(size_t plaintext_size) const override {
    return plaintext_size;
  }
  StringPiece GetKey() const override { return StringPiece(); }
  StringPiece GetNoncePrefix() const override { return StringPiece(); }
  QuicPathId path_id_;
  QuicPacketNumber packet_number_;
  string associated_data_;
  string plaintext_;
};

class TestDecrypter : public QuicDecrypter {
 public:
  ~TestDecrypter() override {}
  bool SetKey(StringPiece key) override { return true; }
  bool SetNoncePrefix(StringPiece nonce_prefix) override { return true; }
  bool SetPreliminaryKey(StringPiece key) override {
    QUIC_BUG << "should not be called";
    return false;
  }
  bool SetDiversificationNonce(const DiversificationNonce& key) override {
    return true;
  }
  bool DecryptPacket(QuicPathId path_id,
                     QuicPacketNumber packet_number,
                     StringPiece associated_data,
                     StringPiece ciphertext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override {
    path_id_ = path_id;
    packet_number_ = packet_number;
    associated_data_ = associated_data.as_string();
    ciphertext_ = ciphertext.as_string();
    memcpy(output, ciphertext.data(), ciphertext.length());
    *output_length = ciphertext.length();
    return true;
  }
  StringPiece GetKey() const override { return StringPiece(); }
  StringPiece GetNoncePrefix() const override { return StringPiece(); }
  const char* cipher_name() const override { return "Test"; }
  // Use a distinct value starting with 0xFFFFFF, which is never used by TLS.
  uint32_t cipher_id() const override { return 0xFFFFFFF2; }
  QuicPathId path_id_;
  QuicPacketNumber packet_number_;
  string associated_data_;
  string ciphertext_;
};

class TestQuicVisitor : public QuicFramerVisitorInterface {
 public:
  TestQuicVisitor()
      : error_count_(0),
        version_mismatch_(0),
        packet_count_(0),
        frame_count_(0),
        complete_packets_(0),
        accept_packet_(true),
        accept_public_header_(true) {}

  ~TestQuicVisitor() override {}

  void OnError(QuicFramer* f) override {
    DVLOG(1) << "QuicFramer Error: " << QuicErrorCodeToString(f->error())
             << " (" << f->error() << ")";
    ++error_count_;
  }

  void OnPacket() override {}

  void OnPublicResetPacket(const QuicPublicResetPacket& packet) override {
    public_reset_packet_.reset(new QuicPublicResetPacket(packet));
  }

  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& packet) override {
    version_negotiation_packet_.reset(new QuicVersionNegotiationPacket(packet));
  }

  bool OnProtocolVersionMismatch(QuicVersion version) override {
    DVLOG(1) << "QuicFramer Version Mismatch, version: " << version;
    ++version_mismatch_;
    return true;
  }

  bool OnUnauthenticatedPublicHeader(
      const QuicPacketPublicHeader& header) override {
    public_header_.reset(new QuicPacketPublicHeader(header));
    return accept_public_header_;
  }

  bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override {
    return true;
  }

  void OnDecryptedPacket(EncryptionLevel level) override {}

  bool OnPacketHeader(const QuicPacketHeader& header) override {
    ++packet_count_;
    header_.reset(new QuicPacketHeader(header));
    return accept_packet_;
  }

  bool OnStreamFrame(const QuicStreamFrame& frame) override {
    ++frame_count_;
    // Save a copy of the data so it is valid after the packet is processed.
    string* string_data = new string();
    StringPiece(frame.data_buffer, frame.data_length)
        .AppendToString(string_data);
    stream_data_.push_back(base::WrapUnique(string_data));
    stream_frames_.push_back(base::MakeUnique<QuicStreamFrame>(
        frame.stream_id, frame.fin, frame.offset, *string_data));
    return true;
  }

  bool OnAckFrame(const QuicAckFrame& frame) override {
    ++frame_count_;
    ack_frames_.push_back(base::MakeUnique<QuicAckFrame>(frame));
    return true;
  }

  bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override {
    ++frame_count_;
    stop_waiting_frames_.push_back(
        base::MakeUnique<QuicStopWaitingFrame>(frame));
    return true;
  }

  bool OnPaddingFrame(const QuicPaddingFrame& frame) override {
    padding_frames_.push_back(base::MakeUnique<QuicPaddingFrame>(frame));
    return true;
  }

  bool OnPingFrame(const QuicPingFrame& frame) override {
    ++frame_count_;
    ping_frames_.push_back(base::MakeUnique<QuicPingFrame>(frame));
    return true;
  }

  void OnPacketComplete() override { ++complete_packets_; }

  bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override {
    rst_stream_frame_ = frame;
    return true;
  }

  bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override {
    connection_close_frame_ = frame;
    return true;
  }

  bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override {
    goaway_frame_ = frame;
    return true;
  }

  bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override {
    window_update_frame_ = frame;
    return true;
  }

  bool OnBlockedFrame(const QuicBlockedFrame& frame) override {
    blocked_frame_ = frame;
    return true;
  }

  bool OnPathCloseFrame(const QuicPathCloseFrame& frame) override {
    path_close_frame_ = frame;
    return true;
  }

  // Counters from the visitor_ callbacks.
  int error_count_;
  int version_mismatch_;
  int packet_count_;
  int frame_count_;
  int complete_packets_;
  bool accept_packet_;
  bool accept_public_header_;

  std::unique_ptr<QuicPacketHeader> header_;
  std::unique_ptr<QuicPacketPublicHeader> public_header_;
  std::unique_ptr<QuicPublicResetPacket> public_reset_packet_;
  std::unique_ptr<QuicVersionNegotiationPacket> version_negotiation_packet_;
  std::vector<std::unique_ptr<QuicStreamFrame>> stream_frames_;
  std::vector<std::unique_ptr<QuicAckFrame>> ack_frames_;
  std::vector<std::unique_ptr<QuicStopWaitingFrame>> stop_waiting_frames_;
  std::vector<std::unique_ptr<QuicPaddingFrame>> padding_frames_;
  std::vector<std::unique_ptr<QuicPingFrame>> ping_frames_;
  QuicRstStreamFrame rst_stream_frame_;
  QuicConnectionCloseFrame connection_close_frame_;
  QuicGoAwayFrame goaway_frame_;
  QuicWindowUpdateFrame window_update_frame_;
  QuicBlockedFrame blocked_frame_;
  QuicPathCloseFrame path_close_frame_;
  std::vector<std::unique_ptr<string>> stream_data_;
};

class QuicFramerTest : public ::testing::TestWithParam<QuicVersion> {
 public:
  QuicFramerTest()
      : encrypter_(new test::TestEncrypter()),
        decrypter_(new test::TestDecrypter()),
        start_(QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(0x10)),
        framer_(AllSupportedVersions(), start_, Perspective::IS_SERVER) {
    version_ = GetParam();
    framer_.set_version(version_);
    framer_.SetDecrypter(ENCRYPTION_NONE, decrypter_);
    framer_.SetEncrypter(ENCRYPTION_NONE, encrypter_);
    framer_.set_visitor(&visitor_);
  }

  // Helper function to get unsigned char representation of digit in the
  // units place of the current QUIC version number.
  unsigned char GetQuicVersionDigitOnes() {
    return static_cast<unsigned char>('0' + version_ % 10);
  }

  // Helper function to get unsigned char representation of digit in the
  // tens place of the current QUIC version number.
  unsigned char GetQuicVersionDigitTens() {
    return static_cast<unsigned char>('0' + (version_ / 10) % 10);
  }

  bool CheckEncryption(QuicPathId path_id,
                       QuicPacketNumber packet_number,
                       QuicPacket* packet) {
    if (packet_number != encrypter_->packet_number_) {
      LOG(ERROR) << "Encrypted incorrect packet number.  expected "
                 << packet_number << " actual: " << encrypter_->packet_number_;
      return false;
    }
    if (packet->AssociatedData(framer_.version()) !=
        encrypter_->associated_data_) {
      LOG(ERROR) << "Encrypted incorrect associated data.  expected "
                 << packet->AssociatedData(framer_.version())
                 << " actual: " << encrypter_->associated_data_;
      return false;
    }
    if (packet->Plaintext(framer_.version()) != encrypter_->plaintext_) {
      LOG(ERROR) << "Encrypted incorrect plaintext data.  expected "
                 << packet->Plaintext(framer_.version())
                 << " actual: " << encrypter_->plaintext_;
      return false;
    }
    return true;
  }

  bool CheckDecryption(const QuicEncryptedPacket& encrypted,
                       bool includes_version,
                       bool includes_path_id,
                       bool includes_diversification_nonce) {
    if (visitor_.header_->packet_number != decrypter_->packet_number_) {
      LOG(ERROR) << "Decrypted incorrect packet number.  expected "
                 << visitor_.header_->packet_number
                 << " actual: " << decrypter_->packet_number_;
      return false;
    }
    if (QuicFramer::GetAssociatedDataFromEncryptedPacket(
            framer_.version(), encrypted, PACKET_8BYTE_CONNECTION_ID,
            includes_version, includes_path_id, includes_diversification_nonce,
            PACKET_6BYTE_PACKET_NUMBER) != decrypter_->associated_data_) {
      LOG(ERROR) << "Decrypted incorrect associated data.  expected "
                 << QuicFramer::GetAssociatedDataFromEncryptedPacket(
                        framer_.version(), encrypted,
                        PACKET_8BYTE_CONNECTION_ID, includes_version,
                        includes_path_id, includes_diversification_nonce,
                        PACKET_6BYTE_PACKET_NUMBER)
                 << " actual: " << decrypter_->associated_data_;
      return false;
    }
    StringPiece ciphertext(
        encrypted.AsStringPiece().substr(GetStartOfEncryptedData(
            framer_.version(), PACKET_8BYTE_CONNECTION_ID, includes_version,
            includes_path_id, includes_diversification_nonce,
            PACKET_6BYTE_PACKET_NUMBER)));
    if (ciphertext != decrypter_->ciphertext_) {
      LOG(ERROR) << "Decrypted incorrect ciphertext data.  expected "
                 << ciphertext << " actual: " << decrypter_->ciphertext_;
      return false;
    }
    return true;
  }

  char* AsChars(unsigned char* data) { return reinterpret_cast<char*>(data); }

  void CheckProcessingFails(unsigned char* packet,
                            size_t len,
                            string expected_error,
                            QuicErrorCode error_code) {
    QuicEncryptedPacket encrypted(AsChars(packet), len, false);
    EXPECT_FALSE(framer_.ProcessPacket(encrypted)) << "len: " << len;
    EXPECT_EQ(expected_error, framer_.detailed_error()) << "len: " << len;
    EXPECT_EQ(error_code, framer_.error()) << "len: " << len;
  }

  // Checks if the supplied string matches data in the supplied StreamFrame.
  void CheckStreamFrameData(string str, QuicStreamFrame* frame) {
    EXPECT_EQ(str, string(frame->data_buffer, frame->data_length));
  }

  void CheckStreamFrameBoundaries(unsigned char* packet,
                                  size_t stream_id_size,
                                  bool include_version) {
    // Now test framing boundaries.
    for (size_t i = kQuicFrameTypeSize; i < GetMinStreamFrameSize(); ++i) {
      string expected_error;
      if (i < kQuicFrameTypeSize + stream_id_size) {
        expected_error = "Unable to read stream_id.";
      } else if (i < kQuicFrameTypeSize + stream_id_size +
                         kQuicMaxStreamOffsetSize) {
        expected_error = "Unable to read offset.";
      } else {
        expected_error = "Unable to read frame data.";
      }
      CheckProcessingFails(
          packet,
          i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                  include_version, !kIncludePathId,
                                  !kIncludeDiversificationNonce,
                                  PACKET_6BYTE_PACKET_NUMBER),
          expected_error, QUIC_INVALID_STREAM_DATA);
    }
  }

  void CheckCalculatePacketNumber(QuicPacketNumber expected_packet_number,
                                  QuicPacketNumber last_packet_number) {
    QuicPacketNumber wire_packet_number = expected_packet_number & kMask;
    QuicFramerPeer::SetLastPacketNumber(&framer_, last_packet_number);
    EXPECT_EQ(
        expected_packet_number,
        QuicFramerPeer::CalculatePacketNumberFromWire(
            &framer_, PACKET_6BYTE_PACKET_NUMBER,
            QuicFramerPeer::GetLastPacketNumber(&framer_), wire_packet_number))
        << "last_packet_number: " << last_packet_number
        << " wire_packet_number: " << wire_packet_number;
  }

  QuicPacket* BuildDataPacket(const QuicPacketHeader& header,
                              const QuicFrames& frames) {
    return BuildUnsizedDataPacket(&framer_, header, frames);
  }

  QuicPacket* BuildDataPacket(const QuicPacketHeader& header,
                              const QuicFrames& frames,
                              size_t packet_size) {
    return BuildUnsizedDataPacket(&framer_, header, frames, packet_size);
  }

  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  test::TestEncrypter* encrypter_;
  test::TestDecrypter* decrypter_;
  QuicVersion version_;
  QuicTime start_;
  QuicFramer framer_;
  test::TestQuicVisitor visitor_;
};

// Run all framer tests with all supported versions of QUIC.
INSTANTIATE_TEST_CASE_P(QuicFramerTests,
                        QuicFramerTest,
                        ::testing::ValuesIn(kSupportedQuicVersions));

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearEpochStart) {
  // A few quick manual sanity checks.
  CheckCalculatePacketNumber(UINT64_C(1), UINT64_C(0));
  CheckCalculatePacketNumber(kEpoch + 1, kMask);
  CheckCalculatePacketNumber(kEpoch, kMask);

  // Cases where the last number was close to the start of the range.
  for (uint64_t last = 0; last < 10; last++) {
    // Small numbers should not wrap (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(j, last);
    }

    // Large numbers should not wrap either (because we're near 0 already).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(kEpoch - 1 - j, last);
    }
  }
}

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearEpochEnd) {
  // Cases where the last number was close to the end of the range
  for (uint64_t i = 0; i < 10; i++) {
    QuicPacketNumber last = kEpoch - i;

    // Small numbers should wrap.
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(kEpoch + j, last);
    }

    // Large numbers should not (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(kEpoch - 1 - j, last);
    }
  }
}

// Next check where we're in a non-zero epoch to verify we handle
// reverse wrapping, too.
TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearPrevEpoch) {
  const uint64_t prev_epoch = 1 * kEpoch;
  const uint64_t cur_epoch = 2 * kEpoch;
  // Cases where the last number was close to the start of the range
  for (uint64_t i = 0; i < 10; i++) {
    uint64_t last = cur_epoch + i;
    // Small number should not wrap (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(cur_epoch + j, last);
    }

    // But large numbers should reverse wrap.
    for (uint64_t j = 0; j < 10; j++) {
      uint64_t num = kEpoch - 1 - j;
      CheckCalculatePacketNumber(prev_epoch + num, last);
    }
  }
}

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearNextEpoch) {
  const uint64_t cur_epoch = 2 * kEpoch;
  const uint64_t next_epoch = 3 * kEpoch;
  // Cases where the last number was close to the end of the range
  for (uint64_t i = 0; i < 10; i++) {
    QuicPacketNumber last = next_epoch - 1 - i;

    // Small numbers should wrap.
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(next_epoch + j, last);
    }

    // but large numbers should not (even if they're out of order).
    for (uint64_t j = 0; j < 10; j++) {
      uint64_t num = kEpoch - 1 - j;
      CheckCalculatePacketNumber(cur_epoch + num, last);
    }
  }
}

TEST_P(QuicFramerTest, CalculatePacketNumberFromWireNearNextMax) {
  const uint64_t max_number = std::numeric_limits<uint64_t>::max();
  const uint64_t max_epoch = max_number & ~kMask;

  // Cases where the last number was close to the end of the range
  for (uint64_t i = 0; i < 10; i++) {
    // Subtract 1, because the expected next packet number is 1 more than the
    // last packet number.
    QuicPacketNumber last = max_number - i - 1;

    // Small numbers should not wrap, because they have nowhere to go.
    for (uint64_t j = 0; j < 10; j++) {
      CheckCalculatePacketNumber(max_epoch + j, last);
    }

    // Large numbers should not wrap either.
    for (uint64_t j = 0; j < 10; j++) {
      uint64_t num = kEpoch - 1 - j;
      CheckCalculatePacketNumber(max_epoch + num, last);
    }
  }
}

TEST_P(QuicFramerTest, EmptyPacket) {
  char packet[] = {0x00};
  QuicEncryptedPacket encrypted(packet, 0, false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_INVALID_PACKET_HEADER, framer_.error());
}

TEST_P(QuicFramerTest, LargePacket) {
  // clang-format off
  unsigned char packet[kMaxPacketSize + 1] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
    // private flags
    0x00,
  };
  // clang-format on

  const size_t header_size = GetPacketHeaderSize(
      framer_.version(), PACKET_8BYTE_CONNECTION_ID, !kIncludeVersion,
      !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_6BYTE_PACKET_NUMBER);

  memset(packet + header_size, 0, kMaxPacketSize - header_size);

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_QUIC_BUG(framer_.ProcessPacket(encrypted), "Packet too large:1");

  ASSERT_TRUE(visitor_.header_.get());
  // Make sure we've parsed the packet header, so we can send an error.
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  // Make sure the correct error is propagated.
  EXPECT_EQ(QUIC_PACKET_TOO_LARGE, framer_.error());
}

TEST_P(QuicFramerTest, PacketHeader) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_FALSE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               !kIncludeVersion, !kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_6BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < GetPacketNumberOffset(!kIncludeVersion, !kIncludePathId)) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWith0ByteConnectionId) {
  QuicFramerPeer::SetLastSerializedConnectionId(&framer_, kConnectionId);

  // clang-format off
  unsigned char packet[] = {
    // public flags (0 byte connection_id)
    0x30,
    // connection_id
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_FALSE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_0BYTE_CONNECTION_ID,
                               !kIncludeVersion, !kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_6BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < GetPacketNumberOffset(PACKET_0BYTE_CONNECTION_ID,
                                         !kIncludeVersion, !kIncludePathId)) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWithVersionFlag) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version)
    0x39,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_FALSE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_TRUE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(GetParam(), visitor_.header_->public_header.versions[0]);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               kIncludeVersion, !kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_6BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < kVersionOffset) {
      expected_error = "Unable to read ConnectionId.";
    } else if (i < GetPacketNumberOffset(kIncludeVersion, !kIncludePathId)) {
      expected_error = "Unable to read protocol version.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWithMultipathFlag) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, kIncludePathId,
                              !kIncludeDiversificationNonce));
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_TRUE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(kPathId, visitor_.header_->path_id);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               !kIncludeVersion, kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_6BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i <
               GetPathIdOffset(PACKET_8BYTE_CONNECTION_ID, !kIncludeVersion)) {
      expected_error = "Unable to read ConnectionId.";
    } else if (i < GetPacketNumberOffset(!kIncludeVersion, kIncludePathId)) {
      expected_error = "Unable to read path id.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWithBothVersionFlagAndMultipathFlag) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version)
    0x79,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, kIncludeVersion, kIncludePathId,
                              !kIncludeDiversificationNonce));
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_TRUE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_TRUE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(GetParam(), visitor_.header_->public_header.versions[0]);
  EXPECT_EQ(kPathId, visitor_.header_->path_id);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               !kIncludeVersion, kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_6BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < kVersionOffset) {
      expected_error = "Unable to read ConnectionId.";
    } else if (i <
               GetPathIdOffset(PACKET_8BYTE_CONNECTION_ID, kIncludeVersion)) {
      expected_error = "Unable to read protocol version.";
    } else if (i < GetPacketNumberOffset(kIncludeVersion, kIncludePathId)) {
      expected_error = "Unable to read path id.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWithPathChange) {
  // Packet 1 from path 0x42.
  // clang-format off
  unsigned char packet1[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  EXPECT_EQ(0u, QuicFramerPeer::GetLastPacketNumber(&framer_));
  EXPECT_EQ(kInvalidPathId, QuicFramerPeer::GetLastPathId(&framer_));
  QuicEncryptedPacket encrypted1(AsChars(packet1), arraysize(packet1), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted1));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(kPathId, visitor_.header_->path_id);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);
  EXPECT_EQ(kPacketNumber, QuicFramerPeer::GetLastPacketNumber(&framer_));
  EXPECT_EQ(kPathId, QuicFramerPeer::GetLastPathId(&framer_));

  // Packet 2 from default path.
  // clang-format off
  unsigned char packet2[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x00,
    // packet number
    0xCC, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted2(AsChars(packet2), arraysize(packet2), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted2));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(kDefaultPathId, visitor_.header_->path_id);
  EXPECT_EQ(kPacketNumber + 16, visitor_.header_->packet_number);
  EXPECT_EQ(kPacketNumber + 16, QuicFramerPeer::GetLastPacketNumber(&framer_));
  EXPECT_EQ(kDefaultPathId, QuicFramerPeer::GetLastPathId(&framer_));

  // Packet 3 from path 0x42.
  // clang-format off
  unsigned char packet3[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x42,
    // packet number
    0xBD, 0x9A, 0x78, 0x56, 0x34, 0x12,
  };
  // clang-format on

  QuicEncryptedPacket encrypted3(AsChars(packet3), arraysize(packet3), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted3));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(kPathId, visitor_.header_->path_id);
  EXPECT_EQ(kPacketNumber + 1, visitor_.header_->packet_number);
  EXPECT_EQ(kPacketNumber + 1, QuicFramerPeer::GetLastPacketNumber(&framer_));
  EXPECT_EQ(kPathId, QuicFramerPeer::GetLastPathId(&framer_));
}

TEST_P(QuicFramerTest, ReceivedPacketOnClosedPath) {
  // Packet 1 from path 0x42.
  // clang-format off
  unsigned char packet[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
    // private flags
    0x00,
  };
  // clang-format on

  framer_.OnPathClosed(kPathId);
  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  EXPECT_EQ(0u, QuicFramerPeer::GetLastPacketNumber(&framer_));
  EXPECT_EQ(kInvalidPathId, QuicFramerPeer::GetLastPathId(&framer_));
}

TEST_P(QuicFramerTest, PacketHeaderWith4BytePacketNumber) {
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id and 4 byte packet number)
    0x28,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_FALSE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               !kIncludeVersion, !kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_4BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < GetPacketNumberOffset(!kIncludeVersion, !kIncludePathId)) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWith2BytePacketNumber) {
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id and 2 byte packet number)
    0x18,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_FALSE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            visitor_.header_->public_header.packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               !kIncludeVersion, !kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_2BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < GetPacketNumberOffset(!kIncludeVersion, !kIncludePathId)) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketHeaderWith1BytePacketNumber) {
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id and 1 byte packet number)
    0x08,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_MISSING_PAYLOAD, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_FALSE(visitor_.header_->public_header.multipath_flag);
  EXPECT_FALSE(visitor_.header_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            visitor_.header_->public_header.packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Now test framing boundaries.
  for (size_t i = 0;
       i < GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                               !kIncludeVersion, !kIncludePathId,
                               !kIncludeDiversificationNonce,
                               PACKET_1BYTE_PACKET_NUMBER);
       ++i) {
    string expected_error;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < GetPacketNumberOffset(!kIncludeVersion, !kIncludePathId)) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read packet number.";
    }
    CheckProcessingFails(packet, i, expected_error, QUIC_INVALID_PACKET_HEADER);
  }
}

TEST_P(QuicFramerTest, PacketNumberDecreasesThenIncreases) {
  // Test the case when a packet is received from the past and future packet
  // numbers are still calculated relative to the largest received packet.
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber - 2;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  QuicEncryptedPacket encrypted(data->data(), data->length(), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(PACKET_6BYTE_PACKET_NUMBER,
            visitor_.header_->public_header.packet_number_length);
  EXPECT_EQ(kPacketNumber - 2, visitor_.header_->packet_number);

  // Receive a 1 byte packet number.
  header.packet_number = kPacketNumber;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  data.reset(BuildDataPacket(header, frames));
  QuicEncryptedPacket encrypted1(data->data(), data->length(), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted1));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            visitor_.header_->public_header.packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  // Process a 2 byte packet number 256 packets ago.
  header.packet_number = kPacketNumber - 256;
  header.public_header.packet_number_length = PACKET_2BYTE_PACKET_NUMBER;
  data.reset(BuildDataPacket(header, frames));
  QuicEncryptedPacket encrypted2(data->data(), data->length(), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted2));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            visitor_.header_->public_header.packet_number_length);
  EXPECT_EQ(kPacketNumber - 256, visitor_.header_->packet_number);

  // Process another 1 byte packet number and ensure it works.
  header.packet_number = kPacketNumber - 1;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  data.reset(BuildDataPacket(header, frames));
  QuicEncryptedPacket encrypted3(data->data(), data->length(), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted3));
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(kConnectionId, visitor_.header_->public_header.connection_id);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            visitor_.header_->public_header.packet_number_length);
  EXPECT_EQ(kPacketNumber - 1, visitor_.header_->packet_number);
}

TEST_P(QuicFramerTest, PacketWithDiversificationNonce) {
  // clang-format off
  unsigned char packet[] = {
    // public flags: includes nonce flag
    0x7C,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // nonce
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

    // frame type (padding)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_TRUE(visitor_.public_header_->nonce != nullptr);
  for (char i = 0; i < 32; ++i) {
    EXPECT_EQ(i, (*visitor_.public_header_->nonce)[static_cast<int>(i)]);
  }
};

TEST_P(QuicFramerTest, LargePublicFlagWithMismatchedVersions) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id, version flag and an unknown flag)
    0x79,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', '0', '0',
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on
  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(0, visitor_.frame_count_);
  EXPECT_EQ(1, visitor_.version_mismatch_);
};

TEST_P(QuicFramerTest, PaddingFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (padding frame)
    0x00,
    // Ignored data (which in this case is a stream frame)
    // frame type (stream frame with fin)
    0xFF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // A packet with no frames is not acceptable.
  CheckProcessingFails(
      packet, GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                  !kIncludeVersion, !kIncludePathId,
                                  !kIncludeDiversificationNonce,
                                  PACKET_6BYTE_PACKET_NUMBER),
      "Packet has no frames.", QUIC_MISSING_PAYLOAD);
}

TEST_P(QuicFramerTest, StreamFrame) {
  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x38,
      // connection_id
      0x10, 0x32, 0x54, 0x76,
      0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56,
      0x34, 0x12,

      // frame type (stream frame with fin)
      0xFF,
      // stream id
      0x04, 0x03, 0x02, 0x01,
      // offset
      0x54, 0x76, 0x10, 0x32,
      0xDC, 0xFE, 0x98, 0xBA,
      // data length
      0x0c, 0x00,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  // Now test framing boundaries.
  CheckStreamFrameBoundaries(packet, kQuicMaxStreamIdSize, !kIncludeVersion);
}

TEST_P(QuicFramerTest, MissingDiversificationNonce) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  framer_.SetDecrypter(ENCRYPTION_NONE, new NullDecrypter());
  decrypter_ = new test::TestDecrypter();
  framer_.SetAlternativeDecrypter(ENCRYPTION_INITIAL, decrypter_, false);

  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x38,
      // connection_id
      0x10, 0x32, 0x54, 0x76,
      0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56,
      0x34, 0x12,

      // frame type (stream frame with fin)
      0xFF,
      // stream id
      0x04, 0x03, 0x02, 0x01,
      // offset
      0x54, 0x76, 0x10, 0x32,
      0xDC, 0xFE, 0x98, 0xBA,
      // data length
      0x0c, 0x00,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_DECRYPTION_FAILURE, framer_.error());
}

TEST_P(QuicFramerTest, StreamFrame3ByteStreamId) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin)
    0xFE,
    // stream id
    0x04, 0x03, 0x02,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  // Now test framing boundaries.
  const size_t stream_id_size = 3;
  CheckStreamFrameBoundaries(packet, stream_id_size, !kIncludeVersion);
}

TEST_P(QuicFramerTest, StreamFrame2ByteStreamId) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin)
    0xFD,
    // stream id
    0x04, 0x03,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // Stream ID should be the last 2 bytes of kStreamId.
  EXPECT_EQ(0x0000FFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  // Now test framing boundaries.
  const size_t stream_id_size = 2;
  CheckStreamFrameBoundaries(packet, stream_id_size, !kIncludeVersion);
}

TEST_P(QuicFramerTest, StreamFrame1ByteStreamId) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin)
    0xFC,
    // stream id
    0x04,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  // Stream ID should be the last byte of kStreamId.
  EXPECT_EQ(0x000000FF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  // Now test framing boundaries.
  const size_t stream_id_size = 1;
  CheckStreamFrameBoundaries(packet, stream_id_size, !kIncludeVersion);
}

TEST_P(QuicFramerTest, StreamFrameWithVersion) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version, 8 byte connection_id)
    0x39,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin)
    0xFF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(visitor_.header_->public_header.version_flag);
  EXPECT_EQ(GetParam(), visitor_.header_->public_header.versions[0]);
  EXPECT_TRUE(CheckDecryption(encrypted, kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
  EXPECT_EQ(kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  // Now test framing boundaries.
  CheckStreamFrameBoundaries(packet, kQuicMaxStreamIdSize, kIncludeVersion);
}

TEST_P(QuicFramerTest, RejectPacket) {
  visitor_.accept_packet_ = false;

  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x38,
      // connection_id
      0x10, 0x32, 0x54, 0x76,
      0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56,
      0x34, 0x12,

      // frame type (stream frame with fin)
      0xFF,
      // stream id
      0x04, 0x03, 0x02, 0x01,
      // offset
      0x54, 0x76, 0x10, 0x32,
      0xDC, 0xFE, 0x98, 0xBA,
      // data length
      0x0c, 0x00,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  ASSERT_EQ(0u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());
}

TEST_P(QuicFramerTest, RejectPublicHeader) {
  visitor_.accept_public_header_ = false;

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.public_header_.get());
  ASSERT_FALSE(visitor_.header_.get());
}

TEST_P(QuicFramerTest, AckFrameOneAckBlock) {
  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x3C,
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

      // frame type (ack frame)
      // (one ack block, 2 byte largest observed, 2 byte block length)
      0x45,
      // largest acked
      0x34, 0x12,
      // Zero delta time.
      0x00, 0x00,
      // first ack block length.
      0x34, 0x12,
      // num timestamps.
      0x00,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0].get();
  EXPECT_EQ(kSmallLargestObserved, frame.largest_observed);
  ASSERT_EQ(4660u, frame.packets.NumPacketsSlow());

  const size_t kLargestAckedOffset = kQuicFrameTypeSize;
  const size_t kLargestAckedDeltaTimeOffset =
      kLargestAckedOffset + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kFirstAckBlockLengthOffset =
      kLargestAckedDeltaTimeOffset + kQuicDeltaTimeLargestObservedSize;
  const size_t kNumTimestampsOffset =
      kFirstAckBlockLengthOffset + PACKET_2BYTE_PACKET_NUMBER;
  // Now test framing boundaries.
  const size_t ack_frame_size =
      kFirstAckBlockLengthOffset + PACKET_2BYTE_PACKET_NUMBER;
  for (size_t i = kQuicFrameTypeSize; i < ack_frame_size; ++i) {
    string expected_error;
    if (i < kLargestAckedDeltaTimeOffset) {
      expected_error = "Unable to read largest acked.";
    } else if (i < kFirstAckBlockLengthOffset) {
      expected_error = "Unable to read ack delay time.";
    } else if (i < kNumTimestampsOffset) {
      expected_error = "Unable to read first ack block length.";
    } else {
      expected_error = "Unable to read num received packets.";
    }
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_ACK_DATA);
  }
}

TEST_P(QuicFramerTest, AckFrameTwoTimeStampsMultipleAckBlocks) {
  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x3C,
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

      // frame type (ack frame)
      // (more than one ack block, 2 byte largest observed, 2 byte block length)
      0x65,
      // largest acked
      0x34, 0x12,
      // Zero delta time.
      0x00, 0x00,
      // num ack blocks ranges.
      0x04,
      // first ack block length.
      0x01, 0x00,
      // gap to next block.
      0x01,
      // ack block length.
      0xaf, 0x0e,
      // gap to next block.
      0xff,
      // ack block length.
      0x00, 0x00,
      // gap to next block.
      0x91,
      // ack block length.
      0xea, 0x01,
      // gap to next block.
      0x05,
      // ack block length.
      0x04, 0x00,
      // Number of timestamps.
      0x02,
      // Delta from largest observed.
      0x01,
      // Delta time.
      0x10, 0x32, 0x54, 0x76,
      // Delta from largest observed.
      0x02,
      // Delta time.
      0x10, 0x32,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  const QuicAckFrame& frame = *visitor_.ack_frames_[0].get();
  EXPECT_EQ(kSmallLargestObserved, frame.largest_observed);
  ASSERT_EQ(4254u, frame.packets.NumPacketsSlow());

  const size_t kLargestAckedOffset = kQuicFrameTypeSize;
  const size_t kLargestAckedDeltaTimeOffset =
      kLargestAckedOffset + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kNumberOfAckBlocksOffset =
      kLargestAckedDeltaTimeOffset + kQuicDeltaTimeLargestObservedSize;
  const size_t kFirstAckBlockLengthOffset =
      kNumberOfAckBlocksOffset + kNumberOfAckBlocksSize;
  const size_t kGapToNextBlockOffset1 =
      kFirstAckBlockLengthOffset + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kAckBlockLengthOffset1 = kGapToNextBlockOffset1 + 1;
  const size_t kGapToNextBlockOffset2 =
      kAckBlockLengthOffset1 + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kAckBlockLengthOffset2 = kGapToNextBlockOffset2 + 1;
  const size_t kGapToNextBlockOffset3 =
      kAckBlockLengthOffset2 + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kAckBlockLengthOffset3 = kGapToNextBlockOffset3 + 1;
  const size_t kGapToNextBlockOffset4 =
      kAckBlockLengthOffset3 + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kAckBlockLengthOffset4 = kGapToNextBlockOffset3 + 1;
  const size_t kNumTimestampsOffset =
      kAckBlockLengthOffset4 + PACKET_2BYTE_PACKET_NUMBER;
  const size_t kTimestampDeltaLargestObserved1 =
      kNumTimestampsOffset + kQuicNumTimestampsSize;
  const size_t kTimestampTimeDeltaLargestObserved1 =
      kTimestampDeltaLargestObserved1 + 1;
  const size_t kTimestampDeltaLargestObserved2 =
      kTimestampTimeDeltaLargestObserved1 + 4;
  const size_t kTimestampTimeDeltaLargestObserved2 =
      kTimestampDeltaLargestObserved2 + 1;

  // Now test framing boundaries.
  const size_t ack_frame_size =
      kAckBlockLengthOffset4 + PACKET_2BYTE_PACKET_NUMBER;
  for (size_t i = kQuicFrameTypeSize; i < ack_frame_size; ++i) {
    string expected_error;
    if (i < kLargestAckedDeltaTimeOffset) {
      expected_error = "Unable to read largest acked.";
    } else if (i < kNumberOfAckBlocksOffset) {
      expected_error = "Unable to read ack delay time.";
    } else if (i < kFirstAckBlockLengthOffset) {
      expected_error = "Unable to read num of ack blocks.";
    } else if (i < kGapToNextBlockOffset1) {
      expected_error = "Unable to read first ack block length.";
    } else if (i < kAckBlockLengthOffset1) {
      expected_error = "Unable to read gap to next ack block.";
    } else if (i < kGapToNextBlockOffset2) {
      expected_error = "Unable to ack block length.";
    } else if (i < kAckBlockLengthOffset2) {
      expected_error = "Unable to read gap to next ack block.";
    } else if (i < kGapToNextBlockOffset3) {
      expected_error = "Unable to ack block length.";
    } else if (i < kAckBlockLengthOffset3) {
      expected_error = "Unable to read gap to next ack block.";
    } else if (i < kGapToNextBlockOffset4) {
      expected_error = "Unable to ack block length.";
    } else if (i < kAckBlockLengthOffset4) {
      expected_error = "Unable to read gap to next ack block.";
    } else if (i < kNumTimestampsOffset) {
      expected_error = "Unable to ack block length.";
    } else if (i < kTimestampDeltaLargestObserved1) {
      expected_error = "Unable to read num received packets.";
    } else if (i < kTimestampTimeDeltaLargestObserved1) {
      expected_error = "Unable to read sequence delta in received packets.";
    } else if (i < kTimestampDeltaLargestObserved2) {
      expected_error = "Unable to read time delta in received packets.";
    } else if (i < kTimestampTimeDeltaLargestObserved2) {
      expected_error = "Unable to read sequence delta in received packets.";
    } else {
      expected_error =
          "Unable to read incremental time delta in received packets.";
    }

    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_ACK_DATA);
  }
}

TEST_P(QuicFramerTest, NewStopWaitingFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x3C,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xA8, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // frame type (stop waiting frame)
    0x06,
    // least packet number awaiting an ack, delta from packet number.
    0x08, 0x00, 0x00, 0x00,
    0x00, 0x00,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());
  ASSERT_EQ(1u, visitor_.stop_waiting_frames_.size());
  const QuicStopWaitingFrame& frame = *visitor_.stop_waiting_frames_[0].get();
  EXPECT_EQ(kLeastUnacked, frame.least_unacked);

  const size_t frame_size = 7;
  for (size_t i = kQuicFrameTypeSize; i < frame_size; ++i) {
    string expected_error;
    expected_error = "Unable to read least unacked delta.";
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_STOP_WAITING_DATA);
  }
}

TEST_P(QuicFramerTest, RstStreamFrameQuic) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (rst stream frame)
    0x01,
    // stream id
    0x04, 0x03, 0x02, 0x01,

    // sent byte offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,

    // error code
    0x01, 0x00, 0x00, 0x00,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(kStreamId, visitor_.rst_stream_frame_.stream_id);
  EXPECT_EQ(0x01, visitor_.rst_stream_frame_.error_code);
  EXPECT_EQ(kStreamOffset, visitor_.rst_stream_frame_.byte_offset);

  // Now test framing boundaries.
  for (size_t i = kQuicFrameTypeSize; i < QuicFramer::GetRstStreamFrameSize();
       ++i) {
    string expected_error;
    if (i < kQuicFrameTypeSize + kQuicMaxStreamIdSize) {
      expected_error = "Unable to read stream_id.";
    } else if (i < kQuicFrameTypeSize + kQuicMaxStreamIdSize +
                       kQuicMaxStreamOffsetSize) {
      expected_error = "Unable to read rst stream sent byte offset.";
    } else if (i < kQuicFrameTypeSize + kQuicMaxStreamIdSize +
                       kQuicMaxStreamOffsetSize + kQuicErrorCodeSize) {
      expected_error = "Unable to read rst stream error code.";
    }
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_RST_STREAM_DATA);
  }
}

TEST_P(QuicFramerTest, ConnectionCloseFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (connection close frame)
    0x02,
    // error code
    0x11, 0x00, 0x00, 0x00,

    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());

  EXPECT_EQ(0x11, visitor_.connection_close_frame_.error_code);
  EXPECT_EQ("because I can", visitor_.connection_close_frame_.error_details);

  ASSERT_EQ(0u, visitor_.ack_frames_.size());

  // Now test framing boundaries.
  for (size_t i = kQuicFrameTypeSize;
       i < QuicFramer::GetMinConnectionCloseFrameSize(); ++i) {
    string expected_error;
    if (i < kQuicFrameTypeSize + kQuicErrorCodeSize) {
      expected_error = "Unable to read connection close error code.";
    } else {
      expected_error = "Unable to read connection close error details.";
    }
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_CONNECTION_CLOSE_DATA);
  }
}

TEST_P(QuicFramerTest, GoAwayFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (go away frame)
    0x03,
    // error code
    0x09, 0x00, 0x00, 0x00,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(kStreamId, visitor_.goaway_frame_.last_good_stream_id);
  EXPECT_EQ(0x9, visitor_.goaway_frame_.error_code);
  EXPECT_EQ("because I can", visitor_.goaway_frame_.reason_phrase);

  const size_t reason_size = arraysize("because I can") - 1;
  // Now test framing boundaries.
  for (size_t i = kQuicFrameTypeSize;
       i < QuicFramer::GetMinGoAwayFrameSize() + reason_size; ++i) {
    string expected_error;
    if (i < kQuicFrameTypeSize + kQuicErrorCodeSize) {
      expected_error = "Unable to read go away error code.";
    } else if (i <
               kQuicFrameTypeSize + kQuicErrorCodeSize + kQuicMaxStreamIdSize) {
      expected_error = "Unable to read last good stream id.";
    } else {
      expected_error = "Unable to read goaway reason.";
    }
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_GOAWAY_DATA);
  }
}

TEST_P(QuicFramerTest, WindowUpdateFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (window update frame)
    0x04,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // byte offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(kStreamId, visitor_.window_update_frame_.stream_id);
  EXPECT_EQ(kStreamOffset, visitor_.window_update_frame_.byte_offset);

  // Now test framing boundaries.
  for (size_t i = kQuicFrameTypeSize;
       i < QuicFramer::GetWindowUpdateFrameSize(); ++i) {
    string expected_error;
    if (i < kQuicFrameTypeSize + kQuicMaxStreamIdSize) {
      expected_error = "Unable to read stream_id.";
    } else {
      expected_error = "Unable to read window byte_offset.";
    }
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_WINDOW_UPDATE_DATA);
  }
}

TEST_P(QuicFramerTest, BlockedFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (blocked frame)
    0x05,
    // stream id
    0x04, 0x03, 0x02, 0x01,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(kStreamId, visitor_.blocked_frame_.stream_id);

  // Now test framing boundaries.
  for (size_t i = kQuicFrameTypeSize; i < QuicFramer::GetBlockedFrameSize();
       ++i) {
    string expected_error = "Unable to read stream_id.";
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, !kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_BLOCKED_DATA);
  }
}

TEST_P(QuicFramerTest, PingFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (ping frame)
    0x07,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(encrypted, !kIncludeVersion, !kIncludePathId,
                              !kIncludeDiversificationNonce));

  EXPECT_EQ(1u, visitor_.ping_frames_.size());

  // No need to check the PING frame boundaries because it has no payload.
}

TEST_P(QuicFramerTest, PathCloseFrame) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x00,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

    // frame type (path_close_frame)
    0x08,
    // path id
    0x42,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.header_.get());
  // TODO(fayang): CheckDecryption after cl/110553865 is landed.
  EXPECT_EQ(kPathId, visitor_.path_close_frame_.path_id);

  // Now test framing boundaries.
  for (size_t i = kQuicFrameTypeSize; i < QuicFramer::GetPathCloseFrameSize();
       ++i) {
    string expected_error;
    if (i < kQuicFrameTypeSize + kQuicPathIdSize) {
      expected_error = "Unable to read path_id.";
    }
    CheckProcessingFails(
        packet,
        i + GetPacketHeaderSize(framer_.version(), PACKET_8BYTE_CONNECTION_ID,
                                !kIncludeVersion, kIncludePathId,
                                !kIncludeDiversificationNonce,
                                PACKET_6BYTE_PACKET_NUMBER),
        expected_error, QUIC_INVALID_PATH_CLOSE_DATA);
  }
}

TEST_P(QuicFramerTest, PublicResetPacketV33) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte connection_id)
    0x0A,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (2) + padding
    0x02, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.public_reset_packet_.get());
  EXPECT_EQ(kConnectionId,
            visitor_.public_reset_packet_->public_header.connection_id);
  EXPECT_TRUE(visitor_.public_reset_packet_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.public_reset_packet_->public_header.version_flag);
  EXPECT_EQ(kNonceProof, visitor_.public_reset_packet_->nonce_proof);
  EXPECT_EQ(0u, visitor_.public_reset_packet_->rejected_packet_number);
  EXPECT_EQ(
      IpAddressFamily::IP_UNSPEC,
      visitor_.public_reset_packet_->client_address.host().address_family());

  // Now test framing boundaries.
  for (size_t i = 0; i < arraysize(packet); ++i) {
    string expected_error;
    DVLOG(1) << "iteration: " << i;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PACKET_HEADER);
    } else if (i < kPublicResetPacketMessageTagOffset) {
      expected_error = "Unable to read ConnectionId.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PACKET_HEADER);
    } else {
      expected_error = "Unable to read reset message.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PUBLIC_RST_PACKET);
    }
  }
}

TEST_P(QuicFramerTest, PublicResetPacket) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte connection_id)
    0x0E,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (2) + padding
    0x02, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.public_reset_packet_.get());
  EXPECT_EQ(kConnectionId,
            visitor_.public_reset_packet_->public_header.connection_id);
  EXPECT_TRUE(visitor_.public_reset_packet_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.public_reset_packet_->public_header.version_flag);
  EXPECT_EQ(kNonceProof, visitor_.public_reset_packet_->nonce_proof);
  EXPECT_EQ(0u, visitor_.public_reset_packet_->rejected_packet_number);
  EXPECT_EQ(
      IpAddressFamily::IP_UNSPEC,
      visitor_.public_reset_packet_->client_address.host().address_family());

  // Now test framing boundaries.
  for (size_t i = 0; i < arraysize(packet); ++i) {
    string expected_error;
    DVLOG(1) << "iteration: " << i;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PACKET_HEADER);
    } else if (i < kPublicResetPacketMessageTagOffset) {
      expected_error = "Unable to read ConnectionId.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PACKET_HEADER);
    } else {
      expected_error = "Unable to read reset message.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PUBLIC_RST_PACKET);
    }
  }
}

TEST_P(QuicFramerTest, PublicResetPacketWithTrailingJunk) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte connection_id)
    0x0A,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (2) + padding
    0x02, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
    // trailing junk
    'j', 'u', 'n', 'k',
  };
  // clang-format on

  string expected_error = "Unable to read reset message.";
  CheckProcessingFails(packet, arraysize(packet), expected_error,
                       QUIC_INVALID_PUBLIC_RST_PACKET);
}

TEST_P(QuicFramerTest, PublicResetPacketWithClientAddress) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte connection_id)
    0x0A,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (3) + padding
    0x03, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // tag kCADR
    'C', 'A', 'D', 'R',
    // end offset 24
    0x18, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
    // client address: 4.31.198.44:443
    0x02, 0x00,
    0x04, 0x1F, 0xC6, 0x2C,
    0xBB, 0x01,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.public_reset_packet_.get());
  EXPECT_EQ(kConnectionId,
            visitor_.public_reset_packet_->public_header.connection_id);
  EXPECT_TRUE(visitor_.public_reset_packet_->public_header.reset_flag);
  EXPECT_FALSE(visitor_.public_reset_packet_->public_header.version_flag);
  EXPECT_EQ(kNonceProof, visitor_.public_reset_packet_->nonce_proof);
  EXPECT_EQ(0u, visitor_.public_reset_packet_->rejected_packet_number);
  EXPECT_EQ("4.31.198.44",
            visitor_.public_reset_packet_->client_address.host().ToString());
  EXPECT_EQ(443, visitor_.public_reset_packet_->client_address.port());

  // Now test framing boundaries.
  for (size_t i = 0; i < arraysize(packet); ++i) {
    string expected_error;
    DVLOG(1) << "iteration: " << i;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PACKET_HEADER);
    } else if (i < kPublicResetPacketMessageTagOffset) {
      expected_error = "Unable to read ConnectionId.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PACKET_HEADER);
    } else {
      expected_error = "Unable to read reset message.";
      CheckProcessingFails(packet, i, expected_error,
                           QUIC_INVALID_PUBLIC_RST_PACKET);
    }
  }
}

TEST_P(QuicFramerTest, VersionNegotiationPacket) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version, 8 byte connection_id)
    0x39,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
    'Q', '2', '.', '0',
  };
  // clang-format on

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.version_negotiation_packet_.get());
  EXPECT_EQ(2u, visitor_.version_negotiation_packet_->versions.size());
  EXPECT_EQ(GetParam(), visitor_.version_negotiation_packet_->versions[0]);

  for (size_t i = 0; i <= kPublicFlagsSize + PACKET_8BYTE_CONNECTION_ID; ++i) {
    string expected_error;
    QuicErrorCode error_code = QUIC_INVALID_PACKET_HEADER;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < kVersionOffset) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read supported version in negotiation.";
      error_code = QUIC_INVALID_VERSION_NEGOTIATION_PACKET;
    }
    CheckProcessingFails(packet, i, expected_error, error_code);
  }
}

TEST_P(QuicFramerTest, OldVersionNegotiationPacket) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (version, 8 byte connection_id)
    0x3D,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
    'Q', '2', '.', '0',
  };
  // clang-format on

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_EQ(QUIC_NO_ERROR, framer_.error());
  ASSERT_TRUE(visitor_.version_negotiation_packet_.get());
  EXPECT_EQ(2u, visitor_.version_negotiation_packet_->versions.size());
  EXPECT_EQ(GetParam(), visitor_.version_negotiation_packet_->versions[0]);

  for (size_t i = 0; i <= kPublicFlagsSize + PACKET_8BYTE_CONNECTION_ID; ++i) {
    string expected_error;
    QuicErrorCode error_code = QUIC_INVALID_PACKET_HEADER;
    if (i < kConnectionIdOffset) {
      expected_error = "Unable to read public flags.";
    } else if (i < kVersionOffset) {
      expected_error = "Unable to read ConnectionId.";
    } else {
      expected_error = "Unable to read supported version in negotiation.";
      error_code = QUIC_INVALID_VERSION_NEGOTIATION_PACKET;
    }
    CheckProcessingFails(packet, i, expected_error, error_code);
  }
}

TEST_P(QuicFramerTest, BuildPaddingFramePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxPacketSize] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  uint64_t header_size = GetPacketHeaderSize(
      framer_.version(), PACKET_8BYTE_CONNECTION_ID, !kIncludeVersion,
      !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_6BYTE_PACKET_NUMBER);
  memset(packet + header_size + 1, 0x00, kMaxPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, Build4ByteSequenceNumberPaddingFramePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.public_header.packet_number_length = PACKET_4BYTE_PACKET_NUMBER;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxPacketSize] = {
    // public flags (8 byte connection_id and 4 byte packet number)
    0x28,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  uint64_t header_size = GetPacketHeaderSize(
      framer_.version(), PACKET_8BYTE_CONNECTION_ID, !kIncludeVersion,
      !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_4BYTE_PACKET_NUMBER);
  memset(packet + header_size + 1, 0x00, kMaxPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, Build2ByteSequenceNumberPaddingFramePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.public_header.packet_number_length = PACKET_2BYTE_PACKET_NUMBER;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxPacketSize] = {
    // public flags (8 byte connection_id and 2 byte packet number)
    0x18,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  uint64_t header_size = GetPacketHeaderSize(
      framer_.version(), PACKET_8BYTE_CONNECTION_ID, !kIncludeVersion,
      !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_2BYTE_PACKET_NUMBER);
  memset(packet + header_size + 1, 0x00, kMaxPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, Build1ByteSequenceNumberPaddingFramePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.public_header.packet_number_length = PACKET_1BYTE_PACKET_NUMBER;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPaddingFrame())};

  // clang-format off
  unsigned char packet[kMaxPacketSize] = {
    // public flags (8 byte connection_id and 1 byte packet number)
    0x08,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC,

    // frame type (padding frame)
    0x00,
    0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  uint64_t header_size = GetPacketHeaderSize(
      framer_.version(), PACKET_8BYTE_CONNECTION_ID, !kIncludeVersion,
      !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_1BYTE_PACKET_NUMBER);
  memset(packet + header_size + 1, 0x00, kMaxPacketSize - header_size - 1);

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildStreamFramePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicStreamFrame stream_frame(kStreamId, true, kStreamOffset,
                               StringPiece("hello world!"));

  QuicFrames frames = {QuicFrame(&stream_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin and no length)
    0xDF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildStreamFramePacketWithVersionFlag) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = true;
  header.packet_number = kPacketNumber;

  QuicStreamFrame stream_frame(kStreamId, true, kStreamOffset,
                               StringPiece("hello world!"));
  QuicFrames frames = {QuicFrame(&stream_frame)};

  // clang-format off
  unsigned char packet[] = {
      // public flags (version, 8 byte connection_id)
      static_cast<unsigned char>(
          FLAGS_quic_remove_v33_hacks2 ? 0x39 : 0x3D),
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // version tag
      'Q', '0',  GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
      // packet number
      0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

      // frame type (stream frame with fin and no length)
      0xDF,
      // stream id
      0x04, 0x03, 0x02, 0x01,
      // offset
      0x54, 0x76, 0x10, 0x32, 0xDC, 0xFE, 0x98, 0xBA,
      // data
      'h',  'e',  'l',  'l',  'o',  ' ',  'w',  'o',  'r', 'l', 'd', '!',
  };
  // clang-format on

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildStreamFramePacketWithMultipathFlag) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.multipath_flag = true;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.path_id = kPathId;
  header.packet_number = kPacketNumber;

  QuicStreamFrame stream_frame(kStreamId, true, kStreamOffset,
                               StringPiece("hello world!"));
  QuicFrames frames = {QuicFrame(&stream_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin and no length)
    0xDF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildStreamFramePacketWithBothVersionAndMultipathFlag) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.multipath_flag = true;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = true;
  header.path_id = kPathId;
  header.packet_number = kPacketNumber;

  QuicStreamFrame stream_frame(kStreamId, true, kStreamOffset,
                               StringPiece("hello world!"));
  QuicFrames frames = {QuicFrame(&stream_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    static_cast<unsigned char>(
        FLAGS_quic_remove_v33_hacks2 ? 0x79 : 0x7D),
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '0', GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin and no length)
    0xDF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildVersionNegotiationPacket) {
  // clang-format off
  unsigned char packet[] = {
      // public flags (version, 8 byte connection_id)
      0x0D,
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // version tag
      'Q', '0',  GetQuicVersionDigitTens(), GetQuicVersionDigitOnes(),
  };
  // clang-format on

  QuicConnectionId connection_id = kConnectionId;
  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildVersionNegotiationPacket(connection_id,
                                            SupportedVersions(GetParam())));
  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildAckFramePacketOneAckBlock) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = kSmallLargestObserved;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ack_frame.packets.Add(1, kSmallLargestObserved + 1);

  QuicFrames frames = {QuicFrame(&ack_frame)};

  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x38,
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

      // frame type (ack frame)
      // (no ack blocks, 2 byte largest observed, 2 byte block length)
      0x45,
      // largest acked
      0x34, 0x12,
      // Zero delta time.
      0x00, 0x00,
      // first ack block length.
      0x34, 0x12,
      // num timestamps.
      0x00,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildAckFramePacketMultipleAckBlocks) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObserved to make this test finished in a short time.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = kSmallLargestObserved;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  ack_frame.packets.Add(1, 5);
  ack_frame.packets.Add(10, 500);
  ack_frame.packets.Add(900, kSmallMissingPacket);
  ack_frame.packets.Add(kSmallMissingPacket + 1, kSmallLargestObserved + 1);

  QuicFrames frames = {QuicFrame(&ack_frame)};

  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x38,
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

      // frame type (ack frame)
      // (has ack blocks, 2 byte largest observed, 2 byte block length)
      0x65,
      // largest acked
      0x34, 0x12,
      // Zero delta time.
      0x00, 0x00,
      // num ack blocks ranges.
      0x04,
      // first ack block length.
      0x01, 0x00,
      // gap to next block.
      0x01,
      // ack block length.
      0xaf, 0x0e,
      // gap to next block.
      0xff,
      // ack block length.
      0x00, 0x00,
      // gap to next block.
      0x91,
      // ack block length.
      0xea, 0x01,
      // gap to next block.
      0x05,
      // ack block length.
      0x04, 0x00,
      // num timestamps.
      0x00,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildAckFramePacketMaxAckBlocks) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Use kSmallLargestObservedto make this test finished in a short time.
  QuicAckFrame ack_frame;
  ack_frame.largest_observed = kSmallLargestObserved;
  ack_frame.ack_delay_time = QuicTime::Delta::Zero();
  // 300 ack blocks.
  for (size_t i = 2; i < 2 * 300; i += 2) {
    ack_frame.packets.Add(i);
  }
  ack_frame.packets.Add(600, kSmallLargestObserved + 1);

  QuicFrames frames = {QuicFrame(&ack_frame)};

  // clang-format off
  unsigned char packet[] = {
      // public flags (8 byte connection_id)
      0x38,
      // connection_id
      0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
      // packet number
      0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
      // frame type (ack frame)
      // (has ack blocks, 2 byte largest observed, 2 byte block length)
      0x65,
      // largest acked
      0x34, 0x12,
      // Zero delta time.
      0x00, 0x00,
      // num ack blocks ranges.
      0xff,
      // first ack block length.
      0xdd, 0x0f,
      // 255 = 4 * 63 + 3
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,

      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,

      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,

      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,

      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,

      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,

      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00,
      // num timestamps.
      0x00,
  };

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildNewStopWaitingPacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicStopWaitingFrame stop_waiting_frame;
  stop_waiting_frame.least_unacked = kLeastUnacked;

  QuicFrames frames = {QuicFrame(&stop_waiting_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

    // frame type (stop waiting frame)
    0x06,
    // least packet number awaiting an ack, delta from packet number.
    0x1C, 0x00, 0x00, 0x00,
    0x00, 0x00,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildRstFramePacketQuic) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicRstStreamFrame rst_frame;
  rst_frame.stream_id = kStreamId;
  rst_frame.error_code = static_cast<QuicRstStreamErrorCode>(0x05060708);
  rst_frame.byte_offset = 0x0807060504030201;

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (rst stream frame)
    0x01,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // sent byte offset
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    // error code
    0x08, 0x07, 0x06, 0x05,
  };
  // clang-format on

  QuicFrames frames = {QuicFrame(&rst_frame)};

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildCloseFramePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicConnectionCloseFrame close_frame;
  close_frame.error_code = static_cast<QuicErrorCode>(0x05060708);
  close_frame.error_details = "because I can";

  QuicFrames frames = {QuicFrame(&close_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (connection close frame)
    0x02,
    // error code
    0x08, 0x07, 0x06, 0x05,
    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildGoAwayPacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicGoAwayFrame goaway_frame;
  goaway_frame.error_code = static_cast<QuicErrorCode>(0x05060708);
  goaway_frame.last_good_stream_id = kStreamId;
  goaway_frame.reason_phrase = "because I can";

  QuicFrames frames = {QuicFrame(&goaway_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (go away frame)
    0x03,
    // error code
    0x08, 0x07, 0x06, 0x05,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // error details length
    0x0d, 0x00,
    // error details
    'b',  'e',  'c',  'a',
    'u',  's',  'e',  ' ',
    'I',  ' ',  'c',  'a',
    'n',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildWindowUpdatePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicWindowUpdateFrame window_update_frame;
  window_update_frame.stream_id = kStreamId;
  window_update_frame.byte_offset = 0x1122334455667788;

  QuicFrames frames = {QuicFrame(&window_update_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (window update frame)
    0x04,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // byte offset
    0x88, 0x77, 0x66, 0x55,
    0x44, 0x33, 0x22, 0x11,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildBlockedPacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicBlockedFrame blocked_frame;
  blocked_frame.stream_id = kStreamId;

  QuicFrames frames = {QuicFrame(&blocked_frame)};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (blocked frame)
    0x05,
    // stream id
    0x04, 0x03, 0x02, 0x01,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildPingPacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicPingFrame())};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (ping frame)
    0x07,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildPathClosePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.multipath_flag = true;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.path_id = kDefaultPathId;
  header.packet_number = kPacketNumber;

  QuicPathCloseFrame path_close;
  path_close.path_id = kPathId;
  QuicFrames frames;
  frames.push_back(QuicFrame(&path_close));

  // clang-format off
  unsigned char packet[] = {
    // public flags (version)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x00,
    // packet number
    0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,

    // frame type (path_close_frame)
    0x08,
    // path id
    0x42,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

// Test that the MTU discovery packet is serialized correctly as a PING packet.
TEST_P(QuicFramerTest, BuildMtuDiscoveryPacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicFrames frames = {QuicFrame(QuicMtuDiscoveryFrame())};

  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (ping frame)
    0x07,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                      data->length(), AsChars(packet),
                                      arraysize(packet));
}

TEST_P(QuicFramerTest, BuildPublicResetPacketOld) {
  FLAGS_quic_use_old_public_reset_packets = true;
  QuicPublicResetPacket reset_packet;
  reset_packet.public_header.connection_id = kConnectionId;
  reset_packet.public_header.reset_flag = true;
  reset_packet.public_header.version_flag = false;
  reset_packet.rejected_packet_number = kPacketNumber;
  reset_packet.nonce_proof = kNonceProof;

  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte ConnectionId)
    0x0E,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (2) + padding
    0x02, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
  };
  unsigned char packet_no_rejected_packet_number[] = {
    // public flags (public reset, 8 byte ConnectionId)
    0x0E,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (1) + padding
    0x01, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildPublicResetPacket(reset_packet));
  ASSERT_TRUE(data != nullptr);
  if (FLAGS_quic_remove_packet_number_from_public_reset) {
    test::CompareCharArraysWithHexError(
        "constructed packet", data->data(), data->length(),
        AsChars(packet_no_rejected_packet_number),
        arraysize(packet_no_rejected_packet_number));
  } else {
    test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                        data->length(), AsChars(packet),
                                        arraysize(packet));
  }
}

TEST_P(QuicFramerTest, BuildPublicResetPacket) {
  FLAGS_quic_use_old_public_reset_packets = false;
  QuicPublicResetPacket reset_packet;
  reset_packet.public_header.connection_id = kConnectionId;
  reset_packet.public_header.reset_flag = true;
  reset_packet.public_header.version_flag = false;
  reset_packet.rejected_packet_number = kPacketNumber;
  reset_packet.nonce_proof = kNonceProof;

  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte ConnectionId)
    0x0A,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (2) + padding
    0x02, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
  };
  unsigned char packet_no_rejected_packet_number[] = {
    // public flags (public reset, 8 byte ConnectionId)
    0x0A,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (1) + padding
    0x01, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildPublicResetPacket(reset_packet));
  ASSERT_TRUE(data != nullptr);

  if (FLAGS_quic_remove_packet_number_from_public_reset) {
    test::CompareCharArraysWithHexError(
        "constructed packet", data->data(), data->length(),
        AsChars(packet_no_rejected_packet_number),
        arraysize(packet_no_rejected_packet_number));
  } else {
    test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                        data->length(), AsChars(packet),
                                        arraysize(packet));
  }
}

TEST_P(QuicFramerTest, BuildPublicResetPacketWithClientAddress) {
  FLAGS_quic_use_old_public_reset_packets = false;
  QuicPublicResetPacket reset_packet;
  reset_packet.public_header.connection_id = kConnectionId;
  reset_packet.public_header.reset_flag = true;
  reset_packet.public_header.version_flag = false;
  reset_packet.rejected_packet_number = kPacketNumber;
  reset_packet.nonce_proof = kNonceProof;
  reset_packet.client_address =
      QuicSocketAddress(QuicIpAddress::Loopback4(), 0x1234);

  // clang-format off
  unsigned char packet[] = {
    // public flags (public reset, 8 byte ConnectionId)
    0x0A,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // message tag (kPRST)
    'P', 'R', 'S', 'T',
    // num_entries (3) + padding
    0x03, 0x00, 0x00, 0x00,
    // tag kRNON
    'R', 'N', 'O', 'N',
    // end offset 8
    0x08, 0x00, 0x00, 0x00,
    // tag kRSEQ
    'R', 'S', 'E', 'Q',
    // end offset 16
    0x10, 0x00, 0x00, 0x00,
    // tag kCADR
    'C', 'A', 'D', 'R',
    // end offset 24
    0x18, 0x00, 0x00, 0x00,
    // nonce proof
    0x89, 0x67, 0x45, 0x23,
    0x01, 0xEF, 0xCD, 0xAB,
    // rejected packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12, 0x00, 0x00,
    // client address
    0x02, 0x00,
    0x7F, 0x00, 0x00, 0x01,
    0x34, 0x12,
  };
  unsigned char packet_no_rejected_packet_number[] = {
      // public flags (public reset, 8 byte ConnectionId)
      0x0A,
      // connection_id
      0x10, 0x32, 0x54, 0x76,
      0x98, 0xBA, 0xDC, 0xFE,
      // message tag (kPRST)
      'P', 'R', 'S', 'T',
      // num_entries (2) + padding
      0x02, 0x00, 0x00, 0x00,
      // tag kRNON
      'R', 'N', 'O', 'N',
      // end offset 8
      0x08, 0x00, 0x00, 0x00,
      // tag kCADR
      'C', 'A', 'D', 'R',
      // end offset 16
      0x10, 0x00, 0x00, 0x00,
      // nonce proof
      0x89, 0x67, 0x45, 0x23,
      0x01, 0xEF, 0xCD, 0xAB,
      // client address
      0x02, 0x00,
      0x7F, 0x00, 0x00, 0x01,
      0x34, 0x12,
    };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> data(
      framer_.BuildPublicResetPacket(reset_packet));
  ASSERT_TRUE(data != nullptr);

  if (FLAGS_quic_remove_packet_number_from_public_reset) {
    test::CompareCharArraysWithHexError(
        "constructed packet", data->data(), data->length(),
        AsChars(packet_no_rejected_packet_number),
        arraysize(packet_no_rejected_packet_number));
  } else {
    test::CompareCharArraysWithHexError("constructed packet", data->data(),
                                        data->length(), AsChars(packet),
                                        arraysize(packet));
  }
}

TEST_P(QuicFramerTest, EncryptPacket) {
  QuicPacketNumber packet_number = kPacketNumber;
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> raw(new QuicPacket(
      AsChars(packet), arraysize(packet), false, PACKET_8BYTE_CONNECTION_ID,
      !kIncludeVersion, !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_6BYTE_PACKET_NUMBER));
  char buffer[kMaxPacketSize];
  size_t encrypted_length =
      framer_.EncryptPayload(ENCRYPTION_NONE, kDefaultPathId, packet_number,
                             *raw, buffer, kMaxPacketSize);

  ASSERT_NE(0u, encrypted_length);
  EXPECT_TRUE(CheckEncryption(kDefaultPathId, packet_number, raw.get()));
}

TEST_P(QuicFramerTest, EncryptPacketWithVersionFlag) {
  QuicPacketNumber packet_number = kPacketNumber;
  // clang-format off
  unsigned char packet[] = {
    // public flags (version, 8 byte connection_id)
    0x39,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '.', '1', '0',
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> raw(new QuicPacket(
      AsChars(packet), arraysize(packet), false, PACKET_8BYTE_CONNECTION_ID,
      kIncludeVersion, !kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_6BYTE_PACKET_NUMBER));
  char buffer[kMaxPacketSize];
  size_t encrypted_length =
      framer_.EncryptPayload(ENCRYPTION_NONE, kDefaultPathId, packet_number,
                             *raw, buffer, kMaxPacketSize);

  ASSERT_NE(0u, encrypted_length);
  EXPECT_TRUE(CheckEncryption(kDefaultPathId, packet_number, raw.get()));
}

TEST_P(QuicFramerTest, EncryptPacketWithMultipathFlag) {
  QuicPacketNumber packet_number = kPacketNumber;
  // clang-format off
  unsigned char packet[] = {
    // public flags (version, 8 byte connection_id)
    0x78,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> raw(new QuicPacket(
      AsChars(packet), arraysize(packet), false, PACKET_8BYTE_CONNECTION_ID,
      !kIncludeVersion, kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_6BYTE_PACKET_NUMBER));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kPathId, packet_number, *raw, buffer, kMaxPacketSize);

  ASSERT_NE(0u, encrypted_length);
  EXPECT_TRUE(CheckEncryption(kPathId, packet_number, raw.get()));
}

TEST_P(QuicFramerTest, EncryptPacketWithBothVersionFlagAndMultipathFlag) {
  QuicPacketNumber packet_number = kPacketNumber;
  // clang-format off
  unsigned char packet[] = {
    // public flags (version, 8 byte connection_id)
    0x79,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // version tag
    'Q', '.', '1', '0',
    // path_id
    0x42,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // redundancy
    'a',  'b',  'c',  'd',
    'e',  'f',  'g',  'h',
    'i',  'j',  'k',  'l',
    'm',  'n',  'o',  'p',
  };
  // clang-format on

  std::unique_ptr<QuicPacket> raw(new QuicPacket(
      AsChars(packet), arraysize(packet), false, PACKET_8BYTE_CONNECTION_ID,
      kIncludeVersion, kIncludePathId, !kIncludeDiversificationNonce,
      PACKET_6BYTE_PACKET_NUMBER));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kPathId, packet_number, *raw, buffer, kMaxPacketSize);

  ASSERT_NE(0u, encrypted_length);
  EXPECT_TRUE(CheckEncryption(kPathId, packet_number, raw.get()));
}

TEST_P(QuicFramerTest, AckTruncationLargePacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame;
  // Create a packet with just the ack.
  ack_frame = MakeAckFrameWithAckBlocks(300, 0u);
  QuicFrames frames = {QuicFrame(&ack_frame)};

  // Build an ack packet with truncation due to limit in number of nack ranges.
  std::unique_ptr<QuicPacket> raw_ack_packet(BuildDataPacket(header, frames));
  ASSERT_TRUE(raw_ack_packet != nullptr);
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, header.packet_number, *raw_ack_packet,
      buffer, kMaxPacketSize);
  ASSERT_NE(0u, encrypted_length);
  // Now make sure we can turn our ack packet back into an ack frame.
  ASSERT_TRUE(framer_.ProcessPacket(
      QuicEncryptedPacket(buffer, encrypted_length, false)));
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  QuicAckFrame& processed_ack_frame = *visitor_.ack_frames_[0].get();
  EXPECT_EQ(600u, processed_ack_frame.largest_observed);
  ASSERT_EQ(256u, processed_ack_frame.packets.NumPacketsSlow());
  EXPECT_EQ(90u, processed_ack_frame.packets.Min());
  EXPECT_EQ(600u, processed_ack_frame.packets.Max());
}

TEST_P(QuicFramerTest, AckTruncationSmallPacket) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  // Create a packet with just the ack.
  QuicAckFrame ack_frame;
  ack_frame = MakeAckFrameWithAckBlocks(300, 0u);
  QuicFrames frames = {QuicFrame(&ack_frame)};

  // Build an ack packet with truncation due to limit in number of nack ranges.
  std::unique_ptr<QuicPacket> raw_ack_packet(
      BuildDataPacket(header, frames, 500));
  ASSERT_TRUE(raw_ack_packet != nullptr);
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, header.packet_number, *raw_ack_packet,
      buffer, kMaxPacketSize);
  ASSERT_NE(0u, encrypted_length);
  // Now make sure we can turn our ack packet back into an ack frame.
  ASSERT_TRUE(framer_.ProcessPacket(
      QuicEncryptedPacket(buffer, encrypted_length, false)));
  ASSERT_EQ(1u, visitor_.ack_frames_.size());
  QuicAckFrame& processed_ack_frame = *visitor_.ack_frames_[0].get();
  EXPECT_EQ(600u, processed_ack_frame.largest_observed);
  ASSERT_EQ(239u, processed_ack_frame.packets.NumPacketsSlow());
  EXPECT_EQ(124u, processed_ack_frame.packets.Min());
  EXPECT_EQ(600u, processed_ack_frame.packets.Max());
}

TEST_P(QuicFramerTest, CleanTruncation) {
  QuicPacketHeader header;
  header.public_header.connection_id = kConnectionId;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicAckFrame ack_frame;
  ack_frame.largest_observed = 201;
  ack_frame.packets.Add(1, ack_frame.largest_observed);

  // Create a packet with just the ack.
  QuicFrames frames = {QuicFrame(&ack_frame)};

  std::unique_ptr<QuicPacket> raw_ack_packet(BuildDataPacket(header, frames));
  ASSERT_TRUE(raw_ack_packet != nullptr);

  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, header.packet_number, *raw_ack_packet,
      buffer, kMaxPacketSize);
  ASSERT_NE(0u, encrypted_length);

  // Now make sure we can turn our ack packet back into an ack frame.
  ASSERT_TRUE(framer_.ProcessPacket(
      QuicEncryptedPacket(buffer, encrypted_length, false)));

  // Test for clean truncation of the ack by comparing the length of the
  // original packets to the re-serialized packets.
  frames.clear();
  frames.push_back(QuicFrame(visitor_.ack_frames_[0].get()));

  size_t original_raw_length = raw_ack_packet->length();
  raw_ack_packet.reset(BuildDataPacket(header, frames));
  ASSERT_TRUE(raw_ack_packet != nullptr);
  EXPECT_EQ(original_raw_length, raw_ack_packet->length());
  ASSERT_TRUE(raw_ack_packet != nullptr);
}

TEST_P(QuicFramerTest, StopPacketProcessing) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x38,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,

    // frame type (stream frame with fin)
    0xFF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',

    // frame type (ack frame)
    0x40,
    // least packet number awaiting an ack
    0xA0, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // largest observed packet number
    0xBF, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // num missing packets
    0x01,
    // missing packet
    0xBE, 0x9A, 0x78, 0x56,
    0x34, 0x12,
  };
  // clang-format on

  MockFramerVisitor visitor;
  framer_.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPacket());
  EXPECT_CALL(visitor, OnPacketHeader(_));
  EXPECT_CALL(visitor, OnStreamFrame(_)).WillOnce(Return(false));
  EXPECT_CALL(visitor, OnAckFrame(_)).Times(0);
  EXPECT_CALL(visitor, OnPacketComplete());
  EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_)).WillOnce(Return(true));
  EXPECT_CALL(visitor, OnUnauthenticatedHeader(_)).WillOnce(Return(true));
  EXPECT_CALL(visitor, OnDecryptedPacket(_));

  QuicEncryptedPacket encrypted(AsChars(packet), arraysize(packet), false);
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
}

static char kTestString[] = "At least 20 characters.";
static QuicStreamId kTestQuicStreamId = 1;
static bool ExpectedStreamFrame(const QuicStreamFrame& frame) {
  return frame.stream_id == kTestQuicStreamId && !frame.fin &&
         frame.offset == 0 &&
         string(frame.data_buffer, frame.data_length) == kTestString;
  // FIN is hard-coded false in ConstructEncryptedPacket.
  // Offset 0 is hard-coded in ConstructEncryptedPacket.
}

// Verify that the packet returned by ConstructEncryptedPacket() can be properly
// parsed by the framer.
TEST_P(QuicFramerTest, ConstructEncryptedPacket) {
  // Since we are using ConstructEncryptedPacket, we have to set the framer's
  // crypto to be Null.
  framer_.SetDecrypter(ENCRYPTION_NONE, QuicDecrypter::Create(kNULL));
  framer_.SetEncrypter(ENCRYPTION_NONE, QuicEncrypter::Create(kNULL));
  QuicVersionVector versions;
  versions.push_back(framer_.version());
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
      42, false, false, false, kDefaultPathId, kTestQuicStreamId, kTestString,
      PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, &versions));

  MockFramerVisitor visitor;
  framer_.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPacket()).Times(1);
  EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnUnauthenticatedHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnPacketHeader(_)).Times(1).WillOnce(Return(true));
  EXPECT_CALL(visitor, OnDecryptedPacket(_)).Times(1);
  EXPECT_CALL(visitor, OnError(_)).Times(0);
  EXPECT_CALL(visitor, OnStreamFrame(_)).Times(0);
  EXPECT_CALL(visitor, OnStreamFrame(Truly(ExpectedStreamFrame))).Times(1);
  EXPECT_CALL(visitor, OnAckFrame(_)).Times(0);
  EXPECT_CALL(visitor, OnPacketComplete()).Times(1);

  EXPECT_TRUE(framer_.ProcessPacket(*packet));
  EXPECT_EQ(QUIC_NO_ERROR, framer_.error());
}

// Verify that the packet returned by ConstructMisFramedEncryptedPacket()
// does cause the framer to return an error.
TEST_P(QuicFramerTest, ConstructMisFramedEncryptedPacket) {
  // Since we are using ConstructEncryptedPacket, we have to set the framer's
  // crypto to be Null.
  framer_.SetDecrypter(ENCRYPTION_NONE, QuicDecrypter::Create(kNULL));
  framer_.SetEncrypter(ENCRYPTION_NONE, QuicEncrypter::Create(kNULL));
  QuicVersionVector versions;
  versions.push_back(framer_.version());
  std::unique_ptr<QuicEncryptedPacket> packet(ConstructMisFramedEncryptedPacket(
      42, false, false, false, kDefaultPathId, kTestQuicStreamId, kTestString,
      PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, &versions,
      Perspective::IS_SERVER));

  MockFramerVisitor visitor;
  framer_.set_visitor(&visitor);
  EXPECT_CALL(visitor, OnPacket()).Times(1);
  EXPECT_CALL(visitor, OnUnauthenticatedPublicHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnUnauthenticatedHeader(_))
      .Times(1)
      .WillOnce(Return(true));
  EXPECT_CALL(visitor, OnPacketHeader(_)).Times(1);
  EXPECT_CALL(visitor, OnDecryptedPacket(_)).Times(1);
  EXPECT_CALL(visitor, OnError(_)).Times(1);
  EXPECT_CALL(visitor, OnStreamFrame(_)).Times(0);
  EXPECT_CALL(visitor, OnAckFrame(_)).Times(0);
  EXPECT_CALL(visitor, OnPacketComplete()).Times(0);

  EXPECT_FALSE(framer_.ProcessPacket(*packet));
  EXPECT_EQ(QUIC_INVALID_FRAME_DATA, framer_.error());
}

// Tests for fuzzing with Dr. Fuzz
// Xref http://www.chromium.org/developers/testing/dr-fuzz for more details.
#ifdef __cplusplus
extern "C" {
#endif

// target function to be fuzzed by Dr. Fuzz
void QuicFramerFuzzFunc(unsigned char* data, size_t size) {
  QuicFramer framer(AllSupportedVersions(), QuicTime::Zero(),
                    Perspective::IS_SERVER);
  const char* const packet_bytes = reinterpret_cast<const char*>(data);

  // Test the CryptoFramer.
  StringPiece crypto_input(packet_bytes, size);
  std::unique_ptr<CryptoHandshakeMessage> handshake_message(
      CryptoFramer::ParseMessage(crypto_input));

  // Test the regular QuicFramer with the same input.
  NoOpFramerVisitor visitor;
  framer.set_visitor(&visitor);
  QuicEncryptedPacket packet(packet_bytes, size);
  framer.ProcessPacket(packet);
}

#ifdef __cplusplus
}
#endif

TEST_P(QuicFramerTest, FramerFuzzTest) {
  // clang-format off
  unsigned char packet[] = {
    // public flags (8 byte connection_id)
    0x3C,
    // connection_id
    0x10, 0x32, 0x54, 0x76,
    0x98, 0xBA, 0xDC, 0xFE,
    // packet number
    0xBC, 0x9A, 0x78, 0x56,
    0x34, 0x12,
    // private flags
    0x00,

    // frame type (stream frame with fin)
    0xFF,
    // stream id
    0x04, 0x03, 0x02, 0x01,
    // offset
    0x54, 0x76, 0x10, 0x32,
    0xDC, 0xFE, 0x98, 0xBA,
    // data length
    0x0c, 0x00,
    // data
    'h',  'e',  'l',  'l',
    'o',  ' ',  'w',  'o',
    'r',  'l',  'd',  '!',
  };
  // clang-format on

  QuicFramerFuzzFunc(packet, arraysize(packet));
}

}  // namespace test
}  // namespace net
