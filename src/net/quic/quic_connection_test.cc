// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection.h"

#include <errno.h>
#include <memory>
#include <ostream>
#include <utility>

#include "base/bind.h"
#include "base/macros.h"
#include "base/stl_util.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/quic/congestion_control/loss_detection_interface.h"
#include "net/quic/congestion_control/send_algorithm_interface.h"
#include "net/quic/crypto/null_encrypter.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_simple_buffer_allocator.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/mock_clock.h"
#include "net/quic/test_tools/mock_random.h"
#include "net/quic/test_tools/quic_config_peer.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/quic/test_tools/quic_framer_peer.h"
#include "net/quic/test_tools/quic_packet_creator_peer.h"
#include "net/quic/test_tools/quic_packet_generator_peer.h"
#include "net/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/quic/test_tools/simple_quic_framer.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::map;
using std::ostream;
using std::string;
using std::vector;
using testing::AnyNumber;
using testing::AtLeast;
using testing::Contains;
using testing::DoAll;
using testing::InSequence;
using testing::InvokeWithoutArgs;
using testing::NiceMock;
using testing::Ref;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::_;

namespace net {
namespace test {
namespace {

const char data1[] = "foo";
const char data2[] = "bar";

const bool kFin = true;
const bool kEntropyFlag = true;
const bool kHasStopWaiting = true;

const QuicPacketEntropyHash kTestEntropyHash = 76;

const int kDefaultRetransmissionTimeMs = 500;

const IPEndPoint kPeerAddress = IPEndPoint(Loopback6(), /*port=*/12345);
const IPEndPoint kSelfAddress = IPEndPoint(Loopback6(), /*port=*/443);

Perspective InvertPerspective(Perspective perspective) {
  return perspective == Perspective::IS_CLIENT ? Perspective::IS_SERVER
                                               : Perspective::IS_CLIENT;
}

// TaggingEncrypter appends kTagSize bytes of |tag| to the end of each message.
class TaggingEncrypter : public QuicEncrypter {
 public:
  explicit TaggingEncrypter(uint8_t tag) : tag_(tag) {}

  ~TaggingEncrypter() override {}

  // QuicEncrypter interface.
  bool SetKey(StringPiece key) override { return true; }

  bool SetNoncePrefix(StringPiece nonce_prefix) override { return true; }

  bool EncryptPacket(QuicPathId path_id,
                     QuicPacketNumber packet_number,
                     StringPiece associated_data,
                     StringPiece plaintext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override {
    const size_t len = plaintext.size() + kTagSize;
    if (max_output_length < len) {
      return false;
    }
    // Memmove is safe for inplace encryption.
    memmove(output, plaintext.data(), plaintext.size());
    output += plaintext.size();
    memset(output, tag_, kTagSize);
    *output_length = len;
    return true;
  }

  size_t GetKeySize() const override { return 0; }
  size_t GetNoncePrefixSize() const override { return 0; }

  size_t GetMaxPlaintextSize(size_t ciphertext_size) const override {
    return ciphertext_size - kTagSize;
  }

  size_t GetCiphertextSize(size_t plaintext_size) const override {
    return plaintext_size + kTagSize;
  }

  StringPiece GetKey() const override { return StringPiece(); }

  StringPiece GetNoncePrefix() const override { return StringPiece(); }

 private:
  enum {
    kTagSize = 12,
  };

  const uint8_t tag_;

  DISALLOW_COPY_AND_ASSIGN(TaggingEncrypter);
};

// TaggingDecrypter ensures that the final kTagSize bytes of the message all
// have the same value and then removes them.
class TaggingDecrypter : public QuicDecrypter {
 public:
  ~TaggingDecrypter() override {}

  // QuicDecrypter interface
  bool SetKey(StringPiece key) override { return true; }

  bool SetNoncePrefix(StringPiece nonce_prefix) override { return true; }

  bool SetPreliminaryKey(StringPiece key) override {
    QUIC_BUG << "should not be called";
    return false;
  }

  bool SetDiversificationNonce(DiversificationNonce key) override {
    return true;
  }

  bool DecryptPacket(QuicPathId path_id,
                     QuicPacketNumber packet_number,
                     StringPiece associated_data,
                     StringPiece ciphertext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override {
    if (ciphertext.size() < kTagSize) {
      return false;
    }
    if (!CheckTag(ciphertext, GetTag(ciphertext))) {
      return false;
    }
    *output_length = ciphertext.size() - kTagSize;
    memcpy(output, ciphertext.data(), *output_length);
    return true;
  }

  StringPiece GetKey() const override { return StringPiece(); }
  StringPiece GetNoncePrefix() const override { return StringPiece(); }
  const char* cipher_name() const override { return "Tagging"; }
  // Use a distinct value starting with 0xFFFFFF, which is never used by TLS.
  uint32_t cipher_id() const override { return 0xFFFFFFF0; }

 protected:
  virtual uint8_t GetTag(StringPiece ciphertext) {
    return ciphertext.data()[ciphertext.size() - 1];
  }

 private:
  enum {
    kTagSize = 12,
  };

  bool CheckTag(StringPiece ciphertext, uint8_t tag) {
    for (size_t i = ciphertext.size() - kTagSize; i < ciphertext.size(); i++) {
      if (ciphertext.data()[i] != tag) {
        return false;
      }
    }

    return true;
  }
};

// StringTaggingDecrypter ensures that the final kTagSize bytes of the message
// match the expected value.
class StrictTaggingDecrypter : public TaggingDecrypter {
 public:
  explicit StrictTaggingDecrypter(uint8_t tag) : tag_(tag) {}
  ~StrictTaggingDecrypter() override {}

  // TaggingQuicDecrypter
  uint8_t GetTag(StringPiece ciphertext) override { return tag_; }

  const char* cipher_name() const override { return "StrictTagging"; }
  // Use a distinct value starting with 0xFFFFFF, which is never used by TLS.
  uint32_t cipher_id() const override { return 0xFFFFFFF1; }

 private:
  const uint8_t tag_;
};

class TestConnectionHelper : public QuicConnectionHelperInterface {
 public:
  TestConnectionHelper(MockClock* clock, MockRandom* random_generator)
      : clock_(clock), random_generator_(random_generator) {
    clock_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

  // QuicConnectionHelperInterface
  const QuicClock* GetClock() const override { return clock_; }

  QuicRandom* GetRandomGenerator() override { return random_generator_; }

  QuicBufferAllocator* GetBufferAllocator() override {
    return &buffer_allocator_;
  }

 private:
  MockClock* clock_;
  MockRandom* random_generator_;
  SimpleBufferAllocator buffer_allocator_;

  DISALLOW_COPY_AND_ASSIGN(TestConnectionHelper);
};

class TestAlarmFactory : public QuicAlarmFactory {
 public:
  class TestAlarm : public QuicAlarm {
   public:
    explicit TestAlarm(QuicArenaScopedPtr<QuicAlarm::Delegate> delegate)
        : QuicAlarm(std::move(delegate)) {}

    void SetImpl() override {}
    void CancelImpl() override {}
    using QuicAlarm::Fire;
  };

  TestAlarmFactory() {}

  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override {
    return new TestAlarm(QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
  }

  QuicArenaScopedPtr<QuicAlarm> CreateAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
      QuicConnectionArena* arena) override {
    return arena->New<TestAlarm>(std::move(delegate));
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(TestAlarmFactory);
};

class TestPacketWriter : public QuicPacketWriter {
 public:
  TestPacketWriter(QuicVersion version, MockClock* clock)
      : version_(version),
        framer_(SupportedVersions(version_)),
        last_packet_size_(0),
        write_blocked_(false),
        write_should_fail_(false),
        block_on_next_write_(false),
        is_write_blocked_data_buffered_(false),
        final_bytes_of_last_packet_(0),
        final_bytes_of_previous_packet_(0),
        use_tagging_decrypter_(false),
        packets_write_attempts_(0),
        clock_(clock),
        write_pause_time_delta_(QuicTime::Delta::Zero()),
        max_packet_size_(kMaxPacketSize) {}

  // QuicPacketWriter interface
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_address,
                          const IPEndPoint& peer_address,
                          PerPacketOptions* options) override {
    QuicEncryptedPacket packet(buffer, buf_len);
    ++packets_write_attempts_;

    if (packet.length() >= sizeof(final_bytes_of_last_packet_)) {
      final_bytes_of_previous_packet_ = final_bytes_of_last_packet_;
      memcpy(&final_bytes_of_last_packet_, packet.data() + packet.length() - 4,
             sizeof(final_bytes_of_last_packet_));
    }

    if (use_tagging_decrypter_) {
      framer_.framer()->SetDecrypter(ENCRYPTION_NONE, new TaggingDecrypter);
    }
    EXPECT_TRUE(framer_.ProcessPacket(packet));
    if (block_on_next_write_) {
      write_blocked_ = true;
      block_on_next_write_ = false;
    }
    if (IsWriteBlocked()) {
      return WriteResult(WRITE_STATUS_BLOCKED, -1);
    }

    if (ShouldWriteFail()) {
      return WriteResult(WRITE_STATUS_ERROR, 0);
    }

    last_packet_size_ = packet.length();

    if (!write_pause_time_delta_.IsZero()) {
      clock_->AdvanceTime(write_pause_time_delta_);
    }
    return WriteResult(WRITE_STATUS_OK, last_packet_size_);
  }

  bool IsWriteBlockedDataBuffered() const override {
    return is_write_blocked_data_buffered_;
  }

  bool ShouldWriteFail() { return write_should_fail_; }

  bool IsWriteBlocked() const override { return write_blocked_; }

  void SetWritable() override { write_blocked_ = false; }

  void SetShouldWriteFail() { write_should_fail_ = true; }

  QuicByteCount GetMaxPacketSize(
      const IPEndPoint& /*peer_address*/) const override {
    return max_packet_size_;
  }

  void BlockOnNextWrite() { block_on_next_write_ = true; }

  // Sets the amount of time that the writer should before the actual write.
  void SetWritePauseTimeDelta(QuicTime::Delta delta) {
    write_pause_time_delta_ = delta;
  }

  const QuicPacketHeader& header() { return framer_.header(); }

  size_t frame_count() const { return framer_.num_frames(); }

  const vector<QuicAckFrame>& ack_frames() const {
    return framer_.ack_frames();
  }

  const vector<QuicStopWaitingFrame>& stop_waiting_frames() const {
    return framer_.stop_waiting_frames();
  }

  const vector<QuicConnectionCloseFrame>& connection_close_frames() const {
    return framer_.connection_close_frames();
  }

  const vector<QuicRstStreamFrame>& rst_stream_frames() const {
    return framer_.rst_stream_frames();
  }

  const vector<QuicStreamFrame*>& stream_frames() const {
    return framer_.stream_frames();
  }

  const vector<QuicPingFrame>& ping_frames() const {
    return framer_.ping_frames();
  }

  size_t last_packet_size() { return last_packet_size_; }

  const QuicVersionNegotiationPacket* version_negotiation_packet() {
    return framer_.version_negotiation_packet();
  }

  void set_is_write_blocked_data_buffered(bool buffered) {
    is_write_blocked_data_buffered_ = buffered;
  }

  void set_perspective(Perspective perspective) {
    // We invert perspective here, because the framer needs to parse packets
    // we send.
    QuicFramerPeer::SetPerspective(framer_.framer(),
                                   InvertPerspective(perspective));
  }

  // final_bytes_of_last_packet_ returns the last four bytes of the previous
  // packet as a little-endian, uint32_t. This is intended to be used with a
  // TaggingEncrypter so that tests can determine which encrypter was used for
  // a given packet.
  uint32_t final_bytes_of_last_packet() { return final_bytes_of_last_packet_; }

  // Returns the final bytes of the second to last packet.
  uint32_t final_bytes_of_previous_packet() {
    return final_bytes_of_previous_packet_;
  }

  void use_tagging_decrypter() { use_tagging_decrypter_ = true; }

  uint32_t packets_write_attempts() { return packets_write_attempts_; }

  void Reset() { framer_.Reset(); }

  void SetSupportedVersions(const QuicVersionVector& versions) {
    framer_.SetSupportedVersions(versions);
  }

  void set_max_packet_size(QuicByteCount max_packet_size) {
    max_packet_size_ = max_packet_size;
  }

 private:
  QuicVersion version_;
  SimpleQuicFramer framer_;
  size_t last_packet_size_;
  bool write_blocked_;
  bool write_should_fail_;
  bool block_on_next_write_;
  bool is_write_blocked_data_buffered_;
  uint32_t final_bytes_of_last_packet_;
  uint32_t final_bytes_of_previous_packet_;
  bool use_tagging_decrypter_;
  uint32_t packets_write_attempts_;
  MockClock* clock_;
  // If non-zero, the clock will pause during WritePacket for this amount of
  // time.
  QuicTime::Delta write_pause_time_delta_;
  QuicByteCount max_packet_size_;

  DISALLOW_COPY_AND_ASSIGN(TestPacketWriter);
};

class TestConnection : public QuicConnection {
 public:
  TestConnection(QuicConnectionId connection_id,
                 IPEndPoint address,
                 TestConnectionHelper* helper,
                 TestAlarmFactory* alarm_factory,
                 TestPacketWriter* writer,
                 Perspective perspective,
                 QuicVersion version)
      : QuicConnection(connection_id,
                       address,
                       helper,
                       alarm_factory,
                       writer,
                       /* owns_writer= */ false,
                       perspective,
                       SupportedVersions(version)) {
    writer->set_perspective(perspective);
  }

  void SendAck() { QuicConnectionPeer::SendAck(this); }

  void SetSendAlgorithm(SendAlgorithmInterface* send_algorithm) {
    QuicConnectionPeer::SetSendAlgorithm(this, send_algorithm);
  }

  void SetLossAlgorithm(LossDetectionInterface* loss_algorithm) {
    // TODO(fayang): connection tests should use MockSentPacketManager.
    QuicSentPacketManagerPeer::SetLossAlgorithm(
        static_cast<QuicSentPacketManager*>(
            QuicConnectionPeer::GetSentPacketManager(this)),
        loss_algorithm);
  }

  void SendPacket(EncryptionLevel level,
                  QuicPathId path_id,
                  QuicPacketNumber packet_number,
                  QuicPacket* packet,
                  QuicPacketEntropyHash entropy_hash,
                  HasRetransmittableData retransmittable,
                  bool has_ack,
                  bool has_pending_frames) {
    char buffer[kMaxPacketSize];
    size_t encrypted_length =
        QuicConnectionPeer::GetFramer(this)->EncryptPayload(
            ENCRYPTION_NONE, path_id, packet_number, *packet, buffer,
            kMaxPacketSize);
    delete packet;
    SerializedPacket serialized_packet(
        kDefaultPathId, packet_number, PACKET_6BYTE_PACKET_NUMBER, buffer,
        encrypted_length, entropy_hash, has_ack, has_pending_frames);
    if (retransmittable == HAS_RETRANSMITTABLE_DATA) {
      serialized_packet.retransmittable_frames.push_back(
          QuicFrame(new QuicStreamFrame()));
    }
    OnSerializedPacket(&serialized_packet);
  }

  QuicConsumedData SendStreamDataWithString(
      QuicStreamId id,
      StringPiece data,
      QuicStreamOffset offset,
      bool fin,
      QuicAckListenerInterface* listener) {
    struct iovec iov;
    QuicIOVector data_iov(MakeIOVector(data, &iov));
    return QuicConnection::SendStreamData(id, data_iov, offset, fin, listener);
  }

  QuicConsumedData SendStreamData3() {
    return SendStreamDataWithString(kClientDataStreamId1, "food", 0, !kFin,
                                    nullptr);
  }

  QuicConsumedData SendStreamData5() {
    return SendStreamDataWithString(kClientDataStreamId2, "food2", 0, !kFin,
                                    nullptr);
  }

  // Ensures the connection can write stream data before writing.
  QuicConsumedData EnsureWritableAndSendStreamData5() {
    EXPECT_TRUE(CanWriteStreamData());
    return SendStreamData5();
  }

  // The crypto stream has special semantics so that it is not blocked by a
  // congestion window limitation, and also so that it gets put into a separate
  // packet (so that it is easier to reason about a crypto frame not being
  // split needlessly across packet boundaries).  As a result, we have separate
  // tests for some cases for this stream.
  QuicConsumedData SendCryptoStreamData() {
    return SendStreamDataWithString(kCryptoStreamId, "chlo", 0, !kFin, nullptr);
  }

  void set_version(QuicVersion version) {
    QuicConnectionPeer::GetFramer(this)->set_version(version);
  }

  void SetSupportedVersions(const QuicVersionVector& versions) {
    QuicConnectionPeer::GetFramer(this)->SetSupportedVersions(versions);
    writer()->SetSupportedVersions(versions);
  }

  void set_perspective(Perspective perspective) {
    writer()->set_perspective(perspective);
    QuicConnectionPeer::SetPerspective(this, perspective);
  }

  // Enable path MTU discovery.  Assumes that the test is performed from the
  // client perspective and the higher value of MTU target is used.
  void EnablePathMtuDiscovery(MockSendAlgorithm* send_algorithm) {
    ASSERT_EQ(Perspective::IS_CLIENT, perspective());

    QuicConfig config;
    QuicTagVector connection_options;
    connection_options.push_back(kMTUH);
    config.SetConnectionOptionsToSend(connection_options);
    EXPECT_CALL(*send_algorithm, SetFromConfig(_, _));
    SetFromConfig(config);

    // Normally, the pacing would be disabled in the test, but calling
    // SetFromConfig enables it.  Set nearly-infinite bandwidth to make the
    // pacing algorithm work.
    EXPECT_CALL(*send_algorithm, PacingRate(_))
        .WillRepeatedly(Return(QuicBandwidth::FromKBytesPerSecond(10000)));
  }

  TestAlarmFactory::TestAlarm* GetAckAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetAckAlarm(this));
  }

  TestAlarmFactory::TestAlarm* GetPingAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetPingAlarm(this));
  }

  TestAlarmFactory::TestAlarm* GetResumeWritesAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetResumeWritesAlarm(this));
  }

  TestAlarmFactory::TestAlarm* GetRetransmissionAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetRetransmissionAlarm(this));
  }

  TestAlarmFactory::TestAlarm* GetSendAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetSendAlarm(this));
  }

  TestAlarmFactory::TestAlarm* GetTimeoutAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetTimeoutAlarm(this));
  }

  TestAlarmFactory::TestAlarm* GetMtuDiscoveryAlarm() {
    return reinterpret_cast<TestAlarmFactory::TestAlarm*>(
        QuicConnectionPeer::GetMtuDiscoveryAlarm(this));
  }

  void DisableTailLossProbe() {
    QuicSentPacketManagerPeer::SetMaxTailLossProbes(
        QuicConnectionPeer::GetSentPacketManager(this), 0);
  }

  using QuicConnection::SelectMutualVersion;
  using QuicConnection::set_defer_send_in_response_to_packets;

 private:
  TestPacketWriter* writer() {
    return static_cast<TestPacketWriter*>(QuicConnection::writer());
  }

  DISALLOW_COPY_AND_ASSIGN(TestConnection);
};

enum class AckResponse { kDefer, kImmediate };

// Run tests with combinations of {QuicVersion, AckResponse}.
struct TestParams {
  TestParams(QuicVersion version, AckResponse ack_response)
      : version(version), ack_response(ack_response) {}

  friend ostream& operator<<(ostream& os, const TestParams& p) {
    os << "{ client_version: " << QuicVersionToString(p.version)
       << " ack_response: "
       << (p.ack_response == AckResponse::kDefer ? "defer" : "immediate")
       << " }";
    return os;
  }

  QuicVersion version;
  AckResponse ack_response;
};

// Constructs various test permutations.
vector<TestParams> GetTestParams() {
  vector<TestParams> params;
  QuicVersionVector all_supported_versions = QuicSupportedVersions();
  for (size_t i = 0; i < all_supported_versions.size(); ++i) {
    for (AckResponse ack_response :
         {AckResponse::kDefer, AckResponse::kImmediate}) {
      params.push_back(TestParams(all_supported_versions[i], ack_response));
    }
  }
  return params;
}

class QuicConnectionTest : public ::testing::TestWithParam<TestParams> {
 protected:
  QuicConnectionTest()
      : connection_id_(42),
        framer_(SupportedVersions(version()),
                QuicTime::Zero(),
                Perspective::IS_CLIENT),
        send_algorithm_(new StrictMock<MockSendAlgorithm>),
        loss_algorithm_(new MockLossAlgorithm()),
        helper_(new TestConnectionHelper(&clock_, &random_generator_)),
        alarm_factory_(new TestAlarmFactory()),
        peer_framer_(SupportedVersions(version()),
                     QuicTime::Zero(),
                     Perspective::IS_SERVER),
        peer_creator_(connection_id_,
                      &peer_framer_,
                      &random_generator_,
                      &buffer_allocator_,
                      /*delegate=*/nullptr),
        writer_(new TestPacketWriter(version(), &clock_)),
        connection_(connection_id_,
                    kPeerAddress,
                    helper_.get(),
                    alarm_factory_.get(),
                    writer_.get(),
                    Perspective::IS_CLIENT,
                    version()),
        creator_(QuicConnectionPeer::GetPacketCreator(&connection_)),
        generator_(QuicConnectionPeer::GetPacketGenerator(&connection_)),
        manager_(QuicConnectionPeer::GetSentPacketManager(&connection_)),
        frame1_(1, false, 0, StringPiece(data1)),
        frame2_(1, false, 3, StringPiece(data2)),
        packet_number_length_(PACKET_6BYTE_PACKET_NUMBER),
        connection_id_length_(PACKET_8BYTE_CONNECTION_ID) {
    connection_.set_defer_send_in_response_to_packets(GetParam().ack_response ==
                                                      AckResponse::kDefer);
    FLAGS_quic_always_log_bugs_for_tests = true;
    connection_.set_visitor(&visitor_);
    connection_.SetSendAlgorithm(send_algorithm_);
    connection_.SetLossAlgorithm(loss_algorithm_);
    framer_.set_received_entropy_calculator(&entropy_calculator_);
    peer_framer_.set_received_entropy_calculator(&peer_entropy_calculator_);
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
        .WillRepeatedly(Return(QuicTime::Delta::Zero()));
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, RetransmissionDelay())
        .WillRepeatedly(Return(QuicTime::Delta::Zero()));
    EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
        .WillRepeatedly(Return(kDefaultTCPMSS));
    EXPECT_CALL(*send_algorithm_, PacingRate(_))
        .WillRepeatedly(Return(QuicBandwidth::Zero()));
    ON_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .WillByDefault(Return(true));
    EXPECT_CALL(*send_algorithm_, HasReliableBandwidthEstimate())
        .Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
        .Times(AnyNumber())
        .WillRepeatedly(Return(QuicBandwidth::Zero()));
    EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
    EXPECT_CALL(visitor_, WillingAndAbleToWrite()).Times(AnyNumber());
    EXPECT_CALL(visitor_, HasPendingHandshake()).Times(AnyNumber());
    EXPECT_CALL(visitor_, OnCanWrite()).Times(AnyNumber());
    EXPECT_CALL(visitor_, PostProcessAfterData()).Times(AnyNumber());
    EXPECT_CALL(visitor_, HasOpenDynamicStreams())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(visitor_, OnCongestionWindowChange(_)).Times(AnyNumber());

    EXPECT_CALL(*loss_algorithm_, GetLossTimeout())
        .WillRepeatedly(Return(QuicTime::Zero()));
    EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
        .Times(AnyNumber());
    // TODO(ianswett): Fix QuicConnectionTests so they don't attempt to write
    // non-crypto stream data at ENCRYPTION_NONE.
    FLAGS_quic_never_write_unencrypted_data = false;
  }

  QuicVersion version() { return GetParam().version; }

  QuicAckFrame* outgoing_ack() {
    QuicFrame ack_frame = QuicConnectionPeer::GetUpdatedAckFrame(&connection_);
    ack_ = *ack_frame.ack_frame;
    return &ack_;
  }

  QuicStopWaitingFrame* stop_waiting() {
    QuicConnectionPeer::PopulateStopWaitingFrame(&connection_, &stop_waiting_);
    return &stop_waiting_;
  }

  QuicPacketNumber least_unacked() {
    if (writer_->stop_waiting_frames().empty()) {
      return 0;
    }
    return writer_->stop_waiting_frames()[0].least_unacked;
  }

  void use_tagging_decrypter() { writer_->use_tagging_decrypter(); }

  void ProcessPacket(QuicPathId path_id, QuicPacketNumber number) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacket(path_id, number, !kEntropyFlag);
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
  }

  QuicPacketEntropyHash ProcessFramePacket(QuicFrame frame) {
    return ProcessFramePacketWithAddresses(frame, kSelfAddress, kPeerAddress);
  }

  QuicPacketEntropyHash ProcessFramePacketWithAddresses(
      QuicFrame frame,
      IPEndPoint self_address,
      IPEndPoint peer_address) {
    QuicFrames frames;
    frames.push_back(QuicFrame(frame));
    QuicPacketCreatorPeer::SetSendVersionInPacket(
        &peer_creator_, connection_.perspective() == Perspective::IS_SERVER);

    char buffer[kMaxPacketSize];
    SerializedPacket serialized_packet =
        QuicPacketCreatorPeer::SerializeAllFrames(&peer_creator_, frames,
                                                  buffer, kMaxPacketSize);
    connection_.ProcessUdpPacket(
        self_address, peer_address,
        QuicReceivedPacket(serialized_packet.encrypted_buffer,
                           serialized_packet.encrypted_length, clock_.Now()));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return serialized_packet.entropy_hash;
  }

  QuicPacketEntropyHash ProcessFramePacketAtLevel(QuicPathId path_id,
                                                  QuicPacketNumber number,
                                                  QuicFrame frame,
                                                  EncryptionLevel level) {
    QuicPacketHeader header;
    header.public_header.connection_id = connection_id_;
    header.public_header.packet_number_length = packet_number_length_;
    header.public_header.connection_id_length = connection_id_length_;
    header.public_header.multipath_flag = path_id != kDefaultPathId;
    header.path_id = path_id;
    header.packet_number = number;
    QuicFrames frames;
    frames.push_back(frame);
    std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));

    char buffer[kMaxPacketSize];
    size_t encrypted_length = framer_.EncryptPayload(
        level, path_id, number, *packet, buffer, kMaxPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
    return base::checked_cast<QuicPacketEntropyHash>(encrypted_length);
  }

  size_t ProcessDataPacket(QuicPathId path_id,
                           QuicPacketNumber number,
                           bool entropy_flag) {
    return ProcessDataPacketAtLevel(path_id, number, entropy_flag, false,
                                    ENCRYPTION_NONE);
  }

  size_t ProcessDataPacketAtLevel(QuicPathId path_id,
                                  QuicPacketNumber number,
                                  bool entropy_flag,
                                  bool has_stop_waiting,
                                  EncryptionLevel level) {
    std::unique_ptr<QuicPacket> packet(
        ConstructDataPacket(path_id, number, entropy_flag, has_stop_waiting));
    char buffer[kMaxPacketSize];
    size_t encrypted_length = framer_.EncryptPayload(
        level, path_id, number, *packet, buffer, kMaxPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  void ProcessClosePacket(QuicPathId path_id, QuicPacketNumber number) {
    std::unique_ptr<QuicPacket> packet(ConstructClosePacket(number));
    char buffer[kMaxPacketSize];
    size_t encrypted_length = framer_.EncryptPayload(
        ENCRYPTION_NONE, path_id, number, *packet, buffer, kMaxPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
  }

  QuicByteCount SendStreamDataToPeer(QuicStreamId id,
                                     StringPiece data,
                                     QuicStreamOffset offset,
                                     bool fin,
                                     QuicPacketNumber* last_packet) {
    QuicByteCount packet_size;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .WillOnce(DoAll(SaveArg<3>(&packet_size), Return(true)));
    connection_.SendStreamDataWithString(id, data, offset, fin, nullptr);
    if (last_packet != nullptr) {
      *last_packet = creator_->packet_number();
    }
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
    return packet_size;
  }

  void SendAckPacketToPeer() {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendAck();
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
  }

  void ProcessAckPacket(QuicPacketNumber packet_number, QuicAckFrame* frame) {
    QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, packet_number - 1);
    ProcessFramePacket(QuicFrame(frame));
  }

  QuicPacketEntropyHash ProcessAckPacket(QuicAckFrame* frame) {
    return ProcessFramePacket(QuicFrame(frame));
  }

  QuicPacketEntropyHash ProcessStopWaitingPacket(QuicStopWaitingFrame* frame) {
    return ProcessFramePacket(QuicFrame(frame));
  }

  QuicPacketEntropyHash ProcessStopWaitingPacketAtLevel(
      QuicPathId path_id,
      QuicPacketNumber number,
      QuicStopWaitingFrame* frame,
      EncryptionLevel level) {
    return ProcessFramePacketAtLevel(path_id, number, QuicFrame(frame),
                                     ENCRYPTION_INITIAL);
  }

  QuicPacketEntropyHash ProcessGoAwayPacket(QuicGoAwayFrame* frame) {
    return ProcessFramePacket(QuicFrame(frame));
  }

  QuicPacketEntropyHash ProcessPathClosePacket(QuicPathCloseFrame* frame) {
    return ProcessFramePacket(QuicFrame(frame));
  }

  bool IsMissing(QuicPacketNumber number) {
    return IsAwaitingPacket(*outgoing_ack(), number, 0);
  }

  QuicPacket* ConstructPacket(QuicPacketHeader header, QuicFrames frames) {
    QuicPacket* packet = BuildUnsizedDataPacket(&peer_framer_, header, frames);
    EXPECT_NE(nullptr, packet);
    return packet;
  }

  QuicPacket* ConstructDataPacket(QuicPathId path_id,
                                  QuicPacketNumber number,
                                  bool entropy_flag,
                                  bool has_stop_waiting) {
    QuicPacketHeader header;
    header.public_header.connection_id = connection_id_;
    header.public_header.packet_number_length = packet_number_length_;
    header.public_header.connection_id_length = connection_id_length_;
    header.public_header.multipath_flag = path_id != kDefaultPathId;
    header.entropy_flag = entropy_flag;
    header.path_id = path_id;
    header.packet_number = number;

    QuicFrames frames;
    frames.push_back(QuicFrame(&frame1_));
    if (has_stop_waiting) {
      frames.push_back(QuicFrame(&stop_waiting_));
    }
    return ConstructPacket(header, frames);
  }

  QuicPacket* ConstructClosePacket(QuicPacketNumber number) {
    QuicPacketHeader header;
    header.public_header.connection_id = connection_id_;
    header.packet_number = number;

    QuicConnectionCloseFrame qccf;
    qccf.error_code = QUIC_PEER_GOING_AWAY;

    QuicFrames frames;
    frames.push_back(QuicFrame(&qccf));
    return ConstructPacket(header, frames);
  }

  QuicTime::Delta DefaultRetransmissionTime() {
    return QuicTime::Delta::FromMilliseconds(kDefaultRetransmissionTimeMs);
  }

  QuicTime::Delta DefaultDelayedAckTime() {
    return QuicTime::Delta::FromMilliseconds(kMaxDelayedAckTimeMs);
  }

  // Initialize a frame acknowledging all packets up to largest_observed.
  const QuicAckFrame InitAckFrame(QuicPacketNumber largest_observed) {
    QuicAckFrame frame(MakeAckFrame(largest_observed));
    if (GetParam().version <= QUIC_VERSION_33) {
      if (largest_observed > 0) {
        frame.entropy_hash = QuicConnectionPeer::GetSentEntropyHash(
            &connection_, largest_observed);
      }
    } else {
      frame.missing = false;
      if (largest_observed > 0) {
        frame.packets.Add(1, largest_observed + 1);
      }
    }
    return frame;
  }

  const QuicStopWaitingFrame InitStopWaitingFrame(
      QuicPacketNumber least_unacked) {
    QuicStopWaitingFrame frame;
    frame.least_unacked = least_unacked;
    return frame;
  }

  // Explicitly nack a packet.
  void NackPacket(QuicPacketNumber missing, QuicAckFrame* frame) {
    if (frame->missing) {
      frame->packets.Add(missing);
      frame->entropy_hash ^=
          QuicConnectionPeer::PacketEntropy(&connection_, missing);
    } else {
      frame->packets.Remove(missing);
    }
  }

  // Undo nacking a packet within the frame.
  void AckPacket(QuicPacketNumber arrived, QuicAckFrame* frame) {
    if (frame->missing) {
      EXPECT_TRUE(frame->packets.Contains(arrived));
      frame->packets.Remove(arrived);
      frame->entropy_hash ^=
          QuicConnectionPeer::PacketEntropy(&connection_, arrived);
    } else {
      EXPECT_FALSE(frame->packets.Contains(arrived));
      frame->packets.Add(arrived);
    }
  }

  void TriggerConnectionClose() {
    // Send an erroneous packet to close the connection.
    EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_INVALID_PACKET_HEADER, _,
                                             ConnectionCloseSource::FROM_SELF));
    // Call ProcessDataPacket rather than ProcessPacket, as we should not get a
    // packet call to the visitor.
    ProcessDataPacket(kDefaultPathId, 6000, !kEntropyFlag);
    EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
                 nullptr);
  }

  void BlockOnNextWrite() {
    writer_->BlockOnNextWrite();
    EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  }

  void SetWritePauseTimeDelta(QuicTime::Delta delta) {
    writer_->SetWritePauseTimeDelta(delta);
  }

  void CongestionBlockWrites() {
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
        .WillRepeatedly(testing::Return(QuicTime::Delta::FromSeconds(1)));
  }

  void CongestionUnblockWrites() {
    EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
        .WillRepeatedly(testing::Return(QuicTime::Delta::Zero()));
  }

  void set_perspective(Perspective perspective) {
    connection_.set_perspective(perspective);
    QuicFramerPeer::SetPerspective(&peer_framer_,
                                   InvertPerspective(perspective));
  }

  QuicConnectionId connection_id_;
  QuicFramer framer_;
  MockEntropyCalculator entropy_calculator_;
  MockEntropyCalculator peer_entropy_calculator_;

  MockSendAlgorithm* send_algorithm_;
  MockLossAlgorithm* loss_algorithm_;
  MockClock clock_;
  MockRandom random_generator_;
  SimpleBufferAllocator buffer_allocator_;
  std::unique_ptr<TestConnectionHelper> helper_;
  std::unique_ptr<TestAlarmFactory> alarm_factory_;
  QuicFramer peer_framer_;
  QuicPacketCreator peer_creator_;
  std::unique_ptr<TestPacketWriter> writer_;
  TestConnection connection_;
  QuicPacketCreator* creator_;
  QuicPacketGenerator* generator_;
  QuicSentPacketManager* manager_;
  StrictMock<MockQuicConnectionVisitor> visitor_;

  QuicStreamFrame frame1_;
  QuicStreamFrame frame2_;
  QuicAckFrame ack_;
  QuicStopWaitingFrame stop_waiting_;
  QuicPacketNumberLength packet_number_length_;
  QuicConnectionIdLength connection_id_length_;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicConnectionTest);
};

// Run all end to end tests with all supported versions.
INSTANTIATE_TEST_CASE_P(SupportedVersion,
                        QuicConnectionTest,
                        ::testing::ValuesIn(GetTestParams()));

TEST_P(QuicConnectionTest, SelfAddressChangeAtClient) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  EXPECT_TRUE(connection_.connected());

  QuicStreamFrame stream_frame(1u, false, 0u, StringPiece());
  EXPECT_CALL(visitor_, OnStreamFrame(_));
  ProcessFramePacketWithAddresses(QuicFrame(&stream_frame), kSelfAddress,
                                  kPeerAddress);
  // Cause change in self_address.
  IPEndPoint self_address(IPAddress(1, 1, 1, 1), 123);
  EXPECT_CALL(visitor_, OnStreamFrame(_));
  ProcessFramePacketWithAddresses(QuicFrame(&stream_frame), self_address,
                                  kPeerAddress);
  EXPECT_TRUE(connection_.connected());
}

TEST_P(QuicConnectionTest, SelfAddressChangeAtServer) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  EXPECT_EQ(Perspective::IS_SERVER, connection_.perspective());
  EXPECT_TRUE(connection_.connected());

  QuicStreamFrame stream_frame(1u, false, 0u, StringPiece());
  EXPECT_CALL(visitor_, OnStreamFrame(_));
  ProcessFramePacketWithAddresses(QuicFrame(&stream_frame), kSelfAddress,
                                  kPeerAddress);
  // Cause change in self_address.
  IPEndPoint self_address(IPAddress(1, 1, 1, 1), 123);
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_ERROR_MIGRATING_ADDRESS, _, _));
  ProcessFramePacketWithAddresses(QuicFrame(&stream_frame), self_address,
                                  kPeerAddress);
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, MaxPacketSize) {
  EXPECT_EQ(Perspective::IS_CLIENT, connection_.perspective());
  EXPECT_EQ(1350u, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, SmallerServerMaxPacketSize) {
  QuicConnectionId connection_id = 42;
  TestConnection connection(connection_id, kPeerAddress, helper_.get(),
                            alarm_factory_.get(), writer_.get(),
                            Perspective::IS_SERVER, version());
  EXPECT_EQ(Perspective::IS_SERVER, connection.perspective());
  EXPECT_EQ(1000u, connection.max_packet_length());
}

TEST_P(QuicConnectionTest, IncreaseServerMaxPacketSize) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  set_perspective(Perspective::IS_SERVER);
  connection_.SetMaxPacketLength(1000);

  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.version_flag = true;
  header.path_id = kDefaultPathId;
  header.packet_number = 1;

  QuicFrames frames;
  QuicPaddingFrame padding;
  frames.push_back(QuicFrame(&frame1_));
  frames.push_back(QuicFrame(padding));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 12, *packet, buffer, kMaxPacketSize);
  EXPECT_EQ(kMaxPacketSize, encrypted_length);

  framer_.set_version(version());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));

  EXPECT_EQ(kMaxPacketSize, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, IncreaseServerMaxPacketSizeWhileWriterLimited) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  const QuicByteCount lower_max_packet_size = 1240;
  writer_->set_max_packet_size(lower_max_packet_size);
  set_perspective(Perspective::IS_SERVER);
  connection_.SetMaxPacketLength(1000);
  EXPECT_EQ(1000u, connection_.max_packet_length());

  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.version_flag = true;
  header.path_id = kDefaultPathId;
  header.packet_number = 1;

  QuicFrames frames;
  QuicPaddingFrame padding;
  frames.push_back(QuicFrame(&frame1_));
  frames.push_back(QuicFrame(padding));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 12, *packet, buffer, kMaxPacketSize);
  EXPECT_EQ(kMaxPacketSize, encrypted_length);

  framer_.set_version(version());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));

  // Here, the limit imposed by the writer is lower than the size of the packet
  // received, so the writer max packet size is used.
  EXPECT_EQ(lower_max_packet_size, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, LimitMaxPacketSizeByWriter) {
  const QuicByteCount lower_max_packet_size = 1240;
  writer_->set_max_packet_size(lower_max_packet_size);

  static_assert(lower_max_packet_size < kDefaultMaxPacketSize,
                "Default maximum packet size is too low");
  connection_.SetMaxPacketLength(kDefaultMaxPacketSize);

  EXPECT_EQ(lower_max_packet_size, connection_.max_packet_length());
}

TEST_P(QuicConnectionTest, LimitMaxPacketSizeByWriterForNewConnection) {
  const QuicConnectionId connection_id = 17;
  const QuicByteCount lower_max_packet_size = 1240;
  writer_->set_max_packet_size(lower_max_packet_size);
  TestConnection connection(connection_id, kPeerAddress, helper_.get(),
                            alarm_factory_.get(), writer_.get(),
                            Perspective::IS_CLIENT, version());
  EXPECT_EQ(Perspective::IS_CLIENT, connection.perspective());
  EXPECT_EQ(lower_max_packet_size, connection.max_packet_length());
}

TEST_P(QuicConnectionTest, PacketsInOrder) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(kDefaultPathId, 1);
  EXPECT_EQ(1u, outgoing_ack()->largest_observed);
  if (outgoing_ack()->missing) {
    EXPECT_TRUE(outgoing_ack()->packets.Empty());
  } else {
    EXPECT_EQ(1u, outgoing_ack()->packets.NumIntervals());
  }

  ProcessPacket(kDefaultPathId, 2);
  EXPECT_EQ(2u, outgoing_ack()->largest_observed);
  if (outgoing_ack()->missing) {
    EXPECT_TRUE(outgoing_ack()->packets.Empty());
  } else {
    EXPECT_EQ(1u, outgoing_ack()->packets.NumIntervals());
  }

  ProcessPacket(kDefaultPathId, 3);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  if (outgoing_ack()->missing) {
    EXPECT_TRUE(outgoing_ack()->packets.Empty());
  } else {
    EXPECT_EQ(1u, outgoing_ack()->packets.NumIntervals());
  }
}

TEST_P(QuicConnectionTest, PacketsOutOfOrder) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(kDefaultPathId, 3);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(kDefaultPathId, 2);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_FALSE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(kDefaultPathId, 1);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_FALSE(IsMissing(2));
  EXPECT_FALSE(IsMissing(1));
}

TEST_P(QuicConnectionTest, DuplicatePacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(kDefaultPathId, 3);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  // Send packet 3 again, but do not set the expectation that
  // the visitor OnStreamFrame() will be called.
  ProcessDataPacket(kDefaultPathId, 3, !kEntropyFlag);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));
}

TEST_P(QuicConnectionTest, PacketsOutOfOrderWithAdditionsAndLeastAwaiting) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(kDefaultPathId, 3);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_TRUE(IsMissing(2));
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(kDefaultPathId, 2);
  EXPECT_EQ(3u, outgoing_ack()->largest_observed);
  EXPECT_TRUE(IsMissing(1));

  ProcessPacket(kDefaultPathId, 5);
  EXPECT_EQ(5u, outgoing_ack()->largest_observed);
  EXPECT_TRUE(IsMissing(1));
  EXPECT_TRUE(IsMissing(4));

  // Pretend at this point the client has gotten acks for 2 and 3 and 1 is a
  // packet the peer will not retransmit.  It indicates this by sending 'least
  // awaiting' is 4.  The connection should then realize 1 will not be
  // retransmitted, and will remove it from the missing list.
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(_, _, _, _));
  ProcessAckPacket(6, &frame);

  // Force an ack to be sent.
  SendAckPacketToPeer();
  EXPECT_TRUE(IsMissing(4));
}

TEST_P(QuicConnectionTest, RejectPacketTooFarOut) {
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_INVALID_PACKET_HEADER, _,
                                           ConnectionCloseSource::FROM_SELF));
  // Call ProcessDataPacket rather than ProcessPacket, as we should not get a
  // packet call to the visitor.
  ProcessDataPacket(kDefaultPathId, 6000, !kEntropyFlag);
  EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
               nullptr);
}

TEST_P(QuicConnectionTest, RejectUnencryptedStreamData) {
  // Process an unencrypted packet from the non-crypto stream.
  frame1_.stream_id = 3;
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_UNENCRYPTED_STREAM_DATA, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_DFATAL(ProcessDataPacket(kDefaultPathId, 1, !kEntropyFlag), "");
  EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
               nullptr);
  const vector<QuicConnectionCloseFrame>& connection_close_frames =
      writer_->connection_close_frames();
  EXPECT_EQ(1u, connection_close_frames.size());
  EXPECT_EQ(QUIC_UNENCRYPTED_STREAM_DATA,
            connection_close_frames[0].error_code);
}

TEST_P(QuicConnectionTest, TruncatedAck) {
  if (GetParam().version > QUIC_VERSION_33) {
    return;
  }
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicPacketNumber num_packets = 256 * 2 + 1;
  for (QuicPacketNumber i = 0; i < num_packets; ++i) {
    SendStreamDataToPeer(3, "foo", i * 3, !kFin, nullptr);
  }

  QuicAckFrame frame = InitAckFrame(num_packets);
  // Create an ack with 256 nacks, none adjacent to one another.
  for (QuicPacketNumber i = 1; i <= 256; ++i) {
    NackPacket(i * 2, &frame);
  }
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(peer_entropy_calculator_, EntropyHash(511))
      .WillOnce(Return(static_cast<QuicPacketEntropyHash>(0)));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&frame);

  // A truncated ack will not have the true largest observed.
  EXPECT_GT(num_packets, manager_->GetLargestObserved(frame.path_id));

  AckPacket(192, &frame);

  // Removing one missing packet allows us to ack 192 and one more range, but
  // 192 has already been declared lost, so it doesn't register as an ack.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&frame);
  EXPECT_EQ(num_packets, manager_->GetLargestObserved(frame.path_id));
}

TEST_P(QuicConnectionTest, AckReceiptCausesAckSendBadEntropy) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(kDefaultPathId, 1);
  // Delay sending, then queue up an ack.
  QuicConnectionPeer::SendAck(&connection_);

  // Process an ack with a least unacked of the received ack.
  // This causes an ack to be sent when TimeUntilSend returns 0.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillRepeatedly(testing::Return(QuicTime::Delta::Zero()));
  // Skip a packet and then record an ack.
  QuicAckFrame frame = InitAckFrame(0);
  ProcessAckPacket(3, &frame);
}

TEST_P(QuicConnectionTest, OutOfOrderReceiptCausesAckSend) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  ProcessPacket(kDefaultPathId, 3);
  // Should ack immediately since we have missing packets.
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  ProcessPacket(kDefaultPathId, 2);
  // Should ack immediately since we have missing packets.
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  ProcessPacket(kDefaultPathId, 1);
  // Should ack immediately, since this fills the last hole.
  EXPECT_EQ(3u, writer_->packets_write_attempts());

  ProcessPacket(kDefaultPathId, 4);
  // Should not cause an ack.
  EXPECT_EQ(3u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, OutOfOrderAckReceiptCausesNoAck) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  SendStreamDataToPeer(1, "foo", 0, !kFin, nullptr);
  SendStreamDataToPeer(1, "bar", 3, !kFin, nullptr);
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  QuicAckFrame ack1 = InitAckFrame(1);
  QuicAckFrame ack2 = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(2, &ack2);
  // Should ack immediately since we have missing packets.
  EXPECT_EQ(2u, writer_->packets_write_attempts());

  ProcessAckPacket(1, &ack1);
  // Should not ack an ack filling a missing packet.
  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, AckReceiptCausesAckSend) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicPacketNumber original;
  QuicByteCount packet_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(
          DoAll(SaveArg<2>(&original), SaveArg<3>(&packet_size), Return(true)));
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, nullptr);
  QuicAckFrame frame = InitAckFrame(original);
  NackPacket(original, &frame);
  // First nack triggers early retransmit.
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicPacketNumber retransmission;
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, packet_size - kQuicVersionSize, _))
      .WillOnce(DoAll(SaveArg<2>(&retransmission), Return(true)));

  ProcessAckPacket(&frame);

  QuicAckFrame frame2 = InitAckFrame(retransmission);
  NackPacket(original, &frame2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  ProcessAckPacket(&frame2);

  // Now if the peer sends an ack which still reports the retransmitted packet
  // as missing, that will bundle an ack with data after two acks in a row
  // indicate the high water mark needs to be raised.
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, HAS_RETRANSMITTABLE_DATA));
  connection_.SendStreamDataWithString(3, "foo", 3, !kFin, nullptr);
  // No ack sent.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());

  // No more packet loss for the rest of the test.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _)).Times(AnyNumber());
  ProcessAckPacket(&frame2);
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, _, HAS_RETRANSMITTABLE_DATA));
  connection_.SendStreamDataWithString(3, "foo", 3, !kFin, nullptr);
  // Ack bundled.
  EXPECT_EQ(3u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_FALSE(writer_->ack_frames().empty());

  // But an ack with no missing packets will not send an ack.
  AckPacket(original, &frame2);
  ProcessAckPacket(&frame2);
  ProcessAckPacket(&frame2);
}

TEST_P(QuicConnectionTest, 20AcksCausesAckSend) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  SendStreamDataToPeer(1, "foo", 0, !kFin, nullptr);

  QuicAlarm* ack_alarm = QuicConnectionPeer::GetAckAlarm(&connection_);
  // But an ack with no missing packets will not send an ack.
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  for (int i = 0; i < 19; ++i) {
    ProcessAckPacket(&frame);
    EXPECT_FALSE(ack_alarm->IsSet());
  }
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  // The 20th ack packet will cause an ack to be sent.
  ProcessAckPacket(&frame);
  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, LeastUnackedLower) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  SendStreamDataToPeer(1, "foo", 0, !kFin, nullptr);
  SendStreamDataToPeer(1, "bar", 3, !kFin, nullptr);
  SendStreamDataToPeer(1, "eep", 6, !kFin, nullptr);

  // Start out saying the least unacked is 2.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 5);
  QuicStopWaitingFrame frame = InitStopWaitingFrame(2);
  ProcessStopWaitingPacket(&frame);

  // Change it to 1, but lower the packet number to fake out-of-order packets.
  // This should be fine.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 1);
  // The scheduler will not process out of order acks, but all packet processing
  // causes the connection to try to write.
  EXPECT_CALL(visitor_, OnCanWrite());
  QuicStopWaitingFrame frame2 = InitStopWaitingFrame(1);
  ProcessStopWaitingPacket(&frame2);

  // Now claim it's one, but set the ordering so it was sent "after" the first
  // one.  This should cause a connection error.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 7);
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_INVALID_STOP_WAITING_DATA, _,
                                           ConnectionCloseSource::FROM_SELF));
  QuicStopWaitingFrame frame3 = InitStopWaitingFrame(1);
  ProcessStopWaitingPacket(&frame3);
}

TEST_P(QuicConnectionTest, TooManySentPackets) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  const int num_packets = kMaxTrackedPackets + 100;
  for (int i = 0; i < num_packets; ++i) {
    SendStreamDataToPeer(1, "foo", 3 * i, !kFin, nullptr);
  }

  // Ack packet 1, which leaves more than the limit outstanding.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  if (GetParam().version <= QUIC_VERSION_33) {
    EXPECT_CALL(visitor_,
                OnConnectionClosed(QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS, _,
                                   ConnectionCloseSource::FROM_SELF));
    // We're receive buffer limited, so the connection won't try to write more.
    EXPECT_CALL(visitor_, OnCanWrite()).Times(0);
  }

  // Nack the first packet and ack the rest, leaving a huge gap.
  QuicAckFrame frame1 = InitAckFrame(num_packets);
  NackPacket(1, &frame1);
  ProcessAckPacket(&frame1);
}

TEST_P(QuicConnectionTest, TooManyReceivedPackets) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  if (GetParam().version <= QUIC_VERSION_33) {
    EXPECT_CALL(visitor_,
                OnConnectionClosed(QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS,
                                   _, ConnectionCloseSource::FROM_SELF));
  }
  // Miss 99 of every 100 packets for 5500 packets.
  for (QuicPacketNumber i = 1; i < kMaxTrackedPackets + 500; i += 100) {
    ProcessPacket(kDefaultPathId, i);
    if (!connection_.connected()) {
      break;
    }
  }
}

TEST_P(QuicConnectionTest, LargestObservedLower) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  SendStreamDataToPeer(1, "foo", 0, !kFin, nullptr);
  SendStreamDataToPeer(1, "bar", 3, !kFin, nullptr);
  SendStreamDataToPeer(1, "eep", 6, !kFin, nullptr);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));

  // Start out saying the largest observed is 2.
  QuicAckFrame frame1 = InitAckFrame(1);
  QuicAckFrame frame2 = InitAckFrame(2);
  ProcessAckPacket(&frame2);

  // Now change it to 1, and it should cause a connection error.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_INVALID_ACK_DATA, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(visitor_, OnCanWrite()).Times(0);
  ProcessAckPacket(&frame1);
}

TEST_P(QuicConnectionTest, AckUnsentData) {
  // Ack a packet which has not been sent.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_INVALID_ACK_DATA, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  QuicAckFrame frame(MakeAckFrame(1));
  EXPECT_CALL(visitor_, OnCanWrite()).Times(0);
  ProcessAckPacket(&frame);
}

TEST_P(QuicConnectionTest, AckAll) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);

  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 1);
  QuicAckFrame frame1 = InitAckFrame(0);
  ProcessAckPacket(&frame1);
}

TEST_P(QuicConnectionTest, BasicSending) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, !kFin, &last_packet);  // Packet 1
  EXPECT_EQ(1u, last_packet);
  SendAckPacketToPeer();  // Packet 2

  EXPECT_EQ(1u, least_unacked());

  SendAckPacketToPeer();  // Packet 3
  EXPECT_EQ(1u, least_unacked());

  SendStreamDataToPeer(1, "bar", 3, !kFin, &last_packet);  // Packet 4
  EXPECT_EQ(4u, last_packet);
  SendAckPacketToPeer();  // Packet 5
  EXPECT_EQ(1u, least_unacked());

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));

  // Peer acks up to packet 3.
  QuicAckFrame frame = InitAckFrame(3);
  ProcessAckPacket(&frame);
  SendAckPacketToPeer();  // Packet 6

  // As soon as we've acked one, we skip ack packets 2 and 3 and note lack of
  // ack for 4.
  EXPECT_EQ(4u, least_unacked());

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));

  // Peer acks up to packet 4, the last packet.
  QuicAckFrame frame2 = InitAckFrame(6);
  ProcessAckPacket(&frame2);  // Acks don't instigate acks.

  // Verify that we did not send an ack.
  EXPECT_EQ(6u, writer_->header().packet_number);

  // So the last ack has not changed.
  EXPECT_EQ(4u, least_unacked());

  // If we force an ack, we shouldn't change our retransmit state.
  SendAckPacketToPeer();  // Packet 7
  EXPECT_EQ(7u, least_unacked());

  // But if we send more data it should.
  SendStreamDataToPeer(1, "eep", 6, !kFin, &last_packet);  // Packet 8
  EXPECT_EQ(8u, last_packet);
  SendAckPacketToPeer();  // Packet 9
  EXPECT_EQ(7u, least_unacked());
}

// QuicConnection should record the the packet sent-time prior to sending the
// packet.
TEST_P(QuicConnectionTest, RecordSentTimeBeforePacketSent) {
  // We're using a MockClock for the tests, so we have complete control over the
  // time.
  // Our recorded timestamp for the last packet sent time will be passed in to
  // the send_algorithm.  Make sure that it is set to the correct value.
  QuicTime actual_recorded_send_time = QuicTime::Zero();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<0>(&actual_recorded_send_time), Return(true)));

  // First send without any pause and check the result.
  QuicTime expected_recorded_send_time = clock_.Now();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(expected_recorded_send_time, actual_recorded_send_time)
      << "Expected time = " << expected_recorded_send_time.ToDebuggingValue()
      << ".  Actual time = " << actual_recorded_send_time.ToDebuggingValue();

  // Now pause during the write, and check the results.
  actual_recorded_send_time = QuicTime::Zero();
  const QuicTime::Delta write_pause_time_delta =
      QuicTime::Delta::FromMilliseconds(5000);
  SetWritePauseTimeDelta(write_pause_time_delta);
  expected_recorded_send_time = clock_.Now();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<0>(&actual_recorded_send_time), Return(true)));
  connection_.SendStreamDataWithString(2, "baz", 0, !kFin, nullptr);
  EXPECT_EQ(expected_recorded_send_time, actual_recorded_send_time)
      << "Expected time = " << expected_recorded_send_time.ToDebuggingValue()
      << ".  Actual time = " << actual_recorded_send_time.ToDebuggingValue();
}

TEST_P(QuicConnectionTest, FramePacking) {
  // Send an ack and two stream frames in 1 packet by queueing them.
  {
    QuicConnection::ScopedPacketBundler bundler(&connection_,
                                                QuicConnection::SEND_ACK);
    connection_.SendStreamData3();
    connection_.SendStreamData5();
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's an ack and two stream frames from
  // two different streams.
  EXPECT_EQ(4u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  ASSERT_EQ(2u, writer_->stream_frames().size());
  EXPECT_EQ(kClientDataStreamId1, writer_->stream_frames()[0]->stream_id);
  EXPECT_EQ(kClientDataStreamId2, writer_->stream_frames()[1]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingNonCryptoThenCrypto) {
  // Send an ack and two stream frames (one non-crypto, then one crypto) in 2
  // packets by queueing them.
  {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
    QuicConnection::ScopedPacketBundler bundler(&connection_,
                                                QuicConnection::SEND_ACK);
    connection_.SendStreamData3();
    connection_.SendCryptoStreamData();
  }
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's the crypto stream frame.
  EXPECT_EQ(1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(kCryptoStreamId, writer_->stream_frames()[0]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingCryptoThenNonCrypto) {
  // Send an ack and two stream frames (one crypto, then one non-crypto) in 2
  // packets by queueing them.
  {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
    QuicConnection::ScopedPacketBundler bundler(&connection_,
                                                QuicConnection::SEND_ACK);
    connection_.SendCryptoStreamData();
    connection_.SendStreamData3();
  }
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's the stream frame from stream 3.
  EXPECT_EQ(1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(kClientDataStreamId1, writer_->stream_frames()[0]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingAckResponse) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  // Process a data packet to queue up a pending ack.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacket(kDefaultPathId, 1, kEntropyFlag);

  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(DoAll(IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData3)),
                      IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData5))));

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);

  // Process an ack to cause the visitor's OnCanWrite to be invoked.
  QuicAckFrame ack_one = InitAckFrame(0);
  ProcessAckPacket(3, &ack_one);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's an ack and two stream frames from
  // two different streams.
  EXPECT_EQ(4u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  ASSERT_EQ(2u, writer_->stream_frames().size());
  EXPECT_EQ(kClientDataStreamId1, writer_->stream_frames()[0]->stream_id);
  EXPECT_EQ(kClientDataStreamId2, writer_->stream_frames()[1]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingSendv) {
  // Send data in 1 packet by writing multiple blocks in a single iovector
  // using writev.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));

  char data[] = "ABCD";
  struct iovec iov[2];
  iov[0].iov_base = data;
  iov[0].iov_len = 2;
  iov[1].iov_base = data + 2;
  iov[1].iov_len = 2;
  connection_.SendStreamData(1, QuicIOVector(iov, 2, 4), 0, !kFin, nullptr);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure multiple iovector blocks have
  // been packed into a single stream frame from one stream.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  QuicStreamFrame* frame = writer_->stream_frames()[0];
  EXPECT_EQ(1u, frame->stream_id);
  EXPECT_EQ("ABCD", StringPiece(frame->data_buffer, frame->data_length));
}

TEST_P(QuicConnectionTest, FramePackingSendvQueued) {
  // Try to send two stream frames in 1 packet by using writev.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));

  BlockOnNextWrite();
  char data[] = "ABCD";
  struct iovec iov[2];
  iov[0].iov_base = data;
  iov[0].iov_len = 2;
  iov[1].iov_base = data + 2;
  iov[1].iov_len = 2;
  connection_.SendStreamData(1, QuicIOVector(iov, 2, 4), 0, !kFin, nullptr);

  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  EXPECT_TRUE(connection_.HasQueuedData());

  // Unblock the writes and actually send.
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());

  // Parse the last packet and ensure it's one stream frame from one stream.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(1u, writer_->stream_frames()[0]->stream_id);
}

TEST_P(QuicConnectionTest, SendingZeroBytes) {
  // Send a zero byte write with a fin using writev.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  QuicIOVector empty_iov(nullptr, 0, 0);
  connection_.SendStreamData(kHeadersStreamId, empty_iov, 0, kFin, nullptr);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's one stream frame from one stream.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(kHeadersStreamId, writer_->stream_frames()[0]->stream_id);
  EXPECT_TRUE(writer_->stream_frames()[0]->fin);
}

TEST_P(QuicConnectionTest, LargeSendWithPendingAck) {
  // Set the ack alarm by processing a ping frame.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Processs a PING frame.
  ProcessFramePacket(QuicFrame(QuicPingFrame()));
  // Ensure that this has caused the ACK alarm to be set.
  QuicAlarm* ack_alarm = QuicConnectionPeer::GetAckAlarm(&connection_);
  EXPECT_TRUE(ack_alarm->IsSet());

  // Send data and ensure the ack is bundled.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(8);
  size_t len = 10000;
  std::unique_ptr<char[]> data_array(new char[len]);
  memset(data_array.get(), '?', len);
  struct iovec iov;
  iov.iov_base = data_array.get();
  iov.iov_len = len;
  QuicIOVector iovector(&iov, 1, len);
  QuicConsumedData consumed =
      connection_.SendStreamData(kHeadersStreamId, iovector, 0, true, nullptr);
  EXPECT_EQ(len, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's one stream frame with a fin.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(kHeadersStreamId, writer_->stream_frames()[0]->stream_id);
  EXPECT_TRUE(writer_->stream_frames()[0]->fin);
  // Ensure the ack alarm was cancelled when the ack was sent.
  EXPECT_FALSE(ack_alarm->IsSet());
}

TEST_P(QuicConnectionTest, OnCanWrite) {
  // Visitor's OnCanWrite will send data, but will have more pending writes.
  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(DoAll(IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData3)),
                      IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData5))));
  EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillOnce(Return(true));
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillRepeatedly(testing::Return(QuicTime::Delta::Zero()));

  connection_.OnCanWrite();

  // Parse the last packet and ensure it's the two stream frames from
  // two different streams.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_EQ(2u, writer_->stream_frames().size());
  EXPECT_EQ(kClientDataStreamId1, writer_->stream_frames()[0]->stream_id);
  EXPECT_EQ(kClientDataStreamId2, writer_->stream_frames()[1]->stream_id);
}

TEST_P(QuicConnectionTest, RetransmitOnNack) {
  QuicPacketNumber last_packet;
  QuicByteCount second_packet_size;
  SendStreamDataToPeer(3, "foo", 0, !kFin, &last_packet);  // Packet 1
  second_packet_size =
      SendStreamDataToPeer(3, "foos", 3, !kFin, &last_packet);  // Packet 2
  SendStreamDataToPeer(3, "fooos", 7, !kFin, &last_packet);     // Packet 3

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Don't lose a packet on an ack, and nothing is retransmitted.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame ack_one = InitAckFrame(1);
  ProcessAckPacket(&ack_one);

  // Lose a packet and ensure it triggers retransmission.
  QuicAckFrame nack_two = InitAckFrame(3);
  NackPacket(2, &nack_two);
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(2, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, second_packet_size - kQuicVersionSize, _))
      .Times(1);
  ProcessAckPacket(&nack_two);
}

TEST_P(QuicConnectionTest, DoNotSendQueuedPacketForResetStream) {
  // Block the connection to queue the packet.
  BlockOnNextWrite();

  QuicStreamId stream_id = 2;
  connection_.SendStreamDataWithString(stream_id, "foo", 0, !kFin, nullptr);

  // Now that there is a queued packet, reset the stream.
  connection_.SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 14);

  // Unblock the connection and verify that only the RST_STREAM is sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
}

TEST_P(QuicConnectionTest, SendQueuedPacketForQuicRstStreamNoError) {
  // Block the connection to queue the packet.
  BlockOnNextWrite();

  QuicStreamId stream_id = 2;
  connection_.SendStreamDataWithString(stream_id, "foo", 0, !kFin, nullptr);

  // Now that there is a queued packet, reset the stream.
  connection_.SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 14);

  // Unblock the connection and verify that the RST_STREAM is sent and the data
  // packet is sent on QUIC_VERSION_29 or later versions.
  if (version() > QUIC_VERSION_28) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AtLeast(2));
  } else {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
}

TEST_P(QuicConnectionTest, DoNotRetransmitForResetStreamOnNack) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, !kFin, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, !kFin, &last_packet);
  SendStreamDataToPeer(stream_id, "fooos", 7, !kFin, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 14);

  // Lose a packet and ensure it does not trigger retransmission.
  QuicAckFrame nack_two = InitAckFrame(last_packet);
  NackPacket(last_packet - 1, &nack_two);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&nack_two);
}

TEST_P(QuicConnectionTest, RetransmitForQuicRstStreamNoErrorOnNack) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, !kFin, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, !kFin, &last_packet);
  SendStreamDataToPeer(stream_id, "fooos", 7, !kFin, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 14);

  // Lose a packet, ensure it triggers retransmission on QUIC_VERSION_29
  // or later versions.
  QuicAckFrame nack_two = InitAckFrame(last_packet);
  NackPacket(last_packet - 1, &nack_two);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(last_packet - 1, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  if (version() > QUIC_VERSION_28) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AtLeast(1));
  } else {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  }
  ProcessAckPacket(&nack_two);
}

TEST_P(QuicConnectionTest, DoNotRetransmitForResetStreamOnRTO) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, !kFin, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 14);

  // Fire the RTO and verify that the RST_STREAM is resent, not stream data.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
  EXPECT_EQ(stream_id, writer_->rst_stream_frames().front().stream_id);
}

TEST_P(QuicConnectionTest, RetransmitForQuicRstStreamNoErrorOnRTO) {
  connection_.DisableTailLossProbe();

  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, !kFin, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 14);

  // Fire the RTO and verify that the RST_STREAM is resent, the stream data
  // is only sent on QUIC_VERSION_29 or later versions.
  if (version() > QUIC_VERSION_28) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AtLeast(2));
  } else {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->rst_stream_frames().size());
  EXPECT_EQ(stream_id, writer_->rst_stream_frames().front().stream_id);
}

TEST_P(QuicConnectionTest, DoNotSendPendingRetransmissionForResetStream) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, !kFin, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, !kFin, &last_packet);
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(stream_id, "fooos", 7, !kFin, nullptr);

  // Lose a packet which will trigger a pending retransmission.
  QuicAckFrame ack = InitAckFrame(last_packet);
  NackPacket(last_packet - 1, &ack);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&ack);

  connection_.SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 14);

  // Unblock the connection and verify that the RST_STREAM is sent but not the
  // second data packet nor a retransmit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
  EXPECT_EQ(stream_id, writer_->rst_stream_frames().front().stream_id);
}

TEST_P(QuicConnectionTest, SendPendingRetransmissionForQuicRstStreamNoError) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, !kFin, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, !kFin, &last_packet);
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(stream_id, "fooos", 7, !kFin, nullptr);

  // Lose a packet which will trigger a pending retransmission.
  QuicAckFrame ack = InitAckFrame(last_packet);
  NackPacket(last_packet - 1, &ack);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(last_packet - 1, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&ack);

  connection_.SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 14);

  // Unblock the connection and verify that the RST_STREAM is sent and the
  // second data packet or a retransmit is only sent on QUIC_VERSION_29 or
  // later versions.
  if (version() > QUIC_VERSION_28) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AtLeast(2));
  } else {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(1u, writer_->frame_count());
  if (version() > QUIC_VERSION_28) {
    EXPECT_EQ(0u, writer_->rst_stream_frames().size());
  } else {
    EXPECT_EQ(1u, writer_->rst_stream_frames().size());
    EXPECT_EQ(stream_id, writer_->rst_stream_frames().front().stream_id);
  }
}

TEST_P(QuicConnectionTest, DiscardRetransmit) {
  FLAGS_quic_always_write_queued_retransmissions = false;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, !kFin, &last_packet);    // Packet 1
  SendStreamDataToPeer(1, "foos", 3, !kFin, &last_packet);   // Packet 2
  SendStreamDataToPeer(1, "fooos", 7, !kFin, &last_packet);  // Packet 3

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Instigate a loss with an ack.
  QuicAckFrame nack_two = InitAckFrame(3);
  NackPacket(2, &nack_two);
  // The first nack should trigger a fast retransmission, but we'll be
  // write blocked, so the packet will be queued.
  BlockOnNextWrite();

  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(2, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&nack_two);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Now, ack the previous transmission.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  QuicAckFrame ack_all = InitAckFrame(3);
  ProcessAckPacket(&ack_all);

  // Unblock the socket and attempt to send the queued packets.  However,
  // since the previous transmission has been acked, we will not
  // send the retransmission.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);

  writer_->SetWritable();
  connection_.OnCanWrite();

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, RetransmitAckedPacket) {
  FLAGS_quic_always_write_queued_retransmissions = true;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, !kFin, &last_packet);    // Packet 1
  SendStreamDataToPeer(1, "foos", 3, !kFin, &last_packet);   // Packet 2
  SendStreamDataToPeer(1, "fooos", 7, !kFin, &last_packet);  // Packet 3

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Instigate a loss with an ack.
  QuicAckFrame nack_two = InitAckFrame(3);
  NackPacket(2, &nack_two);
  // The first nack should trigger a fast retransmission, but we'll be
  // write blocked, so the packet will be queued.
  BlockOnNextWrite();

  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(2, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&nack_two);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Now, ack the previous transmission.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  QuicAckFrame ack_all = InitAckFrame(3);
  ProcessAckPacket(&ack_all);

  // Unblock the socket and attempt to send the queued packets. We will always
  // send the retransmission.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 4, _, _)).Times(1);

  writer_->SetWritable();
  connection_.OnCanWrite();

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  // We do not store retransmittable frames of this retransmission.
  EXPECT_FALSE(connection_.sent_packet_manager().HasRetransmittableFrames(
      kDefaultPathId, 4));
}

TEST_P(QuicConnectionTest, RetransmitNackedLargestObserved) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicPacketNumber largest_observed;
  QuicByteCount packet_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<2>(&largest_observed), SaveArg<3>(&packet_size),
                      Return(true)));
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, nullptr);

  QuicAckFrame frame = InitAckFrame(1);
  NackPacket(largest_observed, &frame);
  // The first nack should retransmit the largest observed packet.
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_,
              OnPacketSent(_, _, _, packet_size - kQuicVersionSize, _));
  ProcessAckPacket(&frame);
}

TEST_P(QuicConnectionTest, QueueAfterTwoRTOs) {
  connection_.DisableTailLossProbe();

  for (int i = 0; i < 10; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    connection_.SendStreamDataWithString(3, "foo", i * 3, !kFin, nullptr);
  }

  // Block the writer and ensure they're queued.
  BlockOnNextWrite();
  clock_.AdvanceTime(DefaultRetransmissionTime());
  // Only one packet should be retransmitted.
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_TRUE(connection_.HasQueuedData());

  // Unblock the writer.
  writer_->SetWritable();
  clock_.AdvanceTime(QuicTime::Delta::FromMicroseconds(
      2 * DefaultRetransmissionTime().ToMicroseconds()));
  // Retransmit already retransmitted packets event though the packet number
  // greater than the largest observed.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  connection_.GetRetransmissionAlarm()->Fire();
  connection_.OnCanWrite();
}

TEST_P(QuicConnectionTest, WriteBlockedBufferedThenSent) {
  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, WriteBlockedThenSent) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // The second packet should also be queued, in order to ensure packets are
  // never sent out of order.
  writer_->SetWritable();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(2u, connection_.NumQueuedPackets());

  // Now both are sent in order when we unblock.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, RetransmitWriteBlockedAckedOriginalThenSent) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, nullptr);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  // Simulate the retransmission alarm firing.
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();

  // Ack the sent packet before the callback returns, which happens in
  // rare circumstances with write blocked sockets.
  QuicAckFrame ack = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&ack);

  writer_->SetWritable();
  connection_.OnCanWrite();
  // There is now a pending packet, but with no retransmittable frames.
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.sent_packet_manager().HasRetransmittableFrames(
      ack.path_id, 2));
}

TEST_P(QuicConnectionTest, AlarmsWhenWriteBlocked) {
  // Block the connection.
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(writer_->IsWriteBlocked());

  // Set the send and resumption alarms. Fire the alarms and ensure they don't
  // attempt to write.
  connection_.GetResumeWritesAlarm()->Set(clock_.ApproximateNow());
  connection_.GetSendAlarm()->Set(clock_.ApproximateNow());
  connection_.GetResumeWritesAlarm()->Fire();
  connection_.GetSendAlarm()->Fire();
  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_EQ(1u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, NoLimitPacketsPerNack) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  int offset = 0;
  // Send packets 1 to 15.
  for (int i = 0; i < 15; ++i) {
    SendStreamDataToPeer(1, "foo", offset, !kFin, nullptr);
    offset += 3;
  }

  // Ack 15, nack 1-14.

  QuicAckFrame nack = InitAckFrame(15);
  for (int i = 1; i < 15; ++i) {
    NackPacket(i, &nack);
  }

  // 14 packets have been NACK'd and lost.
  SendAlgorithmInterface::CongestionVector lost_packets;
  for (int i = 1; i < 15; ++i) {
    lost_packets.push_back(std::make_pair(i, kMaxPacketSize));
  }
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(14);
  ProcessAckPacket(&nack);
}

// Test sending multiple acks from the connection to the session.
TEST_P(QuicConnectionTest, MultipleAcks) {
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, !kFin, &last_packet);  // Packet 1
  EXPECT_EQ(1u, last_packet);
  SendStreamDataToPeer(3, "foo", 0, !kFin, &last_packet);  // Packet 2
  EXPECT_EQ(2u, last_packet);
  SendAckPacketToPeer();                                   // Packet 3
  SendStreamDataToPeer(5, "foo", 0, !kFin, &last_packet);  // Packet 4
  EXPECT_EQ(4u, last_packet);
  SendStreamDataToPeer(1, "foo", 3, !kFin, &last_packet);  // Packet 5
  EXPECT_EQ(5u, last_packet);
  SendStreamDataToPeer(3, "foo", 3, !kFin, &last_packet);  // Packet 6
  EXPECT_EQ(6u, last_packet);

  // Client will ack packets 1, 2, [!3], 4, 5.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame frame1 = InitAckFrame(5);
  NackPacket(3, &frame1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessAckPacket(&frame1);

  // Now the client implicitly acks 3, and explicitly acks 6.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame frame2 = InitAckFrame(6);
  ProcessAckPacket(&frame2);
}

TEST_P(QuicConnectionTest, DontLatchUnackedPacket) {
  SendStreamDataToPeer(1, "foo", 0, !kFin, nullptr);  // Packet 1;
  // From now on, we send acks, so the send algorithm won't mark them pending.
  ON_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillByDefault(Return(false));
  SendAckPacketToPeer();  // Packet 2

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame frame = InitAckFrame(1);
  ProcessAckPacket(&frame);

  // Verify that our internal state has least-unacked as 2, because we're still
  // waiting for a potential ack for 2.

  EXPECT_EQ(2u, stop_waiting()->least_unacked);

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  frame = InitAckFrame(2);
  ProcessAckPacket(&frame);
  EXPECT_EQ(3u, stop_waiting()->least_unacked);

  // When we send an ack, we make sure our least-unacked makes sense.  In this
  // case since we're not waiting on an ack for 2 and all packets are acked, we
  // set it to 3.
  SendAckPacketToPeer();  // Packet 3
  // Least_unacked remains at 3 until another ack is received.
  EXPECT_EQ(3u, stop_waiting()->least_unacked);
  // Check that the outgoing ack had its packet number as least_unacked.
  EXPECT_EQ(3u, least_unacked());

  // Ack the ack, which updates the rtt and raises the least unacked.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  frame = InitAckFrame(3);
  ProcessAckPacket(&frame);

  ON_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillByDefault(Return(true));
  SendStreamDataToPeer(1, "bar", 3, false, nullptr);  // Packet 4
  EXPECT_EQ(4u, stop_waiting()->least_unacked);
  ON_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillByDefault(Return(false));
  SendAckPacketToPeer();  // Packet 5
  EXPECT_EQ(4u, least_unacked());

  // Send two data packets at the end, and ensure if the last one is acked,
  // the least unacked is raised above the ack packets.
  ON_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillByDefault(Return(true));
  SendStreamDataToPeer(1, "bar", 6, false, nullptr);  // Packet 6
  SendStreamDataToPeer(1, "bar", 9, false, nullptr);  // Packet 7

  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  frame = InitAckFrame(7);
  NackPacket(5, &frame);
  NackPacket(6, &frame);
  ProcessAckPacket(&frame);

  EXPECT_EQ(6u, stop_waiting()->least_unacked);
}

TEST_P(QuicConnectionTest, TLP) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(manager_, 1);

  SendStreamDataToPeer(3, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(1u, stop_waiting()->least_unacked);
  QuicTime retransmission_time =
      connection_.GetRetransmissionAlarm()->deadline();
  EXPECT_NE(QuicTime::Zero(), retransmission_time);

  EXPECT_EQ(1u, writer_->header().packet_number);
  // Simulate the retransmission alarm firing and sending a tlp,
  // so send algorithm's OnRetransmissionTimeout is not called.
  clock_.AdvanceTime(retransmission_time.Subtract(clock_.Now()));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 2u, _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(2u, writer_->header().packet_number);
  // We do not raise the high water mark yet.
  EXPECT_EQ(1u, stop_waiting()->least_unacked);
}

TEST_P(QuicConnectionTest, RTO) {
  connection_.DisableTailLossProbe();

  QuicTime default_retransmission_time =
      clock_.ApproximateNow().Add(DefaultRetransmissionTime());
  SendStreamDataToPeer(3, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(1u, stop_waiting()->least_unacked);

  EXPECT_EQ(1u, writer_->header().packet_number);
  EXPECT_EQ(default_retransmission_time,
            connection_.GetRetransmissionAlarm()->deadline());
  // Simulate the retransmission alarm firing.
  clock_.AdvanceTime(DefaultRetransmissionTime());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 2u, _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(2u, writer_->header().packet_number);
  // We do not raise the high water mark yet.
  EXPECT_EQ(1u, stop_waiting()->least_unacked);
}

TEST_P(QuicConnectionTest, RTOWithSameEncryptionLevel) {
  connection_.DisableTailLossProbe();

  QuicTime default_retransmission_time =
      clock_.ApproximateNow().Add(DefaultRetransmissionTime());
  use_tagging_decrypter();

  // A TaggingEncrypter puts kTagSize copies of the given byte (0x01 here) at
  // the end of the packet. We can test this to check which encrypter was used.
  connection_.SetEncrypter(ENCRYPTION_NONE, new TaggingEncrypter(0x01));
  SendStreamDataToPeer(3, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(0x01010101u, writer_->final_bytes_of_last_packet());

  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  SendStreamDataToPeer(3, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());

  EXPECT_EQ(default_retransmission_time,
            connection_.GetRetransmissionAlarm()->deadline());
  {
    InSequence s;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 3, _, _));
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 4, _, _));
  }

  // Simulate the retransmission alarm firing.
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();

  // Packet should have been sent with ENCRYPTION_NONE.
  EXPECT_EQ(0x01010101u, writer_->final_bytes_of_previous_packet());

  // Packet should have been sent with ENCRYPTION_INITIAL.
  EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest, SendHandshakeMessages) {
  use_tagging_decrypter();
  // A TaggingEncrypter puts kTagSize copies of the given byte (0x01 here) at
  // the end of the packet. We can test this to check which encrypter was used.
  connection_.SetEncrypter(ENCRYPTION_NONE, new TaggingEncrypter(0x01));

  // Attempt to send a handshake message and have the socket block.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillRepeatedly(testing::Return(QuicTime::Delta::Zero()));
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  // The packet should be serialized, but not queued.
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Switch to the new encrypter.
  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);

  // Now become writeable and flush the packets.
  writer_->SetWritable();
  EXPECT_CALL(visitor_, OnCanWrite());
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());

  // Verify that the handshake packet went out at the null encryption.
  EXPECT_EQ(0x01010101u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest,
       DropRetransmitsForNullEncryptedPacketAfterForwardSecure) {
  use_tagging_decrypter();
  connection_.SetEncrypter(ENCRYPTION_NONE, new TaggingEncrypter(0x01));
  QuicPacketNumber packet_number;
  SendStreamDataToPeer(3, "foo", 0, !kFin, &packet_number);

  // Simulate the retransmission alarm firing and the socket blocking.
  BlockOnNextWrite();
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();

  // Go forward secure.
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           new TaggingEncrypter(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  connection_.NeuterUnencryptedPackets();

  EXPECT_EQ(QuicTime::Zero(), connection_.GetRetransmissionAlarm()->deadline());
  // Unblock the socket and ensure that no packets are sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  writer_->SetWritable();
  connection_.OnCanWrite();
}

TEST_P(QuicConnectionTest, RetransmitPacketsWithInitialEncryption) {
  use_tagging_decrypter();
  connection_.SetEncrypter(ENCRYPTION_NONE, new TaggingEncrypter(0x01));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_NONE);

  SendStreamDataToPeer(1, "foo", 0, !kFin, nullptr);

  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);

  SendStreamDataToPeer(2, "bar", 0, !kFin, nullptr);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);

  connection_.RetransmitUnackedPackets(ALL_INITIAL_RETRANSMISSION);
}

TEST_P(QuicConnectionTest, DelayForwardSecureEncryptionUntilClientIsReady) {
  // A TaggingEncrypter puts kTagSize copies of the given byte (0x02 here) at
  // the end of the packet. We can test this to check which encrypter was used.
  use_tagging_decrypter();
  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  SendAckPacketToPeer();
  EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());

  // Set a forward-secure encrypter but do not make it the default, and verify
  // that it is not yet used.
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           new TaggingEncrypter(0x03));
  SendAckPacketToPeer();
  EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());

  // Now simulate receipt of a forward-secure packet and verify that the
  // forward-secure encrypter is now used.
  connection_.OnDecryptedPacket(ENCRYPTION_FORWARD_SECURE);
  SendAckPacketToPeer();
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest, DelayForwardSecureEncryptionUntilManyPacketSent) {
  // Set a congestion window of 10 packets.
  QuicPacketCount congestion_window = 10;
  EXPECT_CALL(*send_algorithm_, GetCongestionWindow())
      .WillRepeatedly(Return(congestion_window * kDefaultMaxPacketSize));

  // A TaggingEncrypter puts kTagSize copies of the given byte (0x02 here) at
  // the end of the packet. We can test this to check which encrypter was used.
  use_tagging_decrypter();
  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(0x02));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  SendAckPacketToPeer();
  EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());

  // Set a forward-secure encrypter but do not make it the default, and
  // verify that it is not yet used.
  connection_.SetEncrypter(ENCRYPTION_FORWARD_SECURE,
                           new TaggingEncrypter(0x03));
  SendAckPacketToPeer();
  EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());

  // Now send a packet "Far enough" after the encrypter was set and verify that
  // the forward-secure encrypter is now used.
  for (uint64_t i = 0; i < 3 * congestion_window - 1; ++i) {
    EXPECT_EQ(0x02020202u, writer_->final_bytes_of_last_packet());
    SendAckPacketToPeer();
  }
  EXPECT_EQ(0x03030303u, writer_->final_bytes_of_last_packet());
}

TEST_P(QuicConnectionTest, BufferNonDecryptablePackets) {
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  use_tagging_decrypter();

  const uint8_t tag = 0x07;
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));

  // Process an encrypted packet which can not yet be decrypted which should
  // result in the packet being buffered.
  ProcessDataPacketAtLevel(kDefaultPathId, 1, kEntropyFlag, !kHasStopWaiting,
                           ENCRYPTION_INITIAL);

  // Transition to the new encryption state and process another encrypted packet
  // which should result in the original packet being processed.
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(2);
  ProcessDataPacketAtLevel(kDefaultPathId, 2, kEntropyFlag, !kHasStopWaiting,
                           ENCRYPTION_INITIAL);

  // Finally, process a third packet and note that we do not reprocess the
  // buffered packet.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, 3, kEntropyFlag, !kHasStopWaiting,
                           ENCRYPTION_INITIAL);
}

TEST_P(QuicConnectionTest, Buffer100NonDecryptablePackets) {
  // SetFromConfig is always called after construction from InitializeSession.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  config.set_max_undecryptable_packets(100);
  connection_.SetFromConfig(config);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  use_tagging_decrypter();

  const uint8_t tag = 0x07;
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));

  // Process an encrypted packet which can not yet be decrypted which should
  // result in the packet being buffered.
  for (QuicPacketNumber i = 1; i <= 100; ++i) {
    ProcessDataPacketAtLevel(kDefaultPathId, i, kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }

  // Transition to the new encryption state and process another encrypted packet
  // which should result in the original packets being processed.
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
  connection_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(101);
  ProcessDataPacketAtLevel(kDefaultPathId, 101, kEntropyFlag, !kHasStopWaiting,
                           ENCRYPTION_INITIAL);

  // Finally, process a third packet and note that we do not reprocess the
  // buffered packet.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, 102, kEntropyFlag, !kHasStopWaiting,
                           ENCRYPTION_INITIAL);
}

TEST_P(QuicConnectionTest, TestRetransmitOrder) {
  connection_.DisableTailLossProbe();

  QuicByteCount first_packet_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&first_packet_size), Return(true)));

  connection_.SendStreamDataWithString(3, "first_packet", 0, !kFin, nullptr);
  QuicByteCount second_packet_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&second_packet_size), Return(true)));
  connection_.SendStreamDataWithString(3, "second_packet", 12, !kFin, nullptr);
  EXPECT_NE(first_packet_size, second_packet_size);
  // Advance the clock by huge time to make sure packets will be retransmitted.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10));
  {
    InSequence s;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, first_packet_size, _));
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, second_packet_size, _));
  }
  connection_.GetRetransmissionAlarm()->Fire();

  // Advance again and expect the packets to be sent again in the same order.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(20));
  {
    InSequence s;
    EXPECT_CALL(visitor_, OnPathDegrading());
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, first_packet_size, _));
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, second_packet_size, _));
  }
  connection_.GetRetransmissionAlarm()->Fire();
}

TEST_P(QuicConnectionTest, SetRTOAfterWritingToSocket) {
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  // Make sure that RTO is not started when the packet is queued.
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());

  // Test that RTO is started once we write to the socket.
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, DelayRTOWithAckReceipt) {
  connection_.DisableTailLossProbe();

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  connection_.SendStreamDataWithString(2, "foo", 0, !kFin, nullptr);
  connection_.SendStreamDataWithString(3, "bar", 0, !kFin, nullptr);
  QuicAlarm* retransmission_alarm = connection_.GetRetransmissionAlarm();
  EXPECT_TRUE(retransmission_alarm->IsSet());
  EXPECT_EQ(clock_.Now().Add(DefaultRetransmissionTime()),
            retransmission_alarm->deadline());

  // Advance the time right before the RTO, then receive an ack for the first
  // packet to delay the RTO.
  clock_.AdvanceTime(DefaultRetransmissionTime());
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame ack = InitAckFrame(1);
  ProcessAckPacket(&ack);
  EXPECT_TRUE(retransmission_alarm->IsSet());
  EXPECT_GT(retransmission_alarm->deadline(), clock_.Now());

  // Move forward past the original RTO and ensure the RTO is still pending.
  clock_.AdvanceTime(DefaultRetransmissionTime().Multiply(2));

  // Ensure the second packet gets retransmitted when it finally fires.
  EXPECT_TRUE(retransmission_alarm->IsSet());
  EXPECT_LT(retransmission_alarm->deadline(), clock_.ApproximateNow());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  // Manually cancel the alarm to simulate a real test.
  connection_.GetRetransmissionAlarm()->Fire();

  // The new retransmitted packet number should set the RTO to a larger value
  // than previously.
  EXPECT_TRUE(retransmission_alarm->IsSet());
  QuicTime next_rto_time = retransmission_alarm->deadline();
  QuicTime expected_rto_time =
      connection_.sent_packet_manager().GetRetransmissionTime();
  EXPECT_EQ(next_rto_time, expected_rto_time);
}

TEST_P(QuicConnectionTest, TestQueued) {
  connection_.DisableTailLossProbe();

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Unblock the writes and actually send.
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, InitialTimeout) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());

  // SetFromConfig sets the initial timeouts before negotiation.
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  // Subtract a second from the idle timeout on the client side.
  QuicTime default_timeout = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1));
  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_NETWORK_IDLE_TIMEOUT, _,
                                           ConnectionCloseSource::FROM_SELF));
  // Simulate the timeout alarm firing.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1));
  connection_.GetTimeoutAlarm()->Fire();

  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());

  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetResumeWritesAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, HandshakeTimeout) {
  // Use a shorter handshake timeout than idle timeout for this test.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  connection_.SetNetworkTimeouts(timeout, timeout);
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());

  QuicTime handshake_timeout = clock_.ApproximateNow().Add(timeout).Subtract(
      QuicTime::Delta::FromSeconds(1));
  EXPECT_EQ(handshake_timeout, connection_.GetTimeoutAlarm()->deadline());
  EXPECT_TRUE(connection_.connected());

  // Send and ack new data 3 seconds later to lengthen the idle timeout.
  SendStreamDataToPeer(kHeadersStreamId, "GET /", 0, kFin, nullptr);
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(3));
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&frame);

  // Fire early to verify it wouldn't timeout yet.
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_TRUE(connection_.connected());

  clock_.AdvanceTime(timeout.Subtract(QuicTime::Delta::FromSeconds(2)));

  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_HANDSHAKE_TIMEOUT, _,
                                           ConnectionCloseSource::FROM_SELF));
  // Simulate the timeout alarm firing.
  connection_.GetTimeoutAlarm()->Fire();

  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());

  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetResumeWritesAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, PingAfterSend) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, HasOpenDynamicStreams()).WillRepeatedly(Return(true));
  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());

  // Advance to 5ms, and send a packet to the peer, which will set
  // the ping alarm.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(connection_.GetRetransmissionAlarm()->IsSet());
  SendStreamDataToPeer(kHeadersStreamId, "GET /", 0, kFin, nullptr);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  EXPECT_EQ(clock_.ApproximateNow().Add(QuicTime::Delta::FromSeconds(15)),
            connection_.GetPingAlarm()->deadline());

  // Now recevie and ACK of the previous packet, which will move the
  // ping alarm forward.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  QuicAckFrame frame = InitAckFrame(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&frame);
  EXPECT_TRUE(connection_.GetPingAlarm()->IsSet());
  // The ping timer is set slightly less than 15 seconds in the future, because
  // of the 1s ping timer alarm granularity.
  EXPECT_EQ(clock_.ApproximateNow()
                .Add(QuicTime::Delta::FromSeconds(15))
                .Subtract(QuicTime::Delta::FromMilliseconds(5)),
            connection_.GetPingAlarm()->deadline());

  writer_->Reset();
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(15));
  connection_.GetPingAlarm()->Fire();
  EXPECT_EQ(1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->ping_frames().size());
  writer_->Reset();

  EXPECT_CALL(visitor_, HasOpenDynamicStreams()).WillRepeatedly(Return(false));
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  SendAckPacketToPeer();

  EXPECT_FALSE(connection_.GetPingAlarm()->IsSet());
}

// Tests whether sending an MTU discovery packet to peer successfully causes the
// maximum packet size to increase.
TEST_P(QuicConnectionTest, SendMtuDiscoveryPacket) {
  EXPECT_TRUE(connection_.connected());

  // Send an MTU probe.
  const size_t new_mtu = kDefaultMaxPacketSize + 100;
  QuicByteCount mtu_probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&mtu_probe_size), Return(true)));
  connection_.SendMtuDiscoveryPacket(new_mtu);
  EXPECT_EQ(new_mtu, mtu_probe_size);
  EXPECT_EQ(1u, creator_->packet_number());

  // Send more than MTU worth of data.  No acknowledgement was received so far,
  // so the MTU should be at its old value.
  const string data(kDefaultMaxPacketSize + 1, '.');
  QuicByteCount size_before_mtu_change;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&size_before_mtu_change), Return(true)))
      .WillOnce(Return(true));
  connection_.SendStreamDataWithString(3, data, 0, kFin, nullptr);
  EXPECT_EQ(3u, creator_->packet_number());
  EXPECT_EQ(kDefaultMaxPacketSize, size_before_mtu_change);

  // Acknowledge all packets so far.
  QuicAckFrame probe_ack = InitAckFrame(3);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&probe_ack);
  EXPECT_EQ(new_mtu, connection_.max_packet_length());

  // Send the same data again.  Check that it fits into a single packet now.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(3, data, 0, kFin, nullptr);
  EXPECT_EQ(4u, creator_->packet_number());
}

// Tests whether MTU discovery does not happen when it is not explicitly enabled
// by the connection options.
TEST_P(QuicConnectionTest, MtuDiscoveryDisabled) {
  EXPECT_TRUE(connection_.connected());

  const QuicPacketCount number_of_packets = kPacketsBetweenMtuProbesBase * 2;
  for (QuicPacketCount i = 0; i < number_of_packets; i++) {
    SendStreamDataToPeer(3, ".", i, /*fin=*/false, nullptr);
    EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
    EXPECT_EQ(0u, connection_.mtu_probe_count());
  }
}

// Tests whether MTU discovery works when the probe gets acknowledged on the
// first try.
TEST_P(QuicConnectionTest, MtuDiscoveryEnabled) {
  EXPECT_TRUE(connection_.connected());

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < kPacketsBetweenMtuProbesBase - 1; i++) {
    SendStreamDataToPeer(3, ".", i, /*fin=*/false, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", kPacketsBetweenMtuProbesBase,
                       /*fin=*/false, nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&probe_size), Return(true)));
  connection_.GetMtuDiscoveryAlarm()->Fire();
  EXPECT_EQ(kMtuDiscoveryTargetPacketSizeHigh, probe_size);

  const QuicPacketCount probe_packet_number = kPacketsBetweenMtuProbesBase + 1;
  ASSERT_EQ(probe_packet_number, creator_->packet_number());

  // Acknowledge all packets sent so far.
  QuicAckFrame probe_ack = InitAckFrame(probe_packet_number);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&probe_ack);
  EXPECT_EQ(kMtuDiscoveryTargetPacketSizeHigh, connection_.max_packet_length());
  EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetBytesInFlight(manager_));

  // Send more packets, and ensure that none of them sets the alarm.
  for (QuicPacketCount i = 0; i < 4 * kPacketsBetweenMtuProbesBase; i++) {
    SendStreamDataToPeer(3, ".", i, /*fin=*/false, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  EXPECT_EQ(1u, connection_.mtu_probe_count());
}

// Tests whether MTU discovery works correctly when the probes never get
// acknowledged.
TEST_P(QuicConnectionTest, MtuDiscoveryFailed) {
  EXPECT_TRUE(connection_.connected());

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  const QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(100);

  EXPECT_EQ(kPacketsBetweenMtuProbesBase,
            QuicConnectionPeer::GetPacketsBetweenMtuProbes(&connection_));
  // Lower the number of probes between packets in order to make the test go
  // much faster.
  const QuicPacketCount packets_between_probes_base = 10;
  QuicConnectionPeer::SetPacketsBetweenMtuProbes(&connection_,
                                                 packets_between_probes_base);
  QuicConnectionPeer::SetNextMtuProbeAt(&connection_,
                                        packets_between_probes_base);

  // This tests sends more packets than strictly necessary to make sure that if
  // the connection was to send more discovery packets than needed, those would
  // get caught as well.
  const QuicPacketCount number_of_packets =
      packets_between_probes_base * (1 << (kMtuDiscoveryAttempts + 1));
  vector<QuicPacketNumber> mtu_discovery_packets;
  // Called by the first ack.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  // Called on many acks.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _))
      .Times(AnyNumber());
  for (QuicPacketCount i = 0; i < number_of_packets; i++) {
    SendStreamDataToPeer(3, "!", i, /*fin=*/false, nullptr);
    clock_.AdvanceTime(rtt);

    // Receive an ACK, which marks all data packets as received, and all MTU
    // discovery packets as missing.
    QuicAckFrame ack = InitAckFrame(creator_->packet_number());
    for (QuicPacketNumber& packet : mtu_discovery_packets) {
      NackPacket(packet, &ack);
    }
    ProcessAckPacket(&ack);

    // Trigger MTU probe if it would be scheduled now.
    if (!connection_.GetMtuDiscoveryAlarm()->IsSet()) {
      continue;
    }

    // Fire the alarm.  The alarm should cause a packet to be sent.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .WillOnce(Return(true));
    connection_.GetMtuDiscoveryAlarm()->Fire();
    // Record the packet number of the MTU discovery packet in order to
    // mark it as NACK'd.
    mtu_discovery_packets.push_back(creator_->packet_number());
  }

  // Ensure the number of packets between probes grows exponentially by checking
  // it against the closed-form expression for the packet number.
  ASSERT_EQ(kMtuDiscoveryAttempts, mtu_discovery_packets.size());
  for (QuicPacketNumber i = 0; i < kMtuDiscoveryAttempts; i++) {
    // 2^0 + 2^1 + 2^2 + ... + 2^n = 2^(n + 1) - 1
    const QuicPacketCount packets_between_probes =
        packets_between_probes_base * ((1 << (i + 1)) - 1);
    EXPECT_EQ(packets_between_probes + (i + 1), mtu_discovery_packets[i]);
  }

  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  EXPECT_EQ(kDefaultMaxPacketSize, connection_.max_packet_length());
  EXPECT_EQ(kMtuDiscoveryAttempts, connection_.mtu_probe_count());
}

// Tests whether MTU discovery works when the writer has a limit on how large a
// packet can be.
TEST_P(QuicConnectionTest, MtuDiscoveryWriterLimited) {
  EXPECT_TRUE(connection_.connected());

  const QuicByteCount mtu_limit = kMtuDiscoveryTargetPacketSizeHigh - 1;
  writer_->set_max_packet_size(mtu_limit);
  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < kPacketsBetweenMtuProbesBase - 1; i++) {
    SendStreamDataToPeer(3, ".", i, /*fin=*/false, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", kPacketsBetweenMtuProbesBase,
                       /*fin=*/false, nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&probe_size), Return(true)));
  connection_.GetMtuDiscoveryAlarm()->Fire();
  EXPECT_EQ(mtu_limit, probe_size);

  const QuicPacketCount probe_sequence_number =
      kPacketsBetweenMtuProbesBase + 1;
  ASSERT_EQ(probe_sequence_number, creator_->packet_number());

  // Acknowledge all packets sent so far.
  QuicAckFrame probe_ack = InitAckFrame(probe_sequence_number);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&probe_ack);
  EXPECT_EQ(mtu_limit, connection_.max_packet_length());
  EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetBytesInFlight(manager_));

  // Send more packets, and ensure that none of them sets the alarm.
  for (QuicPacketCount i = 0; i < 4 * kPacketsBetweenMtuProbesBase; i++) {
    SendStreamDataToPeer(3, ".", i, /*fin=*/false, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  EXPECT_EQ(1u, connection_.mtu_probe_count());
}

TEST_P(QuicConnectionTest, NoMtuDiscoveryAfterConnectionClosed) {
  EXPECT_TRUE(connection_.connected());

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < kPacketsBetweenMtuProbesBase - 1; i++) {
    SendStreamDataToPeer(3, ".", i, /*fin=*/false, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  SendStreamDataToPeer(3, "!", kPacketsBetweenMtuProbesBase,
                       /*fin=*/false, nullptr);
  EXPECT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());

  EXPECT_CALL(visitor_, OnConnectionClosed(_, _, _));
  connection_.CloseConnection(QUIC_PEER_GOING_AWAY, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, TimeoutAfterSend) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_FALSE(QuicConnectionPeer::IsSilentCloseEnabled(&connection_));

  const QuicTime::Delta initial_idle_timeout =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow().Add(initial_idle_timeout);

  // When we send a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(kClientDataStreamId1, "foo", 0, kFin, nullptr);
  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  // Now send more data. This will not move the timeout becase
  // no data has been recieved since the previous write.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(kClientDataStreamId1, "foo", 0, kFin, nullptr);
  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(initial_idle_timeout.Subtract(five_ms).Subtract(five_ms));
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(default_timeout.Add(five_ms).Add(five_ms),
            connection_.GetTimeoutAlarm()->deadline());

  // This time, we should time out.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_NETWORK_IDLE_TIMEOUT, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  clock_.AdvanceTime(five_ms);
  EXPECT_EQ(default_timeout.Add(five_ms), clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, NewTimeoutAfterSendSilentClose) {
  // Same test as above, but complete a handshake which enables silent close,
  // causing no connection close packet to be sent.
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;

  // Create a handshake message that also enables silent close.
  CryptoHandshakeMessage msg;
  string error_details;
  QuicConfig client_config;
  client_config.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  client_config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  client_config.SetIdleConnectionStateLifetime(
      QuicTime::Delta::FromSeconds(kDefaultIdleTimeoutSecs),
      QuicTime::Delta::FromSeconds(kDefaultIdleTimeoutSecs));
  client_config.ToHandshakeMessage(&msg);
  const QuicErrorCode error =
      config.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_EQ(QUIC_NO_ERROR, error);

  connection_.SetFromConfig(config);
  EXPECT_TRUE(QuicConnectionPeer::IsSilentCloseEnabled(&connection_));

  const QuicTime::Delta default_idle_timeout =
      QuicTime::Delta::FromSeconds(kDefaultIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow().Add(default_idle_timeout);

  // When we send a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(kClientDataStreamId1, "foo", 0, kFin, nullptr);
  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  // Now send more data. This will not move the timeout becase
  // no data has been recieved since the previous write.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(kClientDataStreamId1, "foo", 0, kFin, nullptr);
  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(default_idle_timeout.Subtract(five_ms).Subtract(five_ms));
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(default_timeout.Add(five_ms).Add(five_ms),
            connection_.GetTimeoutAlarm()->deadline());

  // This time, we should time out.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_NETWORK_IDLE_TIMEOUT, _,
                                           ConnectionCloseSource::FROM_SELF));
  clock_.AdvanceTime(five_ms);
  EXPECT_EQ(default_timeout.Add(five_ms), clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, TimeoutAfterReceive) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_FALSE(QuicConnectionPeer::IsSilentCloseEnabled(&connection_));

  const QuicTime::Delta initial_idle_timeout =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow().Add(initial_idle_timeout);

  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 0, !kFin,
                                       nullptr);
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 3, !kFin,
                                       nullptr);

  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());
  clock_.AdvanceTime(five_ms);

  // When we receive a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  QuicAckFrame ack = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&ack);

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(initial_idle_timeout.Subtract(five_ms));
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_TRUE(connection_.connected());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_EQ(default_timeout.Add(five_ms),
            connection_.GetTimeoutAlarm()->deadline());

  // This time, we should time out.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_NETWORK_IDLE_TIMEOUT, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  clock_.AdvanceTime(five_ms);
  EXPECT_EQ(default_timeout.Add(five_ms), clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, TimeoutAfterReceiveNotSendWhenUnacked) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);
  EXPECT_FALSE(QuicConnectionPeer::IsSilentCloseEnabled(&connection_));

  const QuicTime::Delta initial_idle_timeout =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  connection_.SetNetworkTimeouts(
      QuicTime::Delta::Infinite(),
      initial_idle_timeout.Add(QuicTime::Delta::FromSeconds(1)));
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow().Add(initial_idle_timeout);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 0, !kFin,
                                       nullptr);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 3, !kFin,
                                       nullptr);

  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  clock_.AdvanceTime(five_ms);

  // When we receive a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  QuicAckFrame ack = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&ack);

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(initial_idle_timeout.Subtract(five_ms));
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_TRUE(connection_.connected());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_EQ(default_timeout.Add(five_ms),
            connection_.GetTimeoutAlarm()->deadline());

  // Now, send packets while advancing the time and verify that the connection
  // eventually times out.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_NETWORK_IDLE_TIMEOUT, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  for (int i = 0; i < 100 && connection_.connected(); ++i) {
    VLOG(1) << "sending data packet";
    connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 0, !kFin,
                                         nullptr);
    connection_.GetTimeoutAlarm()->Fire();
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }
  EXPECT_FALSE(connection_.connected());
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, TimeoutAfter5RTOs) {
  QuicSentPacketManagerPeer::SetMaxTailLossProbes(manager_, 2);
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(k5RTO);
  config.SetConnectionOptionsToSend(connection_options);
  connection_.SetFromConfig(config);

  // Send stream data.
  SendStreamDataToPeer(kClientDataStreamId1, "foo", 0, kFin, nullptr);

  EXPECT_CALL(visitor_, OnPathDegrading());
  // Fire the retransmission alarm 6 times, twice for TLP and 4 times for RTO.
  for (int i = 0; i < 6; ++i) {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
    connection_.GetRetransmissionAlarm()->Fire();
    EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
    EXPECT_TRUE(connection_.connected());
  }

  EXPECT_EQ(2u, connection_.sent_packet_manager().GetConsecutiveTlpCount());
  EXPECT_EQ(4u, connection_.sent_packet_manager().GetConsecutiveRtoCount());
  // This time, we should time out.
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_TOO_MANY_RTOS, _,
                                           ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, SendScheduler) {
  // Test that if we send a packet without delay, it is not queued.
  QuicPacket* packet =
      ConstructDataPacket(kDefaultPathId, 1, !kEntropyFlag, !kHasStopWaiting);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendPacket(ENCRYPTION_NONE, kDefaultPathId, 1, packet,
                         kTestEntropyHash, HAS_RETRANSMITTABLE_DATA, false,
                         false);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, FailToSendFirstPacket) {
  // Test that the connection does not crash when it fails to send the first
  // packet at which point self_address_ might be uninitialized.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _, _)).Times(1);
  QuicPacket* packet =
      ConstructDataPacket(kDefaultPathId, 1, !kEntropyFlag, !kHasStopWaiting);
  writer_->SetShouldWriteFail();
  connection_.SendPacket(ENCRYPTION_NONE, kDefaultPathId, 1, packet,
                         kTestEntropyHash, HAS_RETRANSMITTABLE_DATA, false,
                         false);
}

TEST_P(QuicConnectionTest, SendSchedulerEAGAIN) {
  QuicPacket* packet =
      ConstructDataPacket(kDefaultPathId, 1, !kEntropyFlag, !kHasStopWaiting);
  BlockOnNextWrite();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 1, _, _)).Times(0);
  connection_.SendPacket(ENCRYPTION_NONE, kDefaultPathId, 1, packet,
                         kTestEntropyHash, HAS_RETRANSMITTABLE_DATA, false,
                         false);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, TestQueueLimitsOnSendStreamData) {
  // All packets carry version info till version is negotiated.
  size_t payload_length;
  size_t length = GetPacketLengthForOneStream(
      connection_.version(), kIncludeVersion, !kIncludePathId,
      !kIncludeDiversificationNonce, PACKET_8BYTE_CONNECTION_ID,
      PACKET_1BYTE_PACKET_NUMBER, &payload_length);
  connection_.SetMaxPacketLength(length);

  // Queue the first packet.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillOnce(testing::Return(QuicTime::Delta::FromMicroseconds(10)));
  const string payload(payload_length, 'a');
  EXPECT_EQ(0u,
            connection_.SendStreamDataWithString(3, payload, 0, !kFin, nullptr)
                .bytes_consumed);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, LoopThroughSendingPackets) {
  // All packets carry version info till version is negotiated.
  size_t payload_length;
  // GetPacketLengthForOneStream() assumes a stream offset of 0 in determining
  // packet length. The size of the offset field in a stream frame is 0 for
  // offset 0, and 2 for non-zero offsets up through 16K. Increase
  // max_packet_length by 2 so that subsequent packets containing subsequent
  // stream frames with non-zero offets will fit within the packet length.
  size_t length =
      2 + GetPacketLengthForOneStream(
              connection_.version(), kIncludeVersion, !kIncludePathId,
              !kIncludeDiversificationNonce, PACKET_8BYTE_CONNECTION_ID,
              PACKET_1BYTE_PACKET_NUMBER, &payload_length);
  connection_.SetMaxPacketLength(length);

  // Queue the first packet.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(7);
  // The first stream frame will have 2 fewer overhead bytes than the other six.
  const string payload(payload_length * 7 + 2, 'a');
  EXPECT_EQ(payload.size(),
            connection_.SendStreamDataWithString(1, payload, 0, !kFin, nullptr)
                .bytes_consumed);
}

TEST_P(QuicConnectionTest, LoopThroughSendingPacketsWithTruncation) {
  // Set up a larger payload than will fit in one packet.
  const string payload(connection_.max_packet_length(), 'a');
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _)).Times(AnyNumber());

  // Now send some packets with no truncation.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  EXPECT_EQ(payload.size(),
            connection_.SendStreamDataWithString(3, payload, 0, !kFin, nullptr)
                .bytes_consumed);
  // Track the size of the second packet here.  The overhead will be the largest
  // we see in this test, due to the non-truncated connection id.
  size_t non_truncated_packet_size = writer_->last_packet_size();

  // Change to a 0 byte connection id.
  QuicConfig config;
  QuicConfigPeer::SetReceivedBytesForConnectionId(&config, 0);
  connection_.SetFromConfig(config);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
  EXPECT_EQ(payload.size(),
            connection_.SendStreamDataWithString(3, payload, 0, !kFin, nullptr)
                .bytes_consumed);
  // Just like above, we save 8 bytes on payload, and 8 on truncation.
  EXPECT_EQ(non_truncated_packet_size, writer_->last_packet_size() + 8 * 2);
}

TEST_P(QuicConnectionTest, SendDelayedAck) {
  QuicTime ack_time = clock_.ApproximateNow().Add(DefaultDelayedAckTime());
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, 1, !kEntropyFlag, !kHasStopWaiting,
                           ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());
  // Simulate delayed ack alarm firing.
  connection_.GetAckAlarm()->Fire();
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimation) {
  QuicConnectionPeer::SetAckMode(&connection_, QuicConnection::ACK_DECIMATION);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromMilliseconds(kMinRttMs / 4));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  QuicPacketNumber kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, 1 + i, !kEntropyFlag,
                             !kHasStopWaiting, ENCRYPTION_INITIAL);
  }
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket, !kEntropyFlag,
                           !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 9; ++i) {
    EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 1 + i,
                             !kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimationEighthRtt) {
  QuicConnectionPeer::SetAckMode(&connection_, QuicConnection::ACK_DECIMATION);
  QuicConnectionPeer::SetAckDecimationDelay(&connection_, 0.125);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromMilliseconds(kMinRttMs / 8));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  QuicPacketNumber kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, 1 + i, !kEntropyFlag,
                             !kHasStopWaiting, ENCRYPTION_INITIAL);
  }
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket, !kEntropyFlag,
                           !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 9; ++i) {
    EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 1 + i,
                             !kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimationWithReordering) {
  QuicConnectionPeer::SetAckMode(
      &connection_, QuicConnection::ACK_DECIMATION_WITH_REORDERING);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromMilliseconds(kMinRttMs / 4));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  QuicPacketNumber kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, 1 + i, !kEntropyFlag,
                             !kHasStopWaiting, ENCRYPTION_INITIAL);
  }
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket, !kEntropyFlag,
                           !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Process packet 10 first and ensure the alarm is one eighth min_rtt.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 9,
                           !kEntropyFlag, !kHasStopWaiting, ENCRYPTION_INITIAL);
  ack_time = clock_.ApproximateNow().Add(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 8; ++i) {
    EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 1 + i,
                             !kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimationWithLargeReordering) {
  QuicConnectionPeer::SetAckMode(
      &connection_, QuicConnection::ACK_DECIMATION_WITH_REORDERING);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromMilliseconds(kMinRttMs / 4));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  QuicPacketNumber kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, 1 + i, !kEntropyFlag,
                             !kHasStopWaiting, ENCRYPTION_INITIAL);
  }
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket, !kEntropyFlag,
                           !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Process packet 10 first and ensure the alarm is one eighth min_rtt.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 19,
                           !kEntropyFlag, !kHasStopWaiting, ENCRYPTION_INITIAL);
  ack_time = clock_.ApproximateNow().Add(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 8; ++i) {
    EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 1 + i,
                             !kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());

  // The next packet received in order will cause an immediate ack,
  // because it fills a hole.
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 10,
                           !kEntropyFlag, !kHasStopWaiting, ENCRYPTION_INITIAL);
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckDecimationWithReorderingEighthRtt) {
  QuicConnectionPeer::SetAckMode(
      &connection_, QuicConnection::ACK_DECIMATION_WITH_REORDERING);
  QuicConnectionPeer::SetAckDecimationDelay(&connection_, 0.125);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromMilliseconds(kMinRttMs / 8));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  QuicPacketNumber kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, 1 + i, !kEntropyFlag,
                             !kHasStopWaiting, ENCRYPTION_INITIAL);
  }
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket, !kEntropyFlag,
                           !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Process packet 10 first and ensure the alarm is one eighth min_rtt.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 9,
                           !kEntropyFlag, !kHasStopWaiting, ENCRYPTION_INITIAL);
  ack_time = clock_.ApproximateNow().Add(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 8; ++i) {
    EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 1 + i,
                             !kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest,
       SendDelayedAckDecimationWithLargeReorderingEighthRtt) {
  QuicConnectionPeer::SetAckMode(
      &connection_, QuicConnection::ACK_DECIMATION_WITH_REORDERING);
  QuicConnectionPeer::SetAckDecimationDelay(&connection_, 0.125);

  const size_t kMinRttMs = 40;
  RttStats* rtt_stats = const_cast<RttStats*>(manager_->GetRttStats());
  rtt_stats->UpdateRtt(QuicTime::Delta::FromMilliseconds(kMinRttMs),
                       QuicTime::Delta::Zero(), QuicTime::Zero());
  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow().Add(
      QuicTime::Delta::FromMilliseconds(kMinRttMs / 8));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  const uint8_t tag = 0x07;
  connection_.SetDecrypter(ENCRYPTION_INITIAL, new StrictTaggingDecrypter(tag));
  framer_.SetEncrypter(ENCRYPTION_INITIAL, new TaggingEncrypter(tag));
  // Process a packet from the non-crypto stream.
  frame1_.stream_id = 3;

  // Process all the initial packets in order so there aren't missing packets.
  QuicPacketNumber kFirstDecimatedPacket = 101;
  for (unsigned int i = 0; i < kFirstDecimatedPacket - 1; ++i) {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, 1 + i, !kEntropyFlag,
                             !kHasStopWaiting, ENCRYPTION_INITIAL);
  }
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  // The same as ProcessPacket(1) except that ENCRYPTION_INITIAL is used
  // instead of ENCRYPTION_NONE.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket, !kEntropyFlag,
                           !kHasStopWaiting, ENCRYPTION_INITIAL);

  // Check if delayed ack timer is running for the expected interval.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Process packet 10 first and ensure the alarm is one eighth min_rtt.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 19,
                           !kEntropyFlag, !kHasStopWaiting, ENCRYPTION_INITIAL);
  ack_time = clock_.ApproximateNow().Add(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // The 10th received packet causes an ack to be sent.
  for (int i = 0; i < 8; ++i) {
    EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
    ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 1 + i,
                             !kEntropyFlag, !kHasStopWaiting,
                             ENCRYPTION_INITIAL);
  }
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());

  // The next packet received in order will cause an immediate ack,
  // because it fills a hole.
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  ProcessDataPacketAtLevel(kDefaultPathId, kFirstDecimatedPacket + 10,
                           !kEntropyFlag, !kHasStopWaiting, ENCRYPTION_INITIAL);
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnHandshakeConfirmed) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);
  // Check that ack is sent and that delayed ack alarm is set.
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  QuicTime ack_time = clock_.ApproximateNow().Add(DefaultDelayedAckTime());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Completing the handshake as the server does nothing.
  QuicConnectionPeer::SetPerspective(&connection_, Perspective::IS_SERVER);
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(ack_time, connection_.GetAckAlarm()->deadline());

  // Complete the handshake as the client decreases the delayed ack time to 0ms.
  QuicConnectionPeer::SetPerspective(&connection_, Perspective::IS_CLIENT);
  connection_.OnHandshakeComplete();
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
  EXPECT_EQ(clock_.ApproximateNow(), connection_.GetAckAlarm()->deadline());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnSecondPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);
  ProcessPacket(kDefaultPathId, 2);
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, NoAckOnOldNacks) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  // Drop one packet, triggering a sequence of acks.
  ProcessPacket(kDefaultPathId, 2);
  size_t frames_per_ack = 2;
  EXPECT_EQ(frames_per_ack, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  writer_->Reset();
  ProcessPacket(kDefaultPathId, 3);
  EXPECT_EQ(frames_per_ack, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  writer_->Reset();
  ProcessPacket(kDefaultPathId, 4);
  EXPECT_EQ(frames_per_ack, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  writer_->Reset();
  ProcessPacket(kDefaultPathId, 5);
  EXPECT_EQ(frames_per_ack, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  writer_->Reset();
  // Now only set the timer on the 6th packet, instead of sending another ack.
  ProcessPacket(kDefaultPathId, 6);
  EXPECT_EQ(0u, writer_->frame_count());
  EXPECT_TRUE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnOutgoingPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 0, !kFin,
                                       nullptr);
  // Check that ack is bundled with outgoing data and that delayed ack
  // alarm is reset.
  EXPECT_EQ(3u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendDelayedAckOnOutgoingCryptoPacket) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);
  connection_.SendStreamDataWithString(kCryptoStreamId, "foo", 0, !kFin,
                                       nullptr);
  // Check that ack is bundled with outgoing crypto data.
  EXPECT_EQ(3u, writer_->frame_count());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, BlockAndBufferOnFirstCHLOPacketOfTwo) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);
  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  connection_.SendStreamDataWithString(kCryptoStreamId, "foo", 0, !kFin,
                                       nullptr);
  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_FALSE(connection_.HasQueuedData());
  connection_.SendStreamDataWithString(kCryptoStreamId, "bar", 3, !kFin,
                                       nullptr);
  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_TRUE(connection_.HasQueuedData());
}

TEST_P(QuicConnectionTest, BundleAckForSecondCHLO) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(IgnoreResult(InvokeWithoutArgs(
          &connection_, &TestConnection::SendCryptoStreamData)));
  // Process a packet from the crypto stream, which is frame1_'s default.
  // Receiving the CHLO as packet 2 first will cause the connection to
  // immediately send an ack, due to the packet gap.
  ProcessPacket(kDefaultPathId, 2);
  // Check that ack is sent and that delayed ack alarm is reset.
  EXPECT_EQ(3u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, BundleAckWithDataOnIncomingAck) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 0, !kFin,
                                       nullptr);
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 3, !kFin,
                                       nullptr);
  // Ack the second packet, which will retransmit the first packet.
  QuicAckFrame ack = InitAckFrame(2);
  NackPacket(1, &ack);
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&ack);
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  writer_->Reset();

  // Now ack the retransmission, which will both raise the high water mark
  // and see if there is more data to send.
  ack = InitAckFrame(3);
  NackPacket(1, &ack);
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&ack);

  // Check that no packet is sent and the ack alarm isn't set.
  EXPECT_EQ(0u, writer_->frame_count());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
  writer_->Reset();

  // Send the same ack, but send both data and an ack together.
  ack = InitAckFrame(3);
  NackPacket(1, &ack);
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(IgnoreResult(InvokeWithoutArgs(
          &connection_, &TestConnection::EnsureWritableAndSendStreamData5)));
  ProcessAckPacket(&ack);

  // Check that ack is bundled with outgoing data and the delayed ack
  // alarm is reset.
  EXPECT_EQ(3u, writer_->frame_count());
  EXPECT_FALSE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_FALSE(connection_.GetAckAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, NoAckSentForClose) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessPacket(kDefaultPathId, 1);
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_PEER_GOING_AWAY, _,
                                           ConnectionCloseSource::FROM_PEER));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessClosePacket(kDefaultPathId, 2);
}

TEST_P(QuicConnectionTest, SendWhenDisconnected) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_PEER_GOING_AWAY, _,
                                           ConnectionCloseSource::FROM_SELF));
  connection_.CloseConnection(QUIC_PEER_GOING_AWAY, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(connection_.connected());
  EXPECT_FALSE(connection_.CanWriteStreamData());
  QuicPacket* packet =
      ConstructDataPacket(kDefaultPathId, 1, !kEntropyFlag, !kHasStopWaiting);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 1, _, _)).Times(0);
  connection_.SendPacket(ENCRYPTION_NONE, kDefaultPathId, 1, packet,
                         kTestEntropyHash, HAS_RETRANSMITTABLE_DATA, false,
                         false);
}

TEST_P(QuicConnectionTest, PublicReset) {
  QuicPublicResetPacket header;
  header.public_header.connection_id = connection_id_;
  header.public_header.reset_flag = true;
  header.public_header.version_flag = false;
  header.rejected_packet_number = 10101;
  std::unique_ptr<QuicEncryptedPacket> packet(
      framer_.BuildPublicResetPacket(header));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*packet, QuicTime::Zero()));
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_PUBLIC_RESET, _,
                                           ConnectionCloseSource::FROM_PEER));
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);
}

TEST_P(QuicConnectionTest, GoAway) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicGoAwayFrame goaway;
  goaway.last_good_stream_id = 1;
  goaway.error_code = QUIC_PEER_GOING_AWAY;
  goaway.reason_phrase = "Going away.";
  EXPECT_CALL(visitor_, OnGoAway(_));
  ProcessGoAwayPacket(&goaway);
}

TEST_P(QuicConnectionTest, WindowUpdate) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicWindowUpdateFrame window_update;
  window_update.stream_id = 3;
  window_update.byte_offset = 1234;
  EXPECT_CALL(visitor_, OnWindowUpdateFrame(_));
  ProcessFramePacket(QuicFrame(&window_update));
}

TEST_P(QuicConnectionTest, Blocked) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicBlockedFrame blocked;
  blocked.stream_id = 3;
  EXPECT_CALL(visitor_, OnBlockedFrame(_));
  ProcessFramePacket(QuicFrame(&blocked));
}

TEST_P(QuicConnectionTest, PathClose) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  QuicPathCloseFrame path_close = QuicPathCloseFrame(1);
  ProcessPathClosePacket(&path_close);
  EXPECT_TRUE(QuicFramerPeer::IsPathClosed(
      QuicConnectionPeer::GetFramer(&connection_), 1));
}

TEST_P(QuicConnectionTest, ZeroBytePacket) {
  // Don't close the connection for zero byte packets.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _, _)).Times(0);
  QuicReceivedPacket encrypted(nullptr, 0, QuicTime::Zero());
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, encrypted);
}

TEST_P(QuicConnectionTest, MissingPacketsBeforeLeastUnacked) {
  // Set the packet number of the ack packet to be least unacked (4).
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 3);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicStopWaitingFrame frame = InitStopWaitingFrame(4);
  ProcessStopWaitingPacket(&frame);
  if (outgoing_ack()->missing) {
    EXPECT_TRUE(outgoing_ack()->packets.Empty());
  } else {
    EXPECT_FALSE(outgoing_ack()->packets.Empty());
  }
}

TEST_P(QuicConnectionTest, ReceivedEntropyHashCalculation) {
  if (GetParam().version > QUIC_VERSION_33) {
    return;
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AtLeast(1));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessDataPacket(kDefaultPathId, 1, kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 4, kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 3, !kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 7, kEntropyFlag);
  EXPECT_EQ(146u, outgoing_ack()->entropy_hash);
}

TEST_P(QuicConnectionTest, UpdateEntropyForReceivedPackets) {
  if (GetParam().version > QUIC_VERSION_33) {
    return;
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AtLeast(1));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessDataPacket(kDefaultPathId, 1, kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 5, kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 4, !kEntropyFlag);
  EXPECT_EQ(34u, outgoing_ack()->entropy_hash);
  // Make 4th packet my least unacked, and update entropy for 2, 3 packets.
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 5);
  QuicPacketEntropyHash six_packet_entropy_hash = 0;
  QuicPacketEntropyHash random_entropy_hash = 129u;
  QuicStopWaitingFrame frame = InitStopWaitingFrame(4);
  frame.entropy_hash = random_entropy_hash;
  if (ProcessStopWaitingPacket(&frame)) {
    six_packet_entropy_hash = 1 << 6;
  }

  EXPECT_EQ((random_entropy_hash + (1 << 5) + six_packet_entropy_hash),
            outgoing_ack()->entropy_hash);
}

TEST_P(QuicConnectionTest, UpdateEntropyHashUptoCurrentPacket) {
  if (GetParam().version > QUIC_VERSION_33) {
    return;
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AtLeast(1));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessDataPacket(kDefaultPathId, 1, kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 5, !kEntropyFlag);
  ProcessDataPacket(kDefaultPathId, 22, kEntropyFlag);
  EXPECT_EQ(66u, outgoing_ack()->entropy_hash);
  QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 22);
  QuicPacketEntropyHash random_entropy_hash = 85u;
  // Current packet is the least unacked packet.
  QuicPacketEntropyHash ack_entropy_hash;
  QuicStopWaitingFrame frame = InitStopWaitingFrame(23);
  frame.entropy_hash = random_entropy_hash;
  ack_entropy_hash = ProcessStopWaitingPacket(&frame);
  EXPECT_EQ((random_entropy_hash + ack_entropy_hash),
            outgoing_ack()->entropy_hash);
  ProcessDataPacket(kDefaultPathId, 25, kEntropyFlag);
  EXPECT_EQ((random_entropy_hash + ack_entropy_hash + (1 << (25 % 8))),
            outgoing_ack()->entropy_hash);
}

TEST_P(QuicConnectionTest, EntropyCalculationForTruncatedAck) {
  if (GetParam().version > QUIC_VERSION_33) {
    return;
  }
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AtLeast(1));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicPacketEntropyHash entropy[51];
  entropy[0] = 0;
  for (int i = 1; i < 51; ++i) {
    bool should_send = i % 10 != 1;
    bool entropy_flag = (i & (i - 1)) != 0;
    if (!should_send) {
      entropy[i] = entropy[i - 1];
      continue;
    }
    if (entropy_flag) {
      entropy[i] = entropy[i - 1] ^ (1 << (i % 8));
    } else {
      entropy[i] = entropy[i - 1];
    }
    ProcessDataPacket(kDefaultPathId, i, entropy_flag);
  }
  for (int i = 1; i < 50; ++i) {
    EXPECT_EQ(entropy[i],
              QuicConnectionPeer::ReceivedEntropyHash(&connection_, i));
  }
}

TEST_P(QuicConnectionTest, ServerSendsVersionNegotiationPacket) {
  connection_.SetSupportedVersions(QuicSupportedVersions());
  set_perspective(Perspective::IS_SERVER);
  peer_framer_.set_version_for_tests(QUIC_VERSION_UNSUPPORTED);

  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.version_flag = true;
  header.path_id = kDefaultPathId;
  header.packet_number = 12;

  QuicFrames frames;
  frames.push_back(QuicFrame(&frame1_));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 12, *packet, buffer, kMaxPacketSize);

  framer_.set_version(version());
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
  EXPECT_TRUE(writer_->version_negotiation_packet() != nullptr);

  size_t num_versions = arraysize(kSupportedQuicVersions);
  ASSERT_EQ(num_versions,
            writer_->version_negotiation_packet()->versions.size());

  // We expect all versions in kSupportedQuicVersions to be
  // included in the packet.
  for (size_t i = 0; i < num_versions; ++i) {
    EXPECT_EQ(kSupportedQuicVersions[i],
              writer_->version_negotiation_packet()->versions[i]);
  }
}

TEST_P(QuicConnectionTest, ServerSendsVersionNegotiationPacketSocketBlocked) {
  connection_.SetSupportedVersions(QuicSupportedVersions());
  set_perspective(Perspective::IS_SERVER);
  peer_framer_.set_version_for_tests(QUIC_VERSION_UNSUPPORTED);

  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.version_flag = true;
  header.packet_number = 12;

  QuicFrames frames;
  frames.push_back(QuicFrame(&frame1_));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 12, *packet, buffer, kMaxPacketSize);

  framer_.set_version(version());
  BlockOnNextWrite();
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
  EXPECT_EQ(0u, writer_->last_packet_size());
  EXPECT_TRUE(connection_.HasQueuedData());

  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_TRUE(writer_->version_negotiation_packet() != nullptr);

  size_t num_versions = arraysize(kSupportedQuicVersions);
  ASSERT_EQ(num_versions,
            writer_->version_negotiation_packet()->versions.size());

  // We expect all versions in kSupportedQuicVersions to be
  // included in the packet.
  for (size_t i = 0; i < num_versions; ++i) {
    EXPECT_EQ(kSupportedQuicVersions[i],
              writer_->version_negotiation_packet()->versions[i]);
  }
}

TEST_P(QuicConnectionTest,
       ServerSendsVersionNegotiationPacketSocketBlockedDataBuffered) {
  connection_.SetSupportedVersions(QuicSupportedVersions());
  set_perspective(Perspective::IS_SERVER);
  peer_framer_.set_version_for_tests(QUIC_VERSION_UNSUPPORTED);

  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.public_header.version_flag = true;
  header.packet_number = 12;

  QuicFrames frames;
  frames.push_back(QuicFrame(&frame1_));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxPacketSize];
  size_t encryped_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 12, *packet, buffer, kMaxPacketSize);

  framer_.set_version(version());
  set_perspective(Perspective::IS_SERVER);
  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encryped_length, QuicTime::Zero(), false));
  EXPECT_EQ(0u, writer_->last_packet_size());
  EXPECT_FALSE(connection_.HasQueuedData());
}

TEST_P(QuicConnectionTest, ClientHandlesVersionNegotiation) {
  // Start out with some unsupported version.
  QuicConnectionPeer::GetFramer(&connection_)
      ->set_version_for_tests(QUIC_VERSION_UNSUPPORTED);

  // Send a version negotiation packet.
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      framer_.BuildVersionNegotiationPacket(connection_id_,
                                            QuicSupportedVersions()));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*encrypted, QuicTime::Zero()));
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);

  // Now force another packet.  The connection should transition into
  // NEGOTIATED_VERSION state and tell the packet creator to StopSendingVersion.
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.path_id = kDefaultPathId;
  header.packet_number = 12;
  header.public_header.version_flag = false;
  QuicFrames frames;
  frames.push_back(QuicFrame(&frame1_));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 12, *packet, buffer, kMaxPacketSize);
  ASSERT_NE(0u, encrypted_length);
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));

  ASSERT_FALSE(QuicPacketCreatorPeer::SendVersionInPacket(creator_));
}

TEST_P(QuicConnectionTest, BadVersionNegotiation) {
  // Send a version negotiation packet with the version the client started with.
  // It should be rejected.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(QUIC_INVALID_VERSION_NEGOTIATION_PACKET, _,
                                 ConnectionCloseSource::FROM_SELF));
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      framer_.BuildVersionNegotiationPacket(connection_id_,
                                            QuicSupportedVersions()));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*encrypted, QuicTime::Zero()));
  connection_.ProcessUdpPacket(kSelfAddress, kPeerAddress, *received);
}

TEST_P(QuicConnectionTest, CheckSendStats) {
  connection_.DisableTailLossProbe();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendStreamDataWithString(3, "first", 0, !kFin, nullptr);
  size_t first_packet_size = writer_->last_packet_size();

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendStreamDataWithString(5, "second", 0, !kFin, nullptr);
  size_t second_packet_size = writer_->last_packet_size();

  // 2 retransmissions due to rto, 1 due to explicit nack.
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(3);

  // Retransmit due to RTO.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10));
  connection_.GetRetransmissionAlarm()->Fire();

  // Retransmit due to explicit nacks.
  QuicAckFrame nack_three = InitAckFrame(4);
  NackPacket(3, &nack_three);
  NackPacket(1, &nack_three);
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
  lost_packets.push_back(std::make_pair(3, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(visitor_, OnCanWrite());
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  ProcessAckPacket(&nack_three);

  EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
      .WillOnce(Return(QuicBandwidth::Zero()));

  const QuicConnectionStats& stats = connection_.GetStats();
  EXPECT_EQ(3 * first_packet_size + 2 * second_packet_size - kQuicVersionSize,
            stats.bytes_sent);
  EXPECT_EQ(5u, stats.packets_sent);
  EXPECT_EQ(2 * first_packet_size + second_packet_size - kQuicVersionSize,
            stats.bytes_retransmitted);
  EXPECT_EQ(3u, stats.packets_retransmitted);
  EXPECT_EQ(1u, stats.rto_count);
  EXPECT_EQ(kDefaultMaxPacketSize, stats.max_packet_size);
}

TEST_P(QuicConnectionTest, ProcessFramesIfPacketClosedConnection) {
  // Construct a packet with stream frame and connection close frame.
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id_;
  header.packet_number = 1;
  header.public_header.version_flag = false;

  QuicConnectionCloseFrame qccf;
  qccf.error_code = QUIC_PEER_GOING_AWAY;

  QuicFrames frames;
  frames.push_back(QuicFrame(&frame1_));
  frames.push_back(QuicFrame(&qccf));
  std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));
  EXPECT_TRUE(nullptr != packet.get());
  char buffer[kMaxPacketSize];
  size_t encrypted_length = framer_.EncryptPayload(
      ENCRYPTION_NONE, kDefaultPathId, 1, *packet, buffer, kMaxPacketSize);

  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_PEER_GOING_AWAY, _,
                                           ConnectionCloseSource::FROM_PEER));
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
}

TEST_P(QuicConnectionTest, SelectMutualVersion) {
  connection_.SetSupportedVersions(QuicSupportedVersions());
  // Set the connection to speak the lowest quic version.
  connection_.set_version(QuicVersionMin());
  EXPECT_EQ(QuicVersionMin(), connection_.version());

  // Pass in available versions which includes a higher mutually supported
  // version.  The higher mutually supported version should be selected.
  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }
  EXPECT_TRUE(connection_.SelectMutualVersion(supported_versions));
  EXPECT_EQ(QuicVersionMax(), connection_.version());

  // Expect that the lowest version is selected.
  // Ensure the lowest supported version is less than the max, unless they're
  // the same.
  EXPECT_LE(QuicVersionMin(), QuicVersionMax());
  QuicVersionVector lowest_version_vector;
  lowest_version_vector.push_back(QuicVersionMin());
  EXPECT_TRUE(connection_.SelectMutualVersion(lowest_version_vector));
  EXPECT_EQ(QuicVersionMin(), connection_.version());

  // Shouldn't be able to find a mutually supported version.
  QuicVersionVector unsupported_version;
  unsupported_version.push_back(QUIC_VERSION_UNSUPPORTED);
  EXPECT_FALSE(connection_.SelectMutualVersion(unsupported_version));
}

TEST_P(QuicConnectionTest, ConnectionCloseWhenWritable) {
  EXPECT_FALSE(writer_->IsWriteBlocked());

  // Send a packet.
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_EQ(1u, writer_->packets_write_attempts());

  TriggerConnectionClose();
  EXPECT_EQ(2u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, ConnectionCloseGettingWriteBlocked) {
  BlockOnNextWrite();
  TriggerConnectionClose();
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(writer_->IsWriteBlocked());
}

TEST_P(QuicConnectionTest, ConnectionCloseWhenWriteBlocked) {
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(writer_->IsWriteBlocked());
  TriggerConnectionClose();
  EXPECT_EQ(1u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, AckNotifierTriggerCallback) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Create a listener which we expect to be called.
  scoped_refptr<MockAckListener> listener(new MockAckListener);
  EXPECT_CALL(*listener, OnPacketAcked(_, _)).Times(1);

  // Send some data, which will register the listener to be notified.
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, listener.get());

  // Process an ACK from the server which should trigger the callback.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame frame = InitAckFrame(1);
  ProcessAckPacket(&frame);
}

TEST_P(QuicConnectionTest, AckNotifierFailToTriggerCallback) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Create a listener which we don't expect to be called.
  scoped_refptr<MockAckListener> listener(new MockAckListener);
  EXPECT_CALL(*listener, OnPacketAcked(_, _)).Times(0);

  // Send some data, which will register the listener to be notified. This will
  // not be ACKed and so the listener should never be called.
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, listener.get());

  // Send some other data which we will ACK.
  connection_.SendStreamDataWithString(1, "foo", 0, !kFin, nullptr);
  connection_.SendStreamDataWithString(1, "bar", 0, !kFin, nullptr);

  // Now we receive ACK for packets 2 and 3, but importantly missing packet 1
  // which we registered to be notified about.
  QuicAckFrame frame = InitAckFrame(3);
  NackPacket(1, &frame);
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(1, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  ProcessAckPacket(&frame);
}

TEST_P(QuicConnectionTest, AckNotifierCallbackAfterRetransmission) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Create a listener which we expect to be called.
  scoped_refptr<MockAckListener> listener(new MockAckListener);
  EXPECT_CALL(*listener, OnPacketRetransmitted(3)).Times(1);
  EXPECT_CALL(*listener, OnPacketAcked(3, _)).Times(1);

  // Send four packets, and register to be notified on ACK of packet 2.
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, nullptr);
  connection_.SendStreamDataWithString(3, "bar", 0, !kFin, listener.get());
  connection_.SendStreamDataWithString(3, "baz", 0, !kFin, nullptr);
  connection_.SendStreamDataWithString(3, "qux", 0, !kFin, nullptr);

  // Now we receive ACK for packets 1, 3, and 4 and lose 2.
  QuicAckFrame frame = InitAckFrame(4);
  NackPacket(2, &frame);
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(2, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  ProcessAckPacket(&frame);

  // Now we get an ACK for packet 5 (retransmitted packet 2), which should
  // trigger the callback.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame second_ack_frame = InitAckFrame(5);
  ProcessAckPacket(&second_ack_frame);
}

// AckNotifierCallback is triggered by the ack of a packet that timed
// out and was retransmitted, even though the retransmission has a
// different packet number.
TEST_P(QuicConnectionTest, AckNotifierCallbackForAckAfterRTO) {
  connection_.DisableTailLossProbe();

  // Create a listener which we expect to be called.
  scoped_refptr<MockAckListener> listener(new StrictMock<MockAckListener>);

  QuicTime default_retransmission_time =
      clock_.ApproximateNow().Add(DefaultRetransmissionTime());
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, listener.get());
  EXPECT_EQ(1u, stop_waiting()->least_unacked);

  EXPECT_EQ(1u, writer_->header().packet_number);
  EXPECT_EQ(default_retransmission_time,
            connection_.GetRetransmissionAlarm()->deadline());
  // Simulate the retransmission alarm firing.
  clock_.AdvanceTime(DefaultRetransmissionTime());
  EXPECT_CALL(*listener, OnPacketRetransmitted(3));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, 2u, _, _));
  connection_.GetRetransmissionAlarm()->Fire();
  EXPECT_EQ(2u, writer_->header().packet_number);
  // We do not raise the high water mark yet.
  EXPECT_EQ(1u, stop_waiting()->least_unacked);

  // Ack the original packet, which will revert the RTO.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*listener, OnPacketAcked(3, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame ack_frame = InitAckFrame(1);
  ProcessAckPacket(&ack_frame);

  // listener is not notified again when the retransmit is acked.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame second_ack_frame = InitAckFrame(2);
  ProcessAckPacket(&second_ack_frame);
}

// AckNotifierCallback is triggered by the ack of a packet that was
// previously nacked, even though the retransmission has a different
// packet number.
TEST_P(QuicConnectionTest, AckNotifierCallbackForAckOfNackedPacket) {
  // Create a listener which we expect to be called.
  scoped_refptr<MockAckListener> listener(new StrictMock<MockAckListener>);

  // Send four packets, and register to be notified on ACK of packet 2.
  connection_.SendStreamDataWithString(3, "foo", 0, !kFin, nullptr);
  connection_.SendStreamDataWithString(3, "bar", 0, !kFin, listener.get());
  connection_.SendStreamDataWithString(3, "baz", 0, !kFin, nullptr);
  connection_.SendStreamDataWithString(3, "qux", 0, !kFin, nullptr);

  // Now we receive ACK for packets 1, 3, and 4 and lose 2.
  QuicAckFrame frame = InitAckFrame(4);
  NackPacket(2, &frame);
  EXPECT_CALL(*listener, OnPacketRetransmitted(_));
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  SendAlgorithmInterface::CongestionVector lost_packets;
  lost_packets.push_back(std::make_pair(2, kMaxPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _))
      .WillOnce(SetArgPointee<4>(lost_packets));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  ProcessAckPacket(&frame);

  // Now we get an ACK for packet 2, which was previously nacked.
  EXPECT_CALL(*listener, OnPacketAcked(3, _));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  QuicAckFrame second_ack_frame = InitAckFrame(4);
  ProcessAckPacket(&second_ack_frame);

  // Verify that the listener is not notified again when the
  // retransmit is acked.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  QuicAckFrame third_ack_frame = InitAckFrame(5);
  ProcessAckPacket(&third_ack_frame);
}

TEST_P(QuicConnectionTest, OnPacketHeaderDebugVisitor) {
  QuicPacketHeader header;

  std::unique_ptr<MockQuicConnectionDebugVisitor> debug_visitor(
      new MockQuicConnectionDebugVisitor());
  connection_.set_debug_visitor(debug_visitor.get());
  EXPECT_CALL(*debug_visitor, OnPacketHeader(Ref(header))).Times(1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_)).Times(1);
  EXPECT_CALL(*debug_visitor, OnSuccessfulVersionNegotiation(_)).Times(1);
  connection_.OnPacketHeader(header);
}

TEST_P(QuicConnectionTest, Pacing) {
  // static_cast here does not work if using multipath_sent_packet_manager.
  FLAGS_quic_enable_multipath = false;
  TestConnection server(connection_id_, kSelfAddress, helper_.get(),
                        alarm_factory_.get(), writer_.get(),
                        Perspective::IS_SERVER, version());
  TestConnection client(connection_id_, kPeerAddress, helper_.get(),
                        alarm_factory_.get(), writer_.get(),
                        Perspective::IS_CLIENT, version());
  EXPECT_FALSE(QuicSentPacketManagerPeer::UsingPacing(
      static_cast<const QuicSentPacketManager*>(
          &client.sent_packet_manager())));
  EXPECT_FALSE(QuicSentPacketManagerPeer::UsingPacing(
      static_cast<const QuicSentPacketManager*>(
          &server.sent_packet_manager())));
}

TEST_P(QuicConnectionTest, WindowUpdateInstigateAcks) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Send a WINDOW_UPDATE frame.
  QuicWindowUpdateFrame window_update;
  window_update.stream_id = 3;
  window_update.byte_offset = 1234;
  EXPECT_CALL(visitor_, OnWindowUpdateFrame(_));
  ProcessFramePacket(QuicFrame(&window_update));

  // Ensure that this has caused the ACK alarm to be set.
  QuicAlarm* ack_alarm = QuicConnectionPeer::GetAckAlarm(&connection_);
  EXPECT_TRUE(ack_alarm->IsSet());
}

TEST_P(QuicConnectionTest, BlockedFrameInstigateAcks) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Send a BLOCKED frame.
  QuicBlockedFrame blocked;
  blocked.stream_id = 3;
  EXPECT_CALL(visitor_, OnBlockedFrame(_));
  ProcessFramePacket(QuicFrame(&blocked));

  // Ensure that this has caused the ACK alarm to be set.
  QuicAlarm* ack_alarm = QuicConnectionPeer::GetAckAlarm(&connection_);
  EXPECT_TRUE(ack_alarm->IsSet());
}

TEST_P(QuicConnectionTest, NoDataNoFin) {
  // Make sure that a call to SendStreamWithData, with no data and no FIN, does
  // not result in a QuicAckNotifier being used-after-free (fail under ASAN).
  // Regression test for b/18594622
  scoped_refptr<MockAckListener> listener(new MockAckListener);
  EXPECT_DFATAL(
      connection_.SendStreamDataWithString(3, "", 0, !kFin, listener.get()),
      "Attempt to send empty stream frame");
}

TEST_P(QuicConnectionTest, DoNotSendGoAwayTwice) {
  EXPECT_FALSE(connection_.goaway_sent());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendGoAway(QUIC_PEER_GOING_AWAY, kHeadersStreamId, "Going Away.");
  EXPECT_TRUE(connection_.goaway_sent());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.SendGoAway(QUIC_PEER_GOING_AWAY, kHeadersStreamId, "Going Away.");
}

TEST_P(QuicConnectionTest, ReevaluateTimeUntilSendOnAck) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.SendStreamDataWithString(kClientDataStreamId1, "foo", 0, !kFin,
                                       nullptr);

  // Evaluate CanWrite, and have it return a non-Zero value.
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(1)));
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetSendAlarm()->IsSet());
  EXPECT_EQ(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(1)),
            connection_.GetSendAlarm()->deadline());

  // Process an ack and the send alarm will be set to the  new 2ms delay.
  QuicAckFrame ack = InitAckFrame(1);
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _));
  EXPECT_CALL(*send_algorithm_, TimeUntilSend(_, _))
      .WillRepeatedly(Return(QuicTime::Delta::FromMilliseconds(2)));
  ProcessAckPacket(&ack);
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_TRUE(connection_.GetSendAlarm()->IsSet());
  EXPECT_EQ(clock_.Now().Add(QuicTime::Delta::FromMilliseconds(2)),
            connection_.GetSendAlarm()->deadline());
  writer_->Reset();
}

TEST_P(QuicConnectionTest, SendAcksImmediately) {
  CongestionBlockWrites();
  SendAckPacketToPeer();
}

TEST_P(QuicConnectionTest, SendPingImmediately) {
  CongestionBlockWrites();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendPing();
  EXPECT_FALSE(connection_.HasQueuedData());
}

TEST_P(QuicConnectionTest, SendingUnencryptedStreamDataFails) {
  FLAGS_quic_never_write_unencrypted_data = true;
  EXPECT_CALL(visitor_,
              OnConnectionClosed(QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA,
                                 _, ConnectionCloseSource::FROM_SELF));
  EXPECT_DFATAL(connection_.SendStreamDataWithString(3, "", 0, kFin, nullptr),
                "Cannot send stream data without encryption.");
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, EnableMultipathNegotiation) {
  // Test multipath negotiation during crypto handshake. Multipath is enabled
  // when both endpoints enable multipath.
  ValueRestore<bool> old_flag(&FLAGS_quic_enable_multipath, true);
  EXPECT_TRUE(connection_.connected());
  EXPECT_FALSE(QuicConnectionPeer::IsMultipathEnabled(&connection_));
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  // Enable multipath on server side.
  config.SetMultipathEnabled(true);

  // Create a handshake message enables multipath.
  CryptoHandshakeMessage msg;
  string error_details;
  QuicConfig client_config;
  // Enable multipath on client side.
  client_config.SetMultipathEnabled(true);
  client_config.ToHandshakeMessage(&msg);
  const QuicErrorCode error =
      config.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_EQ(QUIC_NO_ERROR, error);

  connection_.SetFromConfig(config);
  EXPECT_TRUE(QuicConnectionPeer::IsMultipathEnabled(&connection_));
}

TEST_P(QuicConnectionTest, ClosePath) {
  QuicPathId kTestPathId = 1;
  connection_.SendPathClose(kTestPathId);
  EXPECT_TRUE(QuicFramerPeer::IsPathClosed(
      QuicConnectionPeer::GetFramer(&connection_), kTestPathId));
}

TEST_P(QuicConnectionTest, BadMultipathFlag) {
  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_BAD_MULTIPATH_FLAG, _,
                                           ConnectionCloseSource::FROM_SELF));

  // Receieve a packet with multipath flag on when multipath is not enabled.
  EXPECT_TRUE(connection_.connected());
  EXPECT_FALSE(QuicConnectionPeer::IsMultipathEnabled(&connection_));
  peer_creator_.SetCurrentPath(/*path_id=*/1u, 1u, 10u);
  QuicStreamFrame stream_frame(1u, false, 0u, StringPiece());
  EXPECT_DFATAL(
      ProcessFramePacket(QuicFrame(&stream_frame)),
      "Received a packet with multipath flag but multipath is not enabled.");
  EXPECT_FALSE(connection_.connected());
}

TEST_P(QuicConnectionTest, OnPathDegrading) {
  QuicByteCount packet_size;
  const size_t kMinTimeoutsBeforePathDegrading = 2;

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(DoAll(SaveArg<3>(&packet_size), Return(true)));
  connection_.SendStreamDataWithString(3, "packet", 0, !kFin, nullptr);
  size_t num_timeouts =
      kMinTimeoutsBeforePathDegrading +
      QuicSentPacketManagerPeer::GetMaxTailLossProbes(
          QuicConnectionPeer::GetSentPacketManager(&connection_));
  for (size_t i = 1; i < num_timeouts; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10 * i));
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, packet_size, _));
    connection_.GetRetransmissionAlarm()->Fire();
  }
  // Next RTO should cause OnPathDegrading to be called before the
  // retransmission is sent out.
  clock_.AdvanceTime(
      QuicTime::Delta::FromSeconds(kMinTimeoutsBeforePathDegrading * 10));
  {
    InSequence s;
    EXPECT_CALL(visitor_, OnPathDegrading());
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, packet_size, _));
  }
  connection_.GetRetransmissionAlarm()->Fire();
}

TEST_P(QuicConnectionTest, MultipleCallsToCloseConnection) {
  // Verifies that multiple calls to CloseConnection do not
  // result in multiple attempts to close the connection - it will be marked as
  // disconnected after the first call.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _, _)).Times(1);
  connection_.CloseConnection(QUIC_NO_ERROR, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  connection_.CloseConnection(QUIC_NO_ERROR, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
}

TEST_P(QuicConnectionTest, ServerReceivesChloOnNonCryptoStream) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  set_perspective(Perspective::IS_SERVER);
  QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);

  CryptoHandshakeMessage message;
  CryptoFramer framer;
  message.set_tag(kCHLO);
  std::unique_ptr<QuicData> data(framer.ConstructHandshakeMessage(message));
  frame1_.stream_id = 10;
  frame1_.data_buffer = data->data();
  frame1_.data_length = data->length();

  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_MAYBE_CORRUPTED_MEMORY, _,
                                           ConnectionCloseSource::FROM_SELF));
  ProcessFramePacket(QuicFrame(&frame1_));
}

TEST_P(QuicConnectionTest, ClientReceivesRejOnNonCryptoStream) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  CryptoHandshakeMessage message;
  CryptoFramer framer;
  message.set_tag(kREJ);
  std::unique_ptr<QuicData> data(framer.ConstructHandshakeMessage(message));
  frame1_.stream_id = 10;
  frame1_.data_buffer = data->data();
  frame1_.data_length = data->length();

  EXPECT_CALL(visitor_, OnConnectionClosed(QUIC_MAYBE_CORRUPTED_MEMORY, _,
                                           ConnectionCloseSource::FROM_SELF));
  ProcessFramePacket(QuicFrame(&frame1_));
}

}  // namespace
}  // namespace test
}  // namespace net
