// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/test_tools/quic_test_utils.h"

#include <memory>

#include "base/sha1.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/crypto/crypto_framer.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_utils.h"
#include "net/quic/crypto/null_encrypter.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/quic_data_writer.h"
#include "net/quic/quic_framer.h"
#include "net/quic/quic_packet_creator.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_connection_peer.h"
#include "net/spdy/spdy_frame_builder.h"
#include "net/tools/quic/quic_per_connection_packet_writer.h"

using base::StringPiece;
using std::max;
using std::min;
using std::string;
using testing::Invoke;
using testing::_;

namespace net {

namespace test {

QuicAckFrame MakeAckFrame(QuicPacketNumber largest_observed) {
  QuicAckFrame ack;
  ack.largest_observed = largest_observed;
  ack.entropy_hash = 0;
  return ack;
}

QuicAckFrame MakeAckFrameWithNackRanges(size_t num_nack_ranges,
                                        QuicPacketNumber least_unacked) {
  QuicAckFrame ack = MakeAckFrame(2 * num_nack_ranges + least_unacked);
  // Add enough missing packets to get num_nack_ranges nack ranges.
  for (QuicPacketNumber i = 1; i < 2 * num_nack_ranges; i += 2) {
    ack.missing_packets.Add(least_unacked + i);
  }
  return ack;
}

QuicPacket* BuildUnsizedDataPacket(QuicFramer* framer,
                                   const QuicPacketHeader& header,
                                   const QuicFrames& frames) {
  const size_t max_plaintext_size = framer->GetMaxPlaintextSize(kMaxPacketSize);
  size_t packet_size = GetPacketHeaderSize(header);
  for (size_t i = 0; i < frames.size(); ++i) {
    DCHECK_LE(packet_size, max_plaintext_size);
    bool first_frame = i == 0;
    bool last_frame = i == frames.size() - 1;
    const size_t frame_size = framer->GetSerializedFrameLength(
        frames[i], max_plaintext_size - packet_size, first_frame, last_frame,
        header.public_header.packet_number_length);
    DCHECK(frame_size);
    packet_size += frame_size;
  }
  return BuildUnsizedDataPacket(framer, header, frames, packet_size);
}

QuicPacket* BuildUnsizedDataPacket(QuicFramer* framer,
                                   const QuicPacketHeader& header,
                                   const QuicFrames& frames,
                                   size_t packet_size) {
  char* buffer = new char[packet_size];
  size_t length = framer->BuildDataPacket(header, frames, buffer, packet_size);
  DCHECK_NE(0u, length);
  // Re-construct the data packet with data ownership.
  return new QuicPacket(buffer, length, /* owns_buffer */ true,
                        header.public_header.connection_id_length,
                        header.public_header.version_flag,
                        header.public_header.multipath_flag,
                        header.public_header.packet_number_length);
}

uint64_t SimpleRandom::RandUint64() {
  unsigned char hash[base::kSHA1Length];
  base::SHA1HashBytes(reinterpret_cast<unsigned char*>(&seed_), sizeof(seed_),
                      hash);
  memcpy(&seed_, hash, sizeof(seed_));
  return seed_;
}

MockFramerVisitor::MockFramerVisitor() {
  // By default, we want to accept packets.
  ON_CALL(*this, OnProtocolVersionMismatch(_))
      .WillByDefault(testing::Return(false));

  // By default, we want to accept packets.
  ON_CALL(*this, OnUnauthenticatedHeader(_))
      .WillByDefault(testing::Return(true));

  ON_CALL(*this, OnUnauthenticatedPublicHeader(_))
      .WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPacketHeader(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnStreamFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnAckFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnStopWaitingFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnPingFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnRstStreamFrame(_)).WillByDefault(testing::Return(true));

  ON_CALL(*this, OnConnectionCloseFrame(_))
      .WillByDefault(testing::Return(true));

  ON_CALL(*this, OnGoAwayFrame(_)).WillByDefault(testing::Return(true));
}

MockFramerVisitor::~MockFramerVisitor() {}

bool NoOpFramerVisitor::OnProtocolVersionMismatch(QuicVersion version) {
  return false;
}

bool NoOpFramerVisitor::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) {
  return true;
}

bool NoOpFramerVisitor::OnUnauthenticatedHeader(
    const QuicPacketHeader& header) {
  return true;
}

bool NoOpFramerVisitor::OnPacketHeader(const QuicPacketHeader& header) {
  return true;
}

bool NoOpFramerVisitor::OnStreamFrame(const QuicStreamFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnAckFrame(const QuicAckFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnStopWaitingFrame(const QuicStopWaitingFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnPingFrame(const QuicPingFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnGoAwayFrame(const QuicGoAwayFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnBlockedFrame(const QuicBlockedFrame& frame) {
  return true;
}

bool NoOpFramerVisitor::OnPathCloseFrame(const QuicPathCloseFrame& frame) {
  return true;
}

MockConnectionVisitor::MockConnectionVisitor() {}

MockConnectionVisitor::~MockConnectionVisitor() {}

MockConnectionHelper::MockConnectionHelper() {}

MockConnectionHelper::~MockConnectionHelper() {}

const QuicClock* MockConnectionHelper::GetClock() const {
  return &clock_;
}

QuicRandom* MockConnectionHelper::GetRandomGenerator() {
  return &random_generator_;
}

QuicAlarm* MockAlarmFactory::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new MockAlarmFactory::TestAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> MockAlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<MockAlarmFactory::TestAlarm>(std::move(delegate));
  } else {
    return QuicArenaScopedPtr<MockAlarmFactory::TestAlarm>(
        new TestAlarm(std::move(delegate)));
  }
}

QuicBufferAllocator* MockConnectionHelper::GetBufferAllocator() {
  return &buffer_allocator_;
}

void MockConnectionHelper::AdvanceTime(QuicTime::Delta delta) {
  clock_.AdvanceTime(delta);
}

MockConnection::MockConnection(MockConnectionHelper* helper,
                               MockAlarmFactory* alarm_factory,
                               Perspective perspective)
    : MockConnection(kTestConnectionId,
                     IPEndPoint(TestPeerIPAddress(), kTestPort),
                     helper,
                     alarm_factory,
                     perspective,
                     QuicSupportedVersions()) {}

MockConnection::MockConnection(IPEndPoint address,
                               MockConnectionHelper* helper,
                               MockAlarmFactory* alarm_factory,
                               Perspective perspective)
    : MockConnection(kTestConnectionId,
                     address,
                     helper,
                     alarm_factory,
                     perspective,
                     QuicSupportedVersions()) {}

MockConnection::MockConnection(QuicConnectionId connection_id,
                               MockConnectionHelper* helper,
                               MockAlarmFactory* alarm_factory,
                               Perspective perspective)
    : MockConnection(connection_id,
                     IPEndPoint(TestPeerIPAddress(), kTestPort),
                     helper,
                     alarm_factory,
                     perspective,
                     QuicSupportedVersions()) {}

MockConnection::MockConnection(MockConnectionHelper* helper,
                               MockAlarmFactory* alarm_factory,
                               Perspective perspective,
                               const QuicVersionVector& supported_versions)
    : MockConnection(kTestConnectionId,
                     IPEndPoint(TestPeerIPAddress(), kTestPort),
                     helper,
                     alarm_factory,
                     perspective,
                     supported_versions) {}

MockConnection::MockConnection(QuicConnectionId connection_id,
                               IPEndPoint address,
                               MockConnectionHelper* helper,
                               MockAlarmFactory* alarm_factory,
                               Perspective perspective,
                               const QuicVersionVector& supported_versions)
    : QuicConnection(connection_id,
                     address,
                     helper,
                     alarm_factory,
                     new testing::NiceMock<MockPacketWriter>(),
                     /* owns_writer= */ true,
                     perspective,
                     supported_versions) {
  ON_CALL(*this, OnError(_))
      .WillByDefault(
          Invoke(this, &PacketSavingConnection::QuicConnection_OnError));
}

MockConnection::~MockConnection() {}

void MockConnection::AdvanceTime(QuicTime::Delta delta) {
  static_cast<MockConnectionHelper*>(helper())->AdvanceTime(delta);
}

PacketSavingConnection::PacketSavingConnection(MockConnectionHelper* helper,
                                               MockAlarmFactory* alarm_factory,
                                               Perspective perspective)
    : MockConnection(helper, alarm_factory, perspective) {}

PacketSavingConnection::PacketSavingConnection(
    MockConnectionHelper* helper,
    MockAlarmFactory* alarm_factory,
    Perspective perspective,
    const QuicVersionVector& supported_versions)
    : MockConnection(helper, alarm_factory, perspective, supported_versions) {}

PacketSavingConnection::~PacketSavingConnection() {
  STLDeleteElements(&encrypted_packets_);
}

void PacketSavingConnection::SendOrQueuePacket(SerializedPacket* packet) {
  encrypted_packets_.push_back(new QuicEncryptedPacket(
      QuicUtils::CopyBuffer(*packet), packet->encrypted_length, true));
  // Transfer ownership of the packet to the SentPacketManager and the
  // ack notifier to the AckNotifierManager.
  sent_packet_manager_.OnPacketSent(packet, 0, QuicTime::Zero(),
                                    NOT_RETRANSMISSION,
                                    HAS_RETRANSMITTABLE_DATA);
}

MockQuicSpdySession::MockQuicSpdySession(QuicConnection* connection)
    : QuicSpdySession(connection, DefaultQuicConfig()) {
  crypto_stream_.reset(new QuicCryptoStream(this));
  Initialize();
  ON_CALL(*this, WritevData(_, _, _, _, _))
      .WillByDefault(testing::Return(QuicConsumedData(0, false)));
}

MockQuicSpdySession::~MockQuicSpdySession() {}

// static
QuicConsumedData MockQuicSpdySession::ConsumeAllData(
    QuicStreamId /*id*/,
    const QuicIOVector& data,
    QuicStreamOffset /*offset*/,
    bool fin,
    QuicAckListenerInterface* /*ack_notifier_delegate*/) {
  return QuicConsumedData(data.total_length, fin);
}

TestQuicSpdyServerSession::TestQuicSpdyServerSession(
    QuicConnection* connection,
    const QuicConfig& config,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicServerSessionBase(config,
                            connection,
                            &visitor_,
                            crypto_config,
                            compressed_certs_cache) {
  Initialize();
}

TestQuicSpdyServerSession::~TestQuicSpdyServerSession() {}

QuicCryptoServerStreamBase*
TestQuicSpdyServerSession::CreateQuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache) {
  return new QuicCryptoServerStream(crypto_config, compressed_certs_cache,
                                    FLAGS_enable_quic_stateless_reject_support,
                                    this);
}

QuicCryptoServerStream* TestQuicSpdyServerSession::GetCryptoStream() {
  return static_cast<QuicCryptoServerStream*>(
      QuicServerSessionBase::GetCryptoStream());
}

TestQuicSpdyClientSession::TestQuicSpdyClientSession(
    QuicConnection* connection,
    const QuicConfig& config,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config)
    : QuicClientSessionBase(connection, &push_promise_index_, config) {
  crypto_stream_.reset(new QuicCryptoClientStream(
      server_id, this, CryptoTestUtils::ProofVerifyContextForTesting(),
      crypto_config, this));
  Initialize();
}

TestQuicSpdyClientSession::~TestQuicSpdyClientSession() {}

bool TestQuicSpdyClientSession::IsAuthorized(const string& authority) {
  return true;
}

QuicCryptoClientStream* TestQuicSpdyClientSession::GetCryptoStream() {
  return crypto_stream_.get();
}

MockPacketWriter::MockPacketWriter() {
  ON_CALL(*this, GetMaxPacketSize(_))
      .WillByDefault(testing::Return(kMaxPacketSize));
}

MockPacketWriter::~MockPacketWriter() {}

MockSendAlgorithm::MockSendAlgorithm() {}

MockSendAlgorithm::~MockSendAlgorithm() {}

MockLossAlgorithm::MockLossAlgorithm() {}

MockLossAlgorithm::~MockLossAlgorithm() {}

MockAckListener::MockAckListener() {}

MockAckListener::~MockAckListener() {}

MockNetworkChangeVisitor::MockNetworkChangeVisitor() {}

MockNetworkChangeVisitor::~MockNetworkChangeVisitor() {}

namespace {

string HexDumpWithMarks(const char* data,
                        int length,
                        const bool* marks,
                        int mark_length) {
  static const char kHexChars[] = "0123456789abcdef";
  static const int kColumns = 4;

  const int kSizeLimit = 1024;
  if (length > kSizeLimit || mark_length > kSizeLimit) {
    LOG(ERROR) << "Only dumping first " << kSizeLimit << " bytes.";
    length = min(length, kSizeLimit);
    mark_length = min(mark_length, kSizeLimit);
  }

  string hex;
  for (const char *row = data; length > 0;
       row += kColumns, length -= kColumns) {
    for (const char* p = row; p < row + 4; ++p) {
      if (p < row + length) {
        const bool mark =
            (marks && (p - data) < mark_length && marks[p - data]);
        hex += mark ? '*' : ' ';
        hex += kHexChars[(*p & 0xf0) >> 4];
        hex += kHexChars[*p & 0x0f];
        hex += mark ? '*' : ' ';
      } else {
        hex += "    ";
      }
    }
    hex = hex + "  ";

    for (const char* p = row; p < row + 4 && p < row + length; ++p) {
      hex += (*p >= 0x20 && *p <= 0x7f) ? (*p) : '.';
    }

    hex = hex + '\n';
  }
  return hex;
}

}  // namespace

IPAddress TestPeerIPAddress() {
  return Loopback4();
}

QuicVersion QuicVersionMax() {
  return QuicSupportedVersions().front();
}

QuicVersion QuicVersionMin() {
  return QuicSupportedVersions().back();
}

IPAddress Loopback4() {
  return IPAddress::IPv4Localhost();
}

IPAddress Loopback6() {
  return IPAddress::IPv6Localhost();
}

IPAddress Any4() {
  return IPAddress::IPv4AllZeros();
}

void GenerateBody(string* body, int length) {
  body->clear();
  body->reserve(length);
  for (int i = 0; i < length; ++i) {
    body->append(1, static_cast<char>(32 + i % (126 - 32)));
  }
}

QuicEncryptedPacket* ConstructEncryptedPacket(QuicConnectionId connection_id,
                                              bool version_flag,
                                              bool multipath_flag,
                                              bool reset_flag,
                                              QuicPathId path_id,
                                              QuicPacketNumber packet_number,
                                              const string& data) {
  return ConstructEncryptedPacket(connection_id, version_flag, multipath_flag,
                                  reset_flag, path_id, packet_number, data,
                                  PACKET_8BYTE_CONNECTION_ID,
                                  PACKET_6BYTE_PACKET_NUMBER);
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId connection_id,
    bool version_flag,
    bool multipath_flag,
    bool reset_flag,
    QuicPathId path_id,
    QuicPacketNumber packet_number,
    const string& data,
    QuicConnectionIdLength connection_id_length,
    QuicPacketNumberLength packet_number_length) {
  return ConstructEncryptedPacket(
      connection_id, version_flag, multipath_flag, reset_flag, path_id,
      packet_number, data, connection_id_length, packet_number_length, nullptr);
}

QuicEncryptedPacket* ConstructEncryptedPacket(
    QuicConnectionId connection_id,
    bool version_flag,
    bool multipath_flag,
    bool reset_flag,
    QuicPathId path_id,
    QuicPacketNumber packet_number,
    const string& data,
    QuicConnectionIdLength connection_id_length,
    QuicPacketNumberLength packet_number_length,
    QuicVersionVector* versions) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id;
  header.public_header.connection_id_length = connection_id_length;
  header.public_header.version_flag = version_flag;
  header.public_header.multipath_flag = multipath_flag;
  header.public_header.reset_flag = reset_flag;
  header.public_header.packet_number_length = packet_number_length;
  header.path_id = path_id;
  header.packet_number = packet_number;
  header.entropy_flag = false;
  header.entropy_hash = 0;
  header.fec_flag = false;
  header.is_in_fec_group = NOT_IN_FEC_GROUP;
  header.fec_group = 0;
  QuicStreamFrame stream_frame(1, false, 0, StringPiece(data));
  QuicFrame frame(&stream_frame);
  QuicFrames frames;
  frames.push_back(frame);
  QuicFramer framer(versions != nullptr ? *versions : QuicSupportedVersions(),
                    QuicTime::Zero(), Perspective::IS_CLIENT);

  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  EXPECT_TRUE(packet != nullptr);
  char* buffer = new char[kMaxPacketSize];
  size_t encrypted_length = framer.EncryptPayload(
      ENCRYPTION_NONE, path_id, packet_number, *packet, buffer, kMaxPacketSize);
  EXPECT_NE(0u, encrypted_length);
  return new QuicEncryptedPacket(buffer, encrypted_length, true);
}

QuicReceivedPacket* ConstructReceivedPacket(
    const QuicEncryptedPacket& encrypted_packet,
    QuicTime receipt_time) {
  char* buffer = new char[encrypted_packet.length()];
  memcpy(buffer, encrypted_packet.data(), encrypted_packet.length());
  return new QuicReceivedPacket(buffer, encrypted_packet.length(), receipt_time,
                                true);
}

QuicEncryptedPacket* ConstructMisFramedEncryptedPacket(
    QuicConnectionId connection_id,
    bool version_flag,
    bool multipath_flag,
    bool reset_flag,
    QuicPathId path_id,
    QuicPacketNumber packet_number,
    const string& data,
    QuicConnectionIdLength connection_id_length,
    QuicPacketNumberLength packet_number_length,
    QuicVersionVector* versions) {
  QuicPacketHeader header;
  header.public_header.connection_id = connection_id;
  header.public_header.connection_id_length = connection_id_length;
  header.public_header.version_flag = version_flag;
  header.public_header.multipath_flag = multipath_flag;
  header.public_header.reset_flag = reset_flag;
  header.public_header.packet_number_length = packet_number_length;
  header.path_id = path_id;
  header.packet_number = packet_number;
  header.entropy_flag = false;
  header.entropy_hash = 0;
  header.fec_flag = false;
  header.is_in_fec_group = NOT_IN_FEC_GROUP;
  header.fec_group = 0;
  QuicStreamFrame stream_frame(1, false, 0, StringPiece(data));
  QuicFrame frame(&stream_frame);
  QuicFrames frames;
  frames.push_back(frame);
  QuicFramer framer(versions != nullptr ? *versions : QuicSupportedVersions(),
                    QuicTime::Zero(), Perspective::IS_CLIENT);

  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  EXPECT_TRUE(packet != nullptr);

  // Now set the packet's private flags byte to 0xFF, which is an invalid value.
  reinterpret_cast<unsigned char*>(
      packet->mutable_data())[GetStartOfEncryptedData(
      connection_id_length, version_flag, multipath_flag,
      packet_number_length)] = 0xFF;

  char* buffer = new char[kMaxPacketSize];
  size_t encrypted_length = framer.EncryptPayload(
      ENCRYPTION_NONE, path_id, packet_number, *packet, buffer, kMaxPacketSize);
  EXPECT_NE(0u, encrypted_length);
  return new QuicEncryptedPacket(buffer, encrypted_length, true);
}

void CompareCharArraysWithHexError(const string& description,
                                   const char* actual,
                                   const int actual_len,
                                   const char* expected,
                                   const int expected_len) {
  EXPECT_EQ(actual_len, expected_len);
  const int min_len = min(actual_len, expected_len);
  const int max_len = max(actual_len, expected_len);
  std::unique_ptr<bool[]> marks(new bool[max_len]);
  bool identical = (actual_len == expected_len);
  for (int i = 0; i < min_len; ++i) {
    if (actual[i] != expected[i]) {
      marks[i] = true;
      identical = false;
    } else {
      marks[i] = false;
    }
  }
  for (int i = min_len; i < max_len; ++i) {
    marks[i] = true;
  }
  if (identical)
    return;
  ADD_FAILURE() << "Description:\n"
                << description << "\n\nExpected:\n"
                << HexDumpWithMarks(expected, expected_len, marks.get(),
                                    max_len)
                << "\nActual:\n"
                << HexDumpWithMarks(actual, actual_len, marks.get(), max_len);
}

bool DecodeHexString(const base::StringPiece& hex, std::string* bytes) {
  bytes->clear();
  if (hex.empty())
    return true;
  std::vector<uint8_t> v;
  if (!base::HexStringToBytes(hex.as_string(), &v))
    return false;
  if (!v.empty())
    bytes->assign(reinterpret_cast<const char*>(&v[0]), v.size());
  return true;
}

static QuicPacket* ConstructPacketFromHandshakeMessage(
    QuicConnectionId connection_id,
    const CryptoHandshakeMessage& message,
    bool should_include_version) {
  CryptoFramer crypto_framer;
  std::unique_ptr<QuicData> data(
      crypto_framer.ConstructHandshakeMessage(message));
  QuicFramer quic_framer(QuicSupportedVersions(), QuicTime::Zero(),
                         Perspective::IS_CLIENT);

  QuicPacketHeader header;
  header.public_header.connection_id = connection_id;
  header.public_header.reset_flag = false;
  header.public_header.version_flag = should_include_version;
  header.packet_number = 1;
  header.entropy_flag = false;
  header.entropy_hash = 0;
  header.fec_flag = false;
  header.fec_group = 0;

  QuicStreamFrame stream_frame(kCryptoStreamId, false, 0,
                               data->AsStringPiece());

  QuicFrame frame(&stream_frame);
  QuicFrames frames;
  frames.push_back(frame);
  return BuildUnsizedDataPacket(&quic_framer, header, frames);
}

QuicPacket* ConstructHandshakePacket(QuicConnectionId connection_id,
                                     QuicTag tag) {
  CryptoHandshakeMessage message;
  message.set_tag(tag);
  return ConstructPacketFromHandshakeMessage(connection_id, message, false);
}

size_t GetPacketLengthForOneStream(QuicVersion version,
                                   bool include_version,
                                   bool include_path_id,
                                   QuicConnectionIdLength connection_id_length,
                                   QuicPacketNumberLength packet_number_length,
                                   size_t* payload_length) {
  *payload_length = 1;
  const size_t stream_length =
      NullEncrypter().GetCiphertextSize(*payload_length) +
      QuicPacketCreator::StreamFramePacketOverhead(
          PACKET_8BYTE_CONNECTION_ID, include_version, include_path_id,
          packet_number_length, 0u);
  const size_t ack_length =
      NullEncrypter().GetCiphertextSize(
          QuicFramer::GetMinAckFrameSize(PACKET_1BYTE_PACKET_NUMBER)) +
      GetPacketHeaderSize(connection_id_length, include_version,
                          include_path_id, packet_number_length);
  if (stream_length < ack_length) {
    *payload_length = 1 + ack_length - stream_length;
  }

  return NullEncrypter().GetCiphertextSize(*payload_length) +
         QuicPacketCreator::StreamFramePacketOverhead(
             connection_id_length, include_version, include_path_id,
             packet_number_length, 0u);
}

TestEntropyCalculator::TestEntropyCalculator() {}

TestEntropyCalculator::~TestEntropyCalculator() {}

QuicPacketEntropyHash TestEntropyCalculator::EntropyHash(
    QuicPacketNumber packet_number) const {
  return 1u;
}

MockEntropyCalculator::MockEntropyCalculator() {}

MockEntropyCalculator::~MockEntropyCalculator() {}

QuicConfig DefaultQuicConfig() {
  QuicConfig config;
  config.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  return config;
}

QuicConfig DefaultQuicConfigStatelessRejects() {
  QuicConfig config = DefaultQuicConfig();
  QuicTagVector copt;
  copt.push_back(kSREJ);
  config.SetConnectionOptionsToSend(copt);
  return config;
}

QuicVersionVector SupportedVersions(QuicVersion version) {
  QuicVersionVector versions;
  versions.push_back(version);
  return versions;
}

MockQuicConnectionDebugVisitor::MockQuicConnectionDebugVisitor() {}

MockQuicConnectionDebugVisitor::~MockQuicConnectionDebugVisitor() {}

MockReceivedPacketManager::MockReceivedPacketManager(QuicConnectionStats* stats)
    : QuicReceivedPacketManager(stats) {}

MockReceivedPacketManager::~MockReceivedPacketManager() {}

void CreateClientSessionForTest(QuicServerId server_id,
                                bool supports_stateless_rejects,
                                QuicTime::Delta connection_start_time,
                                QuicVersionVector supported_versions,
                                MockConnectionHelper* helper,
                                MockAlarmFactory* alarm_factory,
                                QuicCryptoClientConfig* crypto_client_config,
                                PacketSavingConnection** client_connection,
                                TestQuicSpdyClientSession** client_session) {
  CHECK(crypto_client_config);
  CHECK(client_connection);
  CHECK(client_session);
  CHECK(!connection_start_time.IsZero())
      << "Connections must start at non-zero times, otherwise the "
      << "strike-register will be unhappy.";

  QuicConfig config = supports_stateless_rejects
                          ? DefaultQuicConfigStatelessRejects()
                          : DefaultQuicConfig();
  *client_connection = new PacketSavingConnection(
      helper, alarm_factory, Perspective::IS_CLIENT, supported_versions);
  *client_session = new TestQuicSpdyClientSession(
      *client_connection, config, server_id, crypto_client_config);
  (*client_connection)->AdvanceTime(connection_start_time);
}

void CreateServerSessionForTest(
    QuicServerId server_id,
    QuicTime::Delta connection_start_time,
    QuicVersionVector supported_versions,
    MockConnectionHelper* helper,
    MockAlarmFactory* alarm_factory,
    QuicCryptoServerConfig* server_crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    PacketSavingConnection** server_connection,
    TestQuicSpdyServerSession** server_session) {
  CHECK(server_crypto_config);
  CHECK(server_connection);
  CHECK(server_session);
  CHECK(!connection_start_time.IsZero())
      << "Connections must start at non-zero times, otherwise the "
      << "strike-register will be unhappy.";

  *server_connection = new PacketSavingConnection(
      helper, alarm_factory, Perspective::IS_SERVER, supported_versions);
  *server_session = new TestQuicSpdyServerSession(
      *server_connection, DefaultQuicConfig(), server_crypto_config,
      compressed_certs_cache);

  // We advance the clock initially because the default time is zero and the
  // strike register worries that we've just overflowed a uint32_t time.
  (*server_connection)->AdvanceTime(connection_start_time);
}

QuicStreamId QuicClientDataStreamId(int i) {
  return kClientDataStreamId1 + 2 * i;
}

}  // namespace test
}  // namespace net
