// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_dispatcher.h"

#include <memory>
#include <ostream>
#include <string>

#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/crypto/quic_crypto_server_config.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_crypto_stream.h"
#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_buffered_packet_store_peer.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/chlo_extractor.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_packet_writer_wrapper.h"
#include "net/tools/quic/quic_simple_crypto_server_stream_helper.h"
#include "net/tools/quic/quic_time_wait_list_manager.h"
#include "net/tools/quic/stateless_rejector.h"
#include "net/tools/quic/test_tools/mock_quic_time_wait_list_manager.h"
#include "net/tools/quic/test_tools/quic_dispatcher_peer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gmock_mutant.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::IntToString;
using base::StringPiece;
using net::EpollServer;
using net::test::ConstructEncryptedPacket;
using net::test::CryptoTestUtils;
using net::test::MockQuicConnection;
using net::test::MockQuicConnectionHelper;
using std::ostream;
using std::string;
using std::vector;
using testing::CreateFunctor;
using testing::DoAll;
using testing::InSequence;
using testing::Invoke;
using testing::Return;
using testing::WithoutArgs;
using testing::_;

static const size_t kDefaultMaxConnectionsInStore = 100;
static const size_t kMaxConnectionsWithoutCHLO =
    kDefaultMaxConnectionsInStore / 2;
static const int16_t kMaxNumSessionsToCreate = 16;

namespace net {
namespace test {
namespace {

class TestQuicSpdyServerSession : public QuicServerSessionBase {
 public:
  TestQuicSpdyServerSession(const QuicConfig& config,
                            QuicConnection* connection,
                            const QuicCryptoServerConfig* crypto_config,
                            QuicCompressedCertsCache* compressed_certs_cache)
      : QuicServerSessionBase(config,
                              connection,
                              nullptr,
                              nullptr,
                              crypto_config,
                              compressed_certs_cache),
        crypto_stream_(QuicServerSessionBase::GetCryptoStream()) {}

  ~TestQuicSpdyServerSession() override { delete connection(); };

  MOCK_METHOD3(OnConnectionClosed,
               void(QuicErrorCode error,
                    const string& error_details,
                    ConnectionCloseSource source));
  MOCK_METHOD1(CreateIncomingDynamicStream, QuicSpdyStream*(QuicStreamId id));
  MOCK_METHOD1(CreateOutgoingDynamicStream,
               QuicSpdyStream*(SpdyPriority priority));

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache) override {
    return new QuicCryptoServerStream(
        crypto_config, compressed_certs_cache,
        FLAGS_enable_quic_stateless_reject_support, this, stream_helper());
  }

  void SetCryptoStream(QuicCryptoServerStream* crypto_stream) {
    crypto_stream_ = crypto_stream;
  }

  QuicCryptoServerStreamBase* GetCryptoStream() override {
    return crypto_stream_;
  }

  QuicCryptoServerStream::Helper* stream_helper() {
    return QuicServerSessionBase::stream_helper();
  }

 private:
  QuicCryptoServerStreamBase* crypto_stream_;

  DISALLOW_COPY_AND_ASSIGN(TestQuicSpdyServerSession);
};

class TestDispatcher : public QuicDispatcher {
 public:
  TestDispatcher(const QuicConfig& config,
                 const QuicCryptoServerConfig* crypto_config,
                 QuicVersionManager* version_manager,
                 EpollServer* eps)
      : QuicDispatcher(
            config,
            crypto_config,
            version_manager,
            std::unique_ptr<QuicEpollConnectionHelper>(
                new QuicEpollConnectionHelper(eps, QuicAllocator::BUFFER_POOL)),
            std::unique_ptr<QuicCryptoServerStream::Helper>(
                new QuicSimpleCryptoServerStreamHelper(
                    QuicRandom::GetInstance())),
            std::unique_ptr<QuicEpollAlarmFactory>(
                new QuicEpollAlarmFactory(eps))) {}

  MOCK_METHOD2(CreateQuicSession,
               QuicServerSessionBase*(QuicConnectionId connection_id,
                                      const IPEndPoint& client_address));

  MOCK_METHOD1(ShouldCreateOrBufferPacketForConnection,
               bool(QuicConnectionId connection_id));

  using QuicDispatcher::current_server_address;
  using QuicDispatcher::current_client_address;
};

// A Connection class which unregisters the session from the dispatcher when
// sending connection close.
// It'd be slightly more realistic to do this from the Session but it would
// involve a lot more mocking.
class MockServerConnection : public MockQuicConnection {
 public:
  MockServerConnection(QuicConnectionId connection_id,
                       MockQuicConnectionHelper* helper,
                       MockAlarmFactory* alarm_factory,
                       QuicDispatcher* dispatcher)
      : MockQuicConnection(connection_id,
                           helper,
                           alarm_factory,
                           Perspective::IS_SERVER),
        dispatcher_(dispatcher) {}

  void UnregisterOnConnectionClosed() {
    LOG(ERROR) << "Unregistering " << connection_id();
    dispatcher_->OnConnectionClosed(connection_id(), QUIC_NO_ERROR,
                                    "Unregistering.");
  }

 private:
  QuicDispatcher* dispatcher_;
};

class QuicDispatcherTest : public ::testing::Test {
 public:
  QuicDispatcherTest()
      : helper_(&eps_, QuicAllocator::BUFFER_POOL),
        alarm_factory_(&eps_),
        version_manager_(AllSupportedVersions()),
        crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       CryptoTestUtils::ProofSourceForTesting()),
        dispatcher_(new TestDispatcher(config_,
                                       &crypto_config_,
                                       &version_manager_,
                                       &eps_)),
        time_wait_list_manager_(nullptr),
        session1_(nullptr),
        session2_(nullptr),
        store_(nullptr) {}

  void SetUp() override {
    dispatcher_->InitializeWithWriter(new QuicDefaultPacketWriter(1));
    // Set the counter to some value to start with.
    QuicDispatcherPeer::set_new_sessions_allowed_per_event_loop(
        dispatcher_.get(), kMaxNumSessionsToCreate);
    ON_CALL(*dispatcher_, ShouldCreateOrBufferPacketForConnection(_))
        .WillByDefault(Return(true));
  }

  ~QuicDispatcherTest() override {}

  MockQuicConnection* connection1() {
    return reinterpret_cast<MockQuicConnection*>(session1_->connection());
  }

  MockQuicConnection* connection2() {
    return reinterpret_cast<MockQuicConnection*>(session2_->connection());
  }

  // Process a packet with an 8 byte connection id,
  // 6 byte packet number, default path id, and packet number 1,
  // using the first supported version.
  void ProcessPacket(IPEndPoint client_address,
                     QuicConnectionId connection_id,
                     bool has_version_flag,
                     bool has_multipath_flag,
                     const string& data) {
    ProcessPacket(client_address, connection_id, has_version_flag,
                  has_multipath_flag, data, PACKET_8BYTE_CONNECTION_ID,
                  PACKET_6BYTE_PACKET_NUMBER);
  }

  // Process a packet with a default path id, and packet number 1,
  // using the first supported version.
  void ProcessPacket(IPEndPoint client_address,
                     QuicConnectionId connection_id,
                     bool has_version_flag,
                     bool has_multipath_flag,
                     const string& data,
                     QuicConnectionIdLength connection_id_length,
                     QuicPacketNumberLength packet_number_length) {
    ProcessPacket(client_address, connection_id, has_version_flag,
                  has_multipath_flag, data, connection_id_length,
                  packet_number_length, kDefaultPathId, 1);
  }

  // Process a packet using the first supported version.
  void ProcessPacket(IPEndPoint client_address,
                     QuicConnectionId connection_id,
                     bool has_version_flag,
                     bool has_multipath_flag,
                     const string& data,
                     QuicConnectionIdLength connection_id_length,
                     QuicPacketNumberLength packet_number_length,
                     QuicPathId path_id,
                     QuicPacketNumber packet_number) {
    ProcessPacket(client_address, connection_id, has_version_flag,
                  CurrentSupportedVersions().front(), data,
                  connection_id_length, packet_number_length, packet_number);
  }

  // Processes a packet.
  void ProcessPacket(IPEndPoint client_address,
                     QuicConnectionId connection_id,
                     bool has_version_flag,
                     QuicVersion version,
                     const string& data,
                     QuicConnectionIdLength connection_id_length,
                     QuicPacketNumberLength packet_number_length,
                     QuicPacketNumber packet_number) {
    QuicVersionVector versions(SupportedVersions(version));
    std::unique_ptr<QuicEncryptedPacket> packet(ConstructEncryptedPacket(
        connection_id, has_version_flag, false, false, 0, packet_number, data,
        connection_id_length, packet_number_length, &versions));
    std::unique_ptr<QuicReceivedPacket> received_packet(
        ConstructReceivedPacket(*packet, helper_.GetClock()->Now()));

    if (ChloExtractor::Extract(*packet, versions, nullptr)) {
      // Add CHLO packet to the beginning to be verified first, because it is
      // also processed first by new session.
      data_connection_map_[connection_id].push_front(
          string(packet->data(), packet->length()));
    } else {
      // For non-CHLO, always append to last.
      data_connection_map_[connection_id].push_back(
          string(packet->data(), packet->length()));
    }
    dispatcher_->ProcessPacket(server_address_, client_address,
                               *received_packet);
  }

  void ValidatePacket(QuicConnectionId conn_id,
                      const QuicEncryptedPacket& packet) {
    EXPECT_EQ(data_connection_map_[conn_id].front().length(),
              packet.AsStringPiece().length());
    EXPECT_EQ(data_connection_map_[conn_id].front(), packet.AsStringPiece());
    data_connection_map_[conn_id].pop_front();
  }

  QuicServerSessionBase* CreateSession(
      QuicDispatcher* dispatcher,
      const QuicConfig& config,
      QuicConnectionId connection_id,
      const IPEndPoint& client_address,
      MockQuicConnectionHelper* helper,
      MockAlarmFactory* alarm_factory,
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      TestQuicSpdyServerSession** session) {
    MockServerConnection* connection = new MockServerConnection(
        connection_id, helper, alarm_factory, dispatcher);
    *session = new TestQuicSpdyServerSession(config, connection, crypto_config,
                                             compressed_certs_cache);
    connection->set_visitor(*session);
    ON_CALL(*connection, CloseConnection(_, _, _))
        .WillByDefault(WithoutArgs(Invoke(
            connection, &MockServerConnection::UnregisterOnConnectionClosed)));
    return *session;
  }

  void CreateTimeWaitListManager() {
    time_wait_list_manager_ = new MockTimeWaitListManager(
        QuicDispatcherPeer::GetWriter(dispatcher_.get()), dispatcher_.get(),
        &helper_, &alarm_factory_);
    // dispatcher_ takes the ownership of time_wait_list_manager_.
    QuicDispatcherPeer::SetTimeWaitListManager(dispatcher_.get(),
                                               time_wait_list_manager_);
  }

  string SerializeCHLO() {
    CryptoHandshakeMessage client_hello;
    client_hello.set_tag(kCHLO);
    return client_hello.GetSerialized().AsStringPiece().as_string();
  }

  QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  EpollServer eps_;
  QuicEpollConnectionHelper helper_;
  MockQuicConnectionHelper mock_helper_;
  QuicEpollAlarmFactory alarm_factory_;
  MockAlarmFactory mock_alarm_factory_;
  QuicConfig config_;
  QuicVersionManager version_manager_;
  QuicCryptoServerConfig crypto_config_;
  IPEndPoint server_address_;
  std::unique_ptr<TestDispatcher> dispatcher_;
  MockTimeWaitListManager* time_wait_list_manager_;
  TestQuicSpdyServerSession* session1_;
  TestQuicSpdyServerSession* session2_;
  std::map<QuicConnectionId, std::list<string>> data_connection_map_;
  QuicBufferedPacketStore* store_;
};

TEST_F(QuicDispatcherTest, ProcessPackets) {
  IPEndPoint client_address(net::test::Loopback4(), 1);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(1, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
          &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));
  ProcessPacket(client_address, 1, true, false, SerializeCHLO());
  EXPECT_EQ(client_address, dispatcher_->current_client_address());
  EXPECT_EQ(server_address_, dispatcher_->current_server_address());

  EXPECT_CALL(*dispatcher_, CreateQuicSession(2, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, 2, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session2_)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session2_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
          &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 2))));
  ProcessPacket(client_address, 2, true, false, SerializeCHLO());

  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(1)
      .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
          &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));
  ProcessPacket(client_address, 1, false, false, "data");
}

TEST_F(QuicDispatcherTest, StatelessVersionNegotiation) {
  IPEndPoint client_address(net::test::Loopback4(), 1);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(1, client_address)).Times(0);
  QuicVersion version = static_cast<QuicVersion>(QuicVersionMin() - 1);
  ProcessPacket(client_address, 1, true, version, SerializeCHLO(),
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, 1);
}

TEST_F(QuicDispatcherTest, Shutdown) {
  IPEndPoint client_address(net::test::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
          &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));

  ProcessPacket(client_address, 1, true, false, SerializeCHLO());

  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              CloseConnection(QUIC_PEER_GOING_AWAY, _, _));

  dispatcher_->Shutdown();
}

TEST_F(QuicDispatcherTest, TimeWaitListManager) {
  CreateTimeWaitListManager();

  // Create a new session.
  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, connection_id, client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
          &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));

  ProcessPacket(client_address, connection_id, true, false, SerializeCHLO());

  // Close the connection by sending public reset packet.
  QuicPublicResetPacket packet;
  packet.public_header.connection_id = connection_id;
  packet.public_header.reset_flag = true;
  packet.public_header.version_flag = false;
  packet.rejected_packet_number = 19191;
  packet.nonce_proof = 132232;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      QuicFramer::BuildPublicResetPacket(packet));
  std::unique_ptr<QuicReceivedPacket> received(ConstructReceivedPacket(
      *encrypted, session1_->connection()->clock()->Now()));
  EXPECT_CALL(*session1_, OnConnectionClosed(QUIC_PUBLIC_RESET, _,
                                             ConnectionCloseSource::FROM_PEER))
      .Times(1)
      .WillOnce(WithoutArgs(Invoke(
          reinterpret_cast<MockServerConnection*>(session1_->connection()),
          &MockServerConnection::UnregisterOnConnectionClosed)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(
          Invoke(reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                 &MockQuicConnection::ReallyProcessUdpPacket));
  dispatcher_->ProcessPacket(IPEndPoint(), client_address, *received);
  EXPECT_TRUE(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));

  // Dispatcher forwards subsequent packets for this connection_id to the time
  // wait list manager.
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(0);
  ProcessPacket(client_address, connection_id, true, false, "data");
}

TEST_F(QuicDispatcherTest, NoVersionPacketToTimeWaitListManager) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  // Dispatcher forwards all packets for this connection_id to the time wait
  // list manager.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(1);
  ProcessPacket(client_address, connection_id, false, false, SerializeCHLO());
}

TEST_F(QuicDispatcherTest, ProcessPacketWithZeroPort) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 0);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  // dispatcher_ should drop this packet.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(1, client_address)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(0);
  ProcessPacket(client_address, 1, true, false, SerializeCHLO());
}

TEST_F(QuicDispatcherTest, OKSeqNoPacketProcessed) {
  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(1, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
          &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));
  // A packet whose packet number is the largest that is allowed to start a
  // connection.
  ProcessPacket(client_address, connection_id, true, false, SerializeCHLO(),
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                kDefaultPathId,
                QuicDispatcher::kMaxReasonableInitialPacketNumber);
  EXPECT_EQ(client_address, dispatcher_->current_client_address());
  EXPECT_EQ(server_address_, dispatcher_->current_server_address());
}

TEST_F(QuicDispatcherTest, TooBigSeqNoPacketToTimeWaitListManager) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  // Dispatcher forwards this packet for this connection_id to the time wait
  // list manager.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(1);
  // A packet whose packet number is one to large to be allowed to start a
  // connection.
  ProcessPacket(client_address, connection_id, true, false, SerializeCHLO(),
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                kDefaultPathId,
                QuicDispatcher::kMaxReasonableInitialPacketNumber + 1);
}

// Enables mocking of the handshake-confirmation for stateless rejects.
class MockQuicCryptoServerStream : public QuicCryptoServerStream {
 public:
  MockQuicCryptoServerStream(const QuicCryptoServerConfig& crypto_config,
                             QuicCompressedCertsCache* compressed_certs_cache,
                             QuicServerSessionBase* session,
                             QuicCryptoServerStream::Helper* helper)
      : QuicCryptoServerStream(&crypto_config,
                               compressed_certs_cache,
                               FLAGS_enable_quic_stateless_reject_support,
                               session,
                               helper) {}
  void set_handshake_confirmed_for_testing(bool handshake_confirmed) {
    handshake_confirmed_ = handshake_confirmed;
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockQuicCryptoServerStream);
};

struct StatelessRejectTestParams {
  StatelessRejectTestParams(bool enable_stateless_rejects_via_flag,
                            bool client_supports_statelesss_rejects,
                            bool crypto_handshake_successful)
      : enable_stateless_rejects_via_flag(enable_stateless_rejects_via_flag),
        client_supports_statelesss_rejects(client_supports_statelesss_rejects),
        crypto_handshake_successful(crypto_handshake_successful) {}

  friend std::ostream& operator<<(std::ostream& os,
                                  const StatelessRejectTestParams& p) {
    os << "{  enable_stateless_rejects_via_flag: "
       << p.enable_stateless_rejects_via_flag << std::endl;
    os << " client_supports_statelesss_rejects: "
       << p.client_supports_statelesss_rejects << std::endl;
    os << "  crypto_handshake_successful: " << p.crypto_handshake_successful
       << " }";
    return os;
  }

  // This only enables the stateless reject feature via the feature-flag.
  // This should be a no-op if the peer does not support them.
  bool enable_stateless_rejects_via_flag;
  // Whether or not the client supports stateless rejects.
  bool client_supports_statelesss_rejects;
  // Should the initial crypto handshake succeed or not.
  bool crypto_handshake_successful;
};

// Constructs various test permutations for stateless rejects.
vector<StatelessRejectTestParams> GetStatelessRejectTestParams() {
  vector<StatelessRejectTestParams> params;
  for (bool enable_stateless_rejects_via_flag : {true, false}) {
    for (bool client_supports_statelesss_rejects : {true, false}) {
      for (bool crypto_handshake_successful : {true, false}) {
        params.push_back(StatelessRejectTestParams(
            enable_stateless_rejects_via_flag,
            client_supports_statelesss_rejects, crypto_handshake_successful));
      }
    }
  }
  return params;
}

class QuicDispatcherStatelessRejectTest
    : public QuicDispatcherTest,
      public ::testing::WithParamInterface<StatelessRejectTestParams> {
 public:
  QuicDispatcherStatelessRejectTest()
      : QuicDispatcherTest(), crypto_stream1_(nullptr) {}

  ~QuicDispatcherStatelessRejectTest() override {
    if (crypto_stream1_) {
      delete crypto_stream1_;
    }
  }

  // This test setup assumes that all testing will be done using
  // crypto_stream1_.
  void SetUp() override {
    QuicDispatcherTest::SetUp();
    FLAGS_enable_quic_stateless_reject_support =
        GetParam().enable_stateless_rejects_via_flag;
  }

  // Returns true or false, depending on whether the server will emit
  // a stateless reject, depending upon the parameters of the test.
  bool ExpectStatelessReject() {
    return GetParam().enable_stateless_rejects_via_flag &&
           !GetParam().crypto_handshake_successful &&
           GetParam().client_supports_statelesss_rejects;
  }

  // Sets up dispatcher_, session1_, and crypto_stream1_ based on
  // the test parameters.
  QuicServerSessionBase* CreateSessionBasedOnTestParams(
      QuicConnectionId connection_id,
      const IPEndPoint& client_address) {
    CreateSession(dispatcher_.get(), config_, connection_id, client_address,
                  &mock_helper_, &mock_alarm_factory_, &crypto_config_,
                  QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_);

    crypto_stream1_ = new MockQuicCryptoServerStream(
        crypto_config_, QuicDispatcherPeer::GetCache(dispatcher_.get()),
        session1_, session1_->stream_helper());
    session1_->SetCryptoStream(crypto_stream1_);
    crypto_stream1_->set_handshake_confirmed_for_testing(
        GetParam().crypto_handshake_successful);
    crypto_stream1_->SetPeerSupportsStatelessRejects(
        GetParam().client_supports_statelesss_rejects);
    return session1_;
  }

  MockQuicCryptoServerStream* crypto_stream1_;
};

// Parameterized test for stateless rejects.  Should test all
// combinations of enabling/disabling, reject/no-reject for stateless
// rejects.
INSTANTIATE_TEST_CASE_P(QuicDispatcherStatelessRejectTests,
                        QuicDispatcherStatelessRejectTest,
                        ::testing::ValuesIn(GetStatelessRejectTestParams()));

TEST_P(QuicDispatcherStatelessRejectTest, ParameterizedBasicTest) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, client_address))
      .WillOnce(testing::Return(
          CreateSessionBasedOnTestParams(connection_id, client_address)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(testing::WithArgs<2>(
          Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                               base::Unretained(this), connection_id))));
  // Process the first packet for the connection.
  ProcessPacket(client_address, connection_id, true, false, SerializeCHLO());
  if (ExpectStatelessReject()) {
    // If this is a stateless reject, the crypto stream will close the
    // connection.
    session1_->connection()->CloseConnection(
        QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT, "stateless reject",
        ConnectionCloseBehavior::SILENT_CLOSE);
  }

  // Send a second packet and check the results.  If this is a stateless reject,
  // the existing connection_id will go on the time-wait list.
  EXPECT_EQ(ExpectStatelessReject(),
            time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));
  if (ExpectStatelessReject()) {
    // The second packet will be processed on the time-wait list.
    EXPECT_CALL(*time_wait_list_manager_,
                ProcessPacket(_, _, connection_id, _, _))
        .Times(1);
  } else {
    // The second packet will trigger a packet-validation
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .Times(1)
        .WillOnce(testing::WithArgs<2>(
            Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                 base::Unretained(this), connection_id))));
  }
  ProcessPacket(client_address, connection_id, true, false, "data");
}

TEST_P(QuicDispatcherStatelessRejectTest, CheapRejects) {
  FLAGS_quic_use_cheap_stateless_rejects = true;
  FLAGS_quic_buffer_packet_till_chlo = true;
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  if (GetParam().enable_stateless_rejects_via_flag) {
    EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, client_address))
        .Times(0);
  } else {
    EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, client_address))
        .WillOnce(testing::Return(
            CreateSessionBasedOnTestParams(connection_id, client_address)));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
            &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));
  }

  VLOG(1) << "ExpectStatelessReject: " << ExpectStatelessReject();
  VLOG(1) << "Params: " << GetParam();
  // Process the first packet for the connection.
  // clang-format off
  CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "COPT", "SREJ",
      "NONC", "1234567890123456789012",
      "VER\0", "Q025",
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  ProcessPacket(client_address, connection_id, true, false,
                client_hello.GetSerialized().AsStringPiece().as_string());

  if (GetParam().enable_stateless_rejects_via_flag) {
    EXPECT_EQ(true,
              time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));
  }
}

TEST_P(QuicDispatcherStatelessRejectTest, BufferNonChlo) {
  FLAGS_quic_use_cheap_stateless_rejects = true;
  CreateTimeWaitListManager();

  const IPEndPoint client_address(net::test::Loopback4(), 1);
  const QuicConnectionId connection_id = 1;

  if (!GetParam().enable_stateless_rejects_via_flag &&
      !FLAGS_quic_buffer_packet_till_chlo) {
    // If stateless rejects are not being used and early arrived packets are not
    // buffered, then a connection will be created immediately.
    EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, client_address))
        .WillOnce(testing::Return(
            CreateSessionBasedOnTestParams(connection_id, client_address)));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, client_address, _))
        .WillOnce(testing::WithArg<2>(
            Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                 base::Unretained(this), connection_id))));
  }
  bool first_packet_dropped = GetParam().enable_stateless_rejects_via_flag &&
                              !FLAGS_quic_buffer_packet_till_chlo;
  if (first_packet_dropped) {
    // Never do stateless reject while
    // FLAGS_quic_buffer_packet_till_chlo is off.
    EXPECT_QUIC_BUG(
        ProcessPacket(client_address, connection_id, true, false,
                      "NOT DATA FOR A CHLO"),
        "Have to drop packet because buffering non-chlo packet is "
        "not supported while trying to do stateless reject. "
        "--gfe2_reloadable_flag_quic_buffer_packet_till_chlo false "
        "--gfe2_reloadable_flag_quic_use_cheap_stateless_rejects true");
  } else {
    ProcessPacket(client_address, connection_id, true, false,
                  "NOT DATA FOR A CHLO");
  }

  // Process the first packet for the connection.
  // clang-format off
  CryptoHandshakeMessage client_hello = CryptoTestUtils::Message(
      "CHLO",
      "AEAD", "AESG",
      "KEXS", "C255",
      "NONC", "1234567890123456789012",
      "VER\0", "Q025",
      "$padding", static_cast<int>(kClientHelloMinimumSize),
      nullptr);
  // clang-format on

  if (GetParam().enable_stateless_rejects_via_flag ||
      FLAGS_quic_buffer_packet_till_chlo) {
    // If stateless rejects are enabled then a connection will be created now
    // and the buffered packet will be processed
    EXPECT_CALL(*dispatcher_, CreateQuicSession(connection_id, client_address))
        .WillOnce(testing::Return(
            CreateSessionBasedOnTestParams(connection_id, client_address)));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, client_address, _))
        .WillOnce(testing::WithArg<2>(
            Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                 base::Unretained(this), connection_id))));
  }
  if (!first_packet_dropped) {
    // Expect both packets to be passed to ProcessUdpPacket(). And one of them
    // is already expected in CreateSessionBasedOnTestParams().
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, client_address, _))
        .WillOnce(testing::WithArg<2>(
            Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                 base::Unretained(this), connection_id))))
        .RetiresOnSaturation();
  } else {
    // Since first packet is dropped, remove it from map to skip
    // ValidatePacket() on it.
    data_connection_map_[connection_id].pop_front();
  }
  ProcessPacket(client_address, connection_id, true, false,
                client_hello.GetSerialized().AsStringPiece().as_string());
  EXPECT_FALSE(
      time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));
}

// Verify the stopgap test: Packets with truncated connection IDs should be
// dropped.
class QuicDispatcherTestStrayPacketConnectionId : public QuicDispatcherTest {};

// Packets with truncated connection IDs should be dropped.
TEST_F(QuicDispatcherTestStrayPacketConnectionId,
       StrayPacketTruncatedConnectionId) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  // Dispatcher drops this packet.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(0);
  ProcessPacket(client_address, connection_id, true, false, "data",
                PACKET_0BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER);
}

class BlockingWriter : public QuicPacketWriterWrapper {
 public:
  BlockingWriter() : write_blocked_(false) {}

  bool IsWriteBlocked() const override { return write_blocked_; }
  void SetWritable() override { write_blocked_ = false; }

  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const IPAddress& self_client_address,
                          const IPEndPoint& peer_client_address,
                          PerPacketOptions* options) override {
    // It would be quite possible to actually implement this method here with
    // the fake blocked status, but it would be significantly more work in
    // Chromium, and since it's not called anyway, don't bother.
    LOG(DFATAL) << "Not supported";
    return WriteResult();
  }

  bool write_blocked_;
};

class QuicDispatcherWriteBlockedListTest : public QuicDispatcherTest {
 public:
  void SetUp() override {
    QuicDispatcherTest::SetUp();
    writer_ = new BlockingWriter;
    QuicDispatcherPeer::UseWriter(dispatcher_.get(), writer_);

    IPEndPoint client_address(net::test::Loopback4(), 1);

    EXPECT_CALL(*dispatcher_, CreateQuicSession(_, client_address))
        .WillOnce(testing::Return(CreateSession(
            dispatcher_.get(), config_, 1, client_address, &helper_,
            &alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
            &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 1))));
    ProcessPacket(client_address, 1, true, false, SerializeCHLO());

    EXPECT_CALL(*dispatcher_, CreateQuicSession(_, client_address))
        .WillOnce(testing::Return(CreateSession(
            dispatcher_.get(), config_, 2, client_address, &helper_,
            &alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session2_)));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session2_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(testing::WithArgs<2>(Invoke(CreateFunctor(
            &QuicDispatcherTest::ValidatePacket, base::Unretained(this), 2))));
    ProcessPacket(client_address, 2, true, false, SerializeCHLO());

    blocked_list_ = QuicDispatcherPeer::GetWriteBlockedList(dispatcher_.get());
  }

  void TearDown() override {
    EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
    EXPECT_CALL(*connection2(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
    dispatcher_->Shutdown();
  }

  void SetBlocked() { writer_->write_blocked_ = true; }

  void BlockConnection2() {
    writer_->write_blocked_ = true;
    dispatcher_->OnWriteBlocked(connection2());
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  BlockingWriter* writer_;
  QuicDispatcher::WriteBlockedList* blocked_list_;
};

TEST_F(QuicDispatcherWriteBlockedListTest, BasicOnCanWrite) {
  // No OnCanWrite calls because no connections are blocked.
  dispatcher_->OnCanWrite();

  // Register connection 1 for events, and make sure it's notified.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // It should get only one notification.
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_F(QuicDispatcherWriteBlockedListTest, OnCanWriteOrder) {
  // Make sure we handle events in order.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // Check the other ordering.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection2());
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection2(), OnCanWrite());
  EXPECT_CALL(*connection1(), OnCanWrite());
  dispatcher_->OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, OnCanWriteRemove) {
  // Add and remove one connction.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  blocked_list_->erase(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();

  // Add and remove one connction and make sure it doesn't affect others.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  blocked_list_->erase(connection1());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // Add it, remove it, and add it back and make sure things are OK.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  blocked_list_->erase(connection1());
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(1);
  dispatcher_->OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, DoubleAdd) {
  // Make sure a double add does not necessitate a double remove.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection1());
  blocked_list_->erase(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();

  // Make sure a double add does not result in two OnCanWrite calls.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(1);
  dispatcher_->OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, OnCanWriteHandleBlock) {
  // Finally make sure if we write block on a write call, we stop calling.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite())
      .WillOnce(Invoke(this, &QuicDispatcherWriteBlockedListTest::SetBlocked));
  EXPECT_CALL(*connection2(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();

  // And we'll resume where we left off when we get another call.
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, LimitedWrites) {
  // Make sure we call both writers.  The first will register for more writing
  // but should not be immediately called due to limits.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite())
      .WillOnce(
          Invoke(this, &QuicDispatcherWriteBlockedListTest::BlockConnection2));
  dispatcher_->OnCanWrite();
  EXPECT_TRUE(dispatcher_->HasPendingWrites());

  // Now call OnCanWrite again, and connection1 should get its second chance
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_F(QuicDispatcherWriteBlockedListTest, TestWriteLimits) {
  // Finally make sure if we write block on a write call, we stop calling.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite())
      .WillOnce(Invoke(this, &QuicDispatcherWriteBlockedListTest::SetBlocked));
  EXPECT_CALL(*connection2(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();
  EXPECT_TRUE(dispatcher_->HasPendingWrites());

  // And we'll resume where we left off when we get another call.
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

// Tests that bufferring packets works in stateful reject, expensive stateless
// reject and cheap stateless reject.
struct BufferedPacketStoreTestParams {
  BufferedPacketStoreTestParams(bool enable_stateless_rejects_via_flag,
                                bool support_cheap_stateless_reject)
      : enable_stateless_rejects_via_flag(enable_stateless_rejects_via_flag),
        support_cheap_stateless_reject(support_cheap_stateless_reject) {}

  friend ostream& operator<<(ostream& os,
                             const BufferedPacketStoreTestParams& p) {
    os << "{  enable_stateless_rejects_via_flag: "
       << p.enable_stateless_rejects_via_flag << std::endl;
    os << "  support_cheap_stateless_reject: "
       << p.support_cheap_stateless_reject << " }";
    return os;
  }

  // This only enables the stateless reject feature via the feature-flag.
  // This should be a no-op if the peer does not support them.
  bool enable_stateless_rejects_via_flag;
  // Whether to do cheap stateless or not.
  bool support_cheap_stateless_reject;
};

vector<BufferedPacketStoreTestParams> GetBufferedPacketStoreTestParams() {
  vector<BufferedPacketStoreTestParams> params;
  for (bool enable_stateless_rejects_via_flag : {true, false}) {
    for (bool support_cheap_stateless_reject : {true, false}) {
      params.push_back(BufferedPacketStoreTestParams(
          enable_stateless_rejects_via_flag, support_cheap_stateless_reject));
    }
  }
  return params;
}

// A dispatcher whose stateless rejector will always ACCEPTs CHLO.
class BufferedPacketStoreTest
    : public QuicDispatcherTest,
      public ::testing::WithParamInterface<BufferedPacketStoreTestParams> {
 public:
  BufferedPacketStoreTest()
      : QuicDispatcherTest(), client_addr_(Loopback4(), 1234) {
    FLAGS_quic_buffer_packet_till_chlo = true;
    FLAGS_quic_use_cheap_stateless_rejects =
        GetParam().support_cheap_stateless_reject;
    FLAGS_enable_quic_stateless_reject_support =
        GetParam().enable_stateless_rejects_via_flag;
  }

  void SetUp() override {
    QuicDispatcherTest::SetUp();
    clock_ = QuicDispatcherPeer::GetHelper(dispatcher_.get())->GetClock();

    QuicVersion version = AllSupportedVersions().front();
    CryptoHandshakeMessage chlo = CryptoTestUtils::GenerateDefaultInchoateCHLO(
        clock_, version, &crypto_config_);
    chlo.SetVector(net::kCOPT, net::QuicTagVector{net::kSREJ});
    // Pass an inchoate CHLO.
    CryptoTestUtils::GenerateFullCHLO(
        chlo, &crypto_config_, server_ip_, client_addr_, version, clock_,
        &proof_, QuicDispatcherPeer::GetCache(dispatcher_.get()), &full_chlo_);
  }

  string SerializeFullCHLO() {
    return full_chlo_.GetSerialized().AsStringPiece().as_string();
  }

 protected:
  IPAddress server_ip_;
  IPEndPoint client_addr_;
  QuicCryptoProof proof_;
  const QuicClock* clock_;
  CryptoHandshakeMessage full_chlo_;
};

INSTANTIATE_TEST_CASE_P(
    BufferedPacketStoreTests,
    BufferedPacketStoreTest,
    ::testing::ValuesIn(GetBufferedPacketStoreTestParams()));

TEST_P(BufferedPacketStoreTest, ProcessNonChloPacketsUptoLimitAndProcessChlo) {
  InSequence s;
  IPEndPoint client_address(Loopback4(), 1);
  server_address_ = IPEndPoint(Any4(), 5);
  QuicConnectionId conn_id = 1;
  // A bunch of non-CHLO should be buffered upon arrival, and the first one
  // should trigger ShouldCreateOrBufferPacketForConnection().
  EXPECT_CALL(*dispatcher_, ShouldCreateOrBufferPacketForConnection(conn_id))
      .Times(1);
  for (size_t i = 1; i <= kDefaultMaxUndecryptablePackets + 1; ++i) {
    ProcessPacket(client_address, conn_id, true, false,
                  "data packet " + IntToString(i + 1),
                  PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                  kDefaultPathId,
                  /*packet_number=*/i + 1);
  }
  EXPECT_EQ(0u, dispatcher_->session_map().size())
      << "No session should be created before CHLO arrives.";

  // Pop out the last packet as it is also be dropped by the store.
  data_connection_map_[conn_id].pop_back();
  // When CHLO arrives, a new session should be created, and all packets
  // buffered should be delivered to the session.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, conn_id, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));

  // Only |kDefaultMaxUndecryptablePackets| packets were buffered, and they
  // should be delivered in arrival order.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(kDefaultMaxUndecryptablePackets + 1)  // + 1 for CHLO.
      .WillRepeatedly(testing::WithArg<2>(
          Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                               base::Unretained(this), conn_id))));
  ProcessPacket(client_address, conn_id, true, false, SerializeFullCHLO());
}

TEST_P(BufferedPacketStoreTest,
       ProcessNonChloPacketsForDifferentConnectionsUptoLimit) {
  InSequence s;
  server_address_ = IPEndPoint(Any4(), 5);
  // A bunch of non-CHLO should be buffered upon arrival.
  size_t kNumConnections = (FLAGS_quic_limit_num_new_sessions_per_epoll_loop
                                ? kMaxConnectionsWithoutCHLO
                                : kDefaultMaxConnectionsInStore) +
                           1;
  for (size_t i = 1; i <= kNumConnections; ++i) {
    IPEndPoint client_address(Loopback4(), i);
    QuicConnectionId conn_id = i;
    if (FLAGS_quic_create_session_after_insertion) {
      EXPECT_CALL(*dispatcher_,
                  ShouldCreateOrBufferPacketForConnection(conn_id));
    } else {
      if (i <= kNumConnections - 1) {
        // As they are on different connection, they should trigger
        // ShouldCreateOrBufferPacketForConnection(). The last packet should be
        // dropped.
        EXPECT_CALL(*dispatcher_,
                    ShouldCreateOrBufferPacketForConnection(conn_id));
      }
    }
    ProcessPacket(client_address, conn_id, true, false,
                  "data packet on connection " + IntToString(i),
                  PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                  kDefaultPathId,
                  /*packet_number=*/2);
  }

  // Pop out the packet on last connection as it shouldn't be enqueued in store
  // as well.
  data_connection_map_[kNumConnections].pop_front();

  // Reset session creation counter to ensure processing CHLO can always
  // create session.
  QuicDispatcherPeer::set_new_sessions_allowed_per_event_loop(dispatcher_.get(),
                                                              kNumConnections);
  // Process CHLOs to create session for these connections.
  for (size_t i = 1; i <= kNumConnections; ++i) {
    IPEndPoint client_address(Loopback4(), i);
    QuicConnectionId conn_id = i;
    if (FLAGS_quic_create_session_after_insertion &&
        conn_id == kNumConnections) {
      EXPECT_CALL(*dispatcher_,
                  ShouldCreateOrBufferPacketForConnection(conn_id));
    }
    EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_address))
        .WillOnce(testing::Return(CreateSession(
            dispatcher_.get(), config_, conn_id, client_address, &mock_helper_,
            &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
    if (!FLAGS_quic_create_session_after_insertion &&
        conn_id == kNumConnections) {
      // The last CHLO should trigger ShouldCreateOrBufferPacketForConnection()
      // since it's the first packet arrives on that connection.
      EXPECT_CALL(*dispatcher_,
                  ShouldCreateOrBufferPacketForConnection(conn_id));
    }
    // First |kNumConnections| - 1 connections should have buffered
    // a packet in store. The rest should have been dropped.
    size_t upper_limit = FLAGS_quic_limit_num_new_sessions_per_epoll_loop
                             ? kMaxConnectionsWithoutCHLO
                             : kDefaultMaxConnectionsInStore;
    size_t num_packet_to_process = i <= upper_limit ? 2u : 1u;
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, client_address, _))
        .Times(num_packet_to_process)
        .WillRepeatedly(testing::WithArg<2>(
            Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                 base::Unretained(this), conn_id))));
    ProcessPacket(client_address, conn_id, true, false, SerializeFullCHLO());
  }
}

// Tests that store delivers empty packet list if CHLO arrives firstly.
TEST_P(BufferedPacketStoreTest, DeliverEmptyPackets) {
  QuicConnectionId conn_id = 1;
  IPEndPoint client_address(Loopback4(), 1);
  EXPECT_CALL(*dispatcher_, ShouldCreateOrBufferPacketForConnection(conn_id));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_address))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, conn_id, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  ProcessPacket(client_address, conn_id, true, false, SerializeFullCHLO());
}

// Tests that a retransmitted CHLO arrives after a connection for the
// CHLO has been created.
TEST_P(BufferedPacketStoreTest, ReceiveRetransmittedCHLO) {
  InSequence s;
  IPEndPoint client_address(Loopback4(), 1);
  server_address_ = IPEndPoint(Any4(), 5);
  QuicConnectionId conn_id = 1;
  ProcessPacket(client_address, conn_id, true, false,
                "data packet " + IntToString(2), PACKET_8BYTE_CONNECTION_ID,
                PACKET_6BYTE_PACKET_NUMBER, kDefaultPathId,
                /*packet_number=*/2);

  // When CHLO arrives, a new session should be created, and all packets
  // buffered should be delivered to the session.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_address))
      .Times(1)  // Only triggered by 1st CHLO.
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, conn_id, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(3)  // Triggered by 1 data packet and 2 CHLOs.
      .WillRepeatedly(testing::WithArg<2>(
          Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                               base::Unretained(this), conn_id))));
  ProcessPacket(client_address, conn_id, true, false, SerializeFullCHLO());

  ProcessPacket(client_address, conn_id, true, false, SerializeFullCHLO());
}

// Tests that expiration of a connection add connection id to time wait list.
TEST_P(BufferedPacketStoreTest, ReceiveCHLOAfterExpiration) {
  InSequence s;
  CreateTimeWaitListManager();
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  QuicBufferedPacketStorePeer::set_clock(store, mock_helper_.GetClock());

  IPEndPoint client_address(Loopback4(), 1);
  server_address_ = IPEndPoint(Any4(), 5);
  QuicConnectionId conn_id = 1;
  ProcessPacket(client_address, conn_id, true, false,
                "data packet " + IntToString(2), PACKET_8BYTE_CONNECTION_ID,
                PACKET_6BYTE_PACKET_NUMBER, kDefaultPathId,
                /*packet_number=*/2);

  mock_helper_.AdvanceTime(
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs));
  QuicAlarm* alarm = QuicBufferedPacketStorePeer::expiration_alarm(store);
  // Cancel alarm as if it had been fired.
  alarm->Cancel();
  store->OnExpirationTimeout();
  // New arrived CHLO will be dropped because this connection is in time wait
  // list.
  ASSERT_TRUE(time_wait_list_manager_->IsConnectionIdInTimeWait(conn_id));
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, conn_id, _, _));
  ProcessPacket(client_address, conn_id, true, false, SerializeFullCHLO());
}

TEST_P(BufferedPacketStoreTest, ProcessCHLOsUptoLimitAndBufferTheRest) {
  FLAGS_quic_limit_num_new_sessions_per_epoll_loop = true;
  // Process more than (|kMaxNumSessionsToCreate| +
  // |kDefaultMaxConnectionsInStore|) CHLOs,
  // the first |kMaxNumSessionsToCreate| should create connections immediately,
  // the next |kDefaultMaxConnectionsInStore| should be buffered,
  // the rest should be dropped.
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  const size_t kNumCHLOs =
      kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore + 1;
  for (size_t conn_id = 1; conn_id <= kNumCHLOs; ++conn_id) {
    if (FLAGS_quic_create_session_after_insertion) {
      EXPECT_CALL(*dispatcher_,
                  ShouldCreateOrBufferPacketForConnection(conn_id));
    }
    if (!FLAGS_quic_create_session_after_insertion && conn_id < kNumCHLOs) {
      // Except the last connection, all connections for previous CHLOs should
      // be regarded as newly added.
      EXPECT_CALL(*dispatcher_,
                  ShouldCreateOrBufferPacketForConnection(conn_id));
    }
    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_addr_))
          .WillOnce(testing::Return(CreateSession(
              dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
              &mock_alarm_factory_, &crypto_config_,
              QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillOnce(testing::WithArg<2>(
              Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                   base::Unretained(this), conn_id))));
    }
    ProcessPacket(client_addr_, conn_id, true, false, SerializeFullCHLO());
    if (conn_id <= kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore &&
        conn_id > kMaxNumSessionsToCreate) {
      EXPECT_TRUE(store->HasChloForConnection(conn_id));
    } else {
      // First |kMaxNumSessionsToCreate| CHLOs should be passed to new
      // connections immediately, and the last CHLO should be dropped as the
      // store is full.
      EXPECT_FALSE(store->HasChloForConnection(conn_id));
    }
  }

  // Graduately consume buffered CHLOs. The buffered connections should be
  // created but the dropped one shouldn't.
  for (size_t conn_id = kMaxNumSessionsToCreate + 1;
       conn_id <= kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore;
       ++conn_id) {
    EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_addr_))
        .WillOnce(testing::Return(CreateSession(
            dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
            &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(testing::WithArg<2>(
            Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                 base::Unretained(this), conn_id))));
  }
  EXPECT_CALL(*dispatcher_, CreateQuicSession(kNumCHLOs, client_addr_))
      .Times(0);

  while (store->HasChlosBuffered()) {
    dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
  }

  EXPECT_EQ(static_cast<size_t>(kMaxNumSessionsToCreate) +
                kDefaultMaxConnectionsInStore,
            session1_->connection_id());
}

// Duplicated CHLO shouldn't be buffered.
TEST_P(BufferedPacketStoreTest, BufferDuplicatedCHLO) {
  FLAGS_quic_limit_num_new_sessions_per_epoll_loop = true;
  for (QuicConnectionId conn_id = 1; conn_id <= kMaxNumSessionsToCreate + 1;
       ++conn_id) {
    // Last CHLO will be buffered. Others will create connection right away.
    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_addr_))
          .WillOnce(testing::Return(CreateSession(
              dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
              &mock_alarm_factory_, &crypto_config_,
              QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillOnce(testing::WithArg<2>(
              Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                   base::Unretained(this), conn_id))));
    }
    ProcessPacket(client_addr_, conn_id, true, false, SerializeFullCHLO());
  }
  // Retransmit CHLO on last connection should be dropped.
  QuicConnectionId last_connection = kMaxNumSessionsToCreate + 1;
  ProcessPacket(client_addr_, last_connection, true, false,
                SerializeFullCHLO());

  size_t packets_buffered = 2;
  if (!FLAGS_quic_buffer_packets_after_chlo) {
    // The packet sent above is dropped when flag is off.
    packets_buffered = 1;
  }

  // Reset counter and process buffered CHLO.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(last_connection, client_addr_))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, last_connection, client_addr_,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  // Only one packet(CHLO) should be process.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(packets_buffered)
      .WillRepeatedly(testing::WithArg<2>(
          Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                               base::Unretained(this), last_connection))));
  dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
}

TEST_P(BufferedPacketStoreTest, BufferNonChloPacketsUptoLimitWithChloBuffered) {
  FLAGS_quic_limit_num_new_sessions_per_epoll_loop = true;
  QuicConnectionId last_connection_id = kMaxNumSessionsToCreate + 1;
  for (QuicConnectionId conn_id = 1; conn_id <= last_connection_id; ++conn_id) {
    // Last CHLO will be buffered. Others will create connection right away.
    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_addr_))
          .WillOnce(testing::Return(CreateSession(
              dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
              &mock_alarm_factory_, &crypto_config_,
              QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillOnce(testing::WithArg<2>(
              Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                   base::Unretained(this), conn_id))));
    }
    ProcessPacket(client_addr_, conn_id, true, false, SerializeFullCHLO());
  }

  // Process another |kDefaultMaxUndecryptablePackets| + 1 data packets. The
  // last one should be dropped.
  for (QuicPacketNumber packet_number = 2;
       packet_number <= kDefaultMaxUndecryptablePackets + 2; ++packet_number) {
    ProcessPacket(client_addr_, last_connection_id, true, false, "data packet");
  }

  // Reset counter and process buffered CHLO.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(last_connection_id, client_addr_))
      .WillOnce(testing::Return(CreateSession(
          dispatcher_.get(), config_, last_connection_id, client_addr_,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
  // Only CHLO and following |kDefaultMaxUndecryptablePackets| data packets
  // should be process.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(kDefaultMaxUndecryptablePackets + 1)
      .WillRepeatedly(testing::WithArg<2>(
          Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                               base::Unretained(this), last_connection_id))));
  dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
}

// Tests that when dispatcher's packet buffer is full, a CHLO on connection
// which doesn't have buffered CHLO should be buffered.
TEST_P(BufferedPacketStoreTest, ReceiveCHLOForBufferedConnection) {
  FLAGS_quic_limit_num_new_sessions_per_epoll_loop = true;
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());

  QuicConnectionId conn_id = 1;
  ProcessPacket(client_addr_, conn_id, true, false, "data packet",
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                kDefaultPathId,
                /*packet_number=*/1);
  // Fill packet buffer to full with CHLOs on other connections. Need to feed
  // extra CHLOs because the first |kMaxNumSessionsToCreate| are going to create
  // session directly.
  for (conn_id = 2;
       conn_id <= kDefaultMaxConnectionsInStore + kMaxNumSessionsToCreate;
       ++conn_id) {
    if (conn_id <= kMaxNumSessionsToCreate + 1) {
      EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, client_addr_))
          .WillOnce(testing::Return(CreateSession(
              dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
              &mock_alarm_factory_, &crypto_config_,
              QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_)));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillOnce(testing::WithArg<2>(
              Invoke(CreateFunctor(&QuicDispatcherTest::ValidatePacket,
                                   base::Unretained(this), conn_id))));
    }
    ProcessPacket(client_addr_, conn_id, true, false, SerializeFullCHLO());
  }
  EXPECT_FALSE(store->HasChloForConnection(/*connection_id=*/1));

  // CHLO on connection 1 should still be buffered.
  ProcessPacket(client_addr_, /*connection_id=*/1, true, false,
                SerializeFullCHLO());
  EXPECT_TRUE(store->HasChloForConnection(/*connection_id=*/1));
}

}  // namespace
}  // namespace test
}  // namespace net
