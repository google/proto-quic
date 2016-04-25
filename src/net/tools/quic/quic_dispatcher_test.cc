// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_dispatcher.h"

#include <memory>
#include <ostream>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_crypto_stream.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/tools/epoll_server/epoll_server.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_packet_writer_wrapper.h"
#include "net/tools/quic/quic_time_wait_list_manager.h"
#include "net/tools/quic/test_tools/mock_quic_time_wait_list_manager.h"
#include "net/tools/quic/test_tools/quic_dispatcher_peer.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using net::EpollServer;
using net::test::ConstructEncryptedPacket;
using net::test::CryptoTestUtils;
using net::test::MockConnection;
using net::test::MockConnectionHelper;
using net::test::ValueRestore;
using std::string;
using std::vector;
using testing::DoAll;
using testing::InSequence;
using testing::Invoke;
using testing::WithoutArgs;
using testing::_;

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
                              crypto_config,
                              compressed_certs_cache),
        crypto_stream_(QuicServerSessionBase::GetCryptoStream()) {}
  ~TestQuicSpdyServerSession() override{};

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
        FLAGS_enable_quic_stateless_reject_support, this);
  }

  void SetCryptoStream(QuicCryptoServerStream* crypto_stream) {
    crypto_stream_ = crypto_stream;
  }

  QuicCryptoServerStreamBase* GetCryptoStream() override {
    return crypto_stream_;
  }

 private:
  QuicCryptoServerStreamBase* crypto_stream_;

  DISALLOW_COPY_AND_ASSIGN(TestQuicSpdyServerSession);
};

class TestDispatcher : public QuicDispatcher {
 public:
  TestDispatcher(const QuicConfig& config,
                 const QuicCryptoServerConfig* crypto_config,
                 EpollServer* eps)
      : QuicDispatcher(
            config,
            crypto_config,
            QuicSupportedVersions(),
            std::unique_ptr<QuicEpollConnectionHelper>(
                new QuicEpollConnectionHelper(eps, QuicAllocator::BUFFER_POOL)),
            std::unique_ptr<QuicEpollAlarmFactory>(
                new QuicEpollAlarmFactory(eps))) {}

  MOCK_METHOD2(CreateQuicSession,
               QuicServerSessionBase*(QuicConnectionId connection_id,
                                      const IPEndPoint& client_address));

  using QuicDispatcher::current_server_address;
  using QuicDispatcher::current_client_address;
};

// A Connection class which unregisters the session from the dispatcher when
// sending connection close.
// It'd be slightly more realistic to do this from the Session but it would
// involve a lot more mocking.
class MockServerConnection : public MockConnection {
 public:
  MockServerConnection(QuicConnectionId connection_id,
                       MockConnectionHelper* helper,
                       MockAlarmFactory* alarm_factory,
                       QuicDispatcher* dispatcher)
      : MockConnection(connection_id,
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

QuicServerSessionBase* CreateSession(
    QuicDispatcher* dispatcher,
    const QuicConfig& config,
    QuicConnectionId connection_id,
    const IPEndPoint& client_address,
    MockConnectionHelper* helper,
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
  EXPECT_CALL(*reinterpret_cast<MockConnection*>((*session)->connection()),
              ProcessUdpPacket(_, client_address, _));

  return *session;
}

class QuicDispatcherTest : public ::testing::Test {
 public:
  QuicDispatcherTest()
      : helper_(&eps_, QuicAllocator::BUFFER_POOL),
        alarm_factory_(&eps_),
        crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       CryptoTestUtils::ProofSourceForTesting()),
        dispatcher_(config_, &crypto_config_, &eps_),
        time_wait_list_manager_(nullptr),
        session1_(nullptr),
        session2_(nullptr) {
    dispatcher_.InitializeWithWriter(new QuicDefaultPacketWriter(1));
  }

  ~QuicDispatcherTest() override {}

  MockConnection* connection1() {
    return reinterpret_cast<MockConnection*>(session1_->connection());
  }

  MockConnection* connection2() {
    return reinterpret_cast<MockConnection*>(session2_->connection());
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
                  QuicSupportedVersions().front(), data, connection_id_length,
                  packet_number_length, packet_number);
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

    data_ = string(packet->data(), packet->length());
    dispatcher_.ProcessPacket(server_address_, client_address,
                              *received_packet);
  }

  void ValidatePacket(const QuicEncryptedPacket& packet) {
    EXPECT_EQ(data_.length(), packet.AsStringPiece().length());
    EXPECT_EQ(data_, packet.AsStringPiece());
  }

  void CreateTimeWaitListManager() {
    time_wait_list_manager_ =
        new MockTimeWaitListManager(QuicDispatcherPeer::GetWriter(&dispatcher_),
                                    &dispatcher_, &helper_, &alarm_factory_);
    // dispatcher_ takes the ownership of time_wait_list_manager_.
    QuicDispatcherPeer::SetTimeWaitListManager(&dispatcher_,
                                               time_wait_list_manager_);
  }

  EpollServer eps_;
  QuicEpollConnectionHelper helper_;
  MockConnectionHelper mock_helper_;
  QuicEpollAlarmFactory alarm_factory_;
  MockAlarmFactory mock_alarm_factory_;
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  IPEndPoint server_address_;
  TestDispatcher dispatcher_;
  MockTimeWaitListManager* time_wait_list_manager_;
  TestQuicSpdyServerSession* session1_;
  TestQuicSpdyServerSession* session2_;
  string data_;
};

TEST_F(QuicDispatcherTest, ProcessPackets) {
  IPEndPoint client_address(net::test::Loopback4(), 1);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(dispatcher_, CreateQuicSession(1, client_address))
      .WillOnce(testing::Return(CreateSession(
          &dispatcher_, config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(&dispatcher_), &session1_)));
  ProcessPacket(client_address, 1, true, false, "foo");
  EXPECT_EQ(client_address, dispatcher_.current_client_address());
  EXPECT_EQ(server_address_, dispatcher_.current_server_address());

  EXPECT_CALL(dispatcher_, CreateQuicSession(2, client_address))
      .WillOnce(testing::Return(CreateSession(
          &dispatcher_, config_, 2, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(&dispatcher_), &session2_)));
  ProcessPacket(client_address, 2, true, false, "bar");

  EXPECT_CALL(*reinterpret_cast<MockConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(1)
      .WillOnce(testing::WithArgs<2>(
          Invoke(this, &QuicDispatcherTest::ValidatePacket)));
  ProcessPacket(client_address, 1, false, false, "eep");
}

TEST_F(QuicDispatcherTest, StatelessVersionNegotiation) {
  ValueRestore<bool> old_flag(&FLAGS_quic_stateless_version_negotiation, true);
  IPEndPoint client_address(net::test::Loopback4(), 1);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(dispatcher_, CreateQuicSession(1, client_address)).Times(0);
  QuicVersion version = static_cast<QuicVersion>(QuicVersionMin() - 1);
  ProcessPacket(client_address, 1, true, version, "foo",
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, 1);
}

TEST_F(QuicDispatcherTest, StatefulVersionNegotiation) {
  ValueRestore<bool> old_flag(&FLAGS_quic_stateless_version_negotiation, false);
  IPEndPoint client_address(net::test::Loopback4(), 1);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(dispatcher_, CreateQuicSession(1, client_address))
      .WillOnce(testing::Return(CreateSession(
          &dispatcher_, config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(&dispatcher_), &session1_)));
  QuicVersion version = static_cast<QuicVersion>(QuicVersionMin() - 1);
  ProcessPacket(client_address, 1, true, version, "foo",
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER, 1);
}

TEST_F(QuicDispatcherTest, Shutdown) {
  IPEndPoint client_address(net::test::Loopback4(), 1);

  EXPECT_CALL(dispatcher_, CreateQuicSession(_, client_address))
      .WillOnce(testing::Return(CreateSession(
          &dispatcher_, config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(&dispatcher_), &session1_)));

  ProcessPacket(client_address, 1, true, false, "foo");

  EXPECT_CALL(*reinterpret_cast<MockConnection*>(session1_->connection()),
              CloseConnection(QUIC_PEER_GOING_AWAY, _, _));

  dispatcher_.Shutdown();
}

TEST_F(QuicDispatcherTest, TimeWaitListManager) {
  CreateTimeWaitListManager();

  // Create a new session.
  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  EXPECT_CALL(dispatcher_, CreateQuicSession(connection_id, client_address))
      .WillOnce(testing::Return(CreateSession(
          &dispatcher_, config_, connection_id, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(&dispatcher_), &session1_)));
  ProcessPacket(client_address, connection_id, true, false, "foo");

  // Close the connection by sending public reset packet.
  QuicPublicResetPacket packet;
  packet.public_header.connection_id = connection_id;
  packet.public_header.reset_flag = true;
  packet.public_header.version_flag = false;
  packet.rejected_packet_number = 19191;
  packet.nonce_proof = 132232;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      QuicFramer::BuildPublicResetPacket(packet));
  std::unique_ptr<QuicReceivedPacket> received(
      ConstructReceivedPacket(*encrypted, helper_.GetClock()->Now()));
  EXPECT_CALL(*session1_, OnConnectionClosed(QUIC_PUBLIC_RESET, _,
                                             ConnectionCloseSource::FROM_PEER))
      .Times(1)
      .WillOnce(WithoutArgs(Invoke(
          reinterpret_cast<MockServerConnection*>(session1_->connection()),
          &MockServerConnection::UnregisterOnConnectionClosed)));
  EXPECT_CALL(*reinterpret_cast<MockConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(
          Invoke(reinterpret_cast<MockConnection*>(session1_->connection()),
                 &MockConnection::ReallyProcessUdpPacket));
  dispatcher_.ProcessPacket(IPEndPoint(), client_address, *received);
  EXPECT_TRUE(time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id));

  // Dispatcher forwards subsequent packets for this connection_id to the time
  // wait list manager.
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(0);
  ProcessPacket(client_address, connection_id, true, false, "foo");
}

TEST_F(QuicDispatcherTest, NoVersionPacketToTimeWaitListManager) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  // Dispatcher forwards all packets for this connection_id to the time wait
  // list manager.
  EXPECT_CALL(dispatcher_, CreateQuicSession(_, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(1);
  ProcessPacket(client_address, connection_id, false, false, "data");
}

// Enables mocking of the handshake-confirmation for stateless rejects.
class MockQuicCryptoServerStream : public QuicCryptoServerStream {
 public:
  MockQuicCryptoServerStream(const QuicCryptoServerConfig& crypto_config,
                             QuicCompressedCertsCache* compressed_certs_cache,
                             QuicSession* session)
      : QuicCryptoServerStream(&crypto_config,
                               compressed_certs_cache,
                               FLAGS_enable_quic_stateless_reject_support,
                               session) {}
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
    os << "  enable_stateless_rejects_via_flag: "
       << p.enable_stateless_rejects_via_flag << std::endl;
    os << "{ client_supports_statelesss_rejects: "
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
  QuicDispatcherStatelessRejectTest() : crypto_stream1_(nullptr) {}

  ~QuicDispatcherStatelessRejectTest() override {
    if (crypto_stream1_) {
      delete crypto_stream1_;
    }
  }

  // This test setup assumes that all testing will be done using
  // crypto_stream1_.
  void SetUp() override {
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

  // Sets up dispatcher_, sesession1_, and crypto_stream1_ based on
  // the test parameters.
  QuicServerSessionBase* CreateSessionBasedOnTestParams(
      QuicConnectionId connection_id,
      const IPEndPoint& client_address) {
    CreateSession(&dispatcher_, config_, connection_id, client_address,
                  &mock_helper_, &mock_alarm_factory_, &crypto_config_,
                  QuicDispatcherPeer::GetCache(&dispatcher_), &session1_);

    crypto_stream1_ = new MockQuicCryptoServerStream(
        crypto_config_, QuicDispatcherPeer::GetCache(&dispatcher_), session1_);
    session1_->SetCryptoStream(crypto_stream1_);
    crypto_stream1_->set_handshake_confirmed_for_testing(
        GetParam().crypto_handshake_successful);
    crypto_stream1_->SetPeerSupportsStatelessRejects(
        GetParam().client_supports_statelesss_rejects);
    return session1_;
  }

  MockQuicCryptoServerStream* crypto_stream1_;
};

TEST_F(QuicDispatcherTest, ProcessPacketWithZeroPort) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 0);
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  // dispatcher_ should drop this packet.
  EXPECT_CALL(dispatcher_, CreateQuicSession(1, client_address)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(0);
  ProcessPacket(client_address, 1, true, false, "foo");
}

TEST_F(QuicDispatcherTest, OKSeqNoPacketProcessed) {
  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  server_address_ = IPEndPoint(net::test::Any4(), 5);

  EXPECT_CALL(dispatcher_, CreateQuicSession(1, client_address))
      .WillOnce(testing::Return(CreateSession(
          &dispatcher_, config_, 1, client_address, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(&dispatcher_), &session1_)));
  // A packet whose packet number is the largest that is allowed to start a
  // connection.
  ProcessPacket(client_address, connection_id, true, false, "data",
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                kDefaultPathId,
                QuicDispatcher::kMaxReasonableInitialPacketNumber);
  EXPECT_EQ(client_address, dispatcher_.current_client_address());
  EXPECT_EQ(server_address_, dispatcher_.current_server_address());
}

TEST_F(QuicDispatcherTest, TooBigSeqNoPacketToTimeWaitListManager) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  // Dispatcher forwards this packet for this connection_id to the time wait
  // list manager.
  EXPECT_CALL(dispatcher_, CreateQuicSession(_, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(1);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(1);
  // A packet whose packet number is one to large to be allowed to start a
  // connection.
  ProcessPacket(client_address, connection_id, true, false, "data",
                PACKET_8BYTE_CONNECTION_ID, PACKET_6BYTE_PACKET_NUMBER,
                kDefaultPathId,
                QuicDispatcher::kMaxReasonableInitialPacketNumber + 1);
}

INSTANTIATE_TEST_CASE_P(QuicDispatcherStatelessRejectTests,
                        QuicDispatcherStatelessRejectTest,
                        ::testing::ValuesIn(GetStatelessRejectTestParams()));

// Parameterized test for stateless rejects.  Should test all
// combinations of enabling/disabling, reject/no-reject for stateless
// rejects.
TEST_P(QuicDispatcherStatelessRejectTest, ParameterizedBasicTest) {
  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  EXPECT_CALL(dispatcher_, CreateQuicSession(connection_id, client_address))
      .WillOnce(testing::Return(
          CreateSessionBasedOnTestParams(connection_id, client_address)));

  // Process the first packet for the connection.
  ProcessPacket(client_address, connection_id, true, false, "foo");
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
    EXPECT_CALL(*reinterpret_cast<MockConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .Times(1)
        .WillOnce(testing::WithArgs<2>(
            Invoke(this, &QuicDispatcherTest::ValidatePacket)));
  }
  ProcessPacket(client_address, connection_id, true, false, "foo");
}

// Verify the stopgap test: Packets with truncated connection IDs should be
// dropped.
class QuicDispatcherTestStrayPacketConnectionId
    : public QuicDispatcherTest,
      public ::testing::WithParamInterface<QuicConnectionIdLength> {};

// Packets with truncated connection IDs should be dropped.
TEST_P(QuicDispatcherTestStrayPacketConnectionId,
       StrayPacketTruncatedConnectionId) {
  const QuicConnectionIdLength connection_id_length = GetParam();

  CreateTimeWaitListManager();

  IPEndPoint client_address(net::test::Loopback4(), 1);
  QuicConnectionId connection_id = 1;
  // Dispatcher drops this packet.
  EXPECT_CALL(dispatcher_, CreateQuicSession(_, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_,
              ProcessPacket(_, _, connection_id, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _, _, _))
      .Times(0);
  ProcessPacket(client_address, connection_id, true, false, "data",
                connection_id_length, PACKET_6BYTE_PACKET_NUMBER);
}

INSTANTIATE_TEST_CASE_P(ConnectionIdLength,
                        QuicDispatcherTestStrayPacketConnectionId,
                        ::testing::Values(PACKET_0BYTE_CONNECTION_ID,
                                          PACKET_1BYTE_CONNECTION_ID,
                                          PACKET_4BYTE_CONNECTION_ID));

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
    writer_ = new BlockingWriter;
    QuicDispatcherPeer::UseWriter(&dispatcher_, writer_);

    IPEndPoint client_address(net::test::Loopback4(), 1);

    EXPECT_CALL(dispatcher_, CreateQuicSession(_, client_address))
        .WillOnce(testing::Return(CreateSession(
            &dispatcher_, config_, 1, client_address, &helper_, &alarm_factory_,
            &crypto_config_, QuicDispatcherPeer::GetCache(&dispatcher_),
            &session1_)));
    ProcessPacket(client_address, 1, true, false, "foo");

    EXPECT_CALL(dispatcher_, CreateQuicSession(_, client_address))
        .WillOnce(testing::Return(CreateSession(
            &dispatcher_, config_, 2, client_address, &helper_, &alarm_factory_,
            &crypto_config_, QuicDispatcherPeer::GetCache(&dispatcher_),
            &session2_)));
    ProcessPacket(client_address, 2, true, false, "bar");

    blocked_list_ = QuicDispatcherPeer::GetWriteBlockedList(&dispatcher_);
  }

  void TearDown() override {
    EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
    EXPECT_CALL(*connection2(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
    dispatcher_.Shutdown();
  }

  void SetBlocked() { writer_->write_blocked_ = true; }

  void BlockConnection2() {
    writer_->write_blocked_ = true;
    dispatcher_.OnWriteBlocked(connection2());
  }

 protected:
  MockConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  BlockingWriter* writer_;
  QuicDispatcher::WriteBlockedList* blocked_list_;
};

TEST_F(QuicDispatcherWriteBlockedListTest, BasicOnCanWrite) {
  // No OnCanWrite calls because no connections are blocked.
  dispatcher_.OnCanWrite();

  // Register connection 1 for events, and make sure it's notified.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite());
  dispatcher_.OnCanWrite();

  // It should get only one notification.
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_.OnCanWrite();
  EXPECT_FALSE(dispatcher_.HasPendingWrites());
}

TEST_F(QuicDispatcherWriteBlockedListTest, OnCanWriteOrder) {
  // Make sure we handle events in order.
  InSequence s;
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_.OnCanWrite();

  // Check the other ordering.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection2());
  dispatcher_.OnWriteBlocked(connection1());
  EXPECT_CALL(*connection2(), OnCanWrite());
  EXPECT_CALL(*connection1(), OnCanWrite());
  dispatcher_.OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, OnCanWriteRemove) {
  // Add and remove one connction.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  blocked_list_->erase(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_.OnCanWrite();

  // Add and remove one connction and make sure it doesn't affect others.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection2());
  blocked_list_->erase(connection1());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_.OnCanWrite();

  // Add it, remove it, and add it back and make sure things are OK.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  blocked_list_->erase(connection1());
  dispatcher_.OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(1);
  dispatcher_.OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, DoubleAdd) {
  // Make sure a double add does not necessitate a double remove.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection1());
  blocked_list_->erase(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_.OnCanWrite();

  // Make sure a double add does not result in two OnCanWrite calls.
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(1);
  dispatcher_.OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, OnCanWriteHandleBlock) {
  // Finally make sure if we write block on a write call, we stop calling.
  InSequence s;
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite())
      .WillOnce(Invoke(this, &QuicDispatcherWriteBlockedListTest::SetBlocked));
  EXPECT_CALL(*connection2(), OnCanWrite()).Times(0);
  dispatcher_.OnCanWrite();

  // And we'll resume where we left off when we get another call.
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_.OnCanWrite();
}

TEST_F(QuicDispatcherWriteBlockedListTest, LimitedWrites) {
  // Make sure we call both writers.  The first will register for more writing
  // but should not be immediately called due to limits.
  InSequence s;
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite())
      .WillOnce(
          Invoke(this, &QuicDispatcherWriteBlockedListTest::BlockConnection2));
  dispatcher_.OnCanWrite();
  EXPECT_TRUE(dispatcher_.HasPendingWrites());

  // Now call OnCanWrite again, and connection1 should get its second chance
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_.OnCanWrite();
  EXPECT_FALSE(dispatcher_.HasPendingWrites());
}

TEST_F(QuicDispatcherWriteBlockedListTest, TestWriteLimits) {
  // Finally make sure if we write block on a write call, we stop calling.
  InSequence s;
  SetBlocked();
  dispatcher_.OnWriteBlocked(connection1());
  dispatcher_.OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite())
      .WillOnce(Invoke(this, &QuicDispatcherWriteBlockedListTest::SetBlocked));
  EXPECT_CALL(*connection2(), OnCanWrite()).Times(0);
  dispatcher_.OnCanWrite();
  EXPECT_TRUE(dispatcher_.HasPendingWrites());

  // And we'll resume where we left off when we get another call.
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_.OnCanWrite();
  EXPECT_FALSE(dispatcher_.HasPendingWrites());
}

}  // namespace
}  // namespace test
}  // namespace net
