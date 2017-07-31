// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quartc/quartc_session.h"

#include "net/quic/core/crypto/crypto_server_config_protobuf.h"
#include "net/quic/core/quic_simple_buffer_allocator.h"
#include "net/quic/core/quic_types.h"
#include "net/quic/quartc/quartc_factory.h"
#include "net/quic/quartc/quartc_factory_interface.h"
#include "net/quic/quartc/quartc_packet_writer.h"
#include "net/quic/quartc/quartc_stream_interface.h"
#include "net/quic/test_tools/mock_clock.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {

namespace {

static const char kExporterLabel[] = "label";
static const uint8_t kExporterContext[] = "context";
static const size_t kExporterContextLen = sizeof(kExporterContext);
static const size_t kOutputKeyLength = 20;
static QuartcStreamInterface::WriteParameters kDefaultWriteParam;
static QuartcSessionInterface::OutgoingStreamParameters kDefaultStreamParam;
static QuicByteCount kDefaultMaxPacketSize = 1200;

// Single-threaded scheduled task runner based on a MockClock.
//
// Simulates asynchronous execution on a single thread by holding scheduled
// tasks until Run() is called. Performs no synchronization, assumes that
// Schedule() and Run() are called on the same thread.
class FakeTaskRunner : public QuartcTaskRunnerInterface {
 public:
  explicit FakeTaskRunner(MockClock* clock)
      : tasks_([this](const TaskType& l, const TaskType& r) {
          // Items at a later time should run after items at an earlier time.
          // Priority queue comparisons should return true if l appears after r.
          return l->time() > r->time();
        }),
        clock_(clock) {}

  ~FakeTaskRunner() override {}

  // Runs all tasks scheduled in the next total_ms milliseconds.  Advances the
  // clock by total_ms.  Runs tasks in time order.  Executes tasks scheduled at
  // the same in an arbitrary order.
  void Run(uint32_t total_ms) {
    for (uint32_t i = 0; i < total_ms; ++i) {
      while (!tasks_.empty() && tasks_.top()->time() <= clock_->Now()) {
        tasks_.top()->Run();
        tasks_.pop();
      }
      clock_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
    }
  }

 private:
  class InnerTask {
   public:
    InnerTask(std::function<void()> task, QuicTime time)
        : task_(std::move(task)), time_(time) {}

    void Cancel() { cancelled_ = true; }

    void Run() {
      if (!cancelled_) {
        task_();
      }
    }

    QuicTime time() const { return time_; }

   private:
    bool cancelled_ = false;
    std::function<void()> task_;
    QuicTime time_;
  };

 public:
  // Hook for cancelling a scheduled task.
  class ScheduledTask : public QuartcTaskRunnerInterface::ScheduledTask {
   public:
    explicit ScheduledTask(std::shared_ptr<InnerTask> inner)
        : inner_(std::move(inner)) {}

    // Cancel if the caller deletes the ScheduledTask.  This behavior is
    // consistent with the actual task runner Quartc uses.
    ~ScheduledTask() override { Cancel(); }

    // ScheduledTask implementation.
    void Cancel() override { inner_->Cancel(); }

   private:
    std::shared_ptr<InnerTask> inner_;
  };

  // See QuartcTaskRunnerInterface.
  std::unique_ptr<QuartcTaskRunnerInterface::ScheduledTask> Schedule(
      Task* task,
      uint64_t delay_ms) override {
    auto inner = std::shared_ptr<InnerTask>(new InnerTask(
        [task] { task->Run(); },
        clock_->Now() + QuicTime::Delta::FromMilliseconds(delay_ms)));
    tasks_.push(inner);
    return std::unique_ptr<QuartcTaskRunnerInterface::ScheduledTask>(
        new ScheduledTask(inner));
  }

  // Schedules a function to run immediately.
  void Schedule(std::function<void()> task) {
    tasks_.push(std::shared_ptr<InnerTask>(
        new InnerTask(std::move(task), clock_->Now())));
  }

 private:
  // InnerTasks are shared by the queue and ScheduledTask (which hooks into it
  // to implement Cancel()).
  using TaskType = std::shared_ptr<InnerTask>;
  std::priority_queue<TaskType,
                      std::vector<TaskType>,
                      std::function<bool(const TaskType&, const TaskType&)>>
      tasks_;
  MockClock* clock_;
};

// QuartcClock that wraps a MockClock.
//
// This is silly because Quartc wraps it as a QuicClock, and MockClock is
// already a QuicClock.  But we don't have much choice.  We need to pass a
// QuartcClockInterface into the Quartc wrappers.
class MockQuartcClock : public QuartcClockInterface {
 public:
  explicit MockQuartcClock(MockClock* clock) : clock_(clock) {}

  int64_t NowMicroseconds() override {
    return clock_->WallNow().ToUNIXMicroseconds();
  }

 private:
  MockClock* clock_;
};

// Used by QuicCryptoServerConfig to provide server credentials, returning a
// canned response equal to |success|.
class FakeProofSource : public ProofSource {
 public:
  explicit FakeProofSource(bool success) : success_(success) {}

  // ProofSource override.
  void GetProof(const QuicSocketAddress& server_ip,
                const string& hostname,
                const string& server_config,
                QuicVersion quic_version,
                QuicStringPiece chlo_hash,
                const QuicTagVector& connection_options,
                std::unique_ptr<Callback> callback) override {
    QuicReferenceCountedPointer<ProofSource::Chain> chain;
    QuicCryptoProof proof;
    if (success_) {
      std::vector<string> certs;
      certs.push_back("Required to establish handshake");
      chain = new ProofSource::Chain(certs);
      proof.signature = "Signature";
      proof.leaf_cert_scts = "Time";
    }
    callback->Run(success_, chain, proof, nullptr /* details */);
  }

 private:
  // Whether or not obtaining proof source succeeds.
  bool success_;
};

// Used by QuicCryptoClientConfig to verify server credentials, returning a
// canned response of QUIC_SUCCESS if |success| is true.
class FakeProofVerifier : public ProofVerifier {
 public:
  explicit FakeProofVerifier(bool success) : success_(success) {}

  // ProofVerifier override
  QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      QuicVersion quic_version,
      QuicStringPiece chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<ProofVerifyDetails>* verify_details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    return success_ ? QUIC_SUCCESS : QUIC_FAILURE;
  }

  QuicAsyncStatus VerifyCertChain(
      const string& hostname,
      const std::vector<string>& certs,
      const ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<ProofVerifyDetails>* details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    LOG(INFO) << "VerifyProof() ignoring credentials and returning success";
    return success_ ? QUIC_SUCCESS : QUIC_FAILURE;
  }

 private:
  // Whether or not proof verification succeeds.
  bool success_;
};

// Used by the FakeTransportChannel.
class FakeTransportChannelObserver {
 public:
  virtual ~FakeTransportChannelObserver() {}

  // Called when the other peer is trying to send message.
  virtual void OnTransportChannelReadPacket(const string& data) = 0;
};

// Simulate the P2P communication transport. Used by the
// QuartcSessionInterface::Transport.
class FakeTransportChannel {
 public:
  explicit FakeTransportChannel(FakeTaskRunner* task_runner, MockClock* clock)
      : task_runner_(task_runner), clock_(clock) {}

  void SetDestination(FakeTransportChannel* dest) {
    if (!dest_) {
      dest_ = dest;
      dest_->SetDestination(this);
    }
  }

  int SendPacket(const char* data, size_t len) {
    // If the destination is not set.
    if (!dest_) {
      return -1;
    }
    // Advance the time 10us to ensure the RTT is never 0ms.
    clock_->AdvanceTime(QuicTime::Delta::FromMicroseconds(10));
    if (async_ && task_runner_) {
      string packet(data, len);
      task_runner_->Schedule([this, packet] { send(packet); });
    } else {
      send(string(data, len));
    }
    return static_cast<int>(len);
  }

  void send(const string& data) {
    DCHECK(dest_);
    DCHECK(dest_->observer());
    dest_->observer()->OnTransportChannelReadPacket(data);
  }

  FakeTransportChannelObserver* observer() { return observer_; }

  void SetObserver(FakeTransportChannelObserver* observer) {
    observer_ = observer;
  }

  void SetAsync(bool async) { async_ = async; }

 private:
  // The writing destination of this channel.
  FakeTransportChannel* dest_ = nullptr;
  // The observer of this channel. Called when the received the data.
  FakeTransportChannelObserver* observer_ = nullptr;
  // If async, will send packets by running asynchronous tasks.
  bool async_ = false;
  // Used to send data asynchronously.
  FakeTaskRunner* task_runner_;
  // The test clock.  Used to ensure the RTT is not 0.
  MockClock* clock_;
};

// Used by the QuartcPacketWriter.
class FakeTransport : public QuartcSessionInterface::PacketTransport {
 public:
  explicit FakeTransport(FakeTransportChannel* channel) : channel_(channel) {}

  bool CanWrite() override { return true; }

  int Write(const char* buffer, size_t buf_len) override {
    DCHECK(channel_);
    return channel_->SendPacket(buffer, buf_len);
  }

 private:
  FakeTransportChannel* channel_;
};

class FakeQuartcSessionDelegate : public QuartcSessionInterface::Delegate {
 public:
  explicit FakeQuartcSessionDelegate(
      QuartcStreamInterface::Delegate* stream_delegate)
      : stream_delegate_(stream_delegate) {}
  // Called when peers have established forward-secure encryption
  void OnCryptoHandshakeComplete() override {
    LOG(INFO) << "Crypto handshake complete!";
  }
  // Called when connection closes locally, or remotely by peer.
  void OnConnectionClosed(int error_code, bool from_remote) override {
    connected_ = false;
  }
  // Called when an incoming QUIC stream is created.
  void OnIncomingStream(QuartcStreamInterface* quartc_stream) override {
    last_incoming_stream_ = quartc_stream;
    last_incoming_stream_->SetDelegate(stream_delegate_);
  }

  QuartcStreamInterface* incoming_stream() { return last_incoming_stream_; }

  bool connected() { return connected_; }

 private:
  QuartcStreamInterface* last_incoming_stream_;
  bool connected_ = true;
  QuartcStream::Delegate* stream_delegate_;
};

class FakeQuartcStreamDelegate : public QuartcStreamInterface::Delegate {
 public:
  void OnReceived(QuartcStreamInterface* stream,
                  const char* data,
                  size_t size) override {
    last_received_data_ = string(data, size);
  }

  void OnClose(QuartcStreamInterface* stream) override {}

  void OnCanWrite(QuartcStreamInterface* stream) override {}

  string data() { return last_received_data_; }

 private:
  string last_received_data_;
};

class QuartcSessionForTest : public QuartcSession,
                             public FakeTransportChannelObserver {
 public:
  QuartcSessionForTest(std::unique_ptr<QuicConnection> connection,
                       const QuicConfig& config,
                       const string& remote_fingerprint_value,
                       Perspective perspective,
                       QuicConnectionHelperInterface* helper,
                       QuicClock* clock)
      : QuartcSession(std::move(connection),
                      config,
                      remote_fingerprint_value,
                      perspective,
                      helper,
                      clock) {
    stream_delegate_.reset(new FakeQuartcStreamDelegate);
    session_delegate_.reset(
        new FakeQuartcSessionDelegate(stream_delegate_.get()));

    SetDelegate(session_delegate_.get());
  }

  // QuartcPacketWriter override.
  void OnTransportChannelReadPacket(const string& data) override {
    OnTransportReceived(data.c_str(), data.length());
  }

  string data() { return stream_delegate_->data(); }

  bool has_data() { return !data().empty(); }

  FakeQuartcSessionDelegate* session_delegate() {
    return session_delegate_.get();
  }

  FakeQuartcStreamDelegate* stream_delegate() { return stream_delegate_.get(); }

 private:
  std::unique_ptr<FakeQuartcStreamDelegate> stream_delegate_;
  std::unique_ptr<FakeQuartcSessionDelegate> session_delegate_;
};

class QuartcSessionTest : public ::testing::Test,
                          public QuicConnectionHelperInterface {
 public:
  ~QuartcSessionTest() override {}

  void Init() {
    // Quic crashes if packets are sent at time 0, and the clock defaults to 0.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    client_channel_.reset(new FakeTransportChannel(&task_runner_, &clock_));
    server_channel_.reset(new FakeTransportChannel(&task_runner_, &clock_));
    // Make the channel asynchronous so that two peer will not keep calling each
    // other when they exchange information.
    client_channel_->SetAsync(true);
    client_channel_->SetDestination(server_channel_.get());

    client_transport_.reset(new FakeTransport(client_channel_.get()));
    server_transport_.reset(new FakeTransport(server_channel_.get()));

    client_writer_.reset(
        new QuartcPacketWriter(client_transport_.get(), kDefaultMaxPacketSize));
    server_writer_.reset(
        new QuartcPacketWriter(server_transport_.get(), kDefaultMaxPacketSize));
  }

  // The parameters are used to control whether the handshake will success or
  // not.
  void CreateClientAndServerSessions(bool client_handshake_success = true,
                                     bool server_handshake_success = true) {
    Init();
    client_peer_ = CreateSession(Perspective::IS_CLIENT);
    server_peer_ = CreateSession(Perspective::IS_SERVER);

    client_channel_->SetObserver(client_peer_.get());
    server_channel_->SetObserver(server_peer_.get());

    client_peer_->SetClientCryptoConfig(
        new QuicCryptoClientConfig(std::unique_ptr<ProofVerifier>(
            new FakeProofVerifier(client_handshake_success))));

    QuicCryptoServerConfig* server_config = new QuicCryptoServerConfig(
        "TESTING", QuicRandom::GetInstance(),
        std::unique_ptr<FakeProofSource>(
            new FakeProofSource(server_handshake_success)));
    // Provide server with serialized config string to prove ownership.
    QuicCryptoServerConfig::ConfigOptions options;
    std::unique_ptr<QuicServerConfigProtobuf> primary_config(
        server_config->GenerateConfig(QuicRandom::GetInstance(), &clock_,
                                      options));
    std::unique_ptr<CryptoHandshakeMessage> message(
        server_config->AddConfig(std::move(primary_config), clock_.WallNow()));

    server_peer_->SetServerCryptoConfig(server_config);
  }

  std::unique_ptr<QuartcSessionForTest> CreateSession(Perspective perspective) {
    std::unique_ptr<QuicConnection> quic_connection =
        CreateConnection(perspective);
    string remote_fingerprint_value = "value";
    QuicConfig config;
    return std::unique_ptr<QuartcSessionForTest>(new QuartcSessionForTest(
        std::move(quic_connection), config, remote_fingerprint_value,
        perspective, this, &clock_));
  }

  std::unique_ptr<QuicConnection> CreateConnection(Perspective perspective) {
    QuartcPacketWriter* writer = perspective == Perspective::IS_CLIENT
                                     ? client_writer_.get()
                                     : server_writer_.get();
    QuicIpAddress ip;
    ip.FromString("0.0.0.0");
    bool owns_writer = false;
    if (!alarm_factory_) {
      // QuartcFactory is only used as an alarm factory.
      QuartcFactoryConfig config;
      config.clock = &quartc_clock_;
      config.task_runner = &task_runner_;
      alarm_factory_.reset(new QuartcFactory(config));
    }
    return std::unique_ptr<QuicConnection>(new QuicConnection(
        0, QuicSocketAddress(ip, 0), this /*QuicConnectionHelperInterface*/,
        alarm_factory_.get(), writer, owns_writer, perspective,
        AllSupportedVersions()));
  }

  // Runs all tasks scheduled in the next 200 ms.
  void RunTasks() { task_runner_.Run(200); }

  void StartHandshake() {
    server_peer_->StartCryptoHandshake();
    client_peer_->StartCryptoHandshake();
    RunTasks();
  }

  // Test handshake establishment and sending/receiving of data for two
  // directions.
  void TestStreamConnection() {
    ASSERT_TRUE(server_peer_->IsCryptoHandshakeConfirmed());
    ASSERT_TRUE(client_peer_->IsCryptoHandshakeConfirmed());
    ASSERT_TRUE(server_peer_->IsEncryptionEstablished());
    ASSERT_TRUE(client_peer_->IsEncryptionEstablished());

    uint8_t server_key[kOutputKeyLength];
    uint8_t client_key[kOutputKeyLength];
    bool use_context = true;
    bool server_success = server_peer_->ExportKeyingMaterial(
        kExporterLabel, kExporterContext, kExporterContextLen, use_context,
        server_key, kOutputKeyLength);
    ASSERT_TRUE(server_success);
    bool client_success = client_peer_->ExportKeyingMaterial(
        kExporterLabel, kExporterContext, kExporterContextLen, use_context,
        client_key, kOutputKeyLength);
    ASSERT_TRUE(client_success);
    EXPECT_EQ(0, memcmp(server_key, client_key, sizeof(server_key)));

    // Now we can establish encrypted outgoing stream.
    QuartcStreamInterface* outgoing_stream =
        server_peer_->CreateOutgoingStream(kDefaultStreamParam);
    ASSERT_NE(nullptr, outgoing_stream);
    EXPECT_TRUE(server_peer_->HasOpenDynamicStreams());

    outgoing_stream->SetDelegate(server_peer_->stream_delegate());

    // Send a test message from peer 1 to peer 2.
    const char kTestMessage[] = "Hello";
    outgoing_stream->Write(kTestMessage, strlen(kTestMessage),
                           kDefaultWriteParam);
    RunTasks();

    // Wait for peer 2 to receive messages.
    ASSERT_TRUE(client_peer_->has_data());

    QuartcStreamInterface* incoming =
        client_peer_->session_delegate()->incoming_stream();
    ASSERT_TRUE(incoming);
    EXPECT_TRUE(client_peer_->HasOpenDynamicStreams());

    EXPECT_EQ(client_peer_->data(), kTestMessage);
    // Send a test message from peer 2 to peer 1.
    const char kTestResponse[] = "Response";
    incoming->Write(kTestResponse, strlen(kTestResponse), kDefaultWriteParam);
    RunTasks();
    // Wait for peer 1 to receive messages.
    ASSERT_TRUE(server_peer_->has_data());

    EXPECT_EQ(server_peer_->data(), kTestResponse);
  }

  // Test that client and server are not connected after handshake failure.
  void TestDisconnectAfterFailedHandshake() {
    EXPECT_TRUE(!client_peer_->session_delegate()->connected());
    EXPECT_TRUE(!server_peer_->session_delegate()->connected());

    EXPECT_FALSE(client_peer_->IsEncryptionEstablished());
    EXPECT_FALSE(client_peer_->IsCryptoHandshakeConfirmed());

    EXPECT_FALSE(server_peer_->IsEncryptionEstablished());
    EXPECT_FALSE(server_peer_->IsCryptoHandshakeConfirmed());
  }

  const QuicClock* GetClock() const override { return &clock_; }

  QuicRandom* GetRandomGenerator() override {
    return QuicRandom::GetInstance();
  }

  QuicBufferAllocator* GetBufferAllocator() override {
    return &buffer_allocator_;
  }

 protected:
  std::unique_ptr<QuicAlarmFactory> alarm_factory_;
  SimpleBufferAllocator buffer_allocator_;
  MockClock clock_;
  MockQuartcClock quartc_clock_{&clock_};

  std::unique_ptr<FakeTransportChannel> client_channel_;
  std::unique_ptr<FakeTransportChannel> server_channel_;
  std::unique_ptr<FakeTransport> client_transport_;
  std::unique_ptr<FakeTransport> server_transport_;
  std::unique_ptr<QuartcPacketWriter> client_writer_;
  std::unique_ptr<QuartcPacketWriter> server_writer_;
  std::unique_ptr<QuartcSessionForTest> client_peer_;
  std::unique_ptr<QuartcSessionForTest> server_peer_;

  FakeTaskRunner task_runner_{&clock_};
};

TEST_F(QuartcSessionTest, StreamConnection) {
  CreateClientAndServerSessions();
  StartHandshake();
  TestStreamConnection();
}

TEST_F(QuartcSessionTest, ClientRejection) {
  CreateClientAndServerSessions(false /*client_handshake_success*/,
                                true /*server_handshake_success*/);
  StartHandshake();
  TestDisconnectAfterFailedHandshake();
}

TEST_F(QuartcSessionTest, ServerRejection) {
  CreateClientAndServerSessions(true /*client_handshake_success*/,
                                false /*server_handshake_success*/);
  StartHandshake();
  TestDisconnectAfterFailedHandshake();
}

// Test that data streams are not created before handshake.
TEST_F(QuartcSessionTest, CannotCreateDataStreamBeforeHandshake) {
  CreateClientAndServerSessions();
  EXPECT_EQ(nullptr, server_peer_->CreateOutgoingStream(kDefaultStreamParam));
  EXPECT_EQ(nullptr, client_peer_->CreateOutgoingStream(kDefaultStreamParam));
}

TEST_F(QuartcSessionTest, CloseQuartcStream) {
  CreateClientAndServerSessions();
  StartHandshake();
  ASSERT_TRUE(client_peer_->IsCryptoHandshakeConfirmed());
  ASSERT_TRUE(server_peer_->IsCryptoHandshakeConfirmed());
  QuartcStreamInterface* stream =
      client_peer_->CreateOutgoingStream(kDefaultStreamParam);
  ASSERT_NE(nullptr, stream);

  uint32_t id = stream->stream_id();
  EXPECT_FALSE(client_peer_->IsClosedStream(id));
  stream->SetDelegate(client_peer_->stream_delegate());
  stream->Close();
  RunTasks();
  EXPECT_TRUE(client_peer_->IsClosedStream(id));
}

TEST_F(QuartcSessionTest, CancelQuartcStream) {
  CreateClientAndServerSessions();
  StartHandshake();
  ASSERT_TRUE(client_peer_->IsCryptoHandshakeConfirmed());
  ASSERT_TRUE(server_peer_->IsCryptoHandshakeConfirmed());

  QuartcStreamInterface* stream =
      client_peer_->CreateOutgoingStream(kDefaultStreamParam);
  ASSERT_NE(nullptr, stream);

  uint32_t id = stream->stream_id();
  EXPECT_FALSE(client_peer_->IsClosedStream(id));
  stream->SetDelegate(client_peer_->stream_delegate());
  client_peer_->CancelStream(id);
  EXPECT_EQ(stream->stream_error(),
            QuicRstStreamErrorCode::QUIC_STREAM_CANCELLED);
  EXPECT_TRUE(client_peer_->IsClosedStream(id));
}

TEST_F(QuartcSessionTest, GetStats) {
  CreateClientAndServerSessions();
  StartHandshake();
  ASSERT_TRUE(client_peer_->IsCryptoHandshakeConfirmed());
  ASSERT_TRUE(server_peer_->IsCryptoHandshakeConfirmed());

  QuartcSessionStats stats = client_peer_->GetStats();
  EXPECT_GT(stats.bandwidth_estimate_bits_per_second, 0);
}

}  // namespace

}  // namespace net
