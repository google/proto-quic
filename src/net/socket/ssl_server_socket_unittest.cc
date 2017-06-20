// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This test suite uses SSLClientSocket to test the implementation of
// SSLServerSocket. In order to establish connections between the sockets
// we need two additional classes:
// 1. FakeSocket
//    Connects SSL socket to FakeDataChannel. This class is just a stub.
//
// 2. FakeDataChannel
//    Implements the actual exchange of data between two FakeSockets.
//
// Implementations of these two classes are included in this file.

#include "net/socket/ssl_server_socket.h"

#include <stdint.h>
#include <stdlib.h>
#include <queue>
#include <utility>

#include "base/callback_helpers.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "crypto/nss_util.h"
#include "crypto/rsa_private_key.h"
#include "crypto/signature_creator.h"
#include "net/base/address_list.h"
#include "net/base/completion_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/mock_client_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/x509_certificate.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_server_config.h"
#include "net/ssl/test_ssl_private_key.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

const char kClientCertFileName[] = "client_1.pem";
const char kClientPrivateKeyFileName[] = "client_1.pk8";
const char kWrongClientCertFileName[] = "client_2.pem";
const char kWrongClientPrivateKeyFileName[] = "client_2.pk8";
const char kClientCertCAFileName[] = "client_1_ca.pem";

class MockCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  MockCTPolicyEnforcer() = default;
  ~MockCTPolicyEnforcer() override = default;
  ct::CertPolicyCompliance DoesConformToCertPolicy(
      X509Certificate* cert,
      const SCTList& verified_scts,
      const NetLogWithSource& net_log) override {
    return ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS;
  }
};

class FakeDataChannel {
 public:
  FakeDataChannel()
      : read_buf_len_(0),
        closed_(false),
        write_called_after_close_(false),
        weak_factory_(this) {
  }

  int Read(IOBuffer* buf, int buf_len, const CompletionCallback& callback) {
    DCHECK(read_callback_.is_null());
    DCHECK(!read_buf_.get());
    if (closed_)
      return 0;
    if (data_.empty()) {
      read_callback_ = callback;
      read_buf_ = buf;
      read_buf_len_ = buf_len;
      return ERR_IO_PENDING;
    }
    return PropagateData(buf, buf_len);
  }

  int Write(IOBuffer* buf, int buf_len, const CompletionCallback& callback) {
    DCHECK(write_callback_.is_null());
    if (closed_) {
      if (write_called_after_close_)
        return ERR_CONNECTION_RESET;
      write_called_after_close_ = true;
      write_callback_ = callback;
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&FakeDataChannel::DoWriteCallback,
                                weak_factory_.GetWeakPtr()));
      return ERR_IO_PENDING;
    }
    // This function returns synchronously, so make a copy of the buffer.
    data_.push(new DrainableIOBuffer(
        new StringIOBuffer(std::string(buf->data(), buf_len)),
        buf_len));
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&FakeDataChannel::DoReadCallback,
                              weak_factory_.GetWeakPtr()));
    return buf_len;
  }

  // Closes the FakeDataChannel. After Close() is called, Read() returns 0,
  // indicating EOF, and Write() fails with ERR_CONNECTION_RESET. Note that
  // after the FakeDataChannel is closed, the first Write() call completes
  // asynchronously, which is necessary to reproduce bug 127822.
  void Close() {
    closed_ = true;
    if (!read_callback_.is_null()) {
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&FakeDataChannel::DoReadCallback,
                                weak_factory_.GetWeakPtr()));
    }
  }

 private:
  void DoReadCallback() {
    if (read_callback_.is_null())
      return;

    if (closed_) {
      base::ResetAndReturn(&read_callback_).Run(ERR_CONNECTION_CLOSED);
      return;
    }

    if (data_.empty())
      return;

    int copied = PropagateData(read_buf_, read_buf_len_);
    CompletionCallback callback = read_callback_;
    read_callback_.Reset();
    read_buf_ = NULL;
    read_buf_len_ = 0;
    callback.Run(copied);
  }

  void DoWriteCallback() {
    if (write_callback_.is_null())
      return;

    CompletionCallback callback = write_callback_;
    write_callback_.Reset();
    callback.Run(ERR_CONNECTION_RESET);
  }

  int PropagateData(scoped_refptr<IOBuffer> read_buf, int read_buf_len) {
    scoped_refptr<DrainableIOBuffer> buf = data_.front();
    int copied = std::min(buf->BytesRemaining(), read_buf_len);
    memcpy(read_buf->data(), buf->data(), copied);
    buf->DidConsume(copied);

    if (!buf->BytesRemaining())
      data_.pop();
    return copied;
  }

  CompletionCallback read_callback_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_;

  CompletionCallback write_callback_;

  std::queue<scoped_refptr<DrainableIOBuffer> > data_;

  // True if Close() has been called.
  bool closed_;

  // Controls the completion of Write() after the FakeDataChannel is closed.
  // After the FakeDataChannel is closed, the first Write() call completes
  // asynchronously.
  bool write_called_after_close_;

  base::WeakPtrFactory<FakeDataChannel> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(FakeDataChannel);
};

class FakeSocket : public StreamSocket {
 public:
  FakeSocket(FakeDataChannel* incoming_channel,
             FakeDataChannel* outgoing_channel)
      : incoming_(incoming_channel), outgoing_(outgoing_channel) {}

  ~FakeSocket() override {}

  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override {
    // Read random number of bytes.
    buf_len = rand() % buf_len + 1;
    return incoming_->Read(buf, buf_len, callback);
  }

  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override {
    // Write random number of bytes.
    buf_len = rand() % buf_len + 1;
    return outgoing_->Write(buf, buf_len, callback);
  }

  int SetReceiveBufferSize(int32_t size) override { return OK; }

  int SetSendBufferSize(int32_t size) override { return OK; }

  int Connect(const CompletionCallback& callback) override { return OK; }

  void Disconnect() override {
    incoming_->Close();
    outgoing_->Close();
  }

  bool IsConnected() const override { return true; }

  bool IsConnectedAndIdle() const override { return true; }

  int GetPeerAddress(IPEndPoint* address) const override {
    *address = IPEndPoint(IPAddress::IPv4AllZeros(), 0 /*port*/);
    return OK;
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    *address = IPEndPoint(IPAddress::IPv4AllZeros(), 0 /*port*/);
    return OK;
  }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  void SetSubresourceSpeculation() override {}
  void SetOmniboxSpeculation() override {}

  bool WasEverUsed() const override { return true; }

  bool WasAlpnNegotiated() const override { return false; }

  NextProto GetNegotiatedProtocol() const override { return kProtoUnknown; }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  void GetConnectionAttempts(ConnectionAttempts* out) const override {
    out->clear();
  }

  void ClearConnectionAttempts() override {}

  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {}

  int64_t GetTotalReceivedBytes() const override {
    NOTIMPLEMENTED();
    return 0;
  }

 private:
  NetLogWithSource net_log_;
  FakeDataChannel* incoming_;
  FakeDataChannel* outgoing_;

  DISALLOW_COPY_AND_ASSIGN(FakeSocket);
};

}  // namespace

// Verify the correctness of the test helper classes first.
TEST(FakeSocketTest, DataTransfer) {
  // Establish channels between two sockets.
  FakeDataChannel channel_1;
  FakeDataChannel channel_2;
  FakeSocket client(&channel_1, &channel_2);
  FakeSocket server(&channel_2, &channel_1);

  const char kTestData[] = "testing123";
  const int kTestDataSize = strlen(kTestData);
  const int kReadBufSize = 1024;
  scoped_refptr<IOBuffer> write_buf = new StringIOBuffer(kTestData);
  scoped_refptr<IOBuffer> read_buf = new IOBuffer(kReadBufSize);

  // Write then read.
  int written =
      server.Write(write_buf.get(), kTestDataSize, CompletionCallback());
  EXPECT_GT(written, 0);
  EXPECT_LE(written, kTestDataSize);

  int read = client.Read(read_buf.get(), kReadBufSize, CompletionCallback());
  EXPECT_GT(read, 0);
  EXPECT_LE(read, written);
  EXPECT_EQ(0, memcmp(kTestData, read_buf->data(), read));

  // Read then write.
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server.Read(read_buf.get(), kReadBufSize, callback.callback()));

  written = client.Write(write_buf.get(), kTestDataSize, CompletionCallback());
  EXPECT_GT(written, 0);
  EXPECT_LE(written, kTestDataSize);

  read = callback.WaitForResult();
  EXPECT_GT(read, 0);
  EXPECT_LE(read, written);
  EXPECT_EQ(0, memcmp(kTestData, read_buf->data(), read));
}

class SSLServerSocketTest : public PlatformTest {
 public:
  SSLServerSocketTest()
      : socket_factory_(ClientSocketFactory::GetDefaultFactory()),
        cert_verifier_(new MockCertVerifier()),
        client_cert_verifier_(new MockClientCertVerifier()),
        transport_security_state_(new TransportSecurityState),
        ct_verifier_(new DoNothingCTVerifier),
        ct_policy_enforcer_(new MockCTPolicyEnforcer) {}

  void SetUp() override {
    PlatformTest::SetUp();

    cert_verifier_->set_default_result(ERR_CERT_AUTHORITY_INVALID);
    client_cert_verifier_->set_default_result(ERR_CERT_AUTHORITY_INVALID);

    server_cert_ =
        ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
    ASSERT_TRUE(server_cert_);
    server_private_key_ = ReadTestKey("unittest.key.bin");
    ASSERT_TRUE(server_private_key_);

    client_ssl_config_.false_start_enabled = false;
    client_ssl_config_.channel_id_enabled = false;

    // Certificate provided by the host doesn't need authority.
    client_ssl_config_.allowed_bad_certs.emplace_back(
        server_cert_, CERT_STATUS_AUTHORITY_INVALID);
  }

 protected:
  void CreateContext() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset();
    channel_2_.reset();
    server_context_.reset();
    server_context_ = CreateSSLServerContext(
        server_cert_.get(), *server_private_key_, server_ssl_config_);
  }

  void CreateSockets() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset(new FakeDataChannel());
    channel_2_.reset(new FakeDataChannel());
    std::unique_ptr<ClientSocketHandle> client_connection(
        new ClientSocketHandle);
    client_connection->SetSocket(std::unique_ptr<StreamSocket>(
        new FakeSocket(channel_1_.get(), channel_2_.get())));
    std::unique_ptr<StreamSocket> server_socket(
        new FakeSocket(channel_2_.get(), channel_1_.get()));

    HostPortPair host_and_pair("unittest", 0);
    SSLClientSocketContext context;
    context.cert_verifier = cert_verifier_.get();
    context.transport_security_state = transport_security_state_.get();
    context.cert_transparency_verifier = ct_verifier_.get();
    context.ct_policy_enforcer = ct_policy_enforcer_.get();

    client_socket_ = socket_factory_->CreateSSLClientSocket(
        std::move(client_connection), host_and_pair, client_ssl_config_,
        context);
    ASSERT_TRUE(client_socket_);

    server_socket_ =
        server_context_->CreateSSLServerSocket(std::move(server_socket));
    ASSERT_TRUE(server_socket_);
  }

  void ConfigureClientCertsForClient(const char* cert_file_name,
                                     const char* private_key_file_name) {
    client_ssl_config_.send_client_cert = true;
    client_ssl_config_.client_cert =
        ImportCertFromFile(GetTestCertsDirectory(), cert_file_name);
    ASSERT_TRUE(client_ssl_config_.client_cert);

    std::unique_ptr<crypto::RSAPrivateKey> key =
        ReadTestKey(private_key_file_name);
    ASSERT_TRUE(key);

    EVP_PKEY_up_ref(key->key());
    client_ssl_config_.client_private_key =
        WrapOpenSSLPrivateKey(bssl::UniquePtr<EVP_PKEY>(key->key()));
  }

  void ConfigureClientCertsForServer() {
    server_ssl_config_.client_cert_type =
        SSLServerConfig::ClientCertType::REQUIRE_CLIENT_CERT;

    bssl::UniquePtr<STACK_OF(X509_NAME)> cert_names(
        SSL_load_client_CA_file(GetTestCertsDirectory()
                                    .AppendASCII(kClientCertCAFileName)
                                    .MaybeAsASCII()
                                    .c_str()));
    ASSERT_TRUE(cert_names);

    for (size_t i = 0; i < sk_X509_NAME_num(cert_names.get()); ++i) {
      uint8_t* str = nullptr;
      int length = i2d_X509_NAME(sk_X509_NAME_value(cert_names.get(), i), &str);
      ASSERT_LT(0, length);

      server_ssl_config_.cert_authorities_.push_back(std::string(
          reinterpret_cast<const char*>(str), static_cast<size_t>(length)));
      OPENSSL_free(str);
    }

    scoped_refptr<X509Certificate> expected_client_cert(
        ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName));
    ASSERT_TRUE(expected_client_cert);

    client_cert_verifier_->AddResultForCert(expected_client_cert.get(), OK);

    server_ssl_config_.client_cert_verifier = client_cert_verifier_.get();
  }

  std::unique_ptr<crypto::RSAPrivateKey> ReadTestKey(
      const base::StringPiece& name) {
    base::FilePath certs_dir(GetTestCertsDirectory());
    base::FilePath key_path = certs_dir.AppendASCII(name);
    std::string key_string;
    if (!base::ReadFileToString(key_path, &key_string))
      return nullptr;
    std::vector<uint8_t> key_vector(
        reinterpret_cast<const uint8_t*>(key_string.data()),
        reinterpret_cast<const uint8_t*>(key_string.data() +
                                         key_string.length()));
    std::unique_ptr<crypto::RSAPrivateKey> key(
        crypto::RSAPrivateKey::CreateFromPrivateKeyInfo(key_vector));
    return key;
  }

  std::unique_ptr<FakeDataChannel> channel_1_;
  std::unique_ptr<FakeDataChannel> channel_2_;
  SSLConfig client_ssl_config_;
  SSLServerConfig server_ssl_config_;
  std::unique_ptr<SSLClientSocket> client_socket_;
  std::unique_ptr<SSLServerSocket> server_socket_;
  ClientSocketFactory* socket_factory_;
  std::unique_ptr<MockCertVerifier> cert_verifier_;
  std::unique_ptr<MockClientCertVerifier> client_cert_verifier_;
  std::unique_ptr<TransportSecurityState> transport_security_state_;
  std::unique_ptr<DoNothingCTVerifier> ct_verifier_;
  std::unique_ptr<MockCTPolicyEnforcer> ct_policy_enforcer_;
  std::unique_ptr<SSLServerContext> server_context_;
  std::unique_ptr<crypto::RSAPrivateKey> server_private_key_;
  scoped_refptr<X509Certificate> server_cert_;
};

// This test only executes creation of client and server sockets. This is to
// test that creation of sockets doesn't crash and have minimal code to run
// under valgrind in order to help debugging memory problems.
TEST_F(SSLServerSocketTest, Initialize) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
}

// This test executes Connect() on SSLClientSocket and Handshake() on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully.
TEST_F(SSLServerSocketTest, Handshake) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, ssl_info.cert_status);

  // The default cipher suite should be ECDHE and an AEAD.
  uint16_t cipher_suite =
      SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
  const char* key_exchange;
  const char* cipher;
  const char* mac;
  bool is_aead;
  bool is_tls13;
  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          cipher_suite);
  EXPECT_TRUE(is_aead);
  ASSERT_FALSE(is_tls13);
  EXPECT_STREQ("ECDHE_RSA", key_exchange);
}

// This test makes sure the session cache is working.
TEST_F(SSLServerSocketTest, HandshakeCached) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info));
  EXPECT_EQ(ssl_server_info.handshake_type, SSLInfo::HANDSHAKE_FULL);

  // Make sure the second connection is cached.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  client_ret2 = connect_callback2.GetResult(client_ret2);
  server_ret2 = handshake_callback2.GetResult(server_ret2);

  ASSERT_THAT(client_ret2, IsOk());
  ASSERT_THAT(server_ret2, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info2;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info2));
  EXPECT_EQ(ssl_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
  SSLInfo ssl_server_info2;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info2));
  EXPECT_EQ(ssl_server_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
}

// This test makes sure the session cache separates out by server context.
TEST_F(SSLServerSocketTest, HandshakeCachedContextSwitch) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info));
  EXPECT_EQ(ssl_server_info.handshake_type, SSLInfo::HANDSHAKE_FULL);

  // Make sure the second connection is NOT cached when using a new context.
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  client_ret2 = connect_callback2.GetResult(client_ret2);
  server_ret2 = handshake_callback2.GetResult(server_ret2);

  ASSERT_THAT(client_ret2, IsOk());
  ASSERT_THAT(server_ret2, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info2;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info2));
  EXPECT_EQ(ssl_info2.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info2;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info2));
  EXPECT_EQ(ssl_server_info2.handshake_type, SSLInfo::HANDSHAKE_FULL);
}

// This test executes Connect() on SSLClientSocket and Handshake() on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully, using client certificate.
TEST_F(SSLServerSocketTest, HandshakeWithClientCert) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kClientCertFileName, kClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  client_socket_->GetSSLInfo(&ssl_info);
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, ssl_info.cert_status);
  server_socket_->GetSSLInfo(&ssl_info);
  ASSERT_TRUE(ssl_info.cert.get());
  EXPECT_TRUE(client_cert->Equals(ssl_info.cert.get()));
}

// This test executes Connect() on SSLClientSocket and Handshake() twice on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully, using client certificate. The second connection is
// expected to succeed through the session cache.
TEST_F(SSLServerSocketTest, HandshakeWithClientCertCached) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kClientCertFileName, kClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info));
  ASSERT_TRUE(ssl_server_info.cert.get());
  EXPECT_TRUE(client_cert->Equals(ssl_server_info.cert.get()));
  EXPECT_EQ(ssl_server_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  server_socket_->Disconnect();
  client_socket_->Disconnect();

  // Create the connection again.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  client_ret2 = connect_callback2.GetResult(client_ret2);
  server_ret2 = handshake_callback2.GetResult(server_ret2);

  ASSERT_THAT(client_ret2, IsOk());
  ASSERT_THAT(server_ret2, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info2;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info2));
  EXPECT_EQ(ssl_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
  SSLInfo ssl_server_info2;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info2));
  ASSERT_TRUE(ssl_server_info2.cert.get());
  EXPECT_TRUE(client_cert->Equals(ssl_server_info2.cert.get()));
  EXPECT_EQ(ssl_server_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
}

TEST_F(SSLServerSocketTest, HandshakeWithClientCertRequiredNotSupplied) {
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  // Use the default setting for the client socket, which is to not send
  // a client certificate. This will cause the client to receive an
  // ERR_SSL_CLIENT_AUTH_CERT_NEEDED error, and allow for inspecting the
  // requested cert_authorities from the CertificateRequest sent by the
  // server.

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  EXPECT_EQ(ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
            connect_callback.GetResult(
                client_socket_->Connect(connect_callback.callback())));

  scoped_refptr<SSLCertRequestInfo> request_info = new SSLCertRequestInfo();
  client_socket_->GetSSLCertRequestInfo(request_info.get());

  // Check that the authority name that arrived in the CertificateRequest
  // handshake message is as expected.
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);
  EXPECT_TRUE(client_cert->IsIssuedByEncoded(request_info->cert_authorities));

  client_socket_->Disconnect();

  EXPECT_THAT(handshake_callback.GetResult(server_ret),
              IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(SSLServerSocketTest, HandshakeWithClientCertRequiredNotSuppliedCached) {
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  // Use the default setting for the client socket, which is to not send
  // a client certificate. This will cause the client to receive an
  // ERR_SSL_CLIENT_AUTH_CERT_NEEDED error, and allow for inspecting the
  // requested cert_authorities from the CertificateRequest sent by the
  // server.

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  EXPECT_EQ(ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
            connect_callback.GetResult(
                client_socket_->Connect(connect_callback.callback())));

  scoped_refptr<SSLCertRequestInfo> request_info = new SSLCertRequestInfo();
  client_socket_->GetSSLCertRequestInfo(request_info.get());

  // Check that the authority name that arrived in the CertificateRequest
  // handshake message is as expected.
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);
  EXPECT_TRUE(client_cert->IsIssuedByEncoded(request_info->cert_authorities));

  client_socket_->Disconnect();

  EXPECT_THAT(handshake_callback.GetResult(server_ret),
              IsError(ERR_CONNECTION_CLOSED));
  server_socket_->Disconnect();

  // Below, check that the cache didn't store the result of a failed handshake.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  EXPECT_EQ(ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
            connect_callback2.GetResult(
                client_socket_->Connect(connect_callback2.callback())));

  scoped_refptr<SSLCertRequestInfo> request_info2 = new SSLCertRequestInfo();
  client_socket_->GetSSLCertRequestInfo(request_info2.get());

  // Check that the authority name that arrived in the CertificateRequest
  // handshake message is as expected.
  EXPECT_TRUE(client_cert->IsIssuedByEncoded(request_info2->cert_authorities));

  client_socket_->Disconnect();

  EXPECT_THAT(handshake_callback2.GetResult(server_ret2),
              IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(SSLServerSocketTest, HandshakeWithWrongClientCertSupplied) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);

  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kWrongClientCertFileName, kWrongClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            connect_callback.GetResult(client_ret));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback.GetResult(server_ret));
}

TEST_F(SSLServerSocketTest, HandshakeWithWrongClientCertSuppliedCached) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);

  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kWrongClientCertFileName, kWrongClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            connect_callback.GetResult(client_ret));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback.GetResult(server_ret));

  client_socket_->Disconnect();
  server_socket_->Disconnect();

  // Below, check that the cache didn't store the result of a failed handshake.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            connect_callback2.GetResult(client_ret2));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback2.GetResult(server_ret2));
}

TEST_F(SSLServerSocketTest, DataTransfer) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  // Establish connection.
  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  ASSERT_TRUE(client_ret == OK || client_ret == ERR_IO_PENDING);

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_TRUE(server_ret == OK || server_ret == ERR_IO_PENDING);

  client_ret = connect_callback.GetResult(client_ret);
  ASSERT_THAT(client_ret, IsOk());
  server_ret = handshake_callback.GetResult(server_ret);
  ASSERT_THAT(server_ret, IsOk());

  const int kReadBufSize = 1024;
  scoped_refptr<StringIOBuffer> write_buf =
      new StringIOBuffer("testing123");
  scoped_refptr<DrainableIOBuffer> read_buf =
      new DrainableIOBuffer(new IOBuffer(kReadBufSize), kReadBufSize);

  // Write then read.
  TestCompletionCallback write_callback;
  TestCompletionCallback read_callback;
  server_ret = server_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback());
  EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);
  client_ret = client_socket_->Read(
      read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
  EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

  server_ret = write_callback.GetResult(server_ret);
  EXPECT_GT(server_ret, 0);
  client_ret = read_callback.GetResult(client_ret);
  ASSERT_GT(client_ret, 0);

  read_buf->DidConsume(client_ret);
  while (read_buf->BytesConsumed() < write_buf->size()) {
    client_ret = client_socket_->Read(
        read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
    EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);
    client_ret = read_callback.GetResult(client_ret);
    ASSERT_GT(client_ret, 0);
    read_buf->DidConsume(client_ret);
  }
  EXPECT_EQ(write_buf->size(), read_buf->BytesConsumed());
  read_buf->SetOffset(0);
  EXPECT_EQ(0, memcmp(write_buf->data(), read_buf->data(), write_buf->size()));

  // Read then write.
  write_buf = new StringIOBuffer("hello123");
  server_ret = server_socket_->Read(
      read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
  EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);
  client_ret = client_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback());
  EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

  server_ret = read_callback.GetResult(server_ret);
  ASSERT_GT(server_ret, 0);
  client_ret = write_callback.GetResult(client_ret);
  EXPECT_GT(client_ret, 0);

  read_buf->DidConsume(server_ret);
  while (read_buf->BytesConsumed() < write_buf->size()) {
    server_ret = server_socket_->Read(
        read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
    EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);
    server_ret = read_callback.GetResult(server_ret);
    ASSERT_GT(server_ret, 0);
    read_buf->DidConsume(server_ret);
  }
  EXPECT_EQ(write_buf->size(), read_buf->BytesConsumed());
  read_buf->SetOffset(0);
  EXPECT_EQ(0, memcmp(write_buf->data(), read_buf->data(), write_buf->size()));
}

// A regression test for bug 127822 (http://crbug.com/127822).
// If the server closes the connection after the handshake is finished,
// the client's Write() call should not cause an infinite loop.
// NOTE: this is a test for SSLClientSocket rather than SSLServerSocket.
TEST_F(SSLServerSocketTest, ClientWriteAfterServerClose) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  // Establish connection.
  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  ASSERT_TRUE(client_ret == OK || client_ret == ERR_IO_PENDING);

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_TRUE(server_ret == OK || server_ret == ERR_IO_PENDING);

  client_ret = connect_callback.GetResult(client_ret);
  ASSERT_THAT(client_ret, IsOk());
  server_ret = handshake_callback.GetResult(server_ret);
  ASSERT_THAT(server_ret, IsOk());

  scoped_refptr<StringIOBuffer> write_buf = new StringIOBuffer("testing123");

  // The server closes the connection. The server needs to write some
  // data first so that the client's Read() calls from the transport
  // socket won't return ERR_IO_PENDING.  This ensures that the client
  // will call Read() on the transport socket again.
  TestCompletionCallback write_callback;
  server_ret = server_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback());
  EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);

  server_ret = write_callback.GetResult(server_ret);
  EXPECT_GT(server_ret, 0);

  server_socket_->Disconnect();

  // The client writes some data. This should not cause an infinite loop.
  client_ret = client_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback());
  EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

  client_ret = write_callback.GetResult(client_ret);
  EXPECT_GT(client_ret, 0);

  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::MessageLoop::QuitWhenIdleClosure(),
      base::TimeDelta::FromMilliseconds(10));
  base::RunLoop().Run();
}

// This test executes ExportKeyingMaterial() on the client and server sockets,
// after connecting them, and verifies that the results match.
// This test will fail if False Start is enabled (see crbug.com/90208).
TEST_F(SSLServerSocketTest, ExportKeyingMaterial) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  ASSERT_TRUE(client_ret == OK || client_ret == ERR_IO_PENDING);

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_TRUE(server_ret == OK || server_ret == ERR_IO_PENDING);

  if (client_ret == ERR_IO_PENDING) {
    ASSERT_THAT(connect_callback.WaitForResult(), IsOk());
  }
  if (server_ret == ERR_IO_PENDING) {
    ASSERT_THAT(handshake_callback.WaitForResult(), IsOk());
  }

  const int kKeyingMaterialSize = 32;
  const char kKeyingLabel[] = "EXPERIMENTAL-server-socket-test";
  const char kKeyingContext[] = "";
  unsigned char server_out[kKeyingMaterialSize];
  int rv = server_socket_->ExportKeyingMaterial(
      kKeyingLabel, false, kKeyingContext, server_out, sizeof(server_out));
  ASSERT_THAT(rv, IsOk());

  unsigned char client_out[kKeyingMaterialSize];
  rv = client_socket_->ExportKeyingMaterial(kKeyingLabel, false, kKeyingContext,
                                            client_out, sizeof(client_out));
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(0, memcmp(server_out, client_out, sizeof(server_out)));

  const char kKeyingLabelBad[] = "EXPERIMENTAL-server-socket-test-bad";
  unsigned char client_bad[kKeyingMaterialSize];
  rv = client_socket_->ExportKeyingMaterial(
      kKeyingLabelBad, false, kKeyingContext, client_bad, sizeof(client_bad));
  ASSERT_EQ(rv, OK);
  EXPECT_NE(0, memcmp(server_out, client_bad, sizeof(server_out)));
}

// Verifies that SSLConfig::require_ecdhe flags works properly.
TEST_F(SSLServerSocketTest, RequireEcdheFlag) {
  // Disable all ECDHE suites on the client side.
  uint16_t kEcdheCiphers[] = {
      0xc007,  // ECDHE_ECDSA_WITH_RC4_128_SHA
      0xc009,  // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
      0xc00a,  // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
      0xc011,  // ECDHE_RSA_WITH_RC4_128_SHA
      0xc013,  // ECDHE_RSA_WITH_AES_128_CBC_SHA
      0xc014,  // ECDHE_RSA_WITH_AES_256_CBC_SHA
      0xc02b,  // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      0xc02f,  // ECDHE_RSA_WITH_AES_128_GCM_SHA256
      0xcca8,  // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      0xcca9,  // ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
  };
  client_ssl_config_.disabled_cipher_suites.assign(
      kEcdheCiphers, kEcdheCiphers + arraysize(kEcdheCiphers));

  // Require ECDHE on the server.
  server_ssl_config_.require_ecdhe = true;

  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
  ASSERT_THAT(server_ret, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

}  // namespace net
