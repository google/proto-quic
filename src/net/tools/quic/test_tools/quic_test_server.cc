// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/test_tools/quic_test_server.h"

#include "base/logging.h"
#include "base/run_loop.h"
#include "base/synchronization/lock.h"
#include "base/thread_task_runner_handle.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_packet_writer.h"
#include "net/quic/quic_protocol.h"
#include "net/tools/quic/quic_dispatcher.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_simple_server_session.h"
#include "net/tools/quic/quic_simple_server_stream.h"

namespace net {
namespace test {

class CustomStreamSession : public QuicSimpleServerSession {
 public:
  CustomStreamSession(
      const QuicConfig& config,
      QuicConnection* connection,
      QuicServerSessionVisitor* visitor,
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicTestServer::StreamFactory* factory,
      QuicTestServer::CryptoStreamFactory* crypto_stream_factory)
      : QuicSimpleServerSession(config,
                                connection,
                                visitor,
                                crypto_config,
                                compressed_certs_cache),
        stream_factory_(factory),
        crypto_stream_factory_(crypto_stream_factory) {}

  QuicSpdyStream* CreateIncomingDynamicStream(QuicStreamId id) override {
    if (!ShouldCreateIncomingDynamicStream(id)) {
      return nullptr;
    }
    if (stream_factory_) {
      QuicSpdyStream* stream = stream_factory_->CreateStream(id, this);
      ActivateStream(stream);
      return stream;
    }
    return QuicSimpleServerSession::CreateIncomingDynamicStream(id);
  }

  QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache) override {
    if (crypto_stream_factory_) {
      return crypto_stream_factory_->CreateCryptoStream(crypto_config, this);
    }
    return QuicSimpleServerSession::CreateQuicCryptoServerStream(
        crypto_config, compressed_certs_cache);
  }

 private:
  QuicTestServer::StreamFactory* stream_factory_;               // Not owned.
  QuicTestServer::CryptoStreamFactory* crypto_stream_factory_;  // Not owned.
};

class QuicTestDispatcher : public QuicDispatcher {
 public:
  QuicTestDispatcher(const QuicConfig& config,
                     const QuicCryptoServerConfig* crypto_config,
                     const QuicVersionVector& versions,
                     std::unique_ptr<QuicConnectionHelperInterface> helper,
                     std::unique_ptr<QuicAlarmFactory> alarm_factory)
      : QuicDispatcher(config,
                       crypto_config,
                       versions,
                       std::move(helper),
                       std::move(alarm_factory)),
        session_factory_(nullptr),
        stream_factory_(nullptr),
        crypto_stream_factory_(nullptr) {}

  QuicServerSessionBase* CreateQuicSession(QuicConnectionId id,
                                           const IPEndPoint& client) override {
    base::AutoLock lock(factory_lock_);
    if (session_factory_ == nullptr && stream_factory_ == nullptr &&
        crypto_stream_factory_ == nullptr) {
      return QuicDispatcher::CreateQuicSession(id, client);
    }
    QuicConnection* connection = new QuicConnection(
        id, client, helper(), alarm_factory(), CreatePerConnectionWriter(),
        /* owns_writer= */ true, Perspective::IS_SERVER, supported_versions());

    QuicServerSessionBase* session = nullptr;
    if (stream_factory_ != nullptr || crypto_stream_factory_ != nullptr) {
      session = new CustomStreamSession(
          config(), connection, this, crypto_config(), compressed_certs_cache(),
          stream_factory_, crypto_stream_factory_);
    } else {
      session = session_factory_->CreateSession(config(), connection, this,
                                                crypto_config(),
                                                compressed_certs_cache());
    }
    session->Initialize();
    return session;
  }

  void SetSessionFactory(QuicTestServer::SessionFactory* factory) {
    base::AutoLock lock(factory_lock_);
    DCHECK(session_factory_ == nullptr);
    DCHECK(stream_factory_ == nullptr);
    DCHECK(crypto_stream_factory_ == nullptr);
    session_factory_ = factory;
  }

  void SetStreamFactory(QuicTestServer::StreamFactory* factory) {
    base::AutoLock lock(factory_lock_);
    DCHECK(session_factory_ == nullptr);
    DCHECK(stream_factory_ == nullptr);
    stream_factory_ = factory;
  }

  void SetCryptoStreamFactory(QuicTestServer::CryptoStreamFactory* factory) {
    base::AutoLock lock(factory_lock_);
    DCHECK(session_factory_ == nullptr);
    DCHECK(crypto_stream_factory_ == nullptr);
    crypto_stream_factory_ = factory;
  }

 private:
  base::Lock factory_lock_;
  QuicTestServer::SessionFactory* session_factory_;             // Not owned.
  QuicTestServer::StreamFactory* stream_factory_;               // Not owned.
  QuicTestServer::CryptoStreamFactory* crypto_stream_factory_;  // Not owned.
};

QuicTestServer::QuicTestServer(ProofSource* proof_source)
    : QuicServer(proof_source) {}

QuicTestServer::QuicTestServer(ProofSource* proof_source,
                               const QuicConfig& config,
                               const QuicVersionVector& supported_versions)
    : QuicServer(proof_source,
                 config,
                 QuicCryptoServerConfig::ConfigOptions(),
                 supported_versions) {}

QuicDispatcher* QuicTestServer::CreateQuicDispatcher() {
  return new QuicTestDispatcher(
      config(), &crypto_config(), supported_versions(),
      std::unique_ptr<QuicEpollConnectionHelper>(new QuicEpollConnectionHelper(
          epoll_server(), QuicAllocator::BUFFER_POOL)),
      std::unique_ptr<QuicEpollAlarmFactory>(
          new QuicEpollAlarmFactory(epoll_server())));
}

void QuicTestServer::SetSessionFactory(SessionFactory* factory) {
  DCHECK(dispatcher());
  static_cast<QuicTestDispatcher*>(dispatcher())->SetSessionFactory(factory);
}

void QuicTestServer::SetSpdyStreamFactory(StreamFactory* factory) {
  static_cast<QuicTestDispatcher*>(dispatcher())->SetStreamFactory(factory);
}

void QuicTestServer::SetCryptoStreamFactory(CryptoStreamFactory* factory) {
  static_cast<QuicTestDispatcher*>(dispatcher())
      ->SetCryptoStreamFactory(factory);
}

///////////////////////////   TEST SESSIONS ///////////////////////////////

ImmediateGoAwaySession::ImmediateGoAwaySession(
    const QuicConfig& config,
    QuicConnection* connection,
    QuicServerSessionVisitor* visitor,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicSimpleServerSession(config,
                              connection,
                              visitor,
                              crypto_config,
                              compressed_certs_cache) {
  SendGoAway(QUIC_PEER_GOING_AWAY, "");
}

}  // namespace test
}  // namespace net
