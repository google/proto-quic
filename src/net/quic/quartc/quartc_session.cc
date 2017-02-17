// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quartc/quartc_session.h"

#include "base/rand_util.h"

namespace {

// Default priority for incoming QUIC streams.
// TODO(zhihuang): Determine if this value is correct.
static const net::SpdyPriority kDefaultPriority = 3;

// Arbitrary server port number for net::QuicCryptoClientConfig.
const int kQuicServerPort = 0;

// Length of HKDF input keying material, equal to its number of bytes.
// https://tools.ietf.org/html/rfc5869#section-2.2.
// TODO(zhihuang): Verify that input keying material length is correct.
const size_t kInputKeyingMaterialLength = 32;

// Used by QuicCryptoServerConfig to provide dummy proof credentials.
// TODO(zhihuang): Remove when secure P2P QUIC handshake is possible.
class DummyProofSource : public net::ProofSource {
 public:
  DummyProofSource() {}
  ~DummyProofSource() override {}

  // ProofSource override.
  void GetProof(const net::QuicSocketAddress& server_addr,
                const std::string& hostname,
                const std::string& server_config,
                net::QuicVersion quic_version,
                base::StringPiece chlo_hash,
                const net::QuicTagVector& connection_options,
                std::unique_ptr<Callback> callback) override {
    net::QuicReferenceCountedPointer<net::ProofSource::Chain> chain;
    net::QuicCryptoProof proof;
    std::vector<std::string> certs;
    certs.push_back("Dummy cert");
    chain = new ProofSource::Chain(certs);
    proof.signature = "Dummy signature";
    proof.leaf_cert_scts = "Dummy timestamp";
    callback->Run(true, chain, proof, nullptr /* details */);
  }
};

// Used by QuicCryptoClientConfig to ignore the peer's credentials
// and establish an insecure QUIC connection.
// TODO(zhihuang): Remove when secure P2P QUIC handshake is possible.
class InsecureProofVerifier : public net::ProofVerifier {
 public:
  InsecureProofVerifier() {}
  ~InsecureProofVerifier() override {}

  // ProofVerifier override.
  net::QuicAsyncStatus VerifyProof(
      const std::string& hostname,
      const uint16_t port,
      const std::string& server_config,
      net::QuicVersion quic_version,
      base::StringPiece chlo_hash,
      const std::vector<std::string>& certs,
      const std::string& cert_sct,
      const std::string& signature,
      const net::ProofVerifyContext* context,
      std::string* error_details,
      std::unique_ptr<net::ProofVerifyDetails>* verify_details,
      std::unique_ptr<net::ProofVerifierCallback> callback) override {
    return net::QUIC_SUCCESS;
  }

  net::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const std::vector<std::string>& certs,
      const net::ProofVerifyContext* context,
      std::string* error_details,
      std::unique_ptr<net::ProofVerifyDetails>* details,
      std::unique_ptr<net::ProofVerifierCallback> callback) override {
    return net::QUIC_SUCCESS;
  }
};
}

namespace net {

QuicConnectionId QuartcCryptoServerStreamHelper::GenerateConnectionIdForReject(
    QuicConnectionId connection_id) const {
  return 0;
}

bool QuartcCryptoServerStreamHelper::CanAcceptClientHello(
    const CryptoHandshakeMessage& message,
    const QuicSocketAddress& self_address,
    std::string* error_details) const {
  return true;
}

QuartcSession::QuartcSession(std::unique_ptr<QuicConnection> connection,
                             const QuicConfig& config,
                             const std::string& unique_remote_server_id,
                             Perspective perspective,
                             QuicConnectionHelperInterface* helper)
    : QuicSession(connection.get(), nullptr /*visitor*/, config),
      unique_remote_server_id_(unique_remote_server_id),
      perspective_(perspective),
      connection_(std::move(connection)),
      helper_(helper) {
  // Initialization with default crypto configuration.
  if (perspective_ == Perspective::IS_CLIENT) {
    std::unique_ptr<ProofVerifier> proof_verifier(new InsecureProofVerifier);
    quic_crypto_client_config_.reset(
        new QuicCryptoClientConfig(std::move(proof_verifier)));
  } else {
    std::unique_ptr<ProofSource> proof_source(new DummyProofSource);
    std::string source_address_token_secret =
        base::RandBytesAsString(kInputKeyingMaterialLength);
    quic_crypto_server_config_.reset(new QuicCryptoServerConfig(
        source_address_token_secret, helper_->GetRandomGenerator(),
        std::move(proof_source)));
    // Provide server with serialized config string to prove ownership.
    QuicCryptoServerConfig::ConfigOptions options;
    // The |message| is used to handle the return value of AddDefaultConfig
    // which is raw pointer of the CryptoHandshakeMessage.
    std::unique_ptr<CryptoHandshakeMessage> message(
        quic_crypto_server_config_->AddDefaultConfig(
            helper_->GetRandomGenerator(), helper_->GetClock(), options));
  }
}

QuartcSession::~QuartcSession() {}

QuicCryptoStream* QuartcSession::GetCryptoStream() {
  return crypto_stream_.get();
}

QuartcStream* QuartcSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  return CreateDataStream(GetNextOutgoingStreamId(), priority);
}

void QuartcSession::OnCryptoHandshakeEvent(CryptoHandshakeEvent event) {
  QuicSession::OnCryptoHandshakeEvent(event);
  if (event == HANDSHAKE_CONFIRMED) {
    DCHECK(IsEncryptionEstablished());
    DCHECK(IsCryptoHandshakeConfirmed());

    DCHECK(session_delegate_);
    session_delegate_->OnCryptoHandshakeComplete();
  }
}

void QuartcSession::CloseStream(QuicStreamId stream_id) {
  if (IsClosedStream(stream_id)) {
    // When CloseStream has been called recursively (via
    // QuicStream::OnClose), the stream is already closed so return.
    return;
  }
  write_blocked_streams()->UnregisterStream(stream_id);
  QuicSession::CloseStream(stream_id);
}

void QuartcSession::OnConnectionClosed(QuicErrorCode error,
                                       const std::string& error_details,
                                       ConnectionCloseSource source) {
  QuicSession::OnConnectionClosed(error, error_details, source);
  DCHECK(session_delegate_);
  session_delegate_->OnConnectionClosed(
      error, source == ConnectionCloseSource::FROM_PEER);
}

void QuartcSession::StartCryptoHandshake() {
  if (perspective_ == Perspective::IS_CLIENT) {
    QuicServerId server_id(unique_remote_server_id_, kQuicServerPort);
    QuicCryptoClientStream* crypto_stream =
        new QuicCryptoClientStream(server_id, this, new ProofVerifyContext(),
                                   quic_crypto_client_config_.get(), this);
    crypto_stream_.reset(crypto_stream);
    QuicSession::Initialize();
    crypto_stream->CryptoConnect();
  } else {
    quic_compressed_certs_cache_.reset(new QuicCompressedCertsCache(
        QuicCompressedCertsCache::kQuicCompressedCertsCacheSize));
    bool use_stateless_rejects_if_peer_supported = false;
    QuicCryptoServerStream* crypto_stream = new QuicCryptoServerStream(
        quic_crypto_server_config_.get(), quic_compressed_certs_cache_.get(),
        use_stateless_rejects_if_peer_supported, this, &stream_helper_);
    crypto_stream_.reset(crypto_stream);
    QuicSession::Initialize();
  }
}

bool QuartcSession::ExportKeyingMaterial(const std::string& label,
                                         const uint8_t* context,
                                         size_t context_len,
                                         bool used_context,
                                         uint8_t* result,
                                         size_t result_len) {
  std::string quic_context(reinterpret_cast<const char*>(context), context_len);
  std::string quic_result;
  bool success = crypto_stream_->ExportKeyingMaterial(label, quic_context,
                                                      result_len, &quic_result);
  quic_result.copy(reinterpret_cast<char*>(result), result_len);
  DCHECK(quic_result.length() == result_len);
  return success;
}

QuartcStreamInterface* QuartcSession::CreateOutgoingStream(
    const OutgoingStreamParameters& param) {
  // The |param| is for forward-compatibility. Not used for now.
  return CreateOutgoingDynamicStream(kDefaultPriority);
}

void QuartcSession::SetDelegate(
    QuartcSessionInterface::Delegate* session_delegate) {
  if (session_delegate_) {
    LOG(WARNING) << "The delegate for the session has already been set.";
  }
  session_delegate_ = session_delegate;
  DCHECK(session_delegate_);
}

void QuartcSession::OnTransportCanWrite() {
  if (HasDataToWrite()) {
    connection()->OnCanWrite();
  }
}

bool QuartcSession::OnTransportReceived(const char* data, size_t data_len) {
  QuicReceivedPacket packet(data, data_len, clock_.Now());
  ProcessUdpPacket(connection()->self_address(), connection()->peer_address(),
                   packet);
  return true;
}

void QuartcSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& cached) {
  // TODO(zhihuang): Handle the proof verification.
}

void QuartcSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& verify_details) {
  // TODO(zhihuang): Handle the proof verification.
}

void QuartcSession::SetClientCryptoConfig(
    QuicCryptoClientConfig* client_config) {
  quic_crypto_client_config_.reset(client_config);
}

void QuartcSession::SetServerCryptoConfig(
    QuicCryptoServerConfig* server_config) {
  quic_crypto_server_config_.reset(server_config);
}

QuicStream* QuartcSession::CreateIncomingDynamicStream(QuicStreamId id) {
  QuartcStream* stream = CreateDataStream(id, kDefaultPriority);
  if (stream) {
    DCHECK(session_delegate_);
    session_delegate_->OnIncomingStream(stream);
  }
  return stream;
}

QuartcStream* QuartcSession::CreateDataStream(QuicStreamId id,
                                              SpdyPriority priority) {
  if (crypto_stream_ == nullptr || !crypto_stream_->encryption_established()) {
    // Encryption not active so no stream created
    return nullptr;
  }
  QuartcStream* stream = new QuartcStream(id, this);
  if (stream) {
    // Make QuicSession take ownership of the stream.
    ActivateStream(std::unique_ptr<QuicStream>(stream));
    // Register the stream to the QuicWriteBlockedList. |priority| is clamped
    // between 0 and 7, with 0 being the highest priority and 7 the lowest
    // priority.
    write_blocked_streams()->RegisterStream(stream->id(), priority);
  }
  return stream;
}

}  // namespace net
