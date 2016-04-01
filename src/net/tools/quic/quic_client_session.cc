// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client_session.h"

#include "base/logging.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/quic_server_id.h"
#include "net/tools/quic/quic_spdy_client_stream.h"

using std::string;

namespace net {

QuicClientSession::QuicClientSession(
    const QuicConfig& config,
    QuicConnection* connection,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    QuicClientPushPromiseIndex* push_promise_index)
    : QuicClientSessionBase(connection, push_promise_index, config),
      server_id_(server_id),
      crypto_config_(crypto_config),
      respect_goaway_(true) {}

QuicClientSession::~QuicClientSession() {}

void QuicClientSession::Initialize() {
  crypto_stream_.reset(CreateQuicCryptoStream());
  QuicClientSessionBase::Initialize();
}

void QuicClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void QuicClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

bool QuicClientSession::ShouldCreateOutgoingDynamicStream() {
  if (!crypto_stream_->encryption_established()) {
    DVLOG(1) << "Encryption not active so no outgoing stream created.";
    return false;
  }
  if (GetNumOpenOutgoingStreams() >= max_open_outgoing_streams()) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already " << GetNumOpenOutgoingStreams() << " open.";
    return false;
  }
  if (goaway_received() && respect_goaway_) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already received goaway.";
    return false;
  }
  return true;
}

QuicSpdyClientStream* QuicClientSession::CreateOutgoingDynamicStream(
    SpdyPriority priority) {
  if (!ShouldCreateOutgoingDynamicStream()) {
    return nullptr;
  }
  QuicSpdyClientStream* stream = CreateClientStream();
  stream->SetPriority(priority);
  ActivateStream(stream);
  return stream;
}

QuicSpdyClientStream* QuicClientSession::CreateClientStream() {
  return new QuicSpdyClientStream(GetNextOutgoingStreamId(), this);
}

QuicCryptoClientStreamBase* QuicClientSession::GetCryptoStream() {
  return crypto_stream_.get();
}

void QuicClientSession::CryptoConnect() {
  DCHECK(flow_controller());
  crypto_stream_->CryptoConnect();
}

int QuicClientSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

int QuicClientSession::GetNumReceivedServerConfigUpdates() const {
  return crypto_stream_->num_scup_messages_received();
}

bool QuicClientSession::ShouldCreateIncomingDynamicStream(QuicStreamId id) {
  if (!connection()->connected()) {
    LOG(DFATAL) << "ShouldCreateIncomingDynamicStream called when disconnected";
    return false;
  }
  if (goaway_received() && respect_goaway_) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already received goaway.";
    return false;
  }
  if (id % 2 != 0) {
    LOG(WARNING) << "Received invalid push stream id " << id;
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Server created odd numbered stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  return true;
}

QuicSpdyStream* QuicClientSession::CreateIncomingDynamicStream(
    QuicStreamId id) {
  if (!ShouldCreateIncomingDynamicStream(id)) {
    return nullptr;
  }
  QuicSpdyStream* stream = new QuicSpdyClientStream(id, this);
  stream->CloseWriteSide();
  ActivateStream(stream);
  return stream;
}

QuicCryptoClientStreamBase* QuicClientSession::CreateQuicCryptoStream() {
  return new QuicCryptoClientStream(
      server_id_, this, new ProofVerifyContextChromium(0, BoundNetLog()),
      crypto_config_, this);
}

bool QuicClientSession::IsAuthorized(const string& authority) {
  return true;
}

}  // namespace net
