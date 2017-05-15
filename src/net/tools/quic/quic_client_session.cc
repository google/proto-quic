// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_client_session.h"

#include "net/log/net_log_with_source.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/crypto/crypto_protocol.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_ptr_util.h"
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
      crypto_config_(crypto_config) {}

QuicClientSession::~QuicClientSession() {}

void QuicClientSession::Initialize() {
  crypto_stream_ = CreateQuicCryptoStream();
  QuicClientSessionBase::Initialize();
}

void QuicClientSession::OnProofValid(
    const QuicCryptoClientConfig::CachedState& /*cached*/) {}

void QuicClientSession::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

bool QuicClientSession::ShouldCreateOutgoingDynamicStream() {
  DCHECK(!FLAGS_quic_reloadable_flag_quic_refactor_stream_creation);
  if (!crypto_stream_->encryption_established()) {
    QUIC_DLOG(INFO) << "Encryption not active so no outgoing stream created.";
    return false;
  }
  if (GetNumOpenOutgoingStreams() >= max_open_outgoing_streams()) {
    QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
                    << "Already " << GetNumOpenOutgoingStreams() << " open.";
    return false;
  }
  if (goaway_received() && respect_goaway()) {
    QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
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
  std::unique_ptr<QuicSpdyClientStream> stream = CreateClientStream();
  stream->SetPriority(priority);
  QuicSpdyClientStream* stream_ptr = stream.get();
  ActivateStream(std::move(stream));
  return stream_ptr;
}

std::unique_ptr<QuicSpdyClientStream> QuicClientSession::CreateClientStream() {
  return QuicMakeUnique<QuicSpdyClientStream>(GetNextOutgoingStreamId(), this);
}

QuicCryptoClientStreamBase* QuicClientSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoClientStreamBase* QuicClientSession::GetCryptoStream() const {
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
  DCHECK(!FLAGS_quic_reloadable_flag_quic_refactor_stream_creation);
  if (!connection()->connected()) {
    QUIC_BUG << "ShouldCreateIncomingDynamicStream called when disconnected";
    return false;
  }
  if (goaway_received() && respect_goaway()) {
    QUIC_DLOG(INFO) << "Failed to create a new outgoing stream. "
                    << "Already received goaway.";
    return false;
  }
  if (id % 2 != 0) {
    QUIC_LOG(WARNING) << "Received invalid push stream id " << id;
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
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

std::unique_ptr<QuicCryptoClientStreamBase>
QuicClientSession::CreateQuicCryptoStream() {
  return QuicMakeUnique<QuicCryptoClientStream>(
      server_id_, this, new ProofVerifyContextChromium(0, NetLogWithSource()),
      crypto_config_, this);
}

bool QuicClientSession::IsAuthorized(const string& authority) {
  return true;
}

QuicSpdyClientStream* QuicClientSession::MaybeCreateOutgoingDynamicStream(
    SpdyPriority priority) {
  return static_cast<QuicSpdyClientStream*>(
      QuicSpdySession::MaybeCreateOutgoingDynamicStream(priority));
}

QuicSpdyStream* QuicClientSession::MaybeCreateIncomingDynamicStream(
    QuicStreamId id) {
  QuicSpdyStream* stream =
      QuicSpdySession::MaybeCreateIncomingDynamicStream(id);
  if (stream) {
    // Push streams start half-closed.
    stream->CloseWriteSide();
  }
  return stream;
}

std::unique_ptr<QuicStream> QuicClientSession::CreateStream(QuicStreamId id) {
  return QuicMakeUnique<QuicSpdyClientStream>(id, this);
}

}  // namespace net
