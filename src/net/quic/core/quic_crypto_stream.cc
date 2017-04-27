// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_crypto_stream.h"

#include <string>

#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/crypto/crypto_utils.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_session.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_flag_utils.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"

using std::string;

namespace net {

#define ENDPOINT                                                               \
  (session()->perspective() == Perspective::IS_SERVER ? "Server: " : "Client:" \
                                                                     " ")

QuicCryptoStream::QuicCryptoStream(QuicSession* session)
    : QuicStream(kCryptoStreamId, session),
      encryption_established_(false),
      handshake_confirmed_(false),
      crypto_negotiated_params_(new QuicCryptoNegotiatedParameters) {
  crypto_framer_.set_visitor(this);
  // The crypto stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

QuicCryptoStream::~QuicCryptoStream() {}

// static
QuicByteCount QuicCryptoStream::CryptoMessageFramingOverhead(
    QuicVersion version) {
  return QuicPacketCreator::StreamFramePacketOverhead(
      version, PACKET_8BYTE_CONNECTION_ID,
      /*include_version=*/true,
      /*include_diversification_nonce=*/true, PACKET_1BYTE_PACKET_NUMBER,
      /*offset=*/0);
}

void QuicCryptoStream::OnError(CryptoFramer* framer) {
  QUIC_DLOG(WARNING) << "Error processing crypto data: "
                     << QuicErrorCodeToString(framer->error());
}

void QuicCryptoStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QUIC_DVLOG(1) << ENDPOINT << "Received "
                << message.DebugString(session()->perspective());
  session()->OnCryptoHandshakeMessageReceived(message);
}

void QuicCryptoStream::OnDataAvailable() {
  struct iovec iov;
  while (true) {
    if (sequencer()->GetReadableRegions(&iov, 1) != 1) {
      // No more data to read.
      break;
    }
    QuicStringPiece data(static_cast<char*>(iov.iov_base), iov.iov_len);
    if (!crypto_framer_.ProcessInput(data, session()->perspective())) {
      CloseConnectionWithDetails(crypto_framer_.error(),
                                 crypto_framer_.error_detail());
      return;
    }
    sequencer()->MarkConsumed(iov.iov_len);
    if (handshake_confirmed_ && crypto_framer_.InputBytesRemaining() == 0 &&
        FLAGS_quic_reloadable_flag_quic_release_crypto_stream_buffer) {
      QUIC_FLAG_COUNT(quic_reloadable_flag_quic_release_crypto_stream_buffer);
      // If the handshake is complete and the current message has been fully
      // processed then no more handshake messages are likely to arrive soon
      // so release the memory in the stream sequencer.
      sequencer()->ReleaseBufferIfEmpty();
    }
  }
}

void QuicCryptoStream::SendHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  QUIC_DVLOG(1) << ENDPOINT << "Sending "
                << message.DebugString(session()->perspective());
  session()->connection()->NeuterUnencryptedPackets();
  session()->OnCryptoHandshakeMessageSent(message);
  const QuicData& data = message.GetSerialized(session()->perspective());
  WriteOrBufferData(QuicStringPiece(data.data(), data.length()), false,
                    nullptr);
}

bool QuicCryptoStream::ExportKeyingMaterial(QuicStringPiece label,
                                            QuicStringPiece context,
                                            size_t result_len,
                                            string* result) const {
  if (!handshake_confirmed()) {
    QUIC_DLOG(ERROR) << "ExportKeyingMaterial was called before forward-secure"
                     << "encryption was established.";
    return false;
  }
  return CryptoUtils::ExportKeyingMaterial(
      crypto_negotiated_params_->subkey_secret, label, context, result_len,
      result);
}

bool QuicCryptoStream::ExportTokenBindingKeyingMaterial(string* result) const {
  if (!encryption_established()) {
    QUIC_BUG << "ExportTokenBindingKeyingMaterial was called before initial"
             << "encryption was established.";
    return false;
  }
  return CryptoUtils::ExportKeyingMaterial(
      crypto_negotiated_params_->initial_subkey_secret,
      "EXPORTER-Token-Binding",
      /* context= */ "", 32, result);
}

const QuicCryptoNegotiatedParameters&
QuicCryptoStream::crypto_negotiated_params() const {
  return *crypto_negotiated_params_;
}

}  // namespace net
