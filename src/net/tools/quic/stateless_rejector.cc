// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/stateless_rejector.h"

#include "net/quic/core/quic_crypto_server_stream.h"
#include "net/quic/core/quic_flags.h"

namespace net {

class StatelessRejector::ValidateCallback
    : public ValidateClientHelloResultCallback {
 public:
  explicit ValidateCallback(
      std::unique_ptr<StatelessRejector> rejector,
      std::unique_ptr<StatelessRejector::ProcessDoneCallback> cb)
      : rejector_(std::move(rejector)), cb_(std::move(cb)) {}

  ~ValidateCallback() override {}

  void Run(std::unique_ptr<Result> result,
           std::unique_ptr<ProofSource::Details> /* proof_source_details */)
      override {
    StatelessRejector* rejector_ptr = rejector_.get();
    rejector_ptr->ProcessClientHello(*result, std::move(rejector_),
                                     std::move(cb_));
  }

 private:
  std::unique_ptr<StatelessRejector> rejector_;
  std::unique_ptr<StatelessRejector::ProcessDoneCallback> cb_;
};

StatelessRejector::StatelessRejector(
    QuicVersion version,
    const QuicVersionVector& versions,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicClock* clock,
    QuicRandom* random,
    QuicByteCount chlo_packet_size,
    const IPEndPoint& client_address,
    const IPEndPoint& server_address)
    : state_(UNKNOWN),
      error_(QUIC_INTERNAL_ERROR),
      version_(version),
      versions_(versions),
      connection_id_(0),
      chlo_packet_size_(chlo_packet_size),
      client_address_(client_address),
      server_address_(server_address),
      clock_(clock),
      random_(random),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache) {}

StatelessRejector::~StatelessRejector() {}

void StatelessRejector::OnChlo(QuicVersion version,
                               QuicConnectionId connection_id,
                               QuicConnectionId server_designated_connection_id,
                               const CryptoHandshakeMessage& message) {
  DCHECK_EQ(kCHLO, message.tag());
  DCHECK_NE(connection_id, server_designated_connection_id);
  DCHECK_EQ(state_, UNKNOWN);

  if (!FLAGS_enable_quic_stateless_reject_support ||
      !FLAGS_quic_use_cheap_stateless_rejects ||
      !QuicCryptoServerStream::DoesPeerSupportStatelessRejects(message) ||
      version <= QUIC_VERSION_32) {
    state_ = UNSUPPORTED;
    return;
  }

  connection_id_ = connection_id;
  server_designated_connection_id_ = server_designated_connection_id;
  chlo_ = message;  // Note: copies the message
}

void StatelessRejector::Process(std::unique_ptr<StatelessRejector> rejector,
                                std::unique_ptr<ProcessDoneCallback> cb) {
  // If we were able to make a decision about this CHLO based purely on the
  // information available in OnChlo, just invoke the done callback immediately.
  if (rejector->state() != UNKNOWN) {
    cb->Run(std::move(rejector));
    return;
  }

  StatelessRejector* rejector_ptr = rejector.get();
  rejector_ptr->crypto_config_->ValidateClientHello(
      rejector_ptr->chlo_, rejector_ptr->client_address_.address(),
      rejector_ptr->server_address_.address(), rejector_ptr->version_,
      rejector_ptr->clock_, &rejector_ptr->proof_,
      std::unique_ptr<ValidateCallback>(
          new ValidateCallback(std::move(rejector), std::move(cb))));
}

void StatelessRejector::ProcessClientHello(
    const ValidateClientHelloResultCallback::Result& result,
    std::unique_ptr<StatelessRejector> rejector,
    std::unique_ptr<StatelessRejector::ProcessDoneCallback> cb) {
  QuicCryptoNegotiatedParameters params;
  DiversificationNonce diversification_nonce;
  QuicErrorCode error = crypto_config_->ProcessClientHello(
      result,
      /*reject_only=*/true, connection_id_, server_address_.address(),
      client_address_, version_, versions_,
      /*use_stateless_rejects=*/true, server_designated_connection_id_, clock_,
      random_, compressed_certs_cache_, &params, &proof_,
      QuicCryptoStream::CryptoMessageFramingOverhead(version_),
      chlo_packet_size_, &reply_, &diversification_nonce, &error_details_);
  if (error != QUIC_NO_ERROR) {
    error_ = error;
    state_ = FAILED;
  } else if (reply_.tag() == kSREJ) {
    state_ = REJECTED;
  } else {
    state_ = ACCEPTED;
  }
  cb->Run(std::move(rejector));
}

}  // namespace net
