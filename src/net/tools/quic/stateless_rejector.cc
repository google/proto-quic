// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/stateless_rejector.h"

#include "net/quic/quic_crypto_server_stream.h"
#include "net/quic/quic_flags.h"

namespace net {

class StatelessRejector::ValidateCallback
    : public ValidateClientHelloResultCallback {
 public:
  explicit ValidateCallback(StatelessRejector* rejector)
      : rejector_(rejector) {}

  ~ValidateCallback() override {}

  void RunImpl(const CryptoHandshakeMessage& client_hello,
               const Result& result) override {
    rejector_->ProcessClientHello(client_hello, result);
  }

 private:
  StatelessRejector* rejector_;
};

StatelessRejector::StatelessRejector(
    QuicVersion version,
    const QuicVersionVector& versions,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicClock* clock,
    QuicRandom* random,
    const IPEndPoint& client_address,
    const IPEndPoint& server_address)
    : state_(FAILED),
      error_(QUIC_INTERNAL_ERROR),
      version_(version),
      versions_(versions),
      connection_id_(0),
      client_address_(client_address),
      server_address_(server_address),
      clock_(clock),
      random_(random),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      chlo_(nullptr) {}

StatelessRejector::~StatelessRejector() {}

void StatelessRejector::OnChlo(QuicVersion version,
                               QuicConnectionId connection_id,
                               QuicConnectionId server_designated_connection_id,
                               const CryptoHandshakeMessage& message) {
  DCHECK_EQ(kCHLO, message.tag());
  DCHECK_NE(connection_id, server_designated_connection_id);

  if (!FLAGS_enable_quic_stateless_reject_support ||
      !FLAGS_quic_use_cheap_stateless_rejects ||
      !QuicCryptoServerStream::DoesPeerSupportStatelessRejects(message) ||
      version <= QUIC_VERSION_32) {
    state_ = UNSUPPORTED;
    return;
  }

  connection_id_ = connection_id;
  server_designated_connection_id_ = server_designated_connection_id;
  chlo_ = &message;

  crypto_config_->ValidateClientHello(
      message, client_address_.address(), server_address_.address(), version_,
      clock_, &proof_, new ValidateCallback(this));
}

void StatelessRejector::ProcessClientHello(
    const CryptoHandshakeMessage& client_hello,
    const ValidateClientHelloResultCallback::Result& result) {
  QuicCryptoNegotiatedParameters params;
  DiversificationNonce diversification_nonce;
  QuicErrorCode error = crypto_config_->ProcessClientHello(
      result,
      /*reject_only=*/true, connection_id_, server_address_.address(),
      client_address_, version_, versions_,
      /*use_stateless_rejects=*/true, server_designated_connection_id_, clock_,
      random_, compressed_certs_cache_, &params, &proof_, &reply_,
      &diversification_nonce, &error_details_);
  if (error != QUIC_NO_ERROR) {
    error_ = error;
    return;
  }

  if (reply_.tag() == kSREJ) {
    state_ = REJECTED;
    return;
  }

  state_ = ACCEPTED;
}

}  // namespace net
