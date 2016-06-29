// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_STATELESS_REJECTOR_H_
#define NET_QUIC_STATELESS_REJECTOR_H_

#include "base/strings/string_piece.h"
#include "net/quic/crypto/crypto_framer.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/quic_protocol.h"

namespace net {

// The StatelessRejector receives CHLO messages and generates an SREJ
// message in response, if the CHLO can be statelessly rejected.
class StatelessRejector {
 public:
  enum State {
    UNSUPPORTED,  // Stateless rejects are not supported
    FAILED,       // There was an error processing the CHLO.
    ACCEPTED,     // The CHLO was accepted
    REJECTED,     // The CHLO was rejected.
  };

  StatelessRejector(QuicVersion version,
                    const QuicVersionVector& versions,
                    const QuicCryptoServerConfig* crypto_config,
                    QuicCompressedCertsCache* compressed_certs_cache,
                    const QuicClock* clock,
                    QuicRandom* random,
                    const IPEndPoint& client_address,
                    const IPEndPoint& server_address);

  ~StatelessRejector();

  // Called when |chlo| is received for |connection_id| to determine
  // if it should be statelessly rejected.
  void OnChlo(QuicVersion version,
              QuicConnectionId connection_id,
              QuicConnectionId server_designated_connection_id,
              const CryptoHandshakeMessage& chlo);

  // Returns the state of the rejector after OnChlo() has been called.
  State state() const { return state_; }

  // Returns the error code when state() returns FAILED.
  QuicErrorCode error() const { return error_; }

  // Returns the error details when state() returns FAILED.
  std::string error_details() const { return error_details_; }

  // Returns the SREJ message when state() returns REJECTED.
  const CryptoHandshakeMessage& reply() const { return reply_; }

 private:
  // Helper class which is passed in to
  // QuicCryptoServerConfig::ValidateClientHello.
  class ValidateCallback;
  friend class ValidateCallback;

  void ProcessClientHello(
      const CryptoHandshakeMessage& client_hello,
      const ValidateClientHelloResultCallback::Result& result);

  State state_;
  QuicErrorCode error_;
  std::string error_details_;
  QuicVersion version_;
  QuicVersionVector versions_;
  QuicConnectionId connection_id_;
  QuicConnectionId server_designated_connection_id_;
  IPEndPoint client_address_;
  IPEndPoint server_address_;
  const QuicClock* clock_;
  QuicRandom* random_;
  const QuicCryptoServerConfig* crypto_config_;
  QuicCompressedCertsCache* compressed_certs_cache_;
  const CryptoHandshakeMessage* chlo_;
  CryptoHandshakeMessage reply_;
  CryptoFramer crypto_framer_;
  QuicCryptoProof proof_;

  DISALLOW_COPY_AND_ASSIGN(StatelessRejector);
};

}  // namespace net

#endif  // NET_QUIC_STATELESS_REJECTOR_H_
