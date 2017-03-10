// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_CRYPTO_PROOF_SOURCE_H_
#define NET_QUIC_CORE_CRYPTO_PROOF_SOURCE_H_

#include <memory>
#include <string>
#include <vector>

#include "net/quic/core/crypto/quic_crypto_proof.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_export.h"
#include "net/quic/platform/api/quic_reference_counted.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_string_piece.h"

namespace net {

// ProofSource is an interface by which a QUIC server can obtain certificate
// chains and signatures that prove its identity.
class QUIC_EXPORT_PRIVATE ProofSource {
 public:
  // Chain is a reference-counted wrapper for a vector of stringified
  // certificates.
  struct QUIC_EXPORT_PRIVATE Chain : public QuicReferenceCounted {
    explicit Chain(const std::vector<std::string>& certs);

    const std::vector<std::string> certs;

   protected:
    ~Chain() override;

   private:
    DISALLOW_COPY_AND_ASSIGN(Chain);
  };

  // Details is an abstract class which acts as a container for any
  // implementation-specific details that a ProofSource wants to return.
  class Details {
   public:
    virtual ~Details() {}
  };

  // Callback base class for receiving the results of an async call to GetProof.
  class Callback {
   public:
    Callback() {}
    virtual ~Callback() {}

    // Invoked upon completion of GetProof.
    //
    // |ok| indicates whether the operation completed successfully.  If false,
    // the values of the remaining three arguments are undefined.
    //
    // |chain| is a reference-counted pointer to an object representing the
    // certificate chain.
    //
    // |signature| contains the signature of the server config.
    //
    // |leaf_cert_sct| holds the signed timestamp (RFC6962) of the leaf cert.
    //
    // |details| holds a pointer to an object representing the statistics, if
    // any, gathered during the operation of GetProof.  If no stats are
    // available, this will be nullptr.
    virtual void Run(bool ok,
                     const QuicReferenceCountedPointer<Chain>& chain,
                     const QuicCryptoProof& proof,
                     std::unique_ptr<Details> details) = 0;

   private:
    Callback(const Callback&) = delete;
    Callback& operator=(const Callback&) = delete;
  };

  virtual ~ProofSource() {}

  // GetProof finds a certificate chain for |hostname| (in leaf-first order),
  // and calculates a signature of |server_config| using that chain.
  //
  // The signature uses SHA-256 as the hash function and PSS padding when the
  // key is RSA.
  //
  // The signature uses SHA-256 as the hash function when the key is ECDSA.
  // The signature may use an ECDSA key.
  //
  // The signature depends on |chlo_hash| which means that the signature can not
  // be cached.
  //
  // |hostname| may be empty to signify that a default certificate should be
  // used.
  //
  // This function may be called concurrently.
  //
  // Callers should expect that |callback| might be invoked synchronously.
  virtual void GetProof(const QuicSocketAddress& server_address,
                        const std::string& hostname,
                        const std::string& server_config,
                        QuicVersion quic_version,
                        QuicStringPiece chlo_hash,
                        const QuicTagVector& connection_options,
                        std::unique_ptr<Callback> callback) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CORE_CRYPTO_PROOF_SOURCE_H_
