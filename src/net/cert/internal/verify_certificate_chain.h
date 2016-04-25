// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "net/base/net_export.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/der/input.h"

namespace net {

namespace der {
struct GeneralizedTime;
}

class SignaturePolicy;

// Represents a trust anchor (i.e. a trusted root certificate).
class NET_EXPORT TrustAnchor {
 public:
  // The certificate data for this trust anchor may either be owned internally
  // (INTERNAL_COPY) or owned externally (EXTERNAL_REFERENCE). When it is
  // owned internally the data is held by |cert_data_|
  enum class DataSource {
    INTERNAL_COPY,
    EXTERNAL_REFERENCE,
  };

  TrustAnchor();
  ~TrustAnchor();

  // Creates a TrustAnchor given a DER-encoded certificate. Returns nullptr on
  // failure. Failure will occur if the certificate data cannot be parsed to
  // find a subject.
  //
  // The provided certificate data is either copied, or aliased, depending on
  // the value of |source|. See the comments for DataSource for details.
  static std::unique_ptr<TrustAnchor> CreateFromCertificateData(
      const uint8_t* data,
      size_t length,
      DataSource source);

  // Returns true if the trust anchor matches |name|. In other words, returns
  // true if the certificate's subject matches |name|.
  bool MatchesName(const der::Input& name) const;

  // Returns the DER-encoded certificate data for this trust anchor.
  const der::Input& cert() const { return cert_; }

 private:
  // The backing store for the certificate data. This is only applicable when
  // the trust anchor was initialized using DataSource::INTERNAL_COPY.
  std::vector<uint8_t> cert_data_;

  // Note that the backing data for |cert_| and |name_| may come either form
  // |cert_data_| or some external buffer (depending on how the anchor was
  // created).

  // Points to the raw certificate DER.
  der::Input cert_;

  // Points to the subject TLV for the certificate.
  der::Input name_;

  DISALLOW_COPY_AND_ASSIGN(TrustAnchor);
};

// A very simple implementation of a TrustStore, which contains a set of
// trusted certificates.
class NET_EXPORT TrustStore {
 public:
  TrustStore();
  ~TrustStore();

  // Empties the trust store, resetting it to original state.
  void Clear();

  // Adds a trusted certificate to the store. The trust store makes a copy of
  // the provided certificate data.
  bool AddTrustedCertificate(const uint8_t* data,
                             size_t length) WARN_UNUSED_RESULT;
  bool AddTrustedCertificate(const base::StringPiece& data) WARN_UNUSED_RESULT;

  // This function is the same as AddTrustedCertificate() except the underlying
  // data is not copied. The caller is responsible for ensuring that the data
  // pointer remains alive and is not mutated for the lifetime of the
  // TrustStore.
  bool AddTrustedCertificateWithoutCopying(const uint8_t* data,
                                           size_t length) WARN_UNUSED_RESULT;

  // Returns the trust anchor that matches |name|, or nullptr if there is none.
  // TODO(eroman): There may be multiple matches.
  const TrustAnchor* FindTrustAnchorByName(const der::Input& name) const
      WARN_UNUSED_RESULT;

  // Returns true if |cert_der| matches a certificate in the TrustStore.
  bool IsTrustedCertificate(const der::Input& cert_der) const
      WARN_UNUSED_RESULT;

 private:
  bool AddTrustedCertificate(const uint8_t* data,
                             size_t length,
                             TrustAnchor::DataSource source) WARN_UNUSED_RESULT;

  std::vector<std::unique_ptr<TrustAnchor>> anchors_;

  DISALLOW_COPY_AND_ASSIGN(TrustStore);
};

// VerifyCertificateChain() verifies a certificate path (chain) based on the
// rules in RFC 5280.
//
// WARNING: This implementation is in progress, and is currently
// incomplete. DO NOT USE IT unless its limitations are acceptable for your use.
//
// ---------
// Inputs
// ---------
//
//   cert_chain:
//     A non-empty chain of N DER-encoded certificates, listed in the
//     "forward" direction.
//
//      * cert_chain[0] is the target certificate to verify.
//      * cert_chain[i+1] holds the certificate that issued cert_chain[i].
//      * cert_chain[N-1] must have been issued by a trust anchor
//
//   trust_store:
//     Contains the set of trusted public keys (and their names).
//
//   signature_policy:
//     The policy to use when verifying signatures (what hash algorithms are
//     allowed, what length keys, what named curves, etc).
//
//   time:
//     The UTC time to use for expiration checks.
//
// ---------
// Outputs
// ---------
//
//   Returns true if the target certificate can be verified.
NET_EXPORT bool VerifyCertificateChain(const std::vector<der::Input>& certs_der,
                                       const TrustStore& trust_store,
                                       const SignaturePolicy* signature_policy,
                                       const der::GeneralizedTime& time)
    WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
