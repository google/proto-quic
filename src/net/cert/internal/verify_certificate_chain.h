// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"

namespace net {

namespace der {
class Input;
struct GeneralizedTime;
}

class SignaturePolicy;

struct NET_EXPORT TrustAnchor {
  ~TrustAnchor();

  // DER-encoded SubjectPublicKeyInfo for the trusted key.
  std::string spki;

  // DER-encoded "Name" corresponding to the key.
  std::string name;
};

// A very simple implementation of a TrustStore, which contains mappings from
// names to trusted public keys.
struct NET_EXPORT TrustStore {
  TrustStore();
  ~TrustStore();

  std::vector<TrustAnchor> anchors;
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
