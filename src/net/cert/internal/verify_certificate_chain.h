// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_

#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/der/input.h"

namespace net {

namespace der {
struct GeneralizedTime;
}

class SignaturePolicy;
class TrustStore;

// VerifyCertificateChainAssumingTrustedRoot() verifies a certificate path
// (chain) based on the rules in RFC 5280. The caller is responsible for
// building the path and ensuring the chain ends in a trusted root certificate.
//
// WARNING: This implementation is in progress, and is currently incomplete.
// Consult an OWNER before using it.
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
//      * cert_chain[N-1] must be the trust anchor.
//
//   trust_store:
//     Contains the set of trusted public keys (and their names). This is only
//     used to DCHECK that the final cert is a trust anchor.
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
NET_EXPORT bool VerifyCertificateChainAssumingTrustedRoot(
    const ParsedCertificateList& certs,
    // The trust store is only used for assertions.
    const TrustStore& trust_store,
    const SignaturePolicy* signature_policy,
    const der::GeneralizedTime& time) WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
