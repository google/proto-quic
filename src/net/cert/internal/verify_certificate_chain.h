// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_

#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/der/input.h"

namespace net {

namespace der {
struct GeneralizedTime;
}

class ParsedCertificate;
class SignaturePolicy;
class TrustStore;

// VerifyCertificateChain() verifies a certificate path (chain) based on the
// rules in RFC 5280.
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
//      * cert_chain[N-1] must be the trust anchor, or have been directly
//        issued by a trust anchor.
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
//   trusted_chain_out:
//     The vector to populate with the verified trusted certificate chain.
//      * trusted_chain_out[0] is the target certificate verified.
//      * trusted_chain_out[i+1] holds the certificate that issued
//        trusted_chain_out[i].
//      * trusted_chain_out[N-1] is the trust anchor.
//     If a nullptr is passed, this parameter is ignored.
//     If the target certificate can not be verified, this parameter is
//     ignored.
//
// ---------
// Outputs
// ---------
//
//   Returns true if the target certificate can be verified.
NET_EXPORT bool VerifyCertificateChain(
    const std::vector<scoped_refptr<ParsedCertificate>>& cert_chain,
    const TrustStore& trust_store,
    const SignaturePolicy* signature_policy,
    const der::GeneralizedTime& time,
    std::vector<scoped_refptr<ParsedCertificate>>* trusted_chain_out)
    WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
