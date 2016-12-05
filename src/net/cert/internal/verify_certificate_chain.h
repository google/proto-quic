// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
#define NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_

#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/der/input.h"

namespace net {

namespace der {
struct GeneralizedTime;
}

class SignaturePolicy;
class TrustAnchor;

// VerifyCertificateChain() verifies a certificate path (chain) based on the
// rules in RFC 5280. The caller is responsible for building the path and
// finding the trust anchor.
//
// WARNING: This implementation is in progress, and is currently incomplete.
// Consult an OWNER before using it.
//
// TODO(eroman): Take a CertPath instead of ParsedCertificateList +
//               TrustAnchor.
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
//      * cert_chain[N-1] must be issued by the trust anchor.
//
//   trust_anchor:
//     Contains the trust anchor (root) used to verify the chain. Must be
//     non-null.
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
//
//   errors:
//     Must be non-null. The set of errors/warnings encountered while
//     validating the path are appended to this structure. There is no
//     guarantee that on success |errors| is empty, or conversely that
//     on failure |errors| is non-empty. Consumers must only use the
//     boolean return value to determine success/failure.
NET_EXPORT bool VerifyCertificateChain(const ParsedCertificateList& certs,
                                       const TrustAnchor* trust_anchor,
                                       const SignaturePolicy* signature_policy,
                                       const der::GeneralizedTime& time,
                                       CertErrors* errors) WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
