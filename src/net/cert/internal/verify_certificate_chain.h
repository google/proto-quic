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
struct CertificateTrust;

// The key purpose (extended key usage) to check for during verification.
enum class KeyPurpose {
  ANY_EKU,
  SERVER_AUTH,
  CLIENT_AUTH,
};

// VerifyCertificateChain() verifies an ordered certificate path in accordance
// with RFC 5280 (with some modifications [1]).
//
// [1] Deviations from RFC 5280:
//
//   * If Extended Key Usage appears on intermediates it is treated as a
//     restriction on subordinate certificates.
//
// The caller is responsible for additionally checking:
//
//  * The end-entity's KeyUsage before using its SPKI.
//  * The end-entity's name/subjectAltName (note that name constraints from
//    intermediates will have already been applied, so just need to check
//    the end-entity for a match).
//  * Policies
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
//     "forward" direction. The first certificate is the target certificate to
//     verify, and the last certificate has trustedness given by
//     |last_cert_trust|.
//
//      * cert_chain[0] is the target certificate to verify.
//      * cert_chain[i+1] holds the certificate that issued cert_chain[i].
//      * cert_chain[N-1] the root certificate
//
//   last_cert_trust:
//     Trustedness of certs.back(). The trustedness of certs.back() MUST BE
//     decided by the caller -- this function takes it purely as an input.
//     Moreover, the CertificateTrust can be used to specify trust anchor
//     constraints [1]
//
//   signature_policy:
//     The policy to use when verifying signatures (what hash algorithms are
//     allowed, what length keys, what named curves, etc).
//
//   time:
//     The UTC time to use for expiration checks.
//
//   key_purpose:
//     The key purpose that the target certificate needs to be valid for.
//
// ---------
// Outputs
// ---------
//   errors:
//     Must be non-null. The set of errors/warnings encountered while
//     validating the path are appended to this structure. If verification
//     failed, then there is guaranteed to be at least 1 high severity error
//     written to |errors|.
//
// [1] Conceptually VerifyCertificateChain() sets RFC 5937's
// "enforceTrustAnchorConstraints" to true. And one specifies whether to
// interpret a root certificate as having trust anchor constraints through the
// |last_cert_trust| parameter. The constraints are just a subset of the
// extensions present in the certificate:
//
//  * Signature:             No
//  * Validity (expiration): No
//  * Key usage:             No
//  * Extended key usage:    Yes (not part of RFC 5937)
//  * Basic constraints:     Yes, but only the pathlen (CA=false is accepted)
//  * Name constraints:      Yes
//  * Certificate policies:  Not currently, TODO(crbug.com/634453)
//  * inhibitAnyPolicy:      Not currently, TODO(crbug.com/634453)
//  * PolicyConstraints:     Not currently, TODO(crbug.com/634452)
//
// The presence of any other unrecognized extension marked as critical fails
// validation.
NET_EXPORT void VerifyCertificateChain(const ParsedCertificateList& certs,
                                       const CertificateTrust& last_cert_trust,
                                       const SignaturePolicy* signature_policy,
                                       const der::GeneralizedTime& time,
                                       KeyPurpose required_key_purpose,
                                       CertPathErrors* errors);

// TODO(crbug.com/634443): Move exported errors to a central location?
extern CertErrorId kValidityFailedNotAfter;
extern CertErrorId kValidityFailedNotBefore;
NET_EXPORT extern CertErrorId kCertIsDistrusted;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_CERTIFICATE_CHAIN_H_
