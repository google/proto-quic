// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_certificate_chain.h"

#include <memory>

#include "base/logging.h"
#include "net/cert/internal/name_constraints.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_signed_data.h"
#include "net/der/input.h"
#include "net/der/parser.h"

namespace net {

namespace {

// Returns true if the certificate does not contain any unconsumed _critical_
// extensions.
WARN_UNUSED_RESULT bool VerifyNoUnconsumedCriticalExtensions(
    const ParsedCertificate& cert) {
  for (const auto& entry : cert.unparsed_extensions()) {
    if (entry.second.critical)
      return false;
  }
  return true;
}

// Returns true if |cert| was self-issued. The definition of self-issuance
// comes from RFC 5280 section 6.1:
//
//    A certificate is self-issued if the same DN appears in the subject
//    and issuer fields (the two DNs are the same if they match according
//    to the rules specified in Section 7.1).  In general, the issuer and
//    subject of the certificates that make up a path are different for
//    each certificate.  However, a CA may issue a certificate to itself to
//    support key rollover or changes in certificate policies.  These
//    self-issued certificates are not counted when evaluating path length
//    or name constraints.
WARN_UNUSED_RESULT bool IsSelfIssued(const ParsedCertificate& cert) {
  return cert.normalized_subject() == cert.normalized_issuer();
}

// Returns true if |cert| is valid at time |time|.
//
// The certificate's validity requirements are described by RFC 5280 section
// 4.1.2.5:
//
//    The validity period for a certificate is the period of time from
//    notBefore through notAfter, inclusive.
WARN_UNUSED_RESULT bool VerifyTimeValidity(const ParsedCertificate& cert,
                                           const der::GeneralizedTime time) {
  return !(time < cert.tbs().validity_not_before) &&
         !(cert.tbs().validity_not_after < time);
}

// Returns true if |signature_algorithm_tlv| is a valid algorithm encoding for
// RSA with SHA1.
WARN_UNUSED_RESULT bool IsRsaWithSha1SignatureAlgorithm(
    const der::Input& signature_algorithm_tlv) {
  std::unique_ptr<SignatureAlgorithm> algorithm =
      SignatureAlgorithm::CreateFromDer(signature_algorithm_tlv);

  return algorithm &&
         algorithm->algorithm() == SignatureAlgorithmId::RsaPkcs1 &&
         algorithm->digest() == DigestAlgorithm::Sha1;
}

// Returns true if |cert| has internally consistent signature algorithms.
//
// X.509 certificates contain two different signature algorithms:
//  (1) The signatureAlgorithm field of Certificate
//  (2) The signature field of TBSCertificate
//
// According to RFC 5280 section 4.1.1.2 and 4.1.2.3 these two fields must be
// equal:
//
//     This field MUST contain the same algorithm identifier as the
//     signature field in the sequence tbsCertificate (Section 4.1.2.3).
//
// The spec is not explicit about what "the same algorithm identifier" means.
// Our interpretation is that the two DER-encoded fields must be byte-for-byte
// identical.
//
// In practice however there are certificates which use different encodings for
// specifying RSA with SHA1 (different OIDs). This is special-cased for
// compatibility sake.
WARN_UNUSED_RESULT bool VerifySignatureAlgorithmsMatch(
    const ParsedCertificate& cert) {
  const der::Input& alg1_tlv = cert.signature_algorithm_tlv();
  const der::Input& alg2_tlv = cert.tbs().signature_algorithm_tlv;

  // Ensure that the two DER-encoded signature algorithms are byte-for-byte
  // equal, but make a compatibility concession for RSA with SHA1.
  return alg1_tlv == alg2_tlv || (IsRsaWithSha1SignatureAlgorithm(alg1_tlv) &&
                                  IsRsaWithSha1SignatureAlgorithm(alg2_tlv));
}

// This function corresponds to RFC 5280 section 6.1.3's "Basic Certificate
// Processing" procedure.
//
// |skip_issuer_checks| controls whether the function will skip:
//   - Checking that |cert|'s signature using |working_spki|
//   - Checkinging that |cert|'s issuer matches |working_normalized_issuer_name|
// This should be set to true only when verifying a trusted root certificate.
WARN_UNUSED_RESULT bool BasicCertificateProcessing(
    const ParsedCertificate& cert,
    bool is_target_cert,
    bool skip_issuer_checks,
    const SignaturePolicy* signature_policy,
    const der::GeneralizedTime& time,
    const der::Input& working_spki,
    const der::Input& working_normalized_issuer_name,
    const std::vector<const NameConstraints*>& name_constraints_list) {
  // Check that the signature algorithms in Certificate vs TBSCertificate
  // match. This isn't part of RFC 5280 section 6.1.3, but is mandated by
  // sections 4.1.1.2 and 4.1.2.3.
  if (!VerifySignatureAlgorithmsMatch(cert))
    return false;

  // Verify the digital signature using the previous certificate's key (RFC
  // 5280 section 6.1.3 step a.1).
  if (!skip_issuer_checks) {
    if (!cert.has_valid_supported_signature_algorithm() ||
        !VerifySignedData(cert.signature_algorithm(),
                          cert.tbs_certificate_tlv(), cert.signature_value(),
                          working_spki, signature_policy)) {
      return false;
    }
  }

  // Check the time range for the certificate's validity, ensuring it is valid
  // at |time|.
  // (RFC 5280 section 6.1.3 step a.2)
  if (!VerifyTimeValidity(cert, time))
    return false;

  // TODO(eroman): Check revocation (RFC 5280 section 6.1.3 step a.3)

  // Verify the certificate's issuer name matches the issuing certificate's
  // subject name. (RFC 5280 section 6.1.3 step a.4)
  if (!skip_issuer_checks) {
    if (cert.normalized_issuer() != working_normalized_issuer_name)
      return false;
  }

  // Name constraints (RFC 5280 section 6.1.3 step b & c)
  // If certificate i is self-issued and it is not the final certificate in the
  // path, skip this step for certificate i.
  if (!name_constraints_list.empty() &&
      (!IsSelfIssued(cert) || is_target_cert)) {
    for (const NameConstraints* nc : name_constraints_list) {
      if (!nc->IsPermittedCert(cert.normalized_subject(),
                               cert.subject_alt_names())) {
        return false;
      }
    }
  }

  // TODO(eroman): Steps d-f are omitted, as policy constraints are not yet
  // implemented.

  return true;
}

// This function corresponds to RFC 5280 section 6.1.4's "Preparation for
// Certificate i+1" procedure. |cert| is expected to be an intermediary.
WARN_UNUSED_RESULT bool PrepareForNextCertificate(
    const ParsedCertificate& cert,
    size_t* max_path_length_ptr,
    der::Input* working_spki,
    der::Input* working_normalized_issuer_name,
    std::vector<const NameConstraints*>* name_constraints_list) {
  // TODO(eroman): Steps a-b are omitted, as policy constraints are not yet
  // implemented.

  // From RFC 5280 section 6.1.4 step c:
  //
  //    Assign the certificate subject name to working_normalized_issuer_name.
  *working_normalized_issuer_name = cert.normalized_subject();

  // From RFC 5280 section 6.1.4 step d:
  //
  //    Assign the certificate subjectPublicKey to working_public_key.
  *working_spki = cert.tbs().spki_tlv;

  // Note that steps e and f are omitted as they are handled by
  // the assignment to |working_spki| above. See the definition
  // of |working_spki|.

  // From RFC 5280 section 6.1.4 step g:
  if (cert.has_name_constraints())
    name_constraints_list->push_back(&cert.name_constraints());

  // TODO(eroman): Steps h-j are omitted as policy constraints are not yet
  // implemented.

  // From RFC 5280 section 6.1.4 step k:
  //
  //    If certificate i is a version 3 certificate, verify that the
  //    basicConstraints extension is present and that cA is set to
  //    TRUE.  (If certificate i is a version 1 or version 2
  //    certificate, then the application MUST either verify that
  //    certificate i is a CA certificate through out-of-band means
  //    or reject the certificate.  Conforming implementations may
  //    choose to reject all version 1 and version 2 intermediate
  //    certificates.)
  //
  // This code implicitly rejects non version 3 intermediaries, since they
  // can't contain a BasicConstraints extension.
  if (!cert.has_basic_constraints() || !cert.basic_constraints().is_ca)
    return false;

  // From RFC 5280 section 6.1.4 step l:
  //
  //    If the certificate was not self-issued, verify that
  //    max_path_length is greater than zero and decrement
  //    max_path_length by 1.
  if (!IsSelfIssued(cert)) {
    if (*max_path_length_ptr == 0)
      return false;
    --(*max_path_length_ptr);
  }

  // From RFC 5280 section 6.1.4 step m:
  //
  //    If pathLenConstraint is present in the certificate and is
  //    less than max_path_length, set max_path_length to the value
  //    of pathLenConstraint.
  if (cert.basic_constraints().has_path_len &&
      cert.basic_constraints().path_len < *max_path_length_ptr) {
    *max_path_length_ptr = cert.basic_constraints().path_len;
  }

  // From RFC 5280 section 6.1.4 step n:
  //
  //    If a key usage extension is present, verify that the
  //    keyCertSign bit is set.
  if (cert.has_key_usage() &&
      !cert.key_usage().AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN)) {
    return false;
  }

  // From RFC 5280 section 6.1.4 step o:
  //
  //    Recognize and process any other critical extension present in
  //    the certificate.  Process any other recognized non-critical
  //    extension present in the certificate that is relevant to path
  //    processing.
  if (!VerifyNoUnconsumedCriticalExtensions(cert))
    return false;

  return true;
}

// Checks that if the target certificate has properties that only a CA should
// have (keyCertSign, CA=true, pathLenConstraint), then its other properties
// are consistent with being a CA.
//
// This follows from some requirements in RFC 5280 section 4.2.1.9. In
// particular:
//
//    CAs MUST NOT include the pathLenConstraint field unless the cA
//    boolean is asserted and the key usage extension asserts the
//    keyCertSign bit.
//
// And:
//
//    If the cA boolean is not asserted, then the keyCertSign bit in the key
//    usage extension MUST NOT be asserted.
//
// TODO(eroman): Strictly speaking the first requirement is on CAs and not the
// certificate client, so could be skipped.
//
// TODO(eroman): I don't believe Firefox enforces the keyCertSign restriction
// for compatibility reasons. Investigate if we need to similarly relax this
// constraint.
WARN_UNUSED_RESULT bool VerifyTargetCertHasConsistentCaBits(
    const ParsedCertificate& cert) {
  // Check if the certificate contains any property specific to CAs.
  bool has_ca_property =
      (cert.has_basic_constraints() &&
       (cert.basic_constraints().is_ca ||
        cert.basic_constraints().has_path_len)) ||
      (cert.has_key_usage() &&
       cert.key_usage().AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN));

  // If it "looks" like a CA because it has a CA-only property, then check that
  // it sets ALL the properties expected of a CA.
  if (has_ca_property) {
    return cert.has_basic_constraints() && cert.basic_constraints().is_ca &&
           (!cert.has_key_usage() ||
            cert.key_usage().AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN));
  }

  return true;
}

// This function corresponds with RFC 5280 section 6.1.5's "Wrap-Up Procedure".
// It does processing for the final certificate (the target cert).
WARN_UNUSED_RESULT bool WrapUp(const ParsedCertificate& cert) {
  // TODO(eroman): Steps a-b are omitted as policy constraints are not yet
  // implemented.

  // Note step c-e are omitted the verification function does
  // not output the working public key.

  // From RFC 5280 section 6.1.5 step f:
  //
  //    Recognize and process any other critical extension present in
  //    the certificate n.  Process any other recognized non-critical
  //    extension present in certificate n that is relevant to path
  //    processing.
  //
  // Note that this is duplicated by PrepareForNextCertificate() so as to
  // directly match the procedures in RFC 5280's section 6.1.
  if (!VerifyNoUnconsumedCriticalExtensions(cert))
    return false;

  // TODO(eroman): Step g is omitted, as policy constraints are not yet
  // implemented.

  // The following check is NOT part of RFC 5280 6.1.5's "Wrap-Up Procedure",
  // however is implied by RFC 5280 section 4.2.1.9.
  if (!VerifyTargetCertHasConsistentCaBits(cert))
    return false;

  return true;
}

}  // namespace

// TODO(eroman): Move this into existing anonymous namespace.
namespace {

// This implementation is structured to mimic the description of certificate
// path verification given by RFC 5280 section 6.1.
//
// Unlike RFC 5280, the trust anchor is specified as the root certificate in
// the chain. This root certificate is assumed to be trusted, and neither its
// signature nor issuer name are verified. (It needn't be self-signed).
bool VerifyCertificateChainAssumingTrustedRoot(
    const std::vector<scoped_refptr<ParsedCertificate>>& certs,
    // The trust store is only used for assertions.
    const TrustStore& trust_store,
    const SignaturePolicy* signature_policy,
    const der::GeneralizedTime& time) {
  // An empty chain is necessarily invalid.
  if (certs.empty())
    return false;

  // IMPORTANT: the assumption being made is that the root certificate in
  // the given path is the trust anchor (and has already been verified as
  // such).
  DCHECK(trust_store.IsTrustedCertificate(certs.back().get()));

  // Will contain a NameConstraints for each previous cert in the chain which
  // had nameConstraints. This corresponds to the permitted_subtrees and
  // excluded_subtrees state variables from RFC 5280.
  std::vector<const NameConstraints*> name_constraints_list;

  // |working_spki| is an amalgamation of 3 separate variables from RFC 5280:
  //    * working_public_key
  //    * working_public_key_algorithm
  //    * working_public_key_parameters
  //
  // They are combined for simplicity since the signature verification takes an
  // SPKI, and the parameter inheritence is not applicable for the supported
  // key types.
  //
  // An approximate explanation of |working_spki| is this description from RFC
  // 5280 section 6.1.2:
  //
  //    working_public_key:  the public key used to verify the
  //    signature of a certificate.
  der::Input working_spki;

  // |working_normalized_issuer_name| is the normalized value of the
  // working_issuer_name variable in RFC 5280 section 6.1.2:
  //
  //    working_issuer_name:  the issuer distinguished name expected
  //    in the next certificate in the chain.
  der::Input working_normalized_issuer_name;

  // |max_path_length| corresponds with the same named variable in RFC 5280
  // section 6.1.2:
  //
  //    max_path_length:  this integer is initialized to n, is
  //    decremented for each non-self-issued certificate in the path,
  //    and may be reduced to the value in the path length constraint
  //    field within the basic constraints extension of a CA
  //    certificate.
  size_t max_path_length = certs.size();

  // Iterate over all the certificates in the reverse direction: starting from
  // the trust anchor and progressing towards the target certificate.
  //
  // Note that |i| uses 0-based indexing whereas in RFC 5280 it is 1-based.
  //
  //   * i=0    :  Trust anchor.
  //   * i=N-1  :  Target certificate.
  for (size_t i = 0; i < certs.size(); ++i) {
    const size_t index_into_certs = certs.size() - i - 1;

    // |is_target_cert| is true if the current certificate is the target
    // certificate being verified. The target certificate isn't necessarily an
    // end-entity certificate.
    const bool is_target_cert = index_into_certs == 0;

    // |is_trust_anchor| is true if the current certificate is the trust
    // anchor. This certificate is implicitly trusted.
    const bool is_trust_anchor = i == 0;

    const ParsedCertificate& cert = *certs[index_into_certs];

    // Per RFC 5280 section 6.1:
    //  * Do basic processing for each certificate
    //  * If it is the last certificate in the path (target certificate)
    //     - Then run "Wrap up"
    //     - Otherwise run "Prepare for Next cert"
    if (!BasicCertificateProcessing(cert, is_target_cert, is_trust_anchor,
                                    signature_policy, time, working_spki,
                                    working_normalized_issuer_name,
                                    name_constraints_list)) {
      return false;
    }
    if (!is_target_cert) {
      if (!PrepareForNextCertificate(cert, &max_path_length, &working_spki,
                                     &working_normalized_issuer_name,
                                     &name_constraints_list)) {
        return false;
      }
    } else {
      if (!WrapUp(cert))
        return false;
    }
  }

  // TODO(eroman): RFC 5280 forbids duplicate certificates per section 6.1:
  //
  //    A certificate MUST NOT appear more than once in a prospective
  //    certification path.

  return true;
}

// TODO(eroman): This function is a temporary hack in the absence of full
// path building. It may insert 1 certificate at the root of the
// chain to ensure that the path's root certificate is a trust anchor.
//
// Beyond this no other verification is done on the chain. The caller is
// responsible for verifying the subsequent chain's correctness.
WARN_UNUSED_RESULT bool BuildSimplePathToTrustAnchor(
    const TrustStore& trust_store,
    std::vector<scoped_refptr<ParsedCertificate>>* certs) {
  if (certs->empty())
    return false;

  // Check if the current root certificate is trusted. If it is then no
  // extra work is needed.
  if (trust_store.IsTrustedCertificate(certs->back().get()))
    return true;

  std::vector<scoped_refptr<ParsedCertificate>> trust_anchors;
  trust_store.FindTrustAnchorsByNormalizedName(
      certs->back()->normalized_issuer(), &trust_anchors);
  if (trust_anchors.empty())
    return false;
  // TODO(mattm): this only tries the first match, even if there are multiple.
  certs->push_back(std::move(trust_anchors[0]));
  return true;
}

}  // namespace

bool VerifyCertificateChain(
    const std::vector<scoped_refptr<ParsedCertificate>>& cert_chain,
    const TrustStore& trust_store,
    const SignaturePolicy* signature_policy,
    const der::GeneralizedTime& time,
    std::vector<scoped_refptr<ParsedCertificate>>* trusted_chain_out) {
  if (cert_chain.empty())
    return false;

  std::vector<scoped_refptr<ParsedCertificate>> full_chain = cert_chain;

  // Modify the certificate chain so that its root is a trusted certificate.
  if (!BuildSimplePathToTrustAnchor(trust_store, &full_chain))
    return false;

  // Verify the chain.
  bool success = VerifyCertificateChainAssumingTrustedRoot(
      full_chain, trust_store, signature_policy, time);
  if (success && trusted_chain_out != nullptr)
    *trusted_chain_out = std::move(full_chain);
  return success;
}

}  // namespace net
