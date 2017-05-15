// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_certificate_chain.h"

#include <memory>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "net/cert/internal/cert_error_params.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/extended_key_usage.h"
#include "net/cert/internal/name_constraints.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_signed_data.h"
#include "net/der/input.h"
#include "net/der/parser.h"

namespace net {

DEFINE_CERT_ERROR_ID(kValidityFailedNotAfter, "Time is after notAfter");
DEFINE_CERT_ERROR_ID(kValidityFailedNotBefore, "Time is before notBefore");
DEFINE_CERT_ERROR_ID(kCertIsDistrusted, "Certificate is distrusted");

namespace {

// -----------------------------------------------
// Errors/Warnings set by VerifyCertificateChain
// -----------------------------------------------

DEFINE_CERT_ERROR_ID(
    kSignatureAlgorithmMismatch,
    "Certificate.signatureAlgorithm != TBSCertificate.signature");
DEFINE_CERT_ERROR_ID(kChainIsEmpty, "Chain is empty");
DEFINE_CERT_ERROR_ID(kChainIsLength1,
                     "TODO: Cannot verify a chain of length 1");
DEFINE_CERT_ERROR_ID(kUnconsumedCriticalExtension,
                     "Unconsumed critical extension");
DEFINE_CERT_ERROR_ID(
    kTargetCertInconsistentCaBits,
    "Target certificate looks like a CA but does not set all CA properties");
DEFINE_CERT_ERROR_ID(kKeyCertSignBitNotSet, "keyCertSign bit is not set");
DEFINE_CERT_ERROR_ID(kMaxPathLengthViolated, "max_path_length reached");
DEFINE_CERT_ERROR_ID(kBasicConstraintsIndicatesNotCa,
                     "Basic Constraints indicates not a CA");
DEFINE_CERT_ERROR_ID(kMissingBasicConstraints,
                     "Does not have Basic Constraints");
DEFINE_CERT_ERROR_ID(kNotPermittedByNameConstraints,
                     "Not permitted by name constraints");
DEFINE_CERT_ERROR_ID(kSubjectDoesNotMatchIssuer,
                     "subject does not match issuer");
DEFINE_CERT_ERROR_ID(kVerifySignedDataFailed, "VerifySignedData failed");
DEFINE_CERT_ERROR_ID(kSignatureAlgorithmsDifferentEncoding,
                     "Certificate.signatureAlgorithm is encoded differently "
                     "than TBSCertificate.signature");
DEFINE_CERT_ERROR_ID(kEkuLacksServerAuth,
                     "The extended key usage does not include server auth");
DEFINE_CERT_ERROR_ID(kEkuLacksClientAuth,
                     "The extended key usage does not include client auth");
DEFINE_CERT_ERROR_ID(kCertIsNotTrustAnchor,
                     "Certificate is not a trust anchor");

bool IsHandledCriticalExtensionOid(const der::Input& oid) {
  if (oid == BasicConstraintsOid())
    return true;
  // Key Usage is NOT processed for end-entity certificates (this is the
  // responsibility of callers), however it is considered "handled" here in
  // order to allow being marked as critical.
  if (oid == KeyUsageOid())
    return true;
  if (oid == ExtKeyUsageOid())
    return true;
  if (oid == NameConstraintsOid())
    return true;
  if (oid == SubjectAltNameOid())
    return true;

  // TODO(eroman): Make this more complete.
  return false;
}

// Adds errors to |errors| if the certificate contains unconsumed _critical_
// extensions.
void VerifyNoUnconsumedCriticalExtensions(const ParsedCertificate& cert,
                                          CertErrors* errors) {
  for (const auto& it : cert.extensions()) {
    const ParsedExtension& extension = it.second;
    if (extension.critical && !IsHandledCriticalExtensionOid(extension.oid)) {
      errors->AddError(kUnconsumedCriticalExtension,
                       CreateCertErrorParams2Der("oid", extension.oid, "value",
                                                 extension.value));
    }
  }
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

// Adds errors to |errors| if |cert| is not valid at time |time|.
//
// The certificate's validity requirements are described by RFC 5280 section
// 4.1.2.5:
//
//    The validity period for a certificate is the period of time from
//    notBefore through notAfter, inclusive.
void VerifyTimeValidity(const ParsedCertificate& cert,
                        const der::GeneralizedTime time,
                        CertErrors* errors) {
  if (time < cert.tbs().validity_not_before)
    errors->AddError(kValidityFailedNotBefore);

  if (cert.tbs().validity_not_after < time)
    errors->AddError(kValidityFailedNotAfter);
}

// Adds errors to |errors| if |cert| has internally inconsistent signature
// algorithms.
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
void VerifySignatureAlgorithmsMatch(const ParsedCertificate& cert,
                                    CertErrors* errors) {
  const der::Input& alg1_tlv = cert.signature_algorithm_tlv();
  const der::Input& alg2_tlv = cert.tbs().signature_algorithm_tlv;

  // Ensure that the two DER-encoded signature algorithms are byte-for-byte
  // equal.
  if (alg1_tlv == alg2_tlv)
    return;

  // But make a compatibility concession if alternate encodings are used
  // TODO(eroman): Turn this warning into an error.
  // TODO(eroman): Add a unit-test that exercises this case.
  if (SignatureAlgorithm::IsEquivalent(alg1_tlv, alg2_tlv)) {
    errors->AddWarning(
        kSignatureAlgorithmsDifferentEncoding,
        CreateCertErrorParams2Der("Certificate.algorithm", alg1_tlv,
                                  "TBSCertificate.signature", alg2_tlv));
    return;
  }

  errors->AddError(
      kSignatureAlgorithmMismatch,
      CreateCertErrorParams2Der("Certificate.algorithm", alg1_tlv,
                                "TBSCertificate.signature", alg2_tlv));
}

// Verify that |cert| can be used for |required_key_purpose|.
void VerifyExtendedKeyUsage(const ParsedCertificate& cert,
                            KeyPurpose required_key_purpose,
                            CertErrors* errors) {
  switch (required_key_purpose) {
    case KeyPurpose::ANY_EKU:
      return;
    case KeyPurpose::SERVER_AUTH: {
      // TODO(eroman): Is it OK for the target certificate to omit the EKU?
      if (!cert.has_extended_key_usage())
        return;

      for (const auto& key_purpose_oid : cert.extended_key_usage()) {
        if (key_purpose_oid == AnyEKU())
          return;
        if (key_purpose_oid == ServerAuth())
          return;
      }

      errors->AddError(kEkuLacksServerAuth);
      break;
    }
    case KeyPurpose::CLIENT_AUTH: {
      // TODO(eroman): Is it OK for the target certificate to omit the EKU?
      if (!cert.has_extended_key_usage())
        return;

      for (const auto& key_purpose_oid : cert.extended_key_usage()) {
        if (key_purpose_oid == AnyEKU())
          return;
        if (key_purpose_oid == ClientAuth())
          return;
      }

      errors->AddError(kEkuLacksClientAuth);
      break;
    }
  }
}

// This function corresponds to RFC 5280 section 6.1.3's "Basic Certificate
// Processing" procedure.
void BasicCertificateProcessing(
    const ParsedCertificate& cert,
    bool is_target_cert,
    const SignaturePolicy* signature_policy,
    const der::GeneralizedTime& time,
    const der::Input& working_spki,
    const der::Input& working_normalized_issuer_name,
    const std::vector<const NameConstraints*>& name_constraints_list,
    CertErrors* errors) {
  // Check that the signature algorithms in Certificate vs TBSCertificate
  // match. This isn't part of RFC 5280 section 6.1.3, but is mandated by
  // sections 4.1.1.2 and 4.1.2.3.
  VerifySignatureAlgorithmsMatch(cert, errors);

  // Verify the digital signature using the previous certificate's key (RFC
  // 5280 section 6.1.3 step a.1).
  if (!VerifySignedData(cert.signature_algorithm(), cert.tbs_certificate_tlv(),
                        cert.signature_value(), working_spki, signature_policy,
                        errors)) {
    errors->AddError(kVerifySignedDataFailed);
  }

  // Check the time range for the certificate's validity, ensuring it is valid
  // at |time|.
  // (RFC 5280 section 6.1.3 step a.2)
  VerifyTimeValidity(cert, time, errors);

  // TODO(eroman): Check revocation (RFC 5280 section 6.1.3 step a.3)

  // Verify the certificate's issuer name matches the issuing certificate's
  // subject name. (RFC 5280 section 6.1.3 step a.4)
  if (cert.normalized_issuer() != working_normalized_issuer_name)
    errors->AddError(kSubjectDoesNotMatchIssuer);

  // Name constraints (RFC 5280 section 6.1.3 step b & c)
  // If certificate i is self-issued and it is not the final certificate in the
  // path, skip this step for certificate i.
  if (!name_constraints_list.empty() &&
      (!IsSelfIssued(cert) || is_target_cert)) {
    for (const NameConstraints* nc : name_constraints_list) {
      if (!nc->IsPermittedCert(cert.normalized_subject(),
                               cert.subject_alt_names())) {
        errors->AddError(kNotPermittedByNameConstraints);
      }
    }
  }

  // TODO(eroman): Steps d-f are omitted, as policy constraints are not yet
  // implemented.
}

// This function corresponds to RFC 5280 section 6.1.4's "Preparation for
// Certificate i+1" procedure. |cert| is expected to be an intermediate.
void PrepareForNextCertificate(
    const ParsedCertificate& cert,
    size_t* max_path_length_ptr,
    der::Input* working_spki,
    der::Input* working_normalized_issuer_name,
    std::vector<const NameConstraints*>* name_constraints_list,
    CertErrors* errors) {
  // TODO(crbug.com/634456): Steps a-b are omitted, as policy mappings are not
  // yet implemented.

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

  // TODO(eroman): Steps h-j are omitted as policy
  // constraints/mappings/inhibitAnyPolicy are not yet implemented.

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
  // This code implicitly rejects non version 3 intermediates, since they
  // can't contain a BasicConstraints extension.
  if (!cert.has_basic_constraints()) {
    errors->AddError(kMissingBasicConstraints);
  } else if (!cert.basic_constraints().is_ca) {
    errors->AddError(kBasicConstraintsIndicatesNotCa);
  }

  // From RFC 5280 section 6.1.4 step l:
  //
  //    If the certificate was not self-issued, verify that
  //    max_path_length is greater than zero and decrement
  //    max_path_length by 1.
  if (!IsSelfIssued(cert)) {
    if (*max_path_length_ptr == 0) {
      errors->AddError(kMaxPathLengthViolated);
    } else {
      --(*max_path_length_ptr);
    }
  }

  // From RFC 5280 section 6.1.4 step m:
  //
  //    If pathLenConstraint is present in the certificate and is
  //    less than max_path_length, set max_path_length to the value
  //    of pathLenConstraint.
  if (cert.has_basic_constraints() && cert.basic_constraints().has_path_len &&
      cert.basic_constraints().path_len < *max_path_length_ptr) {
    *max_path_length_ptr = cert.basic_constraints().path_len;
  }

  // From RFC 5280 section 6.1.4 step n:
  //
  //    If a key usage extension is present, verify that the
  //    keyCertSign bit is set.
  if (cert.has_key_usage() &&
      !cert.key_usage().AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN)) {
    errors->AddError(kKeyCertSignBitNotSet);
  }

  // From RFC 5280 section 6.1.4 step o:
  //
  //    Recognize and process any other critical extension present in
  //    the certificate.  Process any other recognized non-critical
  //    extension present in the certificate that is relevant to path
  //    processing.
  VerifyNoUnconsumedCriticalExtensions(cert, errors);
}

// Checks that if the target certificate has properties that only a CA should
// have (keyCertSign, CA=true, pathLenConstraint), then its other properties
// are consistent with being a CA. If it does, adds errors to |errors|.
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
void VerifyTargetCertHasConsistentCaBits(const ParsedCertificate& cert,
                                         CertErrors* errors) {
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
    bool success = cert.has_basic_constraints() &&
                   cert.basic_constraints().is_ca &&
                   (!cert.has_key_usage() ||
                    cert.key_usage().AssertsBit(KEY_USAGE_BIT_KEY_CERT_SIGN));
    if (!success) {
      // TODO(eroman): Add DER for basic constraints and key usage.
      errors->AddError(kTargetCertInconsistentCaBits);
    }
  }
}

// This function corresponds with RFC 5280 section 6.1.5's "Wrap-Up Procedure".
// It does processing for the final certificate (the target cert).
void WrapUp(const ParsedCertificate& cert, CertErrors* errors) {
  // TODO(crbug.com/634452): Steps a-b are omitted as policy constraints are not
  // yet implemented.

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
  VerifyNoUnconsumedCriticalExtensions(cert, errors);

  // TODO(eroman): Step g is omitted, as policy constraints are not yet
  // implemented.

  // The following check is NOT part of RFC 5280 6.1.5's "Wrap-Up Procedure",
  // however is implied by RFC 5280 section 4.2.1.9.
  VerifyTargetCertHasConsistentCaBits(cert, errors);
}

// Enforces trust anchor constraints compatibile with RFC 5937.
//
// Note that the anchor constraints are encoded via the attached certificate
// itself.
void ApplyTrustAnchorConstraints(
    const ParsedCertificate& cert,
    KeyPurpose required_key_purpose,
    size_t* max_path_length_ptr,
    std::vector<const NameConstraints*>* name_constraints_list,
    CertErrors* errors) {
  // This is not part of RFC 5937 nor RFC 5280, but matches the EKU handling
  // done for intermediates (described in Web PKI's Baseline Requirements).
  VerifyExtendedKeyUsage(cert, required_key_purpose, errors);

  // The following enforcements follow from RFC 5937 (primarily section 3.2):

  // Initialize name constraints initial-permitted/excluded-subtrees.
  if (cert.has_name_constraints())
    name_constraints_list->push_back(&cert.name_constraints());

  // TODO(eroman): Initialize user-initial-policy-set based on anchor
  // constraints.

  // TODO(eroman): Initialize inhibit any policy based on anchor constraints.

  // TODO(eroman): Initialize require explicit policy based on anchor
  // constraints.

  // TODO(eroman): Initialize inhibit policy mapping based on anchor
  // constraints.

  // From RFC 5937 section 3.2:
  //
  //    If a basic constraints extension is associated with the trust
  //    anchor and contains a pathLenConstraint value, set the
  //    max_path_length state variable equal to the pathLenConstraint
  //    value from the basic constraints extension.
  //
  // NOTE: RFC 5937 does not say to enforce the CA=true part of basic
  // constraints.
  if (cert.has_basic_constraints() && cert.basic_constraints().has_path_len)
    *max_path_length_ptr = cert.basic_constraints().path_len;

  // From RFC 5937 section 2:
  //
  //    Extensions may be marked critical or not critical.  When trust anchor
  //    constraints are enforced, clients MUST reject certification paths
  //    containing a trust anchor with unrecognized critical extensions.
  VerifyNoUnconsumedCriticalExtensions(cert, errors);
}

// Initializes the path validation algorithm given anchor constraints. This
// follows the description in RFC 5937
void ProcessRootCertificate(
    const ParsedCertificate& cert,
    const CertificateTrust& trust,
    KeyPurpose required_key_purpose,
    size_t* max_path_length_ptr,
    std::vector<const NameConstraints*>* name_constraints_list,
    der::Input* working_spki,
    der::Input* working_normalized_issuer_name,
    CertErrors* errors) {
  // Use the certificate's SPKI and subject when verifying the next certificate.
  // Note this is initialized even in the case of untrusted roots (they already
  // emit an error for the distrust).
  *working_spki = cert.tbs().spki_tlv;
  *working_normalized_issuer_name = cert.normalized_subject();

  switch (trust.type) {
    case CertificateTrustType::UNSPECIFIED:
      // Doesn't chain to a trust anchor - implicitly distrusted
      errors->AddError(kCertIsNotTrustAnchor);
      break;
    case CertificateTrustType::DISTRUSTED:
      // Chains to an actively distrusted certificate.
      errors->AddError(kCertIsDistrusted);
      break;
    case CertificateTrustType::TRUSTED_ANCHOR:
    case CertificateTrustType::TRUSTED_ANCHOR_WITH_CONSTRAINTS:
      // If the trust anchor has constraints, enforce them.
      if (trust.type == CertificateTrustType::TRUSTED_ANCHOR_WITH_CONSTRAINTS) {
        ApplyTrustAnchorConstraints(cert, required_key_purpose,
                                    max_path_length_ptr, name_constraints_list,
                                    errors);
      }
      break;
  }
}

}  // namespace

// This implementation is structured to mimic the description of certificate
// path verification given by RFC 5280 section 6.1.
void VerifyCertificateChain(const ParsedCertificateList& certs,
                            const CertificateTrust& last_cert_trust,
                            const SignaturePolicy* signature_policy,
                            const der::GeneralizedTime& time,
                            KeyPurpose required_key_purpose,
                            CertPathErrors* errors) {
  DCHECK(signature_policy);
  DCHECK(errors);

  // An empty chain is necessarily invalid.
  if (certs.empty()) {
    errors->GetOtherErrors()->AddError(kChainIsEmpty);
    return;
  }

  // TODO(eroman): Verifying a trusted leaf certificate is not currently
  // permitted.
  if (certs.size() == 1) {
    errors->GetOtherErrors()->AddError(kChainIsLength1);
    return;
  }

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
  // the root certificate and progressing towards the target certificate.
  //
  //   * i=0               :  Root certificate (i.e. trust anchor)
  //   * i=1               :  Certificated signed by the root certificate
  //   * i=certs.size()-1  :  Target certificate.
  for (size_t i = 0; i < certs.size(); ++i) {
    const size_t index_into_certs = certs.size() - i - 1;

    // |is_target_cert| is true if the current certificate is the target
    // certificate being verified. The target certificate isn't necessarily an
    // end-entity certificate.
    const bool is_target_cert = index_into_certs == 0;
    const bool is_root_cert = i == 0;

    const ParsedCertificate& cert = *certs[index_into_certs];

    // Output errors for the current certificate into an error bucket that is
    // associated with that certificate.
    CertErrors* cert_errors = errors->GetErrorsForCert(index_into_certs);

    if (is_root_cert) {
      ProcessRootCertificate(cert, last_cert_trust, required_key_purpose,
                             &max_path_length, &name_constraints_list,
                             &working_spki, &working_normalized_issuer_name,
                             cert_errors);

      // Don't do any other checks for root certificates.
      continue;
    }

    // Per RFC 5280 section 6.1:
    //  * Do basic processing for each certificate
    //  * If it is the last certificate in the path (target certificate)
    //     - Then run "Wrap up"
    //     - Otherwise run "Prepare for Next cert"
    BasicCertificateProcessing(cert, is_target_cert, signature_policy, time,
                               working_spki, working_normalized_issuer_name,
                               name_constraints_list, cert_errors);

    // The key purpose is checked not just for the end-entity certificate, but
    // also interpreted as a constraint when it appears in intermediates. This
    // goes beyond what RFC 5280 describes, but is the de-facto standard. See
    // https://wiki.mozilla.org/CA:CertificatePolicyV2.1#Frequently_Asked_Questions
    VerifyExtendedKeyUsage(cert, required_key_purpose, cert_errors);

    if (!is_target_cert) {
      PrepareForNextCertificate(cert, &max_path_length, &working_spki,
                                &working_normalized_issuer_name,
                                &name_constraints_list, cert_errors);
    } else {
      WrapUp(cert, cert_errors);
    }
  }

  // TODO(eroman): RFC 5280 forbids duplicate certificates per section 6.1:
  //
  //    A certificate MUST NOT appear more than once in a prospective
  //    certification path.
}

}  // namespace net
