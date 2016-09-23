// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/parse_certificate.h"

#include <utility>

#include "base/strings/string_util.h"
#include "net/cert/internal/cert_errors.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"

namespace net {

namespace {

DEFINE_CERT_ERROR_ID(kCertificateNotSequence,
                     "Failed parsing Certificate SEQUENCE");
DEFINE_CERT_ERROR_ID(kUnconsumedDataInsideCertificateSequence,
                     "Unconsumed data inside Certificate SEQUENCE");
DEFINE_CERT_ERROR_ID(kUnconsumedDataAfterCertificateSequence,
                     "Unconsumed data after Certificate SEQUENCE");
DEFINE_CERT_ERROR_ID(kTbsCertificateNotSequence,
                     "Couldn't read tbsCertificate as SEQUENCE");
DEFINE_CERT_ERROR_ID(
    kSignatureAlgorithmNotSequence,
    "Couldn't read Certificate.signatureAlgorithm as SEQUENCE");
DEFINE_CERT_ERROR_ID(kSignatureValueNotBitString,
                     "Couldn't read Certificate.signatureValue as BIT STRING");

DEFINE_CERT_ERROR_ID(kUnconsumedDataInsideTbsCertificateSequence,
                     "Unconsumed data inside TBSCertificate");

// Returns true if |input| is a SEQUENCE and nothing else.
WARN_UNUSED_RESULT bool IsSequenceTLV(const der::Input& input) {
  der::Parser parser(input);
  der::Parser unused_sequence_parser;
  if (!parser.ReadSequence(&unused_sequence_parser))
    return false;
  // Should by a single SEQUENCE by definition of the function.
  return !parser.HasMore();
}

// Reads a SEQUENCE from |parser| and writes the full tag-length-value into
// |out|. On failure |parser| may or may not have been advanced.
WARN_UNUSED_RESULT bool ReadSequenceTLV(der::Parser* parser, der::Input* out) {
  return parser->ReadRawTLV(out) && IsSequenceTLV(*out);
}

// Parses a Version according to RFC 5280:
//
//     Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
//
// No value other that v1, v2, or v3 is allowed (and if given will fail). RFC
// 5280 minimally requires the handling of v3 (and overwhelmingly these are the
// certificate versions in use today):
//
//     Implementations SHOULD be prepared to accept any version certificate.
//     At a minimum, conforming implementations MUST recognize version 3
//     certificates.
WARN_UNUSED_RESULT bool ParseVersion(const der::Input& in,
                                     CertificateVersion* version) {
  der::Parser parser(in);
  uint64_t version64;
  if (!parser.ReadUint64(&version64))
    return false;

  switch (version64) {
    case 0:
      *version = CertificateVersion::V1;
      break;
    case 1:
      *version = CertificateVersion::V2;
      break;
    case 2:
      *version = CertificateVersion::V3;
      break;
    default:
      // Don't allow any other version identifier.
      return false;
  }

  // By definition the input to this function was a single INTEGER, so there
  // shouldn't be anything else after it.
  return !parser.HasMore();
}

// Consumes a "Time" value (as defined by RFC 5280) from |parser|. On success
// writes the result to |*out| and returns true. On failure no guarantees are
// made about the state of |parser|.
//
// From RFC 5280:
//
//     Time ::= CHOICE {
//          utcTime        UTCTime,
//          generalTime    GeneralizedTime }
WARN_UNUSED_RESULT bool ReadTime(der::Parser* parser,
                                 der::GeneralizedTime* out) {
  der::Input value;
  der::Tag tag;

  if (!parser->ReadTagAndValue(&tag, &value))
    return false;

  if (tag == der::kUtcTime)
    return der::ParseUTCTime(value, out);

  if (tag == der::kGeneralizedTime)
    return der::ParseGeneralizedTime(value, out);

  // Unrecognized tag.
  return false;
}

// Parses a DER-encoded "Validity" as specified by RFC 5280. Returns true on
// success and sets the results in |not_before| and |not_after|:
//
//       Validity ::= SEQUENCE {
//            notBefore      Time,
//            notAfter       Time }
//
// Note that upon success it is NOT guaranteed that |*not_before <= *not_after|.
bool ParseValidity(const der::Input& validity_tlv,
                   der::GeneralizedTime* not_before,
                   der::GeneralizedTime* not_after) {
  der::Parser parser(validity_tlv);

  //     Validity ::= SEQUENCE {
  der::Parser validity_parser;
  if (!parser.ReadSequence(&validity_parser))
    return false;

  //          notBefore      Time,
  if (!ReadTime(&validity_parser, not_before))
    return false;

  //          notAfter       Time }
  if (!ReadTime(&validity_parser, not_after))
    return false;

  // By definition the input was a single Validity sequence, so there shouldn't
  // be unconsumed data.
  if (parser.HasMore())
    return false;

  // The Validity type does not have an extension point.
  if (validity_parser.HasMore())
    return false;

  // Note that RFC 5280 doesn't require notBefore to be <=
  // notAfter, so that will not be considered a "parsing" error here. Instead it
  // will be considered an expired certificate later when testing against the
  // current timestamp.
  return true;
}

// Returns true if every bit in |bits| is zero (including empty).
WARN_UNUSED_RESULT bool BitStringIsAllZeros(const der::BitString& bits) {
  // Note that it is OK to read from the unused bits, since BitString parsing
  // guarantees they are all zero.
  for (size_t i = 0; i < bits.bytes().Length(); ++i) {
    if (bits.bytes().UnsafeData()[i] != 0)
      return false;
  }
  return true;
}

}  // namespace

ParsedTbsCertificate::ParsedTbsCertificate() {}

ParsedTbsCertificate::~ParsedTbsCertificate() {}

bool VerifySerialNumber(const der::Input& value) {
  bool unused_negative;
  if (!der::IsValidInteger(value, &unused_negative))
    return false;

  // Check if the serial number is too long per RFC 5280.
  if (value.Length() > 20)
    return false;

  return true;
}

bool ParseCertificate(const der::Input& certificate_tlv,
                      der::Input* out_tbs_certificate_tlv,
                      der::Input* out_signature_algorithm_tlv,
                      der::BitString* out_signature_value,
                      CertErrors* out_errors) {
  // |out_errors| is optional. But ensure it is non-null for the remainder of
  // this function.
  if (!out_errors) {
    CertErrors unused_errors;
    return ParseCertificate(certificate_tlv, out_tbs_certificate_tlv,
                            out_signature_algorithm_tlv, out_signature_value,
                            &unused_errors);
  }

  der::Parser parser(certificate_tlv);

  //   Certificate  ::=  SEQUENCE  {
  der::Parser certificate_parser;
  if (!parser.ReadSequence(&certificate_parser)) {
    out_errors->AddError(kCertificateNotSequence);
    return false;
  }

  //        tbsCertificate       TBSCertificate,
  if (!ReadSequenceTLV(&certificate_parser, out_tbs_certificate_tlv)) {
    out_errors->AddError(kTbsCertificateNotSequence);
    return false;
  }

  //        signatureAlgorithm   AlgorithmIdentifier,
  if (!ReadSequenceTLV(&certificate_parser, out_signature_algorithm_tlv)) {
    out_errors->AddError(kSignatureAlgorithmNotSequence);
    return false;
  }

  //        signatureValue       BIT STRING  }
  if (!certificate_parser.ReadBitString(out_signature_value)) {
    out_errors->AddError(kSignatureValueNotBitString);
    return false;
  }

  // There isn't an extension point at the end of Certificate.
  if (certificate_parser.HasMore()) {
    out_errors->AddError(kUnconsumedDataInsideCertificateSequence);
    return false;
  }

  // By definition the input was a single Certificate, so there shouldn't be
  // unconsumed data.
  if (parser.HasMore()) {
    out_errors->AddError(kUnconsumedDataAfterCertificateSequence);
    return false;
  }

  return true;
}

// From RFC 5280 section 4.1:
//
//   TBSCertificate  ::=  SEQUENCE  {
//        version         [0]  EXPLICIT Version DEFAULT v1,
//        serialNumber         CertificateSerialNumber,
//        signature            AlgorithmIdentifier,
//        issuer               Name,
//        validity             Validity,
//        subject              Name,
//        subjectPublicKeyInfo SubjectPublicKeyInfo,
//        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                             -- If present, version MUST be v2 or v3
//        extensions      [3]  EXPLICIT Extensions OPTIONAL
//                             -- If present, version MUST be v3
//        }
bool ParseTbsCertificate(const der::Input& tbs_tlv,
                         const ParseCertificateOptions& options,
                         ParsedTbsCertificate* out,
                         CertErrors* errors) {
  // The rest of this function assumes that |errors| is non-null.
  if (!errors) {
    CertErrors unused_errors;
    return ParseTbsCertificate(tbs_tlv, options, out, &unused_errors);
  }

  // TODO(crbug.com/634443): Add useful error information to |errors|.

  der::Parser parser(tbs_tlv);

  //   Certificate  ::=  SEQUENCE  {
  der::Parser tbs_parser;
  if (!parser.ReadSequence(&tbs_parser))
    return false;

  //        version         [0]  EXPLICIT Version DEFAULT v1,
  der::Input version;
  bool has_version;
  if (!tbs_parser.ReadOptionalTag(der::ContextSpecificConstructed(0), &version,
                                  &has_version)) {
    return false;
  }
  if (has_version) {
    if (!ParseVersion(version, &out->version))
      return false;
    if (out->version == CertificateVersion::V1) {
      // The correct way to specify v1 is to omit the version field since v1 is
      // the DEFAULT.
      return false;
    }
  } else {
    out->version = CertificateVersion::V1;
  }

  //        serialNumber         CertificateSerialNumber,
  if (!tbs_parser.ReadTag(der::kInteger, &out->serial_number))
    return false;
  if (!options.allow_invalid_serial_numbers &&
      !VerifySerialNumber(out->serial_number)) {
    return false;
  }

  //        signature            AlgorithmIdentifier,
  if (!ReadSequenceTLV(&tbs_parser, &out->signature_algorithm_tlv))
    return false;

  //        issuer               Name,
  if (!ReadSequenceTLV(&tbs_parser, &out->issuer_tlv))
    return false;

  //        validity             Validity,
  der::Input validity_tlv;
  if (!tbs_parser.ReadRawTLV(&validity_tlv))
    return false;
  if (!ParseValidity(validity_tlv, &out->validity_not_before,
                     &out->validity_not_after)) {
    return false;
  }

  //        subject              Name,
  if (!ReadSequenceTLV(&tbs_parser, &out->subject_tlv))
    return false;

  //        subjectPublicKeyInfo SubjectPublicKeyInfo,
  if (!ReadSequenceTLV(&tbs_parser, &out->spki_tlv))
    return false;

  //        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  //                             -- If present, version MUST be v2 or v3
  der::Input issuer_unique_id;
  if (!tbs_parser.ReadOptionalTag(der::ContextSpecificPrimitive(1),
                                  &issuer_unique_id,
                                  &out->has_issuer_unique_id)) {
    return false;
  }
  if (out->has_issuer_unique_id) {
    if (!der::ParseBitString(issuer_unique_id, &out->issuer_unique_id))
      return false;
    if (out->version != CertificateVersion::V2 &&
        out->version != CertificateVersion::V3) {
      return false;
    }
  }

  //        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  //                             -- If present, version MUST be v2 or v3
  der::Input subject_unique_id;
  if (!tbs_parser.ReadOptionalTag(der::ContextSpecificPrimitive(2),
                                  &subject_unique_id,
                                  &out->has_subject_unique_id)) {
    return false;
  }
  if (out->has_subject_unique_id) {
    if (!der::ParseBitString(subject_unique_id, &out->subject_unique_id))
      return false;
    if (out->version != CertificateVersion::V2 &&
        out->version != CertificateVersion::V3) {
      return false;
    }
  }

  //        extensions      [3]  EXPLICIT Extensions OPTIONAL
  //                             -- If present, version MUST be v3
  if (!tbs_parser.ReadOptionalTag(der::ContextSpecificConstructed(3),
                                  &out->extensions_tlv, &out->has_extensions)) {
    return false;
  }
  if (out->has_extensions) {
    // extensions_tlv must be a single element. Also check that it is a
    // SEQUENCE.
    if (!IsSequenceTLV(out->extensions_tlv))
      return false;
    if (out->version != CertificateVersion::V3)
      return false;
  }

  // Note that there IS an extension point at the end of TBSCertificate
  // (according to RFC 5912), so from that interpretation, unconsumed data would
  // be allowed in |tbs_parser|.
  //
  // However because only v1, v2, and v3 certificates are supported by the
  // parsing, there shouldn't be any subsequent data in those versions, so
  // reject.
  if (tbs_parser.HasMore()) {
    errors->AddError(kUnconsumedDataInsideTbsCertificateSequence);
    return false;
  }

  // By definition the input was a single TBSCertificate, so there shouldn't be
  // unconsumed data.
  if (parser.HasMore())
    return false;

  return true;
}

// From RFC 5280:
//
//    Extension  ::=  SEQUENCE  {
//            extnID      OBJECT IDENTIFIER,
//            critical    BOOLEAN DEFAULT FALSE,
//            extnValue   OCTET STRING
//                        -- contains the DER encoding of an ASN.1 value
//                        -- corresponding to the extension type identified
//                        -- by extnID
//            }
bool ParseExtension(const der::Input& extension_tlv, ParsedExtension* out) {
  der::Parser parser(extension_tlv);

  //    Extension  ::=  SEQUENCE  {
  der::Parser extension_parser;
  if (!parser.ReadSequence(&extension_parser))
    return false;

  //            extnID      OBJECT IDENTIFIER,
  if (!extension_parser.ReadTag(der::kOid, &out->oid))
    return false;

  //            critical    BOOLEAN DEFAULT FALSE,
  out->critical = false;
  bool has_critical;
  der::Input critical;
  if (!extension_parser.ReadOptionalTag(der::kBool, &critical, &has_critical))
    return false;
  if (has_critical) {
    if (!der::ParseBool(critical, &out->critical))
      return false;
    if (!out->critical)
      return false;  // DER-encoding requires DEFAULT values be omitted.
  }

  //            extnValue   OCTET STRING
  if (!extension_parser.ReadTag(der::kOctetString, &out->value))
    return false;

  // The Extension type does not have an extension point (everything goes in
  // extnValue).
  if (extension_parser.HasMore())
    return false;

  // By definition the input was a single Extension sequence, so there shouldn't
  // be unconsumed data.
  if (parser.HasMore())
    return false;

  return true;
}

der::Input KeyUsageOid() {
  // From RFC 5280:
  //
  //     id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
  //
  // In dotted notation: 2.5.29.15
  static const uint8_t oid[] = {0x55, 0x1d, 0x0f};
  return der::Input(oid);
}

der::Input SubjectAltNameOid() {
  // From RFC 5280:
  //
  //     id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
  //
  // In dotted notation: 2.5.29.17
  static const uint8_t oid[] = {0x55, 0x1d, 0x11};
  return der::Input(oid);
}

der::Input BasicConstraintsOid() {
  // From RFC 5280:
  //
  //     id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
  //
  // In dotted notation: 2.5.29.19
  static const uint8_t oid[] = {0x55, 0x1d, 0x13};
  return der::Input(oid);
}

der::Input NameConstraintsOid() {
  // From RFC 5280:
  //
  //     id-ce-nameConstraints OBJECT IDENTIFIER ::=  { id-ce 30 }
  //
  // In dotted notation: 2.5.29.30
  static const uint8_t oid[] = {0x55, 0x1d, 0x1e};
  return der::Input(oid);
}

der::Input CertificatePoliciesOid() {
  // From RFC 5280:
  //
  //     id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
  //
  // In dotted notation: 2.5.29.32
  static const uint8_t oid[] = {0x55, 0x1d, 0x20};
  return der::Input(oid);
}

der::Input PolicyConstraintsOid() {
  // From RFC 5280:
  //
  //     id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
  //
  // In dotted notation: 2.5.29.36
  static const uint8_t oid[] = {0x55, 0x1d, 0x24};
  return der::Input(oid);
}

der::Input ExtKeyUsageOid() {
  // From RFC 5280:
  //
  //     id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
  //
  // In dotted notation: 2.5.29.37
  static const uint8_t oid[] = {0x55, 0x1d, 0x25};
  return der::Input(oid);
}

der::Input AuthorityInfoAccessOid() {
  // From RFC 5280:
  //
  //     id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
  //
  // In dotted notation: 1.3.6.1.5.5.7.1.1
  static const uint8_t oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01};
  return der::Input(oid);
}

der::Input AdCaIssuersOid() {
  // From RFC 5280:
  //
  //     id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
  //
  // In dotted notation: 1.3.6.1.5.5.7.48.2
  static const uint8_t oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02};
  return der::Input(oid);
}

der::Input AdOcspOid() {
  // From RFC 5280:
  //
  //     id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
  //
  // In dotted notation: 1.3.6.1.5.5.7.48.1
  static const uint8_t oid[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01};
  return der::Input(oid);
}

NET_EXPORT bool ParseExtensions(
    const der::Input& extensions_tlv,
    std::map<der::Input, ParsedExtension>* extensions) {
  der::Parser parser(extensions_tlv);

  //    Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
  der::Parser extensions_parser;
  if (!parser.ReadSequence(&extensions_parser))
    return false;

  // The Extensions SEQUENCE must contains at least 1 element (otherwise it
  // should have been omitted).
  if (!extensions_parser.HasMore())
    return false;

  extensions->clear();

  while (extensions_parser.HasMore()) {
    ParsedExtension extension;

    der::Input extension_tlv;
    if (!extensions_parser.ReadRawTLV(&extension_tlv))
      return false;

    if (!ParseExtension(extension_tlv, &extension))
      return false;

    bool is_duplicate =
        !extensions->insert(std::make_pair(extension.oid, extension)).second;

    // RFC 5280 says that an extension should not appear more than once.
    if (is_duplicate)
      return false;
  }

  // By definition the input was a single Extensions sequence, so there
  // shouldn't be unconsumed data.
  if (parser.HasMore())
    return false;

  return true;
}

NET_EXPORT bool ConsumeExtension(
    const der::Input& oid,
    std::map<der::Input, ParsedExtension>* unconsumed_extensions,
    ParsedExtension* extension) {
  auto it = unconsumed_extensions->find(oid);
  if (it == unconsumed_extensions->end())
    return false;

  *extension = it->second;
  unconsumed_extensions->erase(it);
  return true;
}

bool ParseBasicConstraints(const der::Input& basic_constraints_tlv,
                           ParsedBasicConstraints* out) {
  der::Parser parser(basic_constraints_tlv);

  //    BasicConstraints ::= SEQUENCE {
  der::Parser sequence_parser;
  if (!parser.ReadSequence(&sequence_parser))
    return false;

  //         cA                      BOOLEAN DEFAULT FALSE,
  out->is_ca = false;
  bool has_ca;
  der::Input ca;
  if (!sequence_parser.ReadOptionalTag(der::kBool, &ca, &has_ca))
    return false;
  if (has_ca) {
    if (!der::ParseBool(ca, &out->is_ca))
      return false;
    // TODO(eroman): Should reject if CA was set to false, since
    // DER-encoding requires DEFAULT values be omitted. In
    // practice however there are a lot of certificates that use
    // the broken encoding.
  }

  //         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
  der::Input encoded_path_len;
  if (!sequence_parser.ReadOptionalTag(der::kInteger, &encoded_path_len,
                                       &out->has_path_len)) {
    return false;
  }
  if (out->has_path_len) {
    if (!der::ParseUint8(encoded_path_len, &out->path_len))
      return false;
  } else {
    // Default initialize to 0 as a precaution.
    out->path_len = 0;
  }

  // There shouldn't be any unconsumed data in the extension.
  if (sequence_parser.HasMore())
    return false;

  // By definition the input was a single BasicConstraints sequence, so there
  // shouldn't be unconsumed data.
  if (parser.HasMore())
    return false;

  return true;
}

bool ParseKeyUsage(const der::Input& key_usage_tlv, der::BitString* key_usage) {
  der::Parser parser(key_usage_tlv);
  if (!parser.ReadBitString(key_usage))
    return false;

  // By definition the input was a single BIT STRING.
  if (parser.HasMore())
    return false;

  // RFC 5280 section 4.2.1.3:
  //
  //     When the keyUsage extension appears in a certificate, at least
  //     one of the bits MUST be set to 1.
  if (BitStringIsAllZeros(*key_usage))
    return false;

  return true;
}

bool ParseAuthorityInfoAccess(
    const der::Input& authority_info_access_tlv,
    std::vector<base::StringPiece>* out_ca_issuers_uris,
    std::vector<base::StringPiece>* out_ocsp_uris) {
  der::Parser parser(authority_info_access_tlv);

  out_ca_issuers_uris->clear();
  out_ocsp_uris->clear();

  //    AuthorityInfoAccessSyntax  ::=
  //            SEQUENCE SIZE (1..MAX) OF AccessDescription
  der::Parser sequence_parser;
  if (!parser.ReadSequence(&sequence_parser))
    return false;
  if (!sequence_parser.HasMore())
    return false;

  while (sequence_parser.HasMore()) {
    //    AccessDescription  ::=  SEQUENCE {
    der::Parser access_description_sequence_parser;
    if (!sequence_parser.ReadSequence(&access_description_sequence_parser))
      return false;

    //            accessMethod          OBJECT IDENTIFIER,
    der::Input access_method_oid;
    if (!access_description_sequence_parser.ReadTag(der::kOid,
                                                    &access_method_oid))
      return false;

    //            accessLocation        GeneralName  }
    der::Tag access_location_tag;
    der::Input access_location_value;
    if (!access_description_sequence_parser.ReadTagAndValue(
            &access_location_tag, &access_location_value))
      return false;

    // GeneralName ::= CHOICE {
    if (access_location_tag == der::ContextSpecificPrimitive(6)) {
      // uniformResourceIdentifier       [6]     IA5String,
      base::StringPiece uri = access_location_value.AsStringPiece();
      if (!base::IsStringASCII(uri))
        return false;

      if (access_method_oid == AdCaIssuersOid())
        out_ca_issuers_uris->push_back(uri);
      else if (access_method_oid == AdOcspOid())
        out_ocsp_uris->push_back(uri);
    }
  }

  return true;
}

}  // namespace net
