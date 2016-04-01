// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/asn1_util.h"

#include "net/der/input.h"
#include "net/der/parser.h"

namespace net {

namespace asn1 {

namespace {

// Parses input |in| which should point to the beginning of a Certificate, and
// sets |*tbs_certificate| ready to parse the SubjectPublicKeyInfo. If parsing
// fails, this function returns false and |*tbs_certificate| is left in an
// undefined state.
bool SeekToSPKI(der::Input in, der::Parser* tbs_certificate) {
  // From RFC 5280, section 4.1
  //    Certificate  ::=  SEQUENCE  {
  //      tbsCertificate       TBSCertificate,
  //      signatureAlgorithm   AlgorithmIdentifier,
  //      signatureValue       BIT STRING  }

  // TBSCertificate  ::=  SEQUENCE  {
  //      version         [0]  EXPLICIT Version DEFAULT v1,
  //      serialNumber         CertificateSerialNumber,
  //      signature            AlgorithmIdentifier,
  //      issuer               Name,
  //      validity             Validity,
  //      subject              Name,
  //      subjectPublicKeyInfo SubjectPublicKeyInfo,
  //      ... }

  der::Parser parser(in);
  der::Parser certificate;
  if (!parser.ReadSequence(&certificate))
    return false;

  // We don't allow junk after the certificate.
  if (parser.HasMore())
    return false;

  if (!certificate.ReadSequence(tbs_certificate))
    return false;

  bool unused;
  if (!tbs_certificate->SkipOptionalTag(
          der::kTagConstructed | der::kTagContextSpecific | 0, &unused)) {
    return false;
  }

  // serialNumber
  if (!tbs_certificate->SkipTag(der::kInteger))
    return false;
  // signature
  if (!tbs_certificate->SkipTag(der::kSequence))
    return false;
  // issuer
  if (!tbs_certificate->SkipTag(der::kSequence))
    return false;
  // validity
  if (!tbs_certificate->SkipTag(der::kSequence))
    return false;
  // subject
  if (!tbs_certificate->SkipTag(der::kSequence))
    return false;
  return true;
}

}  // namespace

bool ExtractSPKIFromDERCert(base::StringPiece cert,
                            base::StringPiece* spki_out) {
  der::Parser parser;
  if (!SeekToSPKI(der::Input(cert), &parser))
    return false;
  der::Input spki;
  if (!parser.ReadRawTLV(&spki))
    return false;
  *spki_out = spki.AsStringPiece();
  return true;
}

bool ExtractSubjectPublicKeyFromSPKI(base::StringPiece spki,
                                     base::StringPiece* spk_out) {
  // From RFC 5280, Section 4.1
  //   SubjectPublicKeyInfo  ::=  SEQUENCE  {
  //     algorithm            AlgorithmIdentifier,
  //     subjectPublicKey     BIT STRING  }
  //
  //   AlgorithmIdentifier  ::=  SEQUENCE  {
  //     algorithm               OBJECT IDENTIFIER,
  //     parameters              ANY DEFINED BY algorithm OPTIONAL  }

  // Step into SubjectPublicKeyInfo sequence.
  der::Parser parser((der::Input(spki)));
  der::Parser spki_parser;
  if (!parser.ReadSequence(&spki_parser))
    return false;

  // Step over algorithm field (a SEQUENCE).
  if (!spki_parser.SkipTag(der::kSequence))
    return false;

  // Extract the subjectPublicKey field.
  der::Input spk;
  if (!spki_parser.ReadTag(der::kBitString, &spk))
    return false;
  *spk_out = spk.AsStringPiece();
  return true;
}


bool ExtractCRLURLsFromDERCert(base::StringPiece cert,
                               std::vector<base::StringPiece>* urls_out) {
  urls_out->clear();
  std::vector<base::StringPiece> tmp_urls_out;

  bool present;
  der::Parser tbs_cert_parser;
  if (!SeekToSPKI(der::Input(cert), &tbs_cert_parser))
    return false;

  // From RFC 5280, section 4.1
  // TBSCertificate  ::=  SEQUENCE  {
  //      ...
  //      subjectPublicKeyInfo SubjectPublicKeyInfo,
  //      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  //      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  //      extensions      [3]  EXPLICIT Extensions OPTIONAL }

  // subjectPublicKeyInfo
  if (!tbs_cert_parser.SkipTag(der::kSequence))
    return false;
  // issuerUniqueID
  if (!tbs_cert_parser.SkipOptionalTag(
          der::kTagConstructed | der::kTagContextSpecific | 1, &present)) {
    return false;
  }
  // subjectUniqueID
  if (!tbs_cert_parser.SkipOptionalTag(
          der::kTagConstructed | der::kTagContextSpecific | 2, &present)) {
    return false;
  }

  der::Input extensions;
  if (!tbs_cert_parser.ReadOptionalTag(
          der::kTagConstructed | der::kTagContextSpecific | 3, &extensions,
          &present)) {
    return false;
  }

  if (!present)
    return true;

  // Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
  // Extension   ::=  SEQUENCE  {
  //      extnID      OBJECT IDENTIFIER,
  //      critical    BOOLEAN DEFAULT FALSE,
  //      extnValue   OCTET STRING }

  // |extensions| was EXPLICITly tagged, so we still need to remove the
  // ASN.1 SEQUENCE header.
  der::Parser explicit_extensions_parser(extensions);
  der::Parser extensions_parser;
  if (!explicit_extensions_parser.ReadSequence(&extensions_parser))
    return false;

  if (explicit_extensions_parser.HasMore())
    return false;

  while (extensions_parser.HasMore()) {
    der::Parser extension_parser;
    if (!extensions_parser.ReadSequence(&extension_parser))
      return false;

    der::Input oid;
    if (!extension_parser.ReadTag(der::kOid, &oid))
      return false;

    // kCRLDistributionPointsOID is the DER encoding of the OID for the X.509
    // CRL Distribution Points extension.
    static const uint8_t kCRLDistributionPointsOID[] = {0x55, 0x1d, 0x1f};

    if (oid != der::Input(kCRLDistributionPointsOID))
      continue;

    // critical
    if (!extension_parser.SkipOptionalTag(der::kBool, &present))
      return false;

    // extnValue
    der::Input extension_value;
    if (!extension_parser.ReadTag(der::kOctetString, &extension_value))
      return false;

    // RFC 5280, section 4.2.1.13.
    //
    // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    //
    // DistributionPoint ::= SEQUENCE {
    //  distributionPoint       [0]     DistributionPointName OPTIONAL,
    //  reasons                 [1]     ReasonFlags OPTIONAL,
    //  cRLIssuer               [2]     GeneralNames OPTIONAL }

    der::Parser extension_value_parser(extension_value);
    der::Parser distribution_points_parser;
    if (!extension_value_parser.ReadSequence(&distribution_points_parser))
      return false;
    if (extension_value_parser.HasMore())
      return false;

    while (distribution_points_parser.HasMore()) {
      der::Parser distrib_point_parser;
      if (!distribution_points_parser.ReadSequence(&distrib_point_parser))
        return false;

      der::Input name;
      if (!distrib_point_parser.ReadOptionalTag(
              der::kTagContextSpecific | der::kTagConstructed | 0, &name,
              &present)) {
        return false;
      }
      // If it doesn't contain a name then we skip it.
      if (!present)
        continue;

      if (!distrib_point_parser.SkipOptionalTag(der::kTagContextSpecific | 1,
                                                &present)) {
        return false;
      }
      // If it contains a subset of reasons then we skip it. We aren't
      // interested in subsets of CRLs and the RFC states that there MUST be
      // a CRL that covers all reasons.
      if (present)
        continue;

      if (!distrib_point_parser.SkipOptionalTag(
              der::kTagContextSpecific | der::kTagConstructed | 2, &present)) {
        return false;
      }
      // If it contains a alternative issuer, then we skip it.
      if (present)
        continue;

      // DistributionPointName ::= CHOICE {
      //   fullName                [0]     GeneralNames,
      //   nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
      der::Input general_names;
      if (!der::Parser(name).ReadOptionalTag(
              der::kTagContextSpecific | der::kTagConstructed | 0,
              &general_names, &present)) {
        return false;
      }
      if (!present)
        continue;

      // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
      // GeneralName ::= CHOICE {
      //   ...
      //   uniformResourceIdentifier [6]  IA5String,
      //   ... }
      der::Parser general_names_parser(general_names);
      while (general_names_parser.HasMore()) {
        der::Input url;
        if (!general_names_parser.ReadOptionalTag(der::kTagContextSpecific | 6,
                                                  &url, &present)) {
          return false;
        }
        if (present) {
          // This does not validate that |url| is a valid IA5String.
          tmp_urls_out.push_back(url.AsStringPiece());
        } else {
          der::Tag unused_tag;
          der::Input unused_value;
          if (!general_names_parser.ReadTagAndValue(&unused_tag,
                                                    &unused_value)) {
            return false;
          }
        }
      }
    }
  }

  urls_out->swap(tmp_urls_out);
  return true;
}

} // namespace asn1

} // namespace net
