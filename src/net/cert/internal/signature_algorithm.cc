// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/signature_algorithm.h"

#include <memory>
#include <utility>

#include "base/memory/ptr_util.h"
#include "base/numerics/safe_math.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"

namespace net {

namespace {

// md2WithRSAEncryption
// In dotted notation: 1.2.840.113549.1.1.2
const uint8_t kOidMd2WithRsaEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x02};

// md4WithRSAEncryption
// In dotted notation: 1.2.840.113549.1.1.3
const uint8_t kOidMd4WithRsaEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x03};

// md5WithRSAEncryption
// In dotted notation: 1.2.840.113549.1.1.4
const uint8_t kOidMd5WithRsaEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                            0x0d, 0x01, 0x01, 0x04};

// From RFC 5912:
//
//     sha1WithRSAEncryption OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
//      pkcs-1(1) 5 }
//
// In dotted notation: 1.2.840.113549.1.1.5
const uint8_t kOidSha1WithRsaEncryption[] =
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05};

// sha1WithRSASignature is a deprecated equivalent of
// sha1WithRSAEncryption.
//
// It originates from the NIST Open Systems Environment (OSE)
// Implementor's Workshop (OIW).
//
// It is supported for compatibility with Microsoft's certificate APIs and
// tools, particularly makecert.exe, which default(ed/s) to this OID for SHA-1.
//
// See also: https://bugzilla.mozilla.org/show_bug.cgi?id=1042479
//
// In dotted notation: 1.3.14.3.2.29
const uint8_t kOidSha1WithRsaSignature[] = {0x2b, 0x0e, 0x03, 0x02, 0x1d};

// From RFC 5912:
//
//     pkcs-1  OBJECT IDENTIFIER  ::=
//         { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }

// From RFC 5912:
//
//     sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }
//
// In dotted notation: 1.2.840.113549.1.1.11
const uint8_t kOidSha256WithRsaEncryption[] =
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};

// From RFC 5912:
//
//     sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 12 }
//
// In dotted notation: 1.2.840.113549.1.1.11
const uint8_t kOidSha384WithRsaEncryption[] =
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};

// From RFC 5912:
//
//     sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 13 }
//
// In dotted notation: 1.2.840.113549.1.1.13
const uint8_t kOidSha512WithRsaEncryption[] =
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d};

// From RFC 5912:
//
//     ecdsa-with-SHA1 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045)
//      signatures(4) 1 }
//
// In dotted notation: 1.2.840.10045.4.1
const uint8_t kOidEcdsaWithSha1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01};

// From RFC 5912:
//
//     ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
//      ecdsa-with-SHA2(3) 2 }
//
// In dotted notation: 1.2.840.10045.4.3.2
const uint8_t kOidEcdsaWithSha256[] =
    {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};

// From RFC 5912:
//
//     ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
//      ecdsa-with-SHA2(3) 3 }
//
// In dotted notation: 1.2.840.10045.4.3.3
const uint8_t kOidEcdsaWithSha384[] =
    {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};

// From RFC 5912:
//
//     ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
//      iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
//      ecdsa-with-SHA2(3) 4 }
//
// In dotted notation: 1.2.840.10045.4.3.4
const uint8_t kOidEcdsaWithSha512[] =
    {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04};

// From RFC 5912:
//
//     id-RSASSA-PSS  OBJECT IDENTIFIER  ::=  { pkcs-1 10 }
//
// In dotted notation: 1.2.840.113549.1.1.10
const uint8_t kOidRsaSsaPss[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                 0x0d, 0x01, 0x01, 0x0a};

// From RFC 5912:
//
//     id-sha1 OBJECT IDENTIFIER ::= {
//      iso(1) identified-organization(3) oiw(14) secsig(3)
//      algorithm(2) 26 }
//
// In dotted notation: 1.3.14.3.2.26
const uint8_t kOidSha1[] = {0x2B, 0x0E, 0x03, 0x02, 0x1A};

// From RFC 5912:
//
//     id-sha256  OBJECT IDENTIFIER  ::=
//         { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
//         csor(3) nistAlgorithms(4) hashalgs(2) 1 }
//
// In dotted notation: 2.16.840.1.101.3.4.2.1
const uint8_t kOidSha256[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                              0x03, 0x04, 0x02, 0x01};

// From RFC 5912:
//
//     id-sha384  OBJECT IDENTIFIER  ::=
//         { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
//         csor(3) nistAlgorithms(4) hashalgs(2) 2 }
//
// In dotted notation: 2.16.840.1.101.3.4.2.2
const uint8_t kOidSha384[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                              0x03, 0x04, 0x02, 0x02};

// From RFC 5912:
//
//     id-sha512  OBJECT IDENTIFIER  ::=
//         { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
//         csor(3) nistAlgorithms(4) hashalgs(2) 3 }
//
// In dotted notation: 2.16.840.1.101.3.4.2.3
const uint8_t kOidSha512[] = {0x60, 0x86, 0x48, 0x01, 0x65,
                              0x03, 0x04, 0x02, 0x03};

// From RFC 5912:
//
//     id-mgf1  OBJECT IDENTIFIER  ::=  { pkcs-1 8 }
//
// In dotted notation: 1.2.840.113549.1.1.8
const uint8_t kOidMgf1[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                            0x0d, 0x01, 0x01, 0x08};

// RFC 5280 section 4.1.1.2 defines signatureAlgorithm as:
//
//     AlgorithmIdentifier  ::=  SEQUENCE  {
//          algorithm               OBJECT IDENTIFIER,
//          parameters              ANY DEFINED BY algorithm OPTIONAL  }
WARN_UNUSED_RESULT bool ParseAlgorithmIdentifier(const der::Input& input,
                                                 der::Input* algorithm,
                                                 der::Input* parameters) {
  der::Parser parser(input);

  der::Parser algorithm_identifier_parser;
  if (!parser.ReadSequence(&algorithm_identifier_parser))
    return false;

  // There shouldn't be anything after the sequence. This is by definition,
  // as the input to this function is expected to be a single
  // AlgorithmIdentifier.
  if (parser.HasMore())
    return false;

  if (!algorithm_identifier_parser.ReadTag(der::kOid, algorithm))
    return false;

  // Read the optional parameters to a der::Input. The parameters can be at
  // most one TLV (for instance NULL or a sequence).
  //
  // Note that nothing is allowed after the single optional "parameters" TLV.
  // This is because RFC 5912's notation for AlgorithmIdentifier doesn't
  // explicitly list an extension point after "parameters".
  *parameters = der::Input();
  if (algorithm_identifier_parser.HasMore() &&
      !algorithm_identifier_parser.ReadRawTLV(parameters)) {
    return false;
  }
  return !algorithm_identifier_parser.HasMore();
}

// Returns true if |input| is empty.
WARN_UNUSED_RESULT bool IsEmpty(const der::Input& input) {
  return input.Length() == 0;
}

// Returns true if the entirety of the input is a NULL value.
WARN_UNUSED_RESULT bool IsNull(const der::Input& input) {
  der::Parser parser(input);
  der::Input null_value;
  if (!parser.ReadTag(der::kNull, &null_value))
    return false;

  // NULL values are TLV encoded; the value is expected to be empty.
  if (!IsEmpty(null_value))
    return false;

  // By definition of this function, the entire input must be a NULL.
  return !parser.HasMore();
}

// Parses an RSA PKCS#1 v1.5 signature algorithm given the DER-encoded
// "parameters" from the parsed AlgorithmIdentifier, and the hash algorithm
// that was implied by the AlgorithmIdentifier's OID.
//
// Returns a nullptr on failure.
//
// RFC 5912 requires that the parameters for RSA PKCS#1 v1.5 algorithms be NULL
// ("PARAMS TYPE NULL ARE required"), however an empty parameter is also
// allowed for compatibility with non-compliant OCSP responders:
//
//     sa-rsaWithSHA1 SIGNATURE-ALGORITHM ::= {
//      IDENTIFIER sha1WithRSAEncryption
//      PARAMS TYPE NULL ARE required
//      HASHES { mda-sha1 }
//      PUBLIC-KEYS { pk-rsa }
//      SMIME-CAPS {IDENTIFIED BY sha1WithRSAEncryption }
//     }
//
//     sa-sha256WithRSAEncryption SIGNATURE-ALGORITHM ::= {
//         IDENTIFIER sha256WithRSAEncryption
//         PARAMS TYPE NULL ARE required
//         HASHES { mda-sha256 }
//         PUBLIC-KEYS { pk-rsa }
//         SMIME-CAPS { IDENTIFIED BY sha256WithRSAEncryption }
//     }
//
//     sa-sha384WithRSAEncryption SIGNATURE-ALGORITHM ::= {
//         IDENTIFIER sha384WithRSAEncryption
//         PARAMS TYPE NULL ARE required
//         HASHES { mda-sha384 }
//         PUBLIC-KEYS { pk-rsa }
//         SMIME-CAPS { IDENTIFIED BY sha384WithRSAEncryption }
//     }
//
//     sa-sha512WithRSAEncryption SIGNATURE-ALGORITHM ::= {
//         IDENTIFIER sha512WithRSAEncryption
//         PARAMS TYPE NULL ARE required
//         HASHES { mda-sha512 }
//         PUBLIC-KEYS { pk-rsa }
//         SMIME-CAPS { IDENTIFIED BY sha512WithRSAEncryption }
//     }
std::unique_ptr<SignatureAlgorithm> ParseRsaPkcs1(DigestAlgorithm digest,
                                                  const der::Input& params) {
  // TODO(svaldez): Add warning about non-strict parsing.
  if (!IsNull(params) && !IsEmpty(params))
    return nullptr;

  return SignatureAlgorithm::CreateRsaPkcs1(digest);
}

// Parses an ECDSA signature algorithm given the DER-encoded "parameters" from
// the parsed AlgorithmIdentifier, and the hash algorithm that was implied by
// the AlgorithmIdentifier's OID.
//
// On failure returns a nullptr.
//
// RFC 5912 requires that the parameters for ECDSA algorithms be absent
// ("PARAMS TYPE NULL ARE absent"):
//
//     sa-ecdsaWithSHA1 SIGNATURE-ALGORITHM ::= {
//      IDENTIFIER ecdsa-with-SHA1
//      VALUE ECDSA-Sig-Value
//      PARAMS TYPE NULL ARE absent
//      HASHES { mda-sha1 }
//      PUBLIC-KEYS { pk-ec }
//      SMIME-CAPS {IDENTIFIED BY ecdsa-with-SHA1 }
//     }
//
//     sa-ecdsaWithSHA256 SIGNATURE-ALGORITHM ::= {
//      IDENTIFIER ecdsa-with-SHA256
//      VALUE ECDSA-Sig-Value
//      PARAMS TYPE NULL ARE absent
//      HASHES { mda-sha256 }
//      PUBLIC-KEYS { pk-ec }
//      SMIME-CAPS { IDENTIFIED BY ecdsa-with-SHA256 }
//     }
//
//     sa-ecdsaWithSHA384 SIGNATURE-ALGORITHM ::= {
//      IDENTIFIER ecdsa-with-SHA384
//      VALUE ECDSA-Sig-Value
//      PARAMS TYPE NULL ARE absent
//      HASHES { mda-sha384 }
//      PUBLIC-KEYS { pk-ec }
//      SMIME-CAPS { IDENTIFIED BY ecdsa-with-SHA384 }
//     }
//
//     sa-ecdsaWithSHA512 SIGNATURE-ALGORITHM ::= {
//      IDENTIFIER ecdsa-with-SHA512
//      VALUE ECDSA-Sig-Value
//      PARAMS TYPE NULL ARE absent
//      HASHES { mda-sha512 }
//      PUBLIC-KEYS { pk-ec }
//      SMIME-CAPS { IDENTIFIED BY ecdsa-with-SHA512 }
//     }
std::unique_ptr<SignatureAlgorithm> ParseEcdsa(DigestAlgorithm digest,
                                               const der::Input& params) {
  if (!IsEmpty(params))
    return nullptr;

  return SignatureAlgorithm::CreateEcdsa(digest);
}

// Parses a MaskGenAlgorithm as defined by RFC 5912:
//
//     MaskGenAlgorithm ::= AlgorithmIdentifier{ALGORITHM,
//                             {PKCS1MGFAlgorithms}}
//
//     mgf1SHA1 MaskGenAlgorithm ::= {
//         algorithm id-mgf1,
//         parameters HashAlgorithm : sha1Identifier
//     }
//
//     --
//     --  Define the set of mask generation functions
//     --
//     --  If the identifier is id-mgf1, any of the listed hash
//     --    algorithms may be used.
//     --
//
//     PKCS1MGFAlgorithms ALGORITHM ::= {
//         { IDENTIFIER id-mgf1 PARAMS TYPE HashAlgorithm ARE required },
//         ...
//     }
//
// Note that the possible mask gen algorithms is extensible. However at present
// the only function supported is MGF1, as that is the singular mask gen
// function defined by RFC 4055 / RFC 5912.
WARN_UNUSED_RESULT bool ParseMaskGenAlgorithm(const der::Input input,
                                              DigestAlgorithm* mgf1_hash) {
  der::Input oid;
  der::Input params;
  if (!ParseAlgorithmIdentifier(input, &oid, &params))
    return false;

  // MGF1 is the only supported mask generation algorithm.
  if (oid != der::Input(kOidMgf1))
    return false;

  return ParseHashAlgorithm(params, mgf1_hash);
}

// Consumes an optional, explicitly-tagged INTEGER from |parser|, using the
// indicated context-specific class number. Values greater than 32-bits will be
// rejected.
//
// Returns true on success and sets |*present| to true if the field was present.
WARN_UNUSED_RESULT bool ReadOptionalContextSpecificUint32(der::Parser* parser,
                                                          uint8_t class_number,
                                                          uint32_t* out,
                                                          bool* present) {
  der::Input value;
  bool has_value;

  // Read the context specific value.
  if (!parser->ReadOptionalTag(der::ContextSpecificConstructed(class_number),
                               &value, &has_value)) {
    return false;
  }

  if (has_value) {
    // Parse the integer contained in it.
    der::Parser number_parser(value);
    uint64_t uint64_value;

    if (!number_parser.ReadUint64(&uint64_value))
      return false;
    if (number_parser.HasMore())
      return false;

    // Cast the number to a uint32_t
    base::CheckedNumeric<uint32_t> casted(uint64_value);
    if (!casted.IsValid())
      return false;
    *out = casted.ValueOrDie();
  }

  *present = has_value;
  return true;
}

// Parses the parameters for an RSASSA-PSS signature algorithm, as defined by
// RFC 5912:
//
//     sa-rsaSSA-PSS SIGNATURE-ALGORITHM ::= {
//         IDENTIFIER id-RSASSA-PSS
//         PARAMS TYPE RSASSA-PSS-params ARE required
//         HASHES { mda-sha1 | mda-sha224 | mda-sha256 | mda-sha384
//                      | mda-sha512 }
//         PUBLIC-KEYS { pk-rsa | pk-rsaSSA-PSS }
//         SMIME-CAPS { IDENTIFIED BY id-RSASSA-PSS }
//     }
//
//     RSASSA-PSS-params  ::=  SEQUENCE  {
//         hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
//         maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
//         saltLength        [2] INTEGER DEFAULT 20,
//         trailerField      [3] INTEGER DEFAULT 1
//     }
//
// Which is to say the parameters MUST be present, and of type
// RSASSA-PSS-params.
std::unique_ptr<SignatureAlgorithm> ParseRsaPss(const der::Input& params) {
  der::Parser parser(params);
  der::Parser params_parser;
  if (!parser.ReadSequence(&params_parser))
    return nullptr;

  // There shouldn't be anything after the sequence (by definition the
  // parameters is a single sequence).
  if (parser.HasMore())
    return nullptr;

  bool has_field;
  der::Input field;

  // Parse:
  //     hashAlgorithm     [0] HashAlgorithm DEFAULT sha1Identifier,
  DigestAlgorithm hash = DigestAlgorithm::Sha1;
  if (!params_parser.ReadOptionalTag(der::ContextSpecificConstructed(0), &field,
                                     &has_field)) {
    return nullptr;
  }
  if (has_field && !ParseHashAlgorithm(field, &hash))
    return nullptr;

  // Parse:
  //     maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
  DigestAlgorithm mgf1_hash = DigestAlgorithm::Sha1;
  if (!params_parser.ReadOptionalTag(der::ContextSpecificConstructed(1), &field,
                                     &has_field)) {
    return nullptr;
  }
  if (has_field && !ParseMaskGenAlgorithm(field, &mgf1_hash))
    return nullptr;

  // Parse:
  //     saltLength        [2] INTEGER DEFAULT 20,
  uint32_t salt_length = 20u;
  if (!ReadOptionalContextSpecificUint32(&params_parser, 2, &salt_length,
                                         &has_field)) {
    return nullptr;
  }

  // Parse:
  //     trailerField      [3] INTEGER DEFAULT 1
  uint32_t trailer_field = 1u;
  if (!ReadOptionalContextSpecificUint32(&params_parser, 3, &trailer_field,
                                         &has_field)) {
    return nullptr;
  }

  // RFC 4055 says that the trailer field must be 1:
  //
  //     The trailerField field is an integer.  It provides
  //     compatibility with IEEE Std 1363a-2004 [P1363A].  The value
  //     MUST be 1, which represents the trailer field with hexadecimal
  //     value 0xBC.  Other trailer fields, including the trailer field
  //     composed of HashID concatenated with 0xCC that is specified in
  //     IEEE Std 1363a, are not supported.  Implementations that
  //     perform signature generation MUST omit the trailerField field,
  //     indicating that the default trailer field value was used.
  //     Implementations that perform signature validation MUST
  //     recognize both a present trailerField field with value 1 and an
  //     absent trailerField field.
  if (trailer_field != 1)
    return nullptr;

  // There must not be any unconsumed data left. (RFC 5912 does not explicitly
  // include an extensibility point for RSASSA-PSS-params)
  if (params_parser.HasMore())
    return nullptr;

  return SignatureAlgorithm::CreateRsaPss(hash, mgf1_hash, salt_length);
}

}  // namespace

WARN_UNUSED_RESULT bool ParseHashAlgorithm(const der::Input& input,
                                           DigestAlgorithm* out) {
  der::Input oid;
  der::Input params;
  if (!ParseAlgorithmIdentifier(input, &oid, &params))
    return false;

  DigestAlgorithm hash;

  if (oid == der::Input(kOidSha1)) {
    hash = DigestAlgorithm::Sha1;
  } else if (oid == der::Input(kOidSha256)) {
    hash = DigestAlgorithm::Sha256;
  } else if (oid == der::Input(kOidSha384)) {
    hash = DigestAlgorithm::Sha384;
  } else if (oid == der::Input(kOidSha512)) {
    hash = DigestAlgorithm::Sha512;
  } else {
    // TODO(eroman): Support MD2, MD4, MD5 for completeness?
    // Unsupported digest algorithm.
    return false;
  }

  // From RFC 5912: "PARAMS TYPE NULL ARE preferredPresent". Which is to say
  // the can either be absent, or NULL.
  if (!IsEmpty(params) && !IsNull(params))
    return false;

  *out = hash;
  return true;
}

RsaPssParameters::RsaPssParameters(DigestAlgorithm mgf1_hash,
                                   uint32_t salt_length)
    : mgf1_hash_(mgf1_hash), salt_length_(salt_length) {
}

SignatureAlgorithm::~SignatureAlgorithm() {
}

std::unique_ptr<SignatureAlgorithm> SignatureAlgorithm::Create(
    const der::Input& algorithm_identifier,
    CertErrors* errors) {
  // TODO(crbug.com/634443): Add useful error information.

  der::Input oid;
  der::Input params;
  if (!ParseAlgorithmIdentifier(algorithm_identifier, &oid, &params))
    return nullptr;

  // TODO(eroman): Each OID is tested for equality in order, which is not
  // particularly efficient.

  if (oid == der::Input(kOidSha1WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Sha1, params);

  if (oid == der::Input(kOidSha256WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Sha256, params);

  if (oid == der::Input(kOidSha384WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Sha384, params);

  if (oid == der::Input(kOidSha512WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Sha512, params);

  if (oid == der::Input(kOidEcdsaWithSha1))
    return ParseEcdsa(DigestAlgorithm::Sha1, params);

  if (oid == der::Input(kOidEcdsaWithSha256))
    return ParseEcdsa(DigestAlgorithm::Sha256, params);

  if (oid == der::Input(kOidEcdsaWithSha384))
    return ParseEcdsa(DigestAlgorithm::Sha384, params);

  if (oid == der::Input(kOidEcdsaWithSha512))
    return ParseEcdsa(DigestAlgorithm::Sha512, params);

  if (oid == der::Input(kOidRsaSsaPss))
    return ParseRsaPss(params);

  if (oid == der::Input(kOidSha1WithRsaSignature))
    return ParseRsaPkcs1(DigestAlgorithm::Sha1, params);

  if (oid == der::Input(kOidMd2WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Md2, params);

  if (oid == der::Input(kOidMd4WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Md4, params);

  if (oid == der::Input(kOidMd5WithRsaEncryption))
    return ParseRsaPkcs1(DigestAlgorithm::Md5, params);

  // TODO(crbug.com/634443): Add an error indicating what the OID
  // was.

  return nullptr;  // Unsupported OID.
}

std::unique_ptr<SignatureAlgorithm> SignatureAlgorithm::CreateRsaPkcs1(
    DigestAlgorithm digest) {
  return base::WrapUnique(
      new SignatureAlgorithm(SignatureAlgorithmId::RsaPkcs1, digest, nullptr));
}

std::unique_ptr<SignatureAlgorithm> SignatureAlgorithm::CreateEcdsa(
    DigestAlgorithm digest) {
  return base::WrapUnique(
      new SignatureAlgorithm(SignatureAlgorithmId::Ecdsa, digest, nullptr));
}

std::unique_ptr<SignatureAlgorithm> SignatureAlgorithm::CreateRsaPss(
    DigestAlgorithm digest,
    DigestAlgorithm mgf1_hash,
    uint32_t salt_length) {
  return base::WrapUnique(new SignatureAlgorithm(
      SignatureAlgorithmId::RsaPss, digest,
      base::MakeUnique<RsaPssParameters>(mgf1_hash, salt_length)));
}

const RsaPssParameters* SignatureAlgorithm::ParamsForRsaPss() const {
  if (algorithm_ == SignatureAlgorithmId::RsaPss)
    return static_cast<RsaPssParameters*>(params_.get());
  return nullptr;
}

bool SignatureAlgorithm::IsEquivalent(const der::Input& alg1_tlv,
                                      const der::Input& alg2_tlv) {
  if (alg1_tlv == alg2_tlv)
    return true;

  std::unique_ptr<SignatureAlgorithm> alg1 = Create(alg1_tlv, nullptr);
  std::unique_ptr<SignatureAlgorithm> alg2 = Create(alg2_tlv, nullptr);

  // Do checks that apply to all algorithms.
  if (!alg1 || !alg2 || (alg1->algorithm() != alg2->algorithm()) ||
      (alg1->digest() != alg2->digest())) {
    return false;
  }

  // Check algorithm-specific parameters for equality.
  switch (alg1->algorithm()) {
    case SignatureAlgorithmId::RsaPkcs1:
    case SignatureAlgorithmId::Ecdsa:
      DCHECK(!alg1->has_params());
      DCHECK(!alg2->has_params());
      return true;
    case SignatureAlgorithmId::RsaPss: {
      const RsaPssParameters* params1 = alg1->ParamsForRsaPss();
      const RsaPssParameters* params2 = alg2->ParamsForRsaPss();
      return params1 && params2 &&
             (params1->salt_length() == params2->salt_length()) &&
             (params1->mgf1_hash() == params2->mgf1_hash());
    }
  }

  return false;
}

SignatureAlgorithm::SignatureAlgorithm(
    SignatureAlgorithmId algorithm,
    DigestAlgorithm digest,
    std::unique_ptr<SignatureAlgorithmParameters> params)
    : algorithm_(algorithm), digest_(digest), params_(std::move(params)) {}

}  // namespace net
