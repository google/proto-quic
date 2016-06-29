// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>

#include "base/sha1.h"
#include "crypto/sha2.h"
#include "net/cert/internal/parse_ocsp.h"

namespace net {

OCSPCertID::OCSPCertID() {}
OCSPCertID::~OCSPCertID() {}

OCSPSingleResponse::OCSPSingleResponse() {}
OCSPSingleResponse::~OCSPSingleResponse() {}

OCSPResponseData::OCSPResponseData() {}
OCSPResponseData::~OCSPResponseData() {}

OCSPResponse::OCSPResponse() {}
OCSPResponse::~OCSPResponse() {}

der::Input BasicOCSPResponseOid() {
  // From RFC 6960:
  //
  // id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
  // id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
  //
  // In dotted notation: 1.3.6.1.5.5.7.48.1.1
  static const uint8_t oid[] = {0x2b, 0x06, 0x01, 0x05, 0x05,
                                0x07, 0x30, 0x01, 0x01};
  return der::Input(oid);
}

// CertID ::= SEQUENCE {
//    hashAlgorithm           AlgorithmIdentifier,
//    issuerNameHash          OCTET STRING, -- Hash of issuer's DN
//    issuerKeyHash           OCTET STRING, -- Hash of issuer's public key
//    serialNumber            CertificateSerialNumber
// }
bool ParseOCSPCertID(const der::Input& raw_tlv, OCSPCertID* out) {
  der::Parser outer_parser(raw_tlv);
  der::Parser parser;
  if (!outer_parser.ReadSequence(&parser))
    return false;
  if (outer_parser.HasMore())
    return false;

  der::Input sigalg_tlv;
  if (!parser.ReadRawTLV(&sigalg_tlv))
    return false;
  if (!ParseHashAlgorithm(sigalg_tlv, &(out->hash_algorithm)))
    return false;
  if (!parser.ReadTag(der::kOctetString, &(out->issuer_name_hash)))
    return false;
  if (!parser.ReadTag(der::kOctetString, &(out->issuer_key_hash)))
    return false;
  if (!parser.ReadTag(der::kInteger, &(out->serial_number)))
    return false;
  if (!VerifySerialNumber(out->serial_number))
    return false;

  return !parser.HasMore();
}

namespace {

// Parses |raw_tlv| to extract an OCSP RevokedInfo (RFC 6960) and stores the
// result in the OCSPCertStatus |out|. Returns whether the parsing was
// successful.
//
// RevokedInfo ::= SEQUENCE {
//      revocationTime              GeneralizedTime,
//      revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
// }
bool ParseRevokedInfo(const der::Input& raw_tlv, OCSPCertStatus* out) {
  der::Parser parser(raw_tlv);
  if (!parser.ReadGeneralizedTime(&(out->revocation_time)))
    return false;

  der::Input reason_input;
  if (!parser.ReadOptionalTag(der::ContextSpecificConstructed(0), &reason_input,
                              &(out->has_reason))) {
    return false;
  }
  if (out->has_reason) {
    der::Parser reason_parser(reason_input);
    der::Input reason_value_input;
    uint8_t reason_value;
    if (!reason_parser.ReadTag(der::kEnumerated, &reason_value_input))
      return false;
    if (!der::ParseUint8(reason_value_input, &reason_value))
      return false;
    if (reason_value >
        static_cast<uint8_t>(OCSPCertStatus::RevocationReason::LAST)) {
      return false;
    }
    out->revocation_reason =
        static_cast<OCSPCertStatus::RevocationReason>(reason_value);
    if (out->revocation_reason == OCSPCertStatus::RevocationReason::UNUSED)
      return false;
    if (reason_parser.HasMore())
      return false;
  }
  return !parser.HasMore();
}

// Parses |raw_tlv| to extract an OCSP CertStatus (RFC 6960) and stores the
// result in the OCSPCertStatus |out|. Returns whether the parsing was
// successful.
//
// CertStatus ::= CHOICE {
//      good        [0]     IMPLICIT NULL,
//      revoked     [1]     IMPLICIT RevokedInfo,
//      unknown     [2]     IMPLICIT UnknownInfo
// }
//
// UnknownInfo ::= NULL
bool ParseCertStatus(const der::Input& raw_tlv, OCSPCertStatus* out) {
  der::Parser parser(raw_tlv);
  der::Tag status_tag;
  der::Input status;
  if (!parser.ReadTagAndValue(&status_tag, &status))
    return false;

  out->has_reason = false;
  if (status_tag == der::ContextSpecificPrimitive(0)) {
    out->status = OCSPCertStatus::Status::GOOD;
  } else if (status_tag == der::ContextSpecificConstructed(1)) {
    out->status = OCSPCertStatus::Status::REVOKED;
    if (!ParseRevokedInfo(status, out))
      return false;
  } else if (status_tag == der::ContextSpecificPrimitive(2)) {
    out->status = OCSPCertStatus::Status::UNKNOWN;
  } else {
    return false;
  }

  return !parser.HasMore();
}

}  // namespace

// SingleResponse ::= SEQUENCE {
//      certID                       CertID,
//      certStatus                   CertStatus,
//      thisUpdate                   GeneralizedTime,
//      nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
//      singleExtensions   [1]       EXPLICIT Extensions OPTIONAL
// }
bool ParseOCSPSingleResponse(const der::Input& raw_tlv,
                             OCSPSingleResponse* out) {
  der::Parser outer_parser(raw_tlv);
  der::Parser parser;
  if (!outer_parser.ReadSequence(&parser))
    return false;
  if (outer_parser.HasMore())
    return false;

  if (!parser.ReadRawTLV(&(out->cert_id_tlv)))
    return false;
  der::Input status_tlv;
  if (!parser.ReadRawTLV(&status_tlv))
    return false;
  if (!ParseCertStatus(status_tlv, &(out->cert_status)))
    return false;
  if (!parser.ReadGeneralizedTime(&(out->this_update)))
    return false;

  der::Input next_update_input;
  if (!parser.ReadOptionalTag(der::ContextSpecificConstructed(0),
                              &next_update_input, &(out->has_next_update))) {
    return false;
  }
  if (out->has_next_update) {
    der::Parser next_update_parser(next_update_input);
    if (!next_update_parser.ReadGeneralizedTime(&(out->next_update)))
      return false;
    if (next_update_parser.HasMore())
      return false;
  }

  if (!parser.ReadOptionalTag(der::ContextSpecificConstructed(1),
                              &(out->extensions), &(out->has_extensions))) {
    return false;
  }

  return !parser.HasMore();
}

namespace {

// Parses |raw_tlv| to extract a ResponderID (RFC 6960) and stores the
// result in the ResponderID |out|. Returns whether the parsing was successful.
//
// ResponderID ::= CHOICE {
//      byName               [1] Name,
//      byKey                [2] KeyHash
// }
bool ParseResponderID(const der::Input& raw_tlv,
                      OCSPResponseData::ResponderID* out) {
  der::Parser parser(raw_tlv);
  der::Tag id_tag;
  der::Input id_input;
  if (!parser.ReadTagAndValue(&id_tag, &id_input))
    return false;

  if (id_tag == der::ContextSpecificConstructed(1)) {
    out->type = OCSPResponseData::ResponderType::NAME;
    out->name = id_input;
  } else if (id_tag == der::ContextSpecificConstructed(2)) {
    der::Parser key_parser(id_input);
    der::Input responder_key;
    if (!key_parser.ReadTag(der::kOctetString, &responder_key))
      return false;
    if (key_parser.HasMore())
      return false;

    SHA1HashValue key_hash;
    if (responder_key.Length() != sizeof(key_hash.data))
      return false;
    memcpy(key_hash.data, responder_key.UnsafeData(), sizeof(key_hash.data));
    out->type = OCSPResponseData::ResponderType::KEY_HASH;
    out->key_hash = HashValue(key_hash);
  } else {
    return false;
  }
  return !parser.HasMore();
}

}  // namespace

// ResponseData ::= SEQUENCE {
//      version              [0] EXPLICIT Version DEFAULT v1,
//      responderID              ResponderID,
//      producedAt               GeneralizedTime,
//      responses                SEQUENCE OF SingleResponse,
//      responseExtensions   [1] EXPLICIT Extensions OPTIONAL
// }
bool ParseOCSPResponseData(const der::Input& raw_tlv, OCSPResponseData* out) {
  der::Parser outer_parser(raw_tlv);
  der::Parser parser;
  if (!outer_parser.ReadSequence(&parser))
    return false;
  if (outer_parser.HasMore())
    return false;

  der::Input version_input;
  bool version_present;
  if (!parser.ReadOptionalTag(der::ContextSpecificConstructed(0),
                              &version_input, &version_present)) {
    return false;
  }

  // For compatibilty, we ignore the restriction from X.690 Section 11.5 that
  // DEFAULT values should be omitted for values equal to the default value.
  // TODO: Add warning about non-strict parsing.
  if (version_present) {
    der::Parser version_parser(version_input);
    if (!version_parser.ReadUint8(&(out->version)))
      return false;
    if (version_parser.HasMore())
      return false;
  } else {
    out->version = 0;
  }

  if (out->version != 0)
    return false;

  der::Input responder_input;
  if (!parser.ReadRawTLV(&responder_input))
    return false;
  if (!ParseResponderID(responder_input, &(out->responder_id)))
    return false;
  if (!parser.ReadGeneralizedTime(&(out->produced_at)))
    return false;

  der::Parser responses_parser;
  if (!parser.ReadSequence(&responses_parser))
    return false;
  out->responses.clear();
  while (responses_parser.HasMore()) {
    der::Input single_response;
    if (!responses_parser.ReadRawTLV(&single_response))
      return false;
    out->responses.push_back(single_response);
  }

  if (!parser.ReadOptionalTag(der::ContextSpecificConstructed(1),
                              &(out->extensions), &(out->has_extensions))) {
    return false;
  }

  return !parser.HasMore();
}

namespace {

// Parses |raw_tlv| to extract a BasicOCSPResponse (RFC 6960) and stores the
// result in the OCSPResponse |out|. Returns whether the parsing was
// successful.
//
// BasicOCSPResponse       ::= SEQUENCE {
//      tbsResponseData      ResponseData,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signature            BIT STRING,
//      certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
// }
bool ParseBasicOCSPResponse(const der::Input& raw_tlv, OCSPResponse* out) {
  der::Parser outer_parser(raw_tlv);
  der::Parser parser;
  if (!outer_parser.ReadSequence(&parser))
    return false;
  if (outer_parser.HasMore())
    return false;

  if (!parser.ReadRawTLV(&(out->data)))
    return false;
  der::Input sigalg_tlv;
  if (!parser.ReadRawTLV(&sigalg_tlv))
    return false;
  out->signature_algorithm = SignatureAlgorithm::CreateFromDer(sigalg_tlv);
  if (!out->signature_algorithm)
    return false;
  if (!parser.ReadBitString(&(out->signature)))
    return false;
  der::Input certs_input;
  if (!parser.ReadOptionalTag(der::ContextSpecificConstructed(0), &certs_input,
                              &(out->has_certs))) {
    return false;
  }

  out->certs.clear();
  if (out->has_certs) {
    der::Parser certs_seq_parser(certs_input);
    der::Parser certs_parser;
    if (!certs_seq_parser.ReadSequence(&certs_parser))
      return false;
    if (certs_seq_parser.HasMore())
      return false;
    while (certs_parser.HasMore()) {
      der::Input cert_tlv;
      if (!certs_parser.ReadRawTLV(&cert_tlv))
        return false;
      out->certs.push_back(cert_tlv);
    }
  }

  return !parser.HasMore();
}

}  // namespace

// OCSPResponse ::= SEQUENCE {
//      responseStatus         OCSPResponseStatus,
//      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL
// }
//
// ResponseBytes ::=       SEQUENCE {
//      responseType   OBJECT IDENTIFIER,
//      response       OCTET STRING
// }
bool ParseOCSPResponse(const der::Input& raw_tlv, OCSPResponse* out) {
  der::Parser outer_parser(raw_tlv);
  der::Parser parser;
  if (!outer_parser.ReadSequence(&parser))
    return false;
  if (outer_parser.HasMore())
    return false;

  der::Input response_status_input;
  uint8_t response_status;
  if (!parser.ReadTag(der::kEnumerated, &response_status_input))
    return false;
  if (!der::ParseUint8(response_status_input, &response_status))
    return false;
  if (response_status >
      static_cast<uint8_t>(OCSPResponse::ResponseStatus::LAST)) {
    return false;
  }
  out->status = static_cast<OCSPResponse::ResponseStatus>(response_status);
  if (out->status == OCSPResponse::ResponseStatus::UNUSED)
    return false;

  if (out->status == OCSPResponse::ResponseStatus::SUCCESSFUL) {
    der::Parser outer_bytes_parser;
    der::Parser bytes_parser;
    if (!parser.ReadConstructed(der::ContextSpecificConstructed(0),
                                &outer_bytes_parser)) {
      return false;
    }
    if (!outer_bytes_parser.ReadSequence(&bytes_parser))
      return false;
    if (outer_bytes_parser.HasMore())
      return false;

    der::Input type_oid;
    if (!bytes_parser.ReadTag(der::kOid, &type_oid))
      return false;
    if (type_oid != BasicOCSPResponseOid())
      return false;

    // As per RFC 6960 Section 4.2.1, the value of |response| SHALL be the DER
    // encoding of BasicOCSPResponse.
    der::Input response;
    if (!bytes_parser.ReadTag(der::kOctetString, &response))
      return false;
    if (!ParseBasicOCSPResponse(response, out))
      return false;
    if (bytes_parser.HasMore())
      return false;
  }

  return !parser.HasMore();
}

namespace {

// Checks that the |type| hash of |value| is equal to |hash|
bool VerifyHash(HashValueTag type,
                const der::Input& hash,
                const der::Input& value) {
  HashValue target(type);
  if (target.size() != hash.Length())
    return false;
  memcpy(target.data(), hash.UnsafeData(), target.size());

  HashValue value_hash(type);
  if (type == HASH_VALUE_SHA1) {
    base::SHA1HashBytes(value.UnsafeData(), value.Length(), value_hash.data());
  } else if (type == HASH_VALUE_SHA256) {
    std::string hash_string = crypto::SHA256HashString(value.AsString());
    memcpy(value_hash.data(), hash_string.data(), value_hash.size());
  } else {
    return false;
  }

  return target == value_hash;
}

// Checks that the input |id_tlv| parses to a valid CertID and matches the
// issuer |issuer| name and key, as well as the serial number |serial_number|.
bool CheckCertID(const der::Input& id_tlv,
                 const ParsedTbsCertificate& certificate,
                 const ParsedTbsCertificate& issuer,
                 const der::Input& serial_number) {
  OCSPCertID id;
  if (!ParseOCSPCertID(id_tlv, &id))
    return false;

  HashValueTag type = HASH_VALUE_SHA1;
  switch (id.hash_algorithm) {
    case DigestAlgorithm::Sha1:
      type = HASH_VALUE_SHA1;
      break;
    case DigestAlgorithm::Sha256:
      type = HASH_VALUE_SHA256;
      break;
    case DigestAlgorithm::Sha384:
    case DigestAlgorithm::Sha512:
      NOTIMPLEMENTED();
      return false;
  }

  if (!VerifyHash(type, id.issuer_name_hash, certificate.issuer_tlv))
    return false;

  // SubjectPublicKeyInfo  ::=  SEQUENCE  {
  //     algorithm            AlgorithmIdentifier,
  //     subjectPublicKey     BIT STRING
  // }
  der::Parser outer_parser(issuer.spki_tlv);
  der::Parser spki_parser;
  der::BitString key_bits;
  if (!outer_parser.ReadSequence(&spki_parser))
    return false;
  if (outer_parser.HasMore())
    return false;
  if (!spki_parser.SkipTag(der::kSequence))
    return false;
  if (!spki_parser.ReadBitString(&key_bits))
    return false;
  der::Input key_tlv = key_bits.bytes();
  if (!VerifyHash(type, id.issuer_key_hash, key_tlv))
    return false;

  return id.serial_number == serial_number;
}

}  // namespace

bool GetOCSPCertStatus(const OCSPResponseData& response_data,
                       const der::Input& issuer_tbs_certificate_tlv,
                       const der::Input& cert_tbs_certificate_tlv,
                       OCSPCertStatus* out) {
  out->status = OCSPCertStatus::Status::GOOD;

  ParsedTbsCertificate tbs_cert;
  if (!ParseTbsCertificate(cert_tbs_certificate_tlv, {}, &tbs_cert))
    return false;
  ParsedTbsCertificate issuer_tbs_cert;
  if (!ParseTbsCertificate(issuer_tbs_certificate_tlv, {}, &issuer_tbs_cert))
    return false;

  bool found = false;
  for (const auto& response : response_data.responses) {
    OCSPSingleResponse single_response;
    if (!ParseOCSPSingleResponse(response, &single_response))
      return false;
    if (CheckCertID(single_response.cert_id_tlv, tbs_cert, issuer_tbs_cert,
                    tbs_cert.serial_number)) {
      OCSPCertStatus new_status = single_response.cert_status;
      found = true;
      // In the case that we receive multiple responses, we keep only the
      // strictest status (REVOKED > UNKNOWN > GOOD).
      if (out->status == OCSPCertStatus::Status::GOOD ||
          new_status.status == OCSPCertStatus::Status::REVOKED) {
        *out = new_status;
      }
    }
  }

  if (!found)
    out->status = OCSPCertStatus::Status::UNKNOWN;

  return found;
}

}  // namespace net
