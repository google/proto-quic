// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_objects_extractor.h"

#include <string.h>

#include "base/logging.h"
#include "base/sha1.h"
#include "base/strings/string_util.h"
#include "crypto/sha2.h"
#include "net/cert/asn1_util.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/obj.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

namespace net {

namespace ct {

namespace {

// The wire form of the OID 1.3.6.1.4.1.11129.2.4.2. See Section 3.3 of
// RFC6962.
const uint8_t kEmbeddedSCTOid[] = {0x2B, 0x06, 0x01, 0x04, 0x01,
                                   0xD6, 0x79, 0x02, 0x04, 0x02};

// The wire form of the OID 1.3.6.1.4.1.11129.2.4.5 - OCSP SingleExtension for
// X.509v3 Certificate Transparency Signed Certificate Timestamp List, see
// Section 3.3 of RFC6962.
const uint8_t kOCSPExtensionOid[] = {0x2B, 0x06, 0x01, 0x04, 0x01,
                                     0xD6, 0x79, 0x02, 0x04, 0x05};

bool StringEqualToCBS(const std::string& value1, const CBS* value2) {
  if (CBS_len(value2) != value1.size())
    return false;
  return memcmp(value1.data(), CBS_data(value2), CBS_len(value2)) == 0;
}

bssl::UniquePtr<X509> OSCertHandleToOpenSSL(
    X509Certificate::OSCertHandle os_handle) {
#if defined(USE_OPENSSL_CERTS)
  return bssl::UniquePtr<X509>(X509Certificate::DupOSCertHandle(os_handle));
#else
  std::string der_encoded;
  if (!X509Certificate::GetDEREncoded(os_handle, &der_encoded))
    return bssl::UniquePtr<X509>();
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(der_encoded.data());
  return bssl::UniquePtr<X509>(d2i_X509(NULL, &bytes, der_encoded.size()));
#endif
}

// Finds the SignedCertificateTimestampList in an extension with OID |oid| in
// |x509_exts|. If found, returns true and sets |*out_sct_list| to the encoded
// SCT list. |out_sct_list| may be NULL.
bool GetSCTListFromX509_EXTENSIONS(const X509_EXTENSIONS* x509_exts,
                                   const uint8_t* oid,
                                   size_t oid_len,
                                   std::string* out_sct_list) {
  for (size_t i = 0; i < sk_X509_EXTENSION_num(x509_exts); i++) {
    X509_EXTENSION* x509_ext = sk_X509_EXTENSION_value(x509_exts, i);
    if (static_cast<size_t>(x509_ext->object->length) == oid_len &&
        memcmp(x509_ext->object->data, oid, oid_len) == 0) {
      // The SCT list is an OCTET STRING inside the extension.
      CBS ext_value, sct_list;
      CBS_init(&ext_value, x509_ext->value->data, x509_ext->value->length);
      if (!CBS_get_asn1(&ext_value, &sct_list, CBS_ASN1_OCTETSTRING) ||
          CBS_len(&ext_value) != 0) {
        return false;
      }
      if (out_sct_list) {
        *out_sct_list =
            std::string(reinterpret_cast<const char*>(CBS_data(&sct_list)),
                        CBS_len(&sct_list));
      }
      return true;
    }
  }
  return false;
}

// Finds the SingleResponse in |responses| which matches |issuer| and
// |cert_serial_number|. On success, returns true and sets
// |*out_single_response| to the body of the SingleResponse starting at the
// |certStatus| field.
bool FindMatchingSingleResponse(CBS* responses,
                                X509Certificate::OSCertHandle issuer,
                                const std::string& cert_serial_number,
                                CBS* out_single_response) {
  std::string issuer_der;
  if (!X509Certificate::GetDEREncoded(issuer, &issuer_der))
    return false;

  base::StringPiece issuer_spki;
  if (!asn1::ExtractSPKIFromDERCert(issuer_der, &issuer_spki))
    return false;

  // In OCSP, only the key itself is under hash.
  base::StringPiece issuer_spk;
  if (!asn1::ExtractSubjectPublicKeyFromSPKI(issuer_spki, &issuer_spk))
    return false;

  // ExtractSubjectPublicKey... does not remove the initial octet encoding the
  // number of unused bits in the ASN.1 BIT STRING so we do it here. For public
  // keys, the bitstring is in practice always byte-aligned.
  if (issuer_spk.empty() || issuer_spk[0] != 0)
    return false;
  issuer_spk.remove_prefix(1);

  // TODO(ekasper): add SHA-384 to crypto/sha2.h and here if it proves
  // necessary.
  // TODO(ekasper): only compute the hashes on demand.
  std::string issuer_key_sha256_hash = crypto::SHA256HashString(issuer_spk);
  std::string issuer_key_sha1_hash =
      base::SHA1HashString(issuer_spk.as_string());

  while (CBS_len(responses) > 0) {
    CBS single_response, cert_id;
    if (!CBS_get_asn1(responses, &single_response, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&single_response, &cert_id, CBS_ASN1_SEQUENCE)) {
      return false;
    }

    CBS hash_algorithm, hash, serial_number, issuer_name_hash, issuer_key_hash;
    if (!CBS_get_asn1(&cert_id, &hash_algorithm, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&hash_algorithm, &hash, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&cert_id, &issuer_name_hash, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1(&cert_id, &issuer_key_hash, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1(&cert_id, &serial_number, CBS_ASN1_INTEGER) ||
        CBS_len(&cert_id) != 0) {
      return false;
    }

    // Check the serial number matches.
    if (!StringEqualToCBS(cert_serial_number, &serial_number))
      continue;

    // Check if the issuer_key_hash matches.
    // TODO(ekasper): also use the issuer name hash in matching.
    switch (OBJ_cbs2nid(&hash)) {
      case NID_sha1:
        if (StringEqualToCBS(issuer_key_sha1_hash, &issuer_key_hash)) {
          *out_single_response = single_response;
          return true;
        }
        break;
      case NID_sha256:
        if (StringEqualToCBS(issuer_key_sha256_hash, &issuer_key_hash)) {
          *out_single_response = single_response;
          return true;
        }
        break;
    }
  }

  return false;
}

}  // namespace

bool ExtractEmbeddedSCTList(X509Certificate::OSCertHandle cert,
                            std::string* sct_list) {
  bssl::UniquePtr<X509> x509(OSCertHandleToOpenSSL(cert));
  if (!x509)
    return false;
  X509_EXTENSIONS* x509_exts = x509->cert_info->extensions;
  if (!x509_exts)
    return false;
  return GetSCTListFromX509_EXTENSIONS(x509->cert_info->extensions,
                                       kEmbeddedSCTOid, sizeof(kEmbeddedSCTOid),
                                       sct_list);
}

bool GetPrecertLogEntry(X509Certificate::OSCertHandle leaf,
                        X509Certificate::OSCertHandle issuer,
                        LogEntry* result) {
  result->Reset();

  bssl::UniquePtr<X509> leaf_x509(OSCertHandleToOpenSSL(leaf));
  if (!leaf_x509)
    return false;

  // XXX(rsleevi): This check may be overkill, since we should be able to
  // generate precerts for certs without the extension. For now, just a sanity
  // check to match the reference implementation.
  if (!leaf_x509->cert_info->extensions ||
      !GetSCTListFromX509_EXTENSIONS(leaf_x509->cert_info->extensions,
                                     kEmbeddedSCTOid, sizeof(kEmbeddedSCTOid),
                                     NULL)) {
    return false;
  }

  // The Precertificate log entry is the final certificate's TBSCertificate
  // without the SCT extension (RFC6962, section 3.2).
  bssl::UniquePtr<X509> leaf_copy(X509_dup(leaf_x509.get()));
  if (!leaf_copy || !leaf_copy->cert_info->extensions) {
    NOTREACHED();
    return false;
  }
  X509_EXTENSIONS* leaf_copy_exts = leaf_copy->cert_info->extensions;
  for (size_t i = 0; i < sk_X509_EXTENSION_num(leaf_copy_exts); i++) {
    X509_EXTENSION* ext = sk_X509_EXTENSION_value(leaf_copy_exts, i);
    if (static_cast<size_t>(ext->object->length) == sizeof(kEmbeddedSCTOid) &&
        memcmp(ext->object->data, kEmbeddedSCTOid, sizeof(kEmbeddedSCTOid)) ==
            0) {
      X509_EXTENSION_free(sk_X509_EXTENSION_delete(leaf_copy_exts, i));
      X509_CINF_set_modified(leaf_copy->cert_info);
      break;
    }
  }

  std::string to_be_signed;
  int len = i2d_X509_CINF(leaf_copy->cert_info, NULL);
  if (len < 0)
    return false;
  uint8_t* ptr =
      reinterpret_cast<uint8_t*>(base::WriteInto(&to_be_signed, len + 1));
  if (i2d_X509_CINF(leaf_copy->cert_info, &ptr) < 0)
    return false;

  // Extract the issuer's public key.
  std::string issuer_der;
  if (!X509Certificate::GetDEREncoded(issuer, &issuer_der))
    return false;
  base::StringPiece issuer_key;
  if (!asn1::ExtractSPKIFromDERCert(issuer_der, &issuer_key))
    return false;

  // Fill in the LogEntry.
  result->type = ct::LogEntry::LOG_ENTRY_TYPE_PRECERT;
  result->tbs_certificate.swap(to_be_signed);
  crypto::SHA256HashString(issuer_key, result->issuer_key_hash.data,
                           sizeof(result->issuer_key_hash.data));

  return true;
}

bool GetX509LogEntry(X509Certificate::OSCertHandle leaf, LogEntry* result) {
  DCHECK(leaf);

  std::string encoded;
  if (!X509Certificate::GetDEREncoded(leaf, &encoded))
    return false;

  result->Reset();
  result->type = ct::LogEntry::LOG_ENTRY_TYPE_X509;
  result->leaf_certificate.swap(encoded);
  return true;
}

bool ExtractSCTListFromOCSPResponse(X509Certificate::OSCertHandle issuer,
                                    const std::string& cert_serial_number,
                                    base::StringPiece ocsp_response,
                                    std::string* sct_list) {
  // The input is an OCSPResponse. See RFC2560, section 4.2.1. The SCT list is
  // in the extensions field of the SingleResponse which matches the input
  // certificate.
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(ocsp_response.data()),
           ocsp_response.size());

  // Parse down to the ResponseBytes. The ResponseBytes is optional, but if it's
  // missing, this can't include an SCT list.
  CBS sequence, response_status, tagged_response_bytes, response_bytes;
  CBS response_type, response;
  if (!CBS_get_asn1(&cbs, &sequence, CBS_ASN1_SEQUENCE) || CBS_len(&cbs) != 0 ||
      !CBS_get_asn1(&sequence, &response_status, CBS_ASN1_ENUMERATED) ||
      !CBS_get_asn1(&sequence, &tagged_response_bytes,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      CBS_len(&sequence) != 0 ||
      !CBS_get_asn1(&tagged_response_bytes, &response_bytes,
                    CBS_ASN1_SEQUENCE) ||
      CBS_len(&tagged_response_bytes) != 0 ||
      !CBS_get_asn1(&response_bytes, &response_type, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&response_bytes, &response, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&response_bytes) != 0) {
    return false;
  }

  // The only relevant ResponseType is id-pkix-ocsp-basic.
  if (OBJ_cbs2nid(&response_type) != NID_id_pkix_OCSP_basic)
    return false;

  // Parse the ResponseData out of the BasicOCSPResponse. Ignore the rest.
  CBS basic_response, response_data, responses;
  if (!CBS_get_asn1(&response, &basic_response, CBS_ASN1_SEQUENCE) ||
      CBS_len(&response) != 0 ||
      !CBS_get_asn1(&basic_response, &response_data, CBS_ASN1_SEQUENCE)) {
  }

  // Skip the optional version.
  const int kVersionTag = CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0;
  if (CBS_len(&response_data) > 0 &&
      CBS_data(&response_data)[0] == kVersionTag &&
      !CBS_get_asn1(&response_data, NULL /* version */, kVersionTag)) {
    return false;
  }

  // Extract the list of SingleResponses.
  if (!CBS_get_any_asn1_element(&response_data, NULL /* responderID */, NULL,
                                NULL) ||
      !CBS_get_any_asn1_element(&response_data, NULL /* producedAt */, NULL,
                                NULL) ||
      !CBS_get_asn1(&response_data, &responses, CBS_ASN1_SEQUENCE)) {
    return false;
  }

  CBS single_response;
  if (!FindMatchingSingleResponse(&responses, issuer, cert_serial_number,
                                  &single_response)) {
    return false;
  }

  // Skip the certStatus and thisUpdate fields.
  if (!CBS_get_any_asn1_element(&single_response, NULL /* certStatus */, NULL,
                                NULL) ||
      !CBS_get_any_asn1_element(&single_response, NULL /* thisUpdate */, NULL,
                                NULL)) {
    return false;
  }

  const int kNextUpdateTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0;
  const int kSingleExtensionsTag =
      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1;

  // Skip the optional nextUpdate field.
  if (CBS_len(&single_response) > 0 &&
      CBS_data(&single_response)[0] == kNextUpdateTag &&
      !CBS_get_asn1(&single_response, NULL /* nextUpdate */, kNextUpdateTag)) {
    return false;
  }

  CBS extensions;
  if (!CBS_get_asn1(&single_response, &extensions, kSingleExtensionsTag))
    return false;
  const uint8_t* ptr = CBS_data(&extensions);
  bssl::UniquePtr<X509_EXTENSIONS> x509_exts(
      d2i_X509_EXTENSIONS(NULL, &ptr, CBS_len(&extensions)));
  if (!x509_exts || ptr != CBS_data(&extensions) + CBS_len(&extensions))
    return false;

  return GetSCTListFromX509_EXTENSIONS(x509_exts.get(), kOCSPExtensionOid,
                                       sizeof(kOCSPExtensionOid), sct_list);
}

}  // namespace ct

}  // namespace net
