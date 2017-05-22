// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "crypto/openssl_util.h"
#include "net/base/ip_address.h"
#include "net/cert/asn1_util.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/name_constraints.h"
#include "net/cert/internal/parse_name.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/verify_name_match.h"
#include "net/cert/internal/verify_signed_data.h"
#include "net/cert/x509_util.h"
#include "net/der/parser.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/pkcs7.h"
#include "third_party/boringssl/src/include/openssl/pool.h"
#include "third_party/boringssl/src/include/openssl/sha.h"

namespace net {

namespace {

// Converts a GeneralizedTime struct to a base::Time, returning true on success
// or false if |generalized| was invalid or cannot be represented by
// base::Time.
bool GeneralizedTimeToBaseTime(const der::GeneralizedTime& generalized,
                               base::Time* result) {
  base::Time::Exploded exploded = {0};
  exploded.year = generalized.year;
  exploded.month = generalized.month;
  exploded.day_of_month = generalized.day;
  exploded.hour = generalized.hours;
  exploded.minute = generalized.minutes;
  exploded.second = generalized.seconds;
  return base::Time::FromUTCExploded(exploded, result);
}

ParseCertificateOptions DefaultParseCertificateOptions() {
  ParseCertificateOptions options;
  options.allow_invalid_serial_numbers = true;
  return options;
}

// Sets |value| to the Value from a DER Sequence Tag-Length-Value and return
// true, or return false if the TLV was not a valid DER Sequence.
WARN_UNUSED_RESULT bool GetSequenceValue(const der::Input& tlv,
                                         der::Input* value) {
  der::Parser parser(tlv);
  return parser.ReadTag(der::kSequence, value) && !parser.HasMore();
}

// Normalize |cert|'s Issuer and store it in |out_normalized_issuer|, returning
// true on success or false if there was a parsing error.
bool GetNormalizedCertIssuer(CRYPTO_BUFFER* cert,
                             std::string* out_normalized_issuer) {
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  if (!ParseCertificate(
          der::Input(CRYPTO_BUFFER_data(cert), CRYPTO_BUFFER_len(cert)),
          &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
          nullptr)) {
    return false;
  }
  ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           DefaultParseCertificateOptions(), &tbs, nullptr))
    return false;

  der::Input issuer_value;
  if (!GetSequenceValue(tbs.issuer_tlv, &issuer_value))
    return false;

  return NormalizeName(issuer_value, out_normalized_issuer);
}

// Fills |principal| from the DER encoded |name_tlv|, returning true on success
// or false if parsing failed or some of the values could not be converted to
// UTF-8.
bool ParsePrincipal(const der::Input& name_tlv, CertPrincipal* principal) {
  RDNSequence rdns;
  if (!ParseName(name_tlv, &rdns))
    return false;

  for (const RelativeDistinguishedName& rdn : rdns) {
    for (const X509NameAttribute& name_attribute : rdn) {
      if (name_attribute.type == TypeCommonNameOid()) {
        if (principal->common_name.empty() &&
            !name_attribute.ValueAsString(&principal->common_name)) {
          return false;
        }
      } else if (name_attribute.type == TypeLocalityNameOid()) {
        if (principal->locality_name.empty() &&
            !name_attribute.ValueAsString(&principal->locality_name)) {
          return false;
        }
      } else if (name_attribute.type == TypeStateOrProvinceNameOid()) {
        if (principal->state_or_province_name.empty() &&
            !name_attribute.ValueAsString(&principal->state_or_province_name)) {
          return false;
        }
      } else if (name_attribute.type == TypeCountryNameOid()) {
        if (principal->country_name.empty() &&
            !name_attribute.ValueAsString(&principal->country_name)) {
          return false;
        }
      } else if (name_attribute.type == TypeStreetAddressOid()) {
        std::string s;
        if (!name_attribute.ValueAsString(&s))
          return false;
        principal->street_addresses.push_back(s);
      } else if (name_attribute.type == TypeOrganizationNameOid()) {
        std::string s;
        if (!name_attribute.ValueAsString(&s))
          return false;
        principal->organization_names.push_back(s);
      } else if (name_attribute.type == TypeOrganizationUnitNameOid()) {
        std::string s;
        if (!name_attribute.ValueAsString(&s))
          return false;
        principal->organization_unit_names.push_back(s);
      } else if (name_attribute.type == TypeDomainComponentOid()) {
        std::string s;
        if (!name_attribute.ValueAsString(&s))
          return false;
        principal->domain_components.push_back(s);
      }
    }
  }
  return true;
}

// Parses certificates from a PKCS#7 SignedData structure, appending them to
// |handles|.
void CreateOSCertHandlesFromPKCS7Bytes(
    const char* data,
    size_t length,
    X509Certificate::OSCertHandles* handles) {
  crypto::EnsureOpenSSLInit();
  crypto::OpenSSLErrStackTracer err_cleaner(FROM_HERE);

  CBS der_data;
  CBS_init(&der_data, reinterpret_cast<const uint8_t*>(data), length);
  STACK_OF(CRYPTO_BUFFER)* certs = sk_CRYPTO_BUFFER_new_null();

  if (PKCS7_get_raw_certificates(certs, &der_data,
                                 x509_util::GetBufferPool())) {
    for (size_t i = 0; i < sk_CRYPTO_BUFFER_num(certs); ++i) {
      handles->push_back(sk_CRYPTO_BUFFER_value(certs, i));
    }
  }
  // |handles| took ownership of the individual buffers, so only free the list
  // itself.
  sk_CRYPTO_BUFFER_free(certs);
}

}  // namespace

bool X509Certificate::Initialize() {
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;

  if (!ParseCertificate(der::Input(CRYPTO_BUFFER_data(cert_handle_),
                                   CRYPTO_BUFFER_len(cert_handle_)),
                        &tbs_certificate_tlv, &signature_algorithm_tlv,
                        &signature_value, nullptr)) {
    return false;
  }

  ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           DefaultParseCertificateOptions(), &tbs, nullptr))
    return false;

  if (!ParsePrincipal(tbs.subject_tlv, &subject_) ||
      !ParsePrincipal(tbs.issuer_tlv, &issuer_)) {
    return false;
  }

  if (!GeneralizedTimeToBaseTime(tbs.validity_not_before, &valid_start_) ||
      !GeneralizedTimeToBaseTime(tbs.validity_not_after, &valid_expiry_)) {
    return false;
  }
  serial_number_ = tbs.serial_number.AsString();
  return true;
}

bool X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  if (dns_names)
    dns_names->clear();
  if (ip_addrs)
    ip_addrs->clear();

  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  if (!ParseCertificate(der::Input(CRYPTO_BUFFER_data(cert_handle_),
                                   CRYPTO_BUFFER_len(cert_handle_)),
                        &tbs_certificate_tlv, &signature_algorithm_tlv,
                        &signature_value, nullptr)) {
    return false;
  }

  ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           DefaultParseCertificateOptions(), &tbs, nullptr))
    return false;
  if (!tbs.has_extensions)
    return false;

  std::map<der::Input, ParsedExtension> extensions;
  if (!ParseExtensions(tbs.extensions_tlv, &extensions))
    return false;

  ParsedExtension subject_alt_names_extension;
  if (!ConsumeExtension(SubjectAltNameOid(), &extensions,
                        &subject_alt_names_extension)) {
    return false;
  }

  std::unique_ptr<GeneralNames> subject_alt_names =
      GeneralNames::Create(subject_alt_names_extension.value);
  if (!subject_alt_names)
    return false;

  if (dns_names)
    *dns_names = subject_alt_names->dns_names;
  if (ip_addrs) {
    for (const IPAddress& addr : subject_alt_names->ip_addresses) {
      ip_addrs->push_back(
          std::string(reinterpret_cast<const char*>(addr.bytes().data()),
                      addr.bytes().size()));
    }
  }

  return !subject_alt_names->dns_names.empty() ||
         !subject_alt_names->ip_addresses.empty();
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  std::vector<std::string> normalized_issuers;
  for (const auto& raw_issuer : valid_issuers) {
    der::Input issuer_value;
    std::string normalized_issuer;
    if (!GetSequenceValue(der::Input(&raw_issuer), &issuer_value) ||
        !NormalizeName(issuer_value, &normalized_issuer)) {
      continue;
    }
    normalized_issuers.push_back(std::move(normalized_issuer));
  }

  std::string normalized_cert_issuer;
  if (!GetNormalizedCertIssuer(cert_handle_, &normalized_cert_issuer))
    return false;
  if (std::find(normalized_issuers.begin(), normalized_issuers.end(),
                normalized_cert_issuer) != normalized_issuers.end())
    return true;

  for (CRYPTO_BUFFER* intermediate : intermediate_ca_certs_) {
    if (!GetNormalizedCertIssuer(intermediate, &normalized_cert_issuer))
      return false;
    if (std::find(normalized_issuers.begin(), normalized_issuers.end(),
                  normalized_cert_issuer) != normalized_issuers.end())
      return true;
  }
  return false;
}

// static
bool X509Certificate::GetDEREncoded(X509Certificate::OSCertHandle cert_handle,
                                    std::string* encoded) {
  if (!cert_handle)
    return false;
  encoded->assign(
      reinterpret_cast<const char*>(CRYPTO_BUFFER_data(cert_handle)),
      CRYPTO_BUFFER_len(cert_handle));
  return true;
}

// static
void X509Certificate::GetPublicKeyInfo(OSCertHandle cert_handle,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  *type = kPublicKeyTypeUnknown;
  *size_bits = 0;

  base::StringPiece spki;
  if (!asn1::ExtractSPKIFromDERCert(
          base::StringPiece(
              reinterpret_cast<const char*>(CRYPTO_BUFFER_data(cert_handle)),
              CRYPTO_BUFFER_len(cert_handle)),
          &spki)) {
    return;
  }

  bssl::UniquePtr<EVP_PKEY> pkey;
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(spki.data()), spki.size());
  pkey.reset(EVP_parse_public_key(&cbs));
  if (!pkey)
    return;

  switch (pkey->type) {
    case EVP_PKEY_RSA:
      *type = kPublicKeyTypeRSA;
      break;
    case EVP_PKEY_DSA:
      *type = kPublicKeyTypeDSA;
      break;
    case EVP_PKEY_EC:
      *type = kPublicKeyTypeECDSA;
      break;
    case EVP_PKEY_DH:
      *type = kPublicKeyTypeDH;
      break;
  }
  *size_bits = base::saturated_cast<size_t>(EVP_PKEY_bits(pkey.get()));
}

// static
bool X509Certificate::IsSameOSCert(X509Certificate::OSCertHandle a,
                                   X509Certificate::OSCertHandle b) {
  DCHECK(a && b);
  if (a == b)
    return true;
  return CRYPTO_BUFFER_len(a) == CRYPTO_BUFFER_len(b) &&
         memcmp(CRYPTO_BUFFER_data(a), CRYPTO_BUFFER_data(b),
                CRYPTO_BUFFER_len(a)) == 0;
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  // Do a bare minimum of DER parsing here to make sure the input is not
  // completely crazy. (This is required for at least
  // CreateCertificateListFromBytes with FORMAT_AUTO, if not more.)
  if (!ParseCertificate(
          der::Input(reinterpret_cast<const uint8_t*>(data), length),
          &tbs_certificate_tlv, &signature_algorithm_tlv, &signature_value,
          nullptr)) {
    return nullptr;
  }

  return CRYPTO_BUFFER_new(reinterpret_cast<const uint8_t*>(data), length,
                           x509_util::GetBufferPool());
}

// static
X509Certificate::OSCertHandles X509Certificate::CreateOSCertHandlesFromBytes(
    const char* data,
    size_t length,
    Format format) {
  OSCertHandles results;

  switch (format) {
    case FORMAT_SINGLE_CERTIFICATE: {
      OSCertHandle handle = CreateOSCertHandleFromBytes(data, length);
      if (handle)
        results.push_back(handle);
      break;
    }
    case FORMAT_PKCS7: {
      CreateOSCertHandlesFromPKCS7Bytes(data, length, &results);
      break;
    }
    default: {
      NOTREACHED() << "Certificate format " << format << " unimplemented";
      break;
    }
  }

  return results;
}

// static
X509Certificate::OSCertHandle X509Certificate::DupOSCertHandle(
    OSCertHandle cert_handle) {
  CRYPTO_BUFFER_up_ref(cert_handle);
  return cert_handle;
}

// static
void X509Certificate::FreeOSCertHandle(OSCertHandle cert_handle) {
  CRYPTO_BUFFER_free(cert_handle);
}

// static
SHA256HashValue X509Certificate::CalculateFingerprint256(OSCertHandle cert) {
  SHA256HashValue sha256;

  SHA256(CRYPTO_BUFFER_data(cert), CRYPTO_BUFFER_len(cert), sha256.data);
  return sha256;
}

// static
SHA256HashValue X509Certificate::CalculateCAFingerprint256(
    const OSCertHandles& intermediates) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  SHA256_CTX sha256_ctx;
  SHA256_Init(&sha256_ctx);
  for (CRYPTO_BUFFER* cert : intermediates) {
    SHA256_Update(&sha256_ctx, CRYPTO_BUFFER_data(cert),
                  CRYPTO_BUFFER_len(cert));
  }
  SHA256_Final(sha256.data, &sha256_ctx);

  return sha256;
}

// static
bool X509Certificate::IsSelfSigned(OSCertHandle cert_handle) {
  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  if (!ParseCertificate(der::Input(CRYPTO_BUFFER_data(cert_handle),
                                   CRYPTO_BUFFER_len(cert_handle)),
                        &tbs_certificate_tlv, &signature_algorithm_tlv,
                        &signature_value, nullptr)) {
    return false;
  }
  ParsedTbsCertificate tbs;
  if (!ParseTbsCertificate(tbs_certificate_tlv,
                           DefaultParseCertificateOptions(), &tbs, nullptr)) {
    return false;
  }

  der::Input subject_value;
  std::string normalized_subject;
  if (!GetSequenceValue(tbs.subject_tlv, &subject_value) ||
      !NormalizeName(subject_value, &normalized_subject)) {
    return false;
  }
  der::Input issuer_value;
  std::string normalized_issuer;
  if (!GetSequenceValue(tbs.issuer_tlv, &issuer_value) ||
      !NormalizeName(issuer_value, &normalized_issuer)) {
    return false;
  }

  if (normalized_subject != normalized_issuer)
    return false;

  std::unique_ptr<SignatureAlgorithm> signature_algorithm =
      SignatureAlgorithm::Create(signature_algorithm_tlv, nullptr /* errors */);
  if (!signature_algorithm)
    return false;

  SimpleSignaturePolicy signature_policy(1024);
  CertErrors unused_errors;
  return VerifySignedData(*signature_algorithm, tbs_certificate_tlv,
                          signature_value, tbs.spki_tlv, &signature_policy,
                          &unused_errors);
}

// static
X509Certificate::OSCertHandle X509Certificate::ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter) {
  const char* data;
  int length;
  if (!pickle_iter->ReadData(&data, &length))
    return NULL;

  return CreateOSCertHandleFromBytes(data, length);
}

// static
bool X509Certificate::WriteOSCertHandleToPickle(OSCertHandle cert_handle,
                                                base::Pickle* pickle) {
  return pickle->WriteData(
      reinterpret_cast<const char*>(CRYPTO_BUFFER_data(cert_handle)),
      CRYPTO_BUFFER_len(cert_handle));
}

}  // namespace net
