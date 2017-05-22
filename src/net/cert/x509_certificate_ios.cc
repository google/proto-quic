// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>

#include "base/mac/scoped_cftyperef.h"
#include "base/pickle.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "net/base/ip_address.h"
#include "net/cert/x509_util_ios.h"
#include "net/cert/x509_util_openssl.h"
#include "net/ssl/openssl_ssl_util.h"
#include "third_party/boringssl/src/include/openssl/x509.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

using base::ScopedCFTypeRef;

namespace net {

namespace {

bssl::UniquePtr<X509> OSCertHandleToOpenSSL(
    X509Certificate::OSCertHandle os_handle) {
  std::string der_encoded;
  if (!X509Certificate::GetDEREncoded(os_handle, &der_encoded))
    return nullptr;
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(der_encoded.data());
  return bssl::UniquePtr<X509>(d2i_X509(nullptr, &bytes, der_encoded.size()));
}

void CreateOSCertHandlesFromPKCS7Bytes(
    const char* data,
    size_t length,
    X509Certificate::OSCertHandles* handles) {
  crypto::EnsureOpenSSLInit();
  crypto::OpenSSLErrStackTracer err_cleaner(FROM_HERE);

  CBS der_data;
  CBS_init(&der_data, reinterpret_cast<const uint8_t*>(data), length);
  STACK_OF(X509)* certs = sk_X509_new_null();

  if (PKCS7_get_certificates(certs, &der_data)) {
    for (size_t i = 0; i < sk_X509_num(certs); ++i) {
      X509* x509_cert = sk_X509_value(certs, i);
      base::StringPiece der;
      if (!x509_util::GetDER(x509_cert, &der))
        return;
      handles->push_back(X509Certificate::CreateOSCertHandleFromBytes(
          der.data(), der.length()));
    }
  }
  sk_X509_pop_free(certs, X509_free);
}

void ParsePrincipalValues(X509_NAME* name,
                          int nid,
                          std::vector<std::string>* fields) {
  for (int index = -1;
       (index = X509_NAME_get_index_by_NID(name, nid, index)) != -1;) {
    std::string field;
    if (!x509_util::ParsePrincipalValueByIndex(name, index, &field))
      break;
    fields->push_back(field);
  }
}

bool ParsePrincipal(X509Certificate::OSCertHandle os_cert,
                    X509_NAME* x509_name,
                    CertPrincipal* principal) {
  if (!x509_name)
    return false;

  ParsePrincipalValues(x509_name, NID_streetAddress,
                       &principal->street_addresses);
  ParsePrincipalValues(x509_name, NID_organizationName,
                       &principal->organization_names);
  ParsePrincipalValues(x509_name, NID_organizationalUnitName,
                       &principal->organization_unit_names);
  ParsePrincipalValues(x509_name, NID_domainComponent,
                       &principal->domain_components);

  x509_util::ParsePrincipalValueByNID(x509_name, NID_commonName,
                                      &principal->common_name);
  x509_util::ParsePrincipalValueByNID(x509_name, NID_localityName,
                                      &principal->locality_name);
  x509_util::ParsePrincipalValueByNID(x509_name, NID_stateOrProvinceName,
                                      &principal->state_or_province_name);
  x509_util::ParsePrincipalValueByNID(x509_name, NID_countryName,
                                      &principal->country_name);
  return true;
}

bool ParseSubjectAltName(X509Certificate::OSCertHandle os_cert,
                         std::vector<std::string>* dns_names,
                         std::vector<std::string>* ip_addresses) {
  bssl::UniquePtr<X509> cert = OSCertHandleToOpenSSL(os_cert);
  if (!cert.get())
    return false;
  int index = X509_get_ext_by_NID(cert.get(), NID_subject_alt_name, -1);
  X509_EXTENSION* alt_name_ext = X509_get_ext(cert.get(), index);
  if (!alt_name_ext)
    return false;

  bssl::UniquePtr<GENERAL_NAMES> alt_names(
      reinterpret_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(alt_name_ext)));
  if (!alt_names.get())
    return false;

  bool has_san = false;
  for (size_t i = 0; i < sk_GENERAL_NAME_num(alt_names.get()); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(alt_names.get(), i);
    if (name->type == GEN_DNS) {
      has_san = true;
      if (dns_names) {
        const unsigned char* dns_name = ASN1_STRING_data(name->d.dNSName);
        int dns_name_len = ASN1_STRING_length(name->d.dNSName);
        dns_names->push_back(
            base::StringPiece(reinterpret_cast<const char*>(dns_name),
                              dns_name_len)
                .as_string());
      }
    } else if (name->type == GEN_IPADD) {
      has_san = true;
      if (ip_addresses) {
        const unsigned char* ip_addr = name->d.iPAddress->data;
        int ip_addr_len = name->d.iPAddress->length;
        ip_addresses->push_back(
            base::StringPiece(reinterpret_cast<const char*>(ip_addr),
                              ip_addr_len)
                .as_string());
      }
    }
    // Fast path: Found at least one subjectAltName and the caller doesn't
    // need the actual values.
    if (has_san && !ip_addresses && !dns_names)
      return true;
  }

  return has_san;
}

}  // namespace

// static
X509Certificate::OSCertHandle X509Certificate::DupOSCertHandle(
    OSCertHandle handle) {
  if (!handle)
    return nullptr;
  return reinterpret_cast<OSCertHandle>(const_cast<void*>(CFRetain(handle)));
}

// static
void X509Certificate::FreeOSCertHandle(OSCertHandle cert_handle) {
  if (cert_handle)
    CFRelease(cert_handle);
}

bool X509Certificate::Initialize() {
  crypto::EnsureOpenSSLInit();
  bssl::UniquePtr<X509> x509_cert = OSCertHandleToOpenSSL(cert_handle_);
  if (!x509_cert)
    return false;
  ASN1_INTEGER* serial_num = X509_get_serialNumber(x509_cert.get());
  if (!serial_num)
    return false;
  // ASN1_INTEGERS represent the decoded number, in a format internal to
  // OpenSSL. Most notably, this may have leading zeroes stripped off for
  // numbers whose first byte is >= 0x80. Thus, it is necessary to
  // re-encoded the integer back into DER, which is what the interface
  // of X509Certificate exposes, to ensure callers get the proper (DER)
  // value.
  int bytes_required = i2c_ASN1_INTEGER(serial_num, nullptr);
  unsigned char* buffer = reinterpret_cast<unsigned char*>(
      base::WriteInto(&serial_number_, bytes_required + 1));
  int bytes_written = i2c_ASN1_INTEGER(serial_num, &buffer);
  DCHECK_EQ(static_cast<size_t>(bytes_written), serial_number_.size());

  return (
      ParsePrincipal(cert_handle_, X509_get_subject_name(x509_cert.get()),
                     &subject_) &&
      ParsePrincipal(cert_handle_, X509_get_issuer_name(x509_cert.get()),
                     &issuer_) &&
      x509_util::ParseDate(X509_get_notBefore(x509_cert.get()),
                           &valid_start_) &&
      x509_util::ParseDate(X509_get_notAfter(x509_cert.get()), &valid_expiry_));
}

// static
SHA256HashValue X509Certificate::CalculateFingerprint256(OSCertHandle cert) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert));
  if (!cert_data)
    return sha256;
  DCHECK(CFDataGetBytePtr(cert_data));
  DCHECK_NE(0, CFDataGetLength(cert_data));
  CC_SHA256(CFDataGetBytePtr(cert_data), CFDataGetLength(cert_data),
            sha256.data);

  return sha256;
}

// static
SHA256HashValue X509Certificate::CalculateCAFingerprint256(
    const OSCertHandles& intermediates) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  CC_SHA256_CTX sha256_ctx;
  CC_SHA256_Init(&sha256_ctx);
  for (size_t i = 0; i < intermediates.size(); ++i) {
    ScopedCFTypeRef<CFDataRef> cert_data(
        SecCertificateCopyData(intermediates[i]));
    if (!cert_data)
      return sha256;
    CC_SHA256_Update(&sha256_ctx, CFDataGetBytePtr(cert_data),
                     CFDataGetLength(cert_data));
  }
  CC_SHA256_Final(sha256.data, &sha256_ctx);
  return sha256;
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  return x509_util::CreateSecCertificateFromBytes(
      reinterpret_cast<const uint8_t*>(data), length);
}

// static
X509Certificate::OSCertHandles X509Certificate::CreateOSCertHandlesFromBytes(
    const char* data,
    size_t length,
    Format format) {
  OSCertHandles results;

  switch (format) {
    case FORMAT_SINGLE_CERTIFICATE: {
      OSCertHandle handle =
          X509Certificate::CreateOSCertHandleFromBytes(data, length);
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

bool X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  if (dns_names)
    dns_names->clear();
  if (ip_addrs)
    ip_addrs->clear();

  return ParseSubjectAltName(cert_handle_, dns_names, ip_addrs);
}

// static
bool X509Certificate::GetDEREncoded(X509Certificate::OSCertHandle cert_handle,
                                    std::string* encoded) {
  base::StringPiece der;
  if (!cert_handle)
    return false;
  ScopedCFTypeRef<CFDataRef> der_data(SecCertificateCopyData(cert_handle));
  if (!der_data)
    return false;
  encoded->assign(reinterpret_cast<const char*>(CFDataGetBytePtr(der_data)),
                  CFDataGetLength(der_data));
  return true;
}

// static
bool X509Certificate::IsSameOSCert(X509Certificate::OSCertHandle a,
                                   X509Certificate::OSCertHandle b) {
  DCHECK(a && b);
  return CFEqual(a, b);
}

// static
X509Certificate::OSCertHandle X509Certificate::ReadOSCertHandleFromPickle(
    base::PickleIterator* pickle_iter) {
  const char* data;
  int length;
  if (!pickle_iter->ReadData(&data, &length))
    return nullptr;

  return X509Certificate::CreateOSCertHandleFromBytes(data, length);
}

// static
bool X509Certificate::WriteOSCertHandleToPickle(OSCertHandle cert_handle,
                                                base::Pickle* pickle) {
  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert_handle));
  if (!cert_data)
    return false;

  return pickle->WriteData(
      reinterpret_cast<const char*>(CFDataGetBytePtr(cert_data)),
      CFDataGetLength(cert_data));
}

// static
void X509Certificate::GetPublicKeyInfo(OSCertHandle os_cert,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  *type = kPublicKeyTypeUnknown;
  *size_bits = 0;
  bssl::UniquePtr<X509> cert = OSCertHandleToOpenSSL(os_cert);
  if (!cert)
    return;
  bssl::UniquePtr<EVP_PKEY> scoped_key(X509_get_pubkey(cert.get()));
  if (!scoped_key)
    return;

  EVP_PKEY* key = scoped_key.get();

  switch (key->type) {
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
  *size_bits = EVP_PKEY_bits(key);
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  if (valid_issuers.empty())
    return false;

  // Convert to a temporary list of X509_NAME objects.
  // It will own the objects it points to.
  bssl::UniquePtr<STACK_OF(X509_NAME)> issuer_names(sk_X509_NAME_new_null());
  if (!issuer_names)
    return false;

  for (std::vector<std::string>::const_iterator it = valid_issuers.begin();
       it != valid_issuers.end(); ++it) {
    const unsigned char* p = reinterpret_cast<const unsigned char*>(it->data());
    long len = static_cast<long>(it->length());
    X509_NAME* ca_name = d2i_X509_NAME(nullptr, &p, len);
    if (ca_name == nullptr)
      return false;
    sk_X509_NAME_push(issuer_names.get(), ca_name);
  }

  bssl::UniquePtr<X509> x509_cert = OSCertHandleToOpenSSL(cert_handle_);
  if (!x509_cert)
    return false;
  X509_NAME* cert_issuer = X509_get_issuer_name(x509_cert.get());
  if (cert_issuer == nullptr)
    return false;

  for (size_t m = 0; m < sk_X509_NAME_num(issuer_names.get()); ++m) {
    X509_NAME* issuer = sk_X509_NAME_value(issuer_names.get(), m);
    if (X509_NAME_cmp(issuer, cert_issuer) == 0) {
      return true;
    }
  }

  for (OSCertHandles::iterator it = intermediate_ca_certs_.begin();
       it != intermediate_ca_certs_.end(); ++it) {
    bssl::UniquePtr<X509> intermediate_cert = OSCertHandleToOpenSSL(*it);
    if (!intermediate_cert)
      return false;
    cert_issuer = X509_get_issuer_name(intermediate_cert.get());
    if (cert_issuer == nullptr)
      return false;

    for (size_t m = 0; m < sk_X509_NAME_num(issuer_names.get()); ++m) {
      X509_NAME* issuer = sk_X509_NAME_value(issuer_names.get(), m);
      if (X509_NAME_cmp(issuer, cert_issuer) == 0) {
        return true;
      }
    }
  }

  return false;
}

// static
bool X509Certificate::IsSelfSigned(OSCertHandle os_cert) {
  bssl::UniquePtr<X509> cert = OSCertHandleToOpenSSL(os_cert);
  if (!cert)
    return false;
  bssl::UniquePtr<EVP_PKEY> scoped_key(X509_get_pubkey(cert.get()));
  if (!scoped_key)
    return false;
  if (!X509_verify(cert.get(), scoped_key.get()))
    return false;
  return X509_check_issued(cert.get(), cert.get()) == X509_V_OK;
}

}  // namespace net
