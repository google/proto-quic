// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "base/mac/scoped_cftyperef.h"
#include "base/pickle.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/ip_address_number.h"
#include "net/cert/x509_util_openssl.h"
#include "net/ssl/openssl_ssl_util.h"

using base::ScopedCFTypeRef;

namespace net {

namespace {

using ScopedGENERAL_NAMES =
    crypto::ScopedOpenSSL<GENERAL_NAMES, GENERAL_NAMES_free>;

// Returns true if a given |cert_handle| is actually a valid X.509 certificate
// handle.
//
// SecCertificateCreateFromData() does not always force the immediate parsing of
// the certificate, and as such, may return a SecCertificateRef for an
// invalid/unparsable certificate. Force parsing to occur to ensure that the
// SecCertificateRef is correct. On later versions where
// SecCertificateCreateFromData() immediately parses, rather than lazily, this
// call is cheap, as the subject is cached.
bool IsValidOSCertHandle(SecCertificateRef cert_handle) {
  ScopedCFTypeRef<CFStringRef> sanity_check(
      SecCertificateCopySubjectSummary(cert_handle));
  return sanity_check != nullptr;
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

void ParsePrincipal(X509Certificate::OSCertHandle os_cert,
                    X509_NAME* x509_name,
                    CertPrincipal* principal) {
  if (!x509_name)
    return;

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
}

void ParseSubjectAltName(X509Certificate::OSCertHandle os_cert,
                         std::vector<std::string>* dns_names,
                         std::vector<std::string>* ip_addresses) {
  DCHECK(dns_names || ip_addresses);
  ScopedX509 cert = OSCertHandleToOpenSSL(os_cert);
  if (!cert.get())
    return;
  int index = X509_get_ext_by_NID(cert.get(), NID_subject_alt_name, -1);
  X509_EXTENSION* alt_name_ext = X509_get_ext(cert.get(), index);
  if (!alt_name_ext)
    return;

  ScopedGENERAL_NAMES alt_names(
      reinterpret_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(alt_name_ext)));
  if (!alt_names.get())
    return;

  for (size_t i = 0; i < sk_GENERAL_NAME_num(alt_names.get()); ++i) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(alt_names.get(), i);
    if (name->type == GEN_DNS && dns_names) {
      const unsigned char* dns_name = ASN1_STRING_data(name->d.dNSName);
      if (!dns_name)
        continue;
      int dns_name_len = ASN1_STRING_length(name->d.dNSName);
      dns_names->push_back(
          std::string(reinterpret_cast<const char*>(dns_name), dns_name_len));
    } else if (name->type == GEN_IPADD && ip_addresses) {
      const unsigned char* ip_addr = name->d.iPAddress->data;
      if (!ip_addr)
        continue;
      int ip_addr_len = name->d.iPAddress->length;
      if (ip_addr_len != static_cast<int>(kIPv4AddressSize) &&
          ip_addr_len != static_cast<int>(kIPv6AddressSize)) {
        // http://www.ietf.org/rfc/rfc3280.txt requires subjectAltName iPAddress
        // to have 4 or 16 bytes, whereas in a name constraint it includes a
        // net mask hence 8 or 32 bytes. Logging to help diagnose any mixup.
        LOG(WARNING) << "Bad sized IP Address in cert: " << ip_addr_len;
        continue;
      }
      ip_addresses->push_back(
          std::string(reinterpret_cast<const char*>(ip_addr), ip_addr_len));
    }
  }
}

// Used to free a list of X509_NAMEs and the objects it points to.
void sk_X509_NAME_free_all(STACK_OF(X509_NAME) * sk) {
  sk_X509_NAME_pop_free(sk, X509_NAME_free);
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

void X509Certificate::Initialize() {
  crypto::EnsureOpenSSLInit();
  fingerprint_ = CalculateFingerprint(cert_handle_);
  ca_fingerprint_ = CalculateCAFingerprint(intermediate_ca_certs_);
  ScopedX509 x509_cert = OSCertHandleToOpenSSL(cert_handle_);
  if (!x509_cert)
    return;
  ASN1_INTEGER* serial_num = X509_get_serialNumber(x509_cert.get());
  if (serial_num) {
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
  }

  ParsePrincipal(cert_handle_, X509_get_subject_name(x509_cert.get()),
                 &subject_);
  ParsePrincipal(cert_handle_, X509_get_issuer_name(x509_cert.get()), &issuer_);
  x509_util::ParseDate(X509_get_notBefore(x509_cert.get()), &valid_start_);
  x509_util::ParseDate(X509_get_notAfter(x509_cert.get()), &valid_expiry_);
}

// static
SHA1HashValue X509Certificate::CalculateFingerprint(OSCertHandle cert) {
  SHA1HashValue sha1;
  memset(sha1.data, 0, sizeof(sha1.data));

  ScopedCFTypeRef<CFDataRef> cert_data(SecCertificateCopyData(cert));
  if (!cert_data)
    return sha1;
  DCHECK(CFDataGetBytePtr(cert_data));
  DCHECK_NE(0, CFDataGetLength(cert_data));
  CC_SHA1(CFDataGetBytePtr(cert_data), CFDataGetLength(cert_data), sha1.data);

  return sha1;
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
SHA1HashValue X509Certificate::CalculateCAFingerprint(
    const OSCertHandles& intermediates) {
  SHA1HashValue sha1;
  memset(sha1.data, 0, sizeof(sha1.data));

  CC_SHA1_CTX sha1_ctx;
  CC_SHA1_Init(&sha1_ctx);
  for (size_t i = 0; i < intermediates.size(); ++i) {
    ScopedCFTypeRef<CFDataRef> cert_data(
        SecCertificateCopyData(intermediates[i]));
    if (!cert_data)
      return sha1;
    CC_SHA1_Update(&sha1_ctx, CFDataGetBytePtr(cert_data),
                   CFDataGetLength(cert_data));
  }
  CC_SHA1_Final(sha1.data, &sha1_ctx);
  return sha1;
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  ScopedCFTypeRef<CFDataRef> cert_data(CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(data),
      base::checked_cast<CFIndex>(length), kCFAllocatorNull));
  if (!cert_data)
    return nullptr;
  OSCertHandle cert_handle = SecCertificateCreateWithData(nullptr, cert_data);
  if (!cert_handle)
    return nullptr;
  if (!IsValidOSCertHandle(cert_handle)) {
    CFRelease(cert_handle);
    return nullptr;
  }
  return cert_handle;
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

void X509Certificate::GetSubjectAltName(
    std::vector<std::string>* dns_names,
    std::vector<std::string>* ip_addrs) const {
  if (dns_names)
    dns_names->clear();
  if (ip_addrs)
    ip_addrs->clear();

  ParseSubjectAltName(cert_handle_, dns_names, ip_addrs);
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
  ScopedX509 cert = OSCertHandleToOpenSSL(os_cert);
  if (!cert)
    return;
  crypto::ScopedEVP_PKEY scoped_key(X509_get_pubkey(cert.get()));
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

bool X509Certificate::SupportsSSLClientAuth() const {
  return false;
}

CFMutableArrayRef X509Certificate::CreateOSCertChainForCert() const {
  CFMutableArrayRef cert_list =
      CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  if (!cert_list)
    return nullptr;

  CFArrayAppendValue(cert_list, os_cert_handle());
  for (size_t i = 0; i < intermediate_ca_certs_.size(); ++i)
    CFArrayAppendValue(cert_list, intermediate_ca_certs_[i]);

  return cert_list;
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  if (valid_issuers.empty())
    return false;

  // Convert to a temporary list of X509_NAME objects.
  // It will own the objects it points to.
  crypto::ScopedOpenSSL<STACK_OF(X509_NAME), sk_X509_NAME_free_all>
      issuer_names(sk_X509_NAME_new_null());
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

  ScopedX509 x509_cert = OSCertHandleToOpenSSL(cert_handle_);
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
    ScopedX509 intermediate_cert = OSCertHandleToOpenSSL(*it);
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
  ScopedX509 cert = OSCertHandleToOpenSSL(os_cert);
  if (!cert)
    return false;
  crypto::ScopedEVP_PKEY scoped_key(X509_get_pubkey(cert.get()));
  if (!scoped_key)
    return false;

  // NOTE: X509_verify() returns 1 in case of success, 0 or -1 on error.
  return X509_verify(cert.get(), scoped_key.get()) == 1;
}

}  // namespace net
