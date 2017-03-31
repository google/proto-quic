// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_certificate.h"

#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_util.h"
#include "net/cert/x509_util_openssl.h"
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/crypto.h"
#include "third_party/boringssl/src/include/openssl/obj_mac.h"
#include "third_party/boringssl/src/include/openssl/pem.h"
#include "third_party/boringssl/src/include/openssl/sha.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

#if defined(OS_ANDROID)
#include "base/logging.h"
#include "net/android/network_library.h"
#endif

namespace net {

namespace {

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
      X509* x509_cert =
          X509Certificate::DupOSCertHandle(sk_X509_value(certs, i));
      handles->push_back(x509_cert);
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

bool ParsePrincipal(X509Certificate::OSCertHandle cert,
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

bool ParseSubjectAltName(X509Certificate::OSCertHandle cert,
                         std::vector<std::string>* dns_names,
                         std::vector<std::string>* ip_addresses) {
  int index = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1);
  X509_EXTENSION* alt_name_ext = X509_get_ext(cert, index);
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

class X509InitSingleton {
 public:
  static X509InitSingleton* GetInstance() {
    // We allow the X509 store to leak, because it is used from a non-joinable
    // worker that is not stopped on shutdown, hence may still be using
    // OpenSSL library after the AtExit runner has completed.
    return base::Singleton<X509InitSingleton, base::LeakySingletonTraits<
                                                  X509InitSingleton>>::get();
  }
  X509_STORE* store() const { return store_.get(); }

  void ResetCertStore() {
    store_.reset(X509_STORE_new());
    DCHECK(store_.get());
    X509_STORE_set_default_paths(store_.get());
    // TODO(joth): Enable CRL (see X509_STORE_set_flags(X509_V_FLAG_CRL_CHECK)).
  }

 private:
  friend struct base::DefaultSingletonTraits<X509InitSingleton>;
  X509InitSingleton() {
    crypto::EnsureOpenSSLInit();
    ResetCertStore();
  }

  bssl::UniquePtr<X509_STORE> store_;

  DISALLOW_COPY_AND_ASSIGN(X509InitSingleton);
};

}  // namespace

// static
X509Certificate::OSCertHandle X509Certificate::DupOSCertHandle(
    OSCertHandle cert_handle) {
  DCHECK(cert_handle);
  X509_up_ref(cert_handle);
  return cert_handle;
}

// static
void X509Certificate::FreeOSCertHandle(OSCertHandle cert_handle) {
  // Decrement the ref-count for the cert and, if all references are gone,
  // free the memory and any application-specific data associated with the
  // certificate.
  X509_free(cert_handle);
}

bool X509Certificate::Initialize() {
  crypto::EnsureOpenSSLInit();

  ASN1_INTEGER* serial_num = X509_get_serialNumber(cert_handle_);
  if (!serial_num)
    return false;
  // ASN1_INTEGERS represent the decoded number, in a format internal to
  // OpenSSL. Most notably, this may have leading zeroes stripped off for
  // numbers whose first byte is >= 0x80. Thus, it is necessary to
  // re-encoded the integer back into DER, which is what the interface
  // of X509Certificate exposes, to ensure callers get the proper (DER)
  // value.
  int bytes_required = i2c_ASN1_INTEGER(serial_num, NULL);
  unsigned char* buffer = reinterpret_cast<unsigned char*>(
      base::WriteInto(&serial_number_, bytes_required + 1));
  int bytes_written = i2c_ASN1_INTEGER(serial_num, &buffer);
  DCHECK_EQ(static_cast<size_t>(bytes_written), serial_number_.size());

  return (
      ParsePrincipal(cert_handle_, X509_get_subject_name(cert_handle_),
                     &subject_) &&
      ParsePrincipal(cert_handle_, X509_get_issuer_name(cert_handle_),
                     &issuer_) &&
      x509_util::ParseDate(X509_get_notBefore(cert_handle_), &valid_start_) &&
      x509_util::ParseDate(X509_get_notAfter(cert_handle_), &valid_expiry_));
}

// static
void X509Certificate::ResetCertStore() {
  X509InitSingleton::GetInstance()->ResetCertStore();
}

// static
SHA256HashValue X509Certificate::CalculateFingerprint256(OSCertHandle cert) {
  SHA256HashValue sha256;
  unsigned int sha256_size = static_cast<unsigned int>(sizeof(sha256.data));
  int ret = X509_digest(cert, EVP_sha256(), sha256.data, &sha256_size);
  CHECK(ret);
  CHECK_EQ(sha256_size, sizeof(sha256.data));
  return sha256;
}

// static
SHA256HashValue X509Certificate::CalculateCAFingerprint256(
    const OSCertHandles& intermediates) {
  SHA256HashValue sha256;
  memset(sha256.data, 0, sizeof(sha256.data));

  SHA256_CTX sha256_ctx;
  SHA256_Init(&sha256_ctx);
  base::StringPiece der;
  for (size_t i = 0; i < intermediates.size(); ++i) {
    if (!x509_util::GetDER(intermediates[i], &der))
      return sha256;
    SHA256_Update(&sha256_ctx, der.data(), der.length());
  }
  SHA256_Final(sha256.data, &sha256_ctx);

  return sha256;
}

// static
X509Certificate::OSCertHandle X509Certificate::CreateOSCertHandleFromBytes(
    const char* data,
    size_t length) {
  crypto::EnsureOpenSSLInit();
  bssl::UniquePtr<CRYPTO_BUFFER> buffer = x509_util::CreateCryptoBuffer(
      reinterpret_cast<const uint8_t*>(data), length);
  return X509_parse_from_buffer(buffer.get());
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
X509_STORE* X509Certificate::cert_store() {
  return X509InitSingleton::GetInstance()->store();
}

// static
bool X509Certificate::GetDEREncoded(X509Certificate::OSCertHandle cert_handle,
                                    std::string* encoded) {
  base::StringPiece der;
  if (!cert_handle || !x509_util::GetDER(cert_handle, &der))
    return false;
  encoded->assign(der.data(), der.length());
  return true;
}

// static
bool X509Certificate::IsSameOSCert(X509Certificate::OSCertHandle a,
                                   X509Certificate::OSCertHandle b) {
  DCHECK(a && b);
  if (a == b)
    return true;

  // X509_cmp only checks the fingerprint, but we want to compare the whole
  // DER data. Encoding it from OSCertHandle is an expensive operation, so we
  // cache the DER (if not already cached via X509_set_ex_data).
  base::StringPiece der_a, der_b;

  return x509_util::GetDER(a, &der_a) &&
      x509_util::GetDER(b, &der_b) &&
      der_a == der_b;
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
  base::StringPiece der;
  if (!x509_util::GetDER(cert_handle, &der))
    return false;

  return pickle->WriteData(der.data(), der.length());
}

// static
void X509Certificate::GetPublicKeyInfo(OSCertHandle cert_handle,
                                       size_t* size_bits,
                                       PublicKeyType* type) {
  *type = kPublicKeyTypeUnknown;
  *size_bits = 0;

  bssl::UniquePtr<EVP_PKEY> scoped_key(X509_get_pubkey(cert_handle));
  if (!scoped_key.get())
    return;

  EVP_PKEY* key = scoped_key.get();

  switch (key->type) {
    case EVP_PKEY_RSA:
      *type = kPublicKeyTypeRSA;
      *size_bits = EVP_PKEY_size(key) * 8;
      break;
    case EVP_PKEY_DSA:
      *type = kPublicKeyTypeDSA;
      *size_bits = EVP_PKEY_size(key) * 8;
      break;
    case EVP_PKEY_EC:
      *type = kPublicKeyTypeECDSA;
      *size_bits = EVP_PKEY_bits(key);
      break;
    case EVP_PKEY_DH:
      *type = kPublicKeyTypeDH;
      *size_bits = EVP_PKEY_size(key) * 8;
      break;
  }
}

bool X509Certificate::IsIssuedByEncoded(
    const std::vector<std::string>& valid_issuers) {
  if (valid_issuers.empty())
    return false;

  // Convert to a temporary list of X509_NAME objects.
  // It will own the objects it points to.
  bssl::UniquePtr<STACK_OF(X509_NAME)> issuer_names(sk_X509_NAME_new_null());
  if (!issuer_names.get())
    return false;

  for (std::vector<std::string>::const_iterator it = valid_issuers.begin();
      it != valid_issuers.end(); ++it) {
    const unsigned char* p =
        reinterpret_cast<const unsigned char*>(it->data());
    long len = static_cast<long>(it->length());
    X509_NAME* ca_name = d2i_X509_NAME(NULL, &p, len);
    if (ca_name == NULL)
      return false;
    sk_X509_NAME_push(issuer_names.get(), ca_name);
  }

  // Create a temporary list of X509_NAME objects corresponding
  // to the certificate chain. It doesn't own the object it points to.
  std::vector<X509_NAME*> cert_names;
  X509_NAME* issuer = X509_get_issuer_name(cert_handle_);
  if (issuer == NULL)
    return false;

  cert_names.push_back(issuer);
  for (OSCertHandles::iterator it = intermediate_ca_certs_.begin();
      it != intermediate_ca_certs_.end(); ++it) {
    issuer = X509_get_issuer_name(*it);
    if (issuer == NULL)
      return false;
    cert_names.push_back(issuer);
  }

  // and 'cert_names'.
  for (size_t n = 0; n < cert_names.size(); ++n) {
    for (size_t m = 0; m < sk_X509_NAME_num(issuer_names.get()); ++m) {
      X509_NAME* issuer = sk_X509_NAME_value(issuer_names.get(), m);
      if (X509_NAME_cmp(issuer, cert_names[n]) == 0) {
        return true;
      }
    }
  }

  return false;
}

// static
bool X509Certificate::IsSelfSigned(OSCertHandle cert_handle) {
  bssl::UniquePtr<EVP_PKEY> scoped_key(X509_get_pubkey(cert_handle));
  if (!scoped_key)
    return false;
  if (!X509_verify(cert_handle, scoped_key.get()))
    return false;
  return X509_check_issued(cert_handle, cert_handle) == X509_V_OK;
}

}  // namespace net
