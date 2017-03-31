// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_openssl.h"

#include <limits.h>

#include <algorithm>
#include <memory>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "crypto/ec_private_key.h"
#include "crypto/openssl_util.h"
#include "crypto/rsa_private_key.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/x509_cert_types.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "third_party/boringssl/src/include/openssl/asn1.h"
#include "third_party/boringssl/src/include/openssl/digest.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

namespace net {

namespace {

const EVP_MD* ToEVP(x509_util::DigestAlgorithm alg) {
  switch (alg) {
    case x509_util::DIGEST_SHA1:
      return EVP_sha1();
    case x509_util::DIGEST_SHA256:
      return EVP_sha256();
  }
  return NULL;
}

}  // namespace

namespace x509_util {

namespace {

bssl::UniquePtr<X509> CreateCertificate(EVP_PKEY* key,
                                        DigestAlgorithm alg,
                                        const std::string& common_name,
                                        uint32_t serial_number,
                                        base::Time not_valid_before,
                                        base::Time not_valid_after) {
  // Put the serial number into an OpenSSL-friendly object.
  bssl::UniquePtr<ASN1_INTEGER> asn1_serial(ASN1_INTEGER_new());
  if (!asn1_serial.get() ||
      !ASN1_INTEGER_set(asn1_serial.get(), static_cast<long>(serial_number))) {
    LOG(ERROR) << "Invalid serial number " << serial_number;
    return nullptr;
  }

  // Do the same for the time stamps.
  bssl::UniquePtr<ASN1_TIME> asn1_not_before_time(
      ASN1_TIME_set(nullptr, not_valid_before.ToTimeT()));
  if (!asn1_not_before_time.get()) {
    LOG(ERROR) << "Invalid not_valid_before time: "
               << not_valid_before.ToTimeT();
    return nullptr;
  }

  bssl::UniquePtr<ASN1_TIME> asn1_not_after_time(
      ASN1_TIME_set(nullptr, not_valid_after.ToTimeT()));
  if (!asn1_not_after_time.get()) {
    LOG(ERROR) << "Invalid not_valid_after time: " << not_valid_after.ToTimeT();
    return nullptr;
  }

  // Because |common_name| only contains a common name and starts with 'CN=',
  // there is no need for a full RFC 2253 parser here. Do some sanity checks
  // though.
  static const char kCommonNamePrefix[] = "CN=";
  const size_t kCommonNamePrefixLen = sizeof(kCommonNamePrefix) - 1;
  if (common_name.size() < kCommonNamePrefixLen ||
      strncmp(common_name.c_str(), kCommonNamePrefix, kCommonNamePrefixLen)) {
    LOG(ERROR) << "Common name must begin with " << kCommonNamePrefix;
    return nullptr;
  }
  if (common_name.size() > INT_MAX) {
    LOG(ERROR) << "Common name too long";
    return nullptr;
  }
  unsigned char* common_name_str =
      reinterpret_cast<unsigned char*>(const_cast<char*>(common_name.data())) +
      kCommonNamePrefixLen;
  int common_name_len =
      static_cast<int>(common_name.size() - kCommonNamePrefixLen);

  bssl::UniquePtr<X509_NAME> name(X509_NAME_new());
  if (!name.get() || !X509_NAME_add_entry_by_NID(name.get(),
                                                 NID_commonName,
                                                 MBSTRING_ASC,
                                                 common_name_str,
                                                 common_name_len,
                                                 -1,
                                                 0)) {
    LOG(ERROR) << "Can't parse common name: " << common_name.c_str();
    return nullptr;
  }

  // Now create certificate and populate it.
  bssl::UniquePtr<X509> cert(X509_new());
  if (!cert.get() || !X509_set_version(cert.get(), 2L) /* i.e. version 3 */ ||
      !X509_set_pubkey(cert.get(), key) ||
      !X509_set_serialNumber(cert.get(), asn1_serial.get()) ||
      !X509_set_notBefore(cert.get(), asn1_not_before_time.get()) ||
      !X509_set_notAfter(cert.get(), asn1_not_after_time.get()) ||
      !X509_set_subject_name(cert.get(), name.get()) ||
      !X509_set_issuer_name(cert.get(), name.get())) {
    LOG(ERROR) << "Could not create certificate";
    return nullptr;
  }

  return cert;
}

// DER-encodes |x509|. On success, returns true and writes the
// encoding to |*out_der|.
bool DerEncodeCert(X509* x509, std::string* out_der) {
  int len = i2d_X509(x509, NULL);
  if (len < 0)
    return false;

  uint8_t* ptr = reinterpret_cast<uint8_t*>(base::WriteInto(out_der, len + 1));
  if (i2d_X509(x509, &ptr) < 0) {
    NOTREACHED();
    out_der->clear();
    return false;
  }
  return true;
}

bool SignAndDerEncodeCert(X509* cert,
                          EVP_PKEY* key,
                          DigestAlgorithm alg,
                          std::string* der_encoded) {
  // Get the message digest algorithm
  const EVP_MD* md = ToEVP(alg);
  if (!md) {
    LOG(ERROR) << "Unrecognized hash algorithm.";
    return false;
  }

  // Sign it with the private key.
  if (!X509_sign(cert, key, md)) {
    LOG(ERROR) << "Could not sign certificate with key.";
    return false;
  }

  // Convert it into a DER-encoded string copied to |der_encoded|.
  return DerEncodeCert(cert, der_encoded);
}

struct DERCache {
  std::string data;
};

void DERCache_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int idx,
                   long argl, void* argp) {
  DERCache* der_cache = static_cast<DERCache*>(ptr);
  delete der_cache;
}

class DERCacheInitSingleton {
 public:
  DERCacheInitSingleton() {
    crypto::EnsureOpenSSLInit();
    der_cache_ex_index_ = X509_get_ex_new_index(0, 0, 0, 0, DERCache_free);
    DCHECK_NE(-1, der_cache_ex_index_);
  }

  int der_cache_ex_index() const { return der_cache_ex_index_; }

 private:
  int der_cache_ex_index_;

  DISALLOW_COPY_AND_ASSIGN(DERCacheInitSingleton);
};

base::LazyInstance<DERCacheInitSingleton>::Leaky g_der_cache_singleton =
    LAZY_INSTANCE_INITIALIZER;

class BufferPoolSingleton {
 public:
  BufferPoolSingleton() : pool_(CRYPTO_BUFFER_POOL_new()) {}
  CRYPTO_BUFFER_POOL* pool() { return pool_; }

 private:
  // The singleton is leaky, so there is no need to use a smart pointer.
  CRYPTO_BUFFER_POOL* pool_;
};

base::LazyInstance<BufferPoolSingleton>::Leaky g_buffer_pool_singleton =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

bool CreateSelfSignedCert(crypto::RSAPrivateKey* key,
                          DigestAlgorithm alg,
                          const std::string& common_name,
                          uint32_t serial_number,
                          base::Time not_valid_before,
                          base::Time not_valid_after,
                          std::string* der_encoded) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  bssl::UniquePtr<X509> cert =
      CreateCertificate(key->key(), alg, common_name, serial_number,
                        not_valid_before, not_valid_after);
  if (!cert)
    return false;

  return SignAndDerEncodeCert(cert.get(), key->key(), alg, der_encoded);
}

bool ParsePrincipalKeyAndValue(X509_NAME_ENTRY* entry,
                               std::string* key,
                               std::string* value) {
  if (key) {
    ASN1_OBJECT* object = X509_NAME_ENTRY_get_object(entry);
    key->assign(OBJ_nid2sn(OBJ_obj2nid(object)));
  }

  ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
  if (!data)
    return false;

  unsigned char* buf = NULL;
  int len = ASN1_STRING_to_UTF8(&buf, data);
  if (len <= 0)
    return false;

  value->assign(reinterpret_cast<const char*>(buf), len);
  OPENSSL_free(buf);
  return true;
}

bool ParsePrincipalKeyAndValueByIndex(X509_NAME* name,
                                      int index,
                                      std::string* key,
                                      std::string* value) {
  X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, index);
  if (!entry)
    return false;

  return ParsePrincipalKeyAndValue(entry, key, value);
}

bool ParsePrincipalValueByIndex(X509_NAME* name,
                                int index,
                                std::string* value) {
  return ParsePrincipalKeyAndValueByIndex(name, index, NULL, value);
}

bool ParsePrincipalValueByNID(X509_NAME* name, int nid, std::string* value) {
  int index = X509_NAME_get_index_by_NID(name, nid, -1);
  if (index < 0)
    return false;

  return ParsePrincipalValueByIndex(name, index, value);
}

bool ParseDate(ASN1_TIME* x509_time, base::Time* time) {
  if (!x509_time ||
      (x509_time->type != V_ASN1_UTCTIME &&
       x509_time->type != V_ASN1_GENERALIZEDTIME))
    return false;

  base::StringPiece str_date(reinterpret_cast<const char*>(x509_time->data),
                             x509_time->length);

  CertDateFormat format = x509_time->type == V_ASN1_UTCTIME ?
      CERT_DATE_FORMAT_UTC_TIME : CERT_DATE_FORMAT_GENERALIZED_TIME;
  return ParseCertificateDate(str_date, format, time);
}

// Returns true if |der_cache| points to valid data, false otherwise.
// (note: the DER-encoded data in |der_cache| is owned by |x509|, callers should
// not free it).
bool GetDER(X509* x509, base::StringPiece* der_cache) {
  if (x509->buf) {
    *der_cache = base::StringPiece(
        reinterpret_cast<const char*>(CRYPTO_BUFFER_data(x509->buf)),
        CRYPTO_BUFFER_len(x509->buf));
    return true;
  }

  int x509_der_cache_index =
      g_der_cache_singleton.Get().der_cache_ex_index();

  // Re-encoding the DER data via i2d_X509 is an expensive operation,
  // but it's necessary for comparing two certificates. Re-encode at
  // most once per certificate and cache the data within the X509 cert
  // using X509_set_ex_data.
  DERCache* internal_cache = static_cast<DERCache*>(
      X509_get_ex_data(x509, x509_der_cache_index));
  if (!internal_cache) {
    std::unique_ptr<DERCache> new_cache(new DERCache);
    if (!DerEncodeCert(x509, &new_cache->data))
      return false;
    internal_cache = new_cache.get();
    X509_set_ex_data(x509, x509_der_cache_index, new_cache.release());
  }
  *der_cache = base::StringPiece(internal_cache->data);
  return true;
}

bool GetTLSServerEndPointChannelBinding(const X509Certificate& certificate,
                                        std::string* token) {
  static const char kChannelBindingPrefix[] = "tls-server-end-point:";

  std::string der_encoded_certificate;
  if (!X509Certificate::GetDEREncoded(certificate.os_cert_handle(),
                                      &der_encoded_certificate))
    return false;

  der::Input tbs_certificate_tlv;
  der::Input signature_algorithm_tlv;
  der::BitString signature_value;
  if (!ParseCertificate(der::Input(&der_encoded_certificate),
                        &tbs_certificate_tlv, &signature_algorithm_tlv,
                        &signature_value, nullptr))
    return false;

  std::unique_ptr<SignatureAlgorithm> signature_algorithm =
      SignatureAlgorithm::Create(signature_algorithm_tlv, nullptr);
  if (!signature_algorithm)
    return false;

  const EVP_MD* digest_evp_md = nullptr;
  switch (signature_algorithm->digest()) {
    case net::DigestAlgorithm::Md2:
    case net::DigestAlgorithm::Md4:
      // Shouldn't be reachable.
      digest_evp_md = nullptr;
      break;

    // Per RFC 5929 section 4.1, MD5 and SHA1 map to SHA256.
    case net::DigestAlgorithm::Md5:
    case net::DigestAlgorithm::Sha1:
    case net::DigestAlgorithm::Sha256:
      digest_evp_md = EVP_sha256();
      break;

    case net::DigestAlgorithm::Sha384:
      digest_evp_md = EVP_sha384();
      break;

    case net::DigestAlgorithm::Sha512:
      digest_evp_md = EVP_sha512();
      break;
  }
  if (!digest_evp_md)
    return false;

  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned int out_size;
  if (!EVP_Digest(der_encoded_certificate.data(),
                  der_encoded_certificate.size(), digest, &out_size,
                  digest_evp_md, nullptr))
    return false;

  token->assign(kChannelBindingPrefix);
  token->append(digest, digest + out_size);
  return true;
}

CRYPTO_BUFFER_POOL* GetBufferPool() {
  return g_buffer_pool_singleton.Get().pool();
}

bssl::UniquePtr<CRYPTO_BUFFER> CreateCryptoBuffer(const uint8_t* data,
                                                  size_t length) {
  return bssl::UniquePtr<CRYPTO_BUFFER>(
      CRYPTO_BUFFER_new(data, length, GetBufferPool()));
}

bssl::UniquePtr<CRYPTO_BUFFER> CreateCryptoBuffer(
    const base::StringPiece& data) {
  return bssl::UniquePtr<CRYPTO_BUFFER>(
      CRYPTO_BUFFER_new(reinterpret_cast<const uint8_t*>(data.data()),
                        data.size(), GetBufferPool()));
}

}  // namespace x509_util

}  // namespace net
