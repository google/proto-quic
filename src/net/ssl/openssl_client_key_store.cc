// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/openssl_client_key_store.h"

#include <utility>

#include "base/memory/singleton.h"
#include "net/cert/asn1_util.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_private_key.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

namespace net {

namespace {

// Serializes the SubjectPublicKeyInfo for |cert|.
bool GetCertificateSPKI(const X509Certificate* cert, std::string* spki) {
#if BUILDFLAG(USE_BYTE_CERTS)
  base::StringPiece cert_der(
      reinterpret_cast<const char*>(CRYPTO_BUFFER_data(cert->os_cert_handle())),
      CRYPTO_BUFFER_len(cert->os_cert_handle()));
  base::StringPiece spki_tmp;
  if (!asn1::ExtractSPKIFromDERCert(cert_der, &spki_tmp))
    return false;
  spki_tmp.CopyToString(spki);
  return true;
#else
  bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(cert->os_cert_handle()));
  if (!pkey) {
    LOG(ERROR) << "Can't extract private key from certificate!";
    return false;
  }

  bssl::ScopedCBB cbb;
  uint8_t* der;
  size_t der_len;
  if (!CBB_init(cbb.get(), 0) ||
      !EVP_marshal_public_key(cbb.get(), pkey.get()) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }

  spki->assign(reinterpret_cast<char*>(der),
               reinterpret_cast<char*>(der) + der_len);
  OPENSSL_free(der);
  return true;
#endif
}

}  // namespace

OpenSSLClientKeyStore* OpenSSLClientKeyStore::GetInstance() {
  return base::Singleton<OpenSSLClientKeyStore>::get();
}

bool OpenSSLClientKeyStore::RecordClientCertPrivateKey(
    const X509Certificate* client_cert,
    scoped_refptr<SSLPrivateKey> private_key) {
  DCHECK(client_cert);
  DCHECK(private_key);

  std::string spki;
  if (!GetCertificateSPKI(client_cert, &spki))
    return false;

  key_map_[spki] = std::move(private_key);
  return true;
}

scoped_refptr<SSLPrivateKey> OpenSSLClientKeyStore::FetchClientCertPrivateKey(
    const X509Certificate* client_cert) {
  DCHECK(client_cert);

  std::string spki;
  if (!GetCertificateSPKI(client_cert, &spki))
    return nullptr;

  auto iter = key_map_.find(spki);
  if (iter == key_map_.end())
    return nullptr;

  return iter->second;
}

void OpenSSLClientKeyStore::Flush() {
  key_map_.clear();
}

OpenSSLClientKeyStore::OpenSSLClientKeyStore() {}

OpenSSLClientKeyStore::~OpenSSLClientKeyStore() {}

}  // namespace net
