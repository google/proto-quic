// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util_win.h"

#include "crypto/scoped_capi_types.h"
#include "crypto/sha2.h"
#include "net/cert/x509_certificate.h"
#include "net/net_features.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

namespace net {

namespace x509_util {

namespace {

using ScopedHCERTSTORE = crypto::ScopedCAPIHandle<
    HCERTSTORE,
    crypto::CAPIDestroyerWithFlags<HCERTSTORE, CertCloseStore, 0>>;

}  // namespace

scoped_refptr<X509Certificate> CreateX509CertificateFromCertContexts(
    PCCERT_CONTEXT os_cert,
    const std::vector<PCCERT_CONTEXT>& os_chain) {
#if BUILDFLAG(USE_BYTE_CERTS)
  if (!os_cert || !os_cert->pbCertEncoded || !os_cert->cbCertEncoded)
    return nullptr;
  bssl::UniquePtr<CRYPTO_BUFFER> cert_handle(
      X509Certificate::CreateOSCertHandleFromBytes(
          reinterpret_cast<const char*>(os_cert->pbCertEncoded),
          os_cert->cbCertEncoded));
  if (!cert_handle)
    return nullptr;
  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  X509Certificate::OSCertHandles intermediates_raw;
  for (PCCERT_CONTEXT os_intermediate : os_chain) {
    if (!os_intermediate || !os_intermediate->pbCertEncoded ||
        !os_intermediate->cbCertEncoded)
      return nullptr;
    bssl::UniquePtr<CRYPTO_BUFFER> intermediate_cert_handle(
        X509Certificate::CreateOSCertHandleFromBytes(
            reinterpret_cast<const char*>(os_intermediate->pbCertEncoded),
            os_intermediate->cbCertEncoded));
    if (!intermediate_cert_handle)
      return nullptr;
    intermediates_raw.push_back(intermediate_cert_handle.get());
    intermediates.push_back(std::move(intermediate_cert_handle));
  }
  scoped_refptr<X509Certificate> result(
      X509Certificate::CreateFromHandle(cert_handle.get(), intermediates_raw));
  return result;
#else
  return X509Certificate::CreateFromHandle(os_cert, os_chain);
#endif
}

ScopedPCCERT_CONTEXT CreateCertContextWithChain(const X509Certificate* cert) {
  // Create an in-memory certificate store to hold the certificate and its
  // intermediate certificates. The store will be referenced in the returned
  // PCCERT_CONTEXT, and will not be freed until the PCCERT_CONTEXT is freed.
  ScopedHCERTSTORE store(
      CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL,
                    CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG, NULL));
  if (!store.get())
    return nullptr;

  PCCERT_CONTEXT primary_cert = nullptr;

#if BUILDFLAG(USE_BYTE_CERTS)
  BOOL ok = CertAddEncodedCertificateToStore(
      store.get(), X509_ASN_ENCODING,
      CRYPTO_BUFFER_data(cert->os_cert_handle()),
      base::checked_cast<DWORD>(CRYPTO_BUFFER_len(cert->os_cert_handle())),
      CERT_STORE_ADD_ALWAYS, &primary_cert);
  if (!ok || !primary_cert)
    return nullptr;
  ScopedPCCERT_CONTEXT scoped_primary_cert(primary_cert);

  for (X509Certificate::OSCertHandle intermediate :
       cert->GetIntermediateCertificates()) {
    ok = CertAddEncodedCertificateToStore(
        store.get(), X509_ASN_ENCODING, CRYPTO_BUFFER_data(intermediate),
        base::checked_cast<DWORD>(CRYPTO_BUFFER_len(intermediate)),
        CERT_STORE_ADD_ALWAYS, NULL);
    if (!ok)
      return nullptr;
  }
#else
  PCCERT_CONTEXT os_cert_handle = cert->os_cert_handle();
  const std::vector<PCCERT_CONTEXT>& intermediate_ca_certs =
      cert->GetIntermediateCertificates();

  // NOTE: This preserves all of the properties of |os_cert_handle| except
  // for CERT_KEY_PROV_HANDLE_PROP_ID and CERT_KEY_CONTEXT_PROP_ID - the two
  // properties that hold access to already-opened private keys. If a handle
  // has already been unlocked (eg: PIN prompt), then the first time that the
  // identity is used for client auth, it may prompt the user again.
  BOOL ok = CertAddCertificateContextToStore(
      store.get(), os_cert_handle, CERT_STORE_ADD_ALWAYS, &primary_cert);
  if (!ok || !primary_cert)
    return nullptr;
  ScopedPCCERT_CONTEXT scoped_primary_cert(primary_cert);

  for (PCCERT_CONTEXT intermediate : intermediate_ca_certs) {
    CertAddCertificateContextToStore(store.get(), intermediate,
                                     CERT_STORE_ADD_ALWAYS, NULL);
  }
#endif

  // Note: |primary_cert| retains a reference to |store|, so the store will
  // actually be freed when |primary_cert| is freed.
  return scoped_primary_cert;
}

SHA256HashValue CalculateFingerprint256(PCCERT_CONTEXT cert) {
  DCHECK(NULL != cert->pbCertEncoded);
  DCHECK_NE(0u, cert->cbCertEncoded);

  SHA256HashValue sha256;

  // Use crypto::SHA256HashString for two reasons:
  // * < Windows Vista does not have universal SHA-256 support.
  // * More efficient on Windows > Vista (less overhead since non-default CSP
  // is not needed).
  base::StringPiece der_cert(reinterpret_cast<const char*>(cert->pbCertEncoded),
                             cert->cbCertEncoded);
  crypto::SHA256HashString(der_cert, sha256.data, sizeof(sha256.data));
  return sha256;
}

bool IsSelfSigned(PCCERT_CONTEXT cert_handle) {
  bool valid_signature = !!CryptVerifyCertificateSignatureEx(
      NULL, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
      reinterpret_cast<void*>(const_cast<PCERT_CONTEXT>(cert_handle)),
      CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
      reinterpret_cast<void*>(const_cast<PCERT_CONTEXT>(cert_handle)), 0, NULL);
  if (!valid_signature)
    return false;
  return !!CertCompareCertificateName(X509_ASN_ENCODING,
                                      &cert_handle->pCertInfo->Subject,
                                      &cert_handle->pCertInfo->Issuer);
}

}  // namespace x509_util

}  // namespace net
