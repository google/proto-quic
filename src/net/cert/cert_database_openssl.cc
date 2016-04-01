// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_database.h"

#include <openssl/x509.h>

#include "base/logging.h"
#include "base/observer_list_threadsafe.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/crypto_module.h"
#include "net/base/net_errors.h"
#include "net/base/openssl_private_key_store.h"
#include "net/cert/x509_certificate.h"

namespace net {

CertDatabase::CertDatabase()
    : observer_list_(new base::ObserverListThreadSafe<Observer>) {
}

CertDatabase::~CertDatabase() {}

// This method is used to check a client certificate before trying to
// install it on the system, which will happen later by calling
// AddUserCert() below.
//
// On the Linux/OpenSSL build, there is simply no system keystore, but
// OpenSSLPrivateKeyStore() implements a small in-memory store for
// (public/private) key pairs generated through keygen.
//
// Try to check for a private key in the in-memory store to check
// for the case when the browser is trying to install a server-generated
// certificate from a <keygen> exchange.
int CertDatabase::CheckUserCert(X509Certificate* cert) {
  if (!cert)
    return ERR_CERT_INVALID;
  if (cert->HasExpired())
    return ERR_CERT_DATE_INVALID;

  // X509_PUBKEY_get() transfers ownership, not X509_get_X509_PUBKEY()
  crypto::ScopedEVP_PKEY public_key(
      X509_PUBKEY_get(X509_get_X509_PUBKEY(cert->os_cert_handle())));

  if (!OpenSSLPrivateKeyStore::HasPrivateKey(public_key.get()))
    return ERR_NO_PRIVATE_KEY_FOR_CERT;

  return OK;
}

int CertDatabase::AddUserCert(X509Certificate* cert) {
  // There is no certificate store on the Linux/OpenSSL build.
  NOTIMPLEMENTED();
  return ERR_NOT_IMPLEMENTED;
}

}  // namespace net
