// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_database.h"

#include <windows.h>

#include "base/observer_list_threadsafe.h"
#include "crypto/wincrypt_shim.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"

#pragma comment(lib, "crypt32.lib")

namespace net {

CertDatabase::CertDatabase()
    : observer_list_(new base::ObserverListThreadSafe<Observer>) {
}

CertDatabase::~CertDatabase() {}

int CertDatabase::CheckUserCert(X509Certificate* cert) {
  if (!cert)
    return ERR_CERT_INVALID;
  if (cert->HasExpired())
    return ERR_CERT_DATE_INVALID;

  // TODO(rsleevi): Should CRYPT_FIND_SILENT_KEYSET_FLAG be specified? A UI
  // may be shown here / this call may block.
  if (!CryptFindCertificateKeyProvInfo(cert->os_cert_handle(), 0, NULL))
    return ERR_NO_PRIVATE_KEY_FOR_CERT;

  return OK;
}

int CertDatabase::AddUserCert(X509Certificate* cert) {
  // TODO(rsleevi): Would it be more appropriate to have the CertDatabase take
  // construction parameters (Keychain filepath on Mac OS X, PKCS #11 slot on
  // NSS, and Store Type / Path) here? For now, certs will be stashed into the
  // user's personal store, which will not automatically mark them as trusted,
  // but will allow them to be used for client auth.
  HCERTSTORE cert_db = CertOpenSystemStore(NULL, L"MY");
  if (!cert_db)
    return ERR_ADD_USER_CERT_FAILED;

  BOOL added = CertAddCertificateContextToStore(cert_db,
                                                cert->os_cert_handle(),
                                                CERT_STORE_ADD_USE_EXISTING,
                                                NULL);

  CertCloseStore(cert_db, 0);

  if (!added)
    return ERR_ADD_USER_CERT_FAILED;

  NotifyObserversOfCertAdded(cert);
  return OK;
}

}  // namespace net
