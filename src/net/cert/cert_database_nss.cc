// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_database.h"

#include <cert.h>
#include <pk11pub.h>
#include <secmod.h>

#include <vector>

#include "base/logging.h"
#include "base/observer_list_threadsafe.h"
#include "crypto/nss_util.h"
#include "crypto/scoped_nss_types.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util_nss.h"
#include "net/third_party/mozilla_security_manager/nsNSSCertificateDB.h"

// PSM = Mozilla's Personal Security Manager.
namespace psm = mozilla_security_manager;

namespace net {

CertDatabase::CertDatabase()
    : observer_list_(new base::ObserverListThreadSafe<Observer>) {
  crypto::EnsureNSSInit();
}

CertDatabase::~CertDatabase() {}

int CertDatabase::CheckUserCert(X509Certificate* cert_obj) {
  if (!cert_obj)
    return ERR_CERT_INVALID;
  if (cert_obj->HasExpired())
    return ERR_CERT_DATE_INVALID;

  // Check if the private key corresponding to the certificate exist
  // We shouldn't accept any random client certificate sent by a CA.

  // Note: The NSS source documentation wrongly suggests that this
  // also imports the certificate if the private key exists. This
  // doesn't seem to be the case.

  CERTCertificate* cert = cert_obj->os_cert_handle();
  PK11SlotInfo* slot = PK11_KeyForCertExists(cert, NULL, NULL);
  if (!slot)
    return ERR_NO_PRIVATE_KEY_FOR_CERT;

  PK11_FreeSlot(slot);

  return OK;
}

int CertDatabase::AddUserCert(X509Certificate* cert_obj) {
  CertificateList cert_list;
  cert_list.push_back(cert_obj);
  int result = psm::ImportUserCert(cert_list);

  if (result == OK)
    NotifyObserversOfCertAdded(NULL);

  return result;
}

}  // namespace net
