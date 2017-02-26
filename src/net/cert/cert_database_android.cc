// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_database.h"

#include "base/logging.h"
#include "base/observer_list_threadsafe.h"
#include "net/base/net_errors.h"
#include "net/ssl/openssl_client_key_store.h"

namespace net {

CertDatabase::CertDatabase()
    : observer_list_(new base::ObserverListThreadSafe<Observer>) {
}

CertDatabase::~CertDatabase() {}

void CertDatabase::OnAndroidKeyStoreChanged() {
  NotifyObserversCertDBChanged();
  // Dump the OpenSSLClientKeyStore to drop references to now disconnected
  // PrivateKeys stored in the in-memory key store. Note: this assumes that
  // every SSLClientAuthCache is dumped as part of notifying
  // OnCertDBChanged. Otherwise client auth decisions will be silently converted
  // to no-certificate decisions. See https://crbug.com/382696
  OpenSSLClientKeyStore::GetInstance()->Flush();
}

void CertDatabase::OnAndroidKeyChainChanged() {
  observer_list_->Notify(FROM_HERE, &Observer::OnCertDBChanged);
}

}  // namespace net
