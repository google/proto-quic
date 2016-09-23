// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/client_key_store.h"

#include <algorithm>
#include <utility>

#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_private_key.h"

namespace net {

namespace {
static base::LazyInstance<ClientKeyStore>::Leaky g_client_key_store =
    LAZY_INSTANCE_INITIALIZER;
}  // namespace

ClientKeyStore::ClientKeyStore() {}

ClientKeyStore::~ClientKeyStore() {}

// static
ClientKeyStore* ClientKeyStore::GetInstance() {
  return g_client_key_store.Pointer();
}

void ClientKeyStore::AddProvider(CertKeyProvider* provider) {
  base::AutoLock auto_lock(lock_);
  providers_.push_back(provider);
}

void ClientKeyStore::RemoveProvider(const CertKeyProvider* provider) {
  base::AutoLock auto_lock(lock_);

  const auto& it = std::find(providers_.begin(), providers_.end(), provider);
  if (it != providers_.end())
    providers_.erase(it);
}

scoped_refptr<SSLPrivateKey> ClientKeyStore::FetchClientCertPrivateKey(
    const X509Certificate& certificate) {
  base::AutoLock auto_lock(lock_);

  for (auto* provider : providers_) {
    scoped_refptr<SSLPrivateKey> key;
    if (provider->GetCertificateKey(certificate, &key))
      return key;
  }
  return nullptr;
}

}  // namespace net
