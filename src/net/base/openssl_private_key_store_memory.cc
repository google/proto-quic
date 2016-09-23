// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Defines an in-memory private key store, primarily used for testing.

#include "net/base/openssl_private_key_store.h"

#include <openssl/evp.h>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/synchronization/lock.h"

namespace net {

namespace {

// A small in-memory store for public/private key pairs held in
// a single EVP_PKEY object. This is intentionally distinct from
// net::SSLClientKeyStore.
class MemoryKeyPairStore {
 public:
  MemoryKeyPairStore() {}

  static MemoryKeyPairStore* GetInstance() {
    return base::Singleton<MemoryKeyPairStore>::get();
  }

  ~MemoryKeyPairStore() {
    base::AutoLock lock(lock_);
    for (std::vector<EVP_PKEY*>::iterator it = keys_.begin();
         it != keys_.end(); ++it) {
      EVP_PKEY_free(*it);
    }
  }

  bool StoreKeyPair(EVP_PKEY* pkey) {
    EVP_PKEY_up_ref(pkey);
    base::AutoLock lock(lock_);
    keys_.push_back(pkey);
    return true;
  }

  bool HasPrivateKey(EVP_PKEY* pkey) {
    base::AutoLock lock(lock_);
    for (std::vector<EVP_PKEY*>::iterator it = keys_.begin();
         it != keys_.end(); ++it) {
      if (EVP_PKEY_cmp(*it, pkey) == 1)
        return true;
    }
    return false;
  }

 private:
  std::vector<EVP_PKEY*> keys_;
  base::Lock lock_;

  DISALLOW_COPY_AND_ASSIGN(MemoryKeyPairStore);
};

}  // namespace

bool OpenSSLPrivateKeyStore::StoreKeyPair(const GURL& url,
                                          EVP_PKEY* pkey) {
  return MemoryKeyPairStore::GetInstance()->StoreKeyPair(pkey);
}

bool OpenSSLPrivateKeyStore::HasPrivateKey(EVP_PKEY* pub_key) {
  return MemoryKeyPairStore::GetInstance()->HasPrivateKey(pub_key);
}

} // namespace net

