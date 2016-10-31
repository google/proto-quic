// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/openssl_private_key_store.h"

#include "base/logging.h"
#include "base/memory/singleton.h"
#include "crypto/openssl_util.h"
#include "net/android/network_library.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"

namespace net {

bool OpenSSLPrivateKeyStore::StoreKeyPair(const GURL& url, EVP_PKEY* pkey) {
  // Always clear openssl errors on exit.
  crypto::OpenSSLErrStackTracer err_trace(FROM_HERE);

  uint8_t* public_key;
  size_t public_len;
  bssl::ScopedCBB cbb;
  if (!CBB_init(cbb.get(), 0) || !EVP_marshal_public_key(cbb.get(), pkey) ||
      !CBB_finish(cbb.get(), &public_key, &public_len)) {
    return false;
  }
  bssl::UniquePtr<uint8_t> free_public_key(public_key);

  uint8_t* private_key;
  size_t private_len;
  cbb.Reset();
  if (!CBB_init(cbb.get(), 0) || !EVP_marshal_private_key(cbb.get(), pkey) ||
      !CBB_finish(cbb.get(), &private_key, &private_len)) {
    return false;
  }
  bssl::UniquePtr<uint8_t> free_private_key(private_key);

  if (!android::StoreKeyPair(public_key, public_len, private_key,
                             private_len)) {
    LOG(ERROR) << "StoreKeyPair failed. public_len = " << public_len
               << " private_len = " << private_len;
  }
  return true;
}

}  // namespace net
