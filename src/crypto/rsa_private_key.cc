// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/rsa_private_key.h"

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <stdint.h>

#include <memory>

#include "base/logging.h"
#include "crypto/auto_cbb.h"
#include "crypto/openssl_util.h"
#include "crypto/scoped_openssl_types.h"

namespace crypto {

// static
RSAPrivateKey* RSAPrivateKey::Create(uint16_t num_bits) {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  ScopedRSA rsa_key(RSA_new());
  ScopedBIGNUM bn(BN_new());
  if (!rsa_key.get() || !bn.get() || !BN_set_word(bn.get(), 65537L))
    return NULL;

  if (!RSA_generate_key_ex(rsa_key.get(), num_bits, bn.get(), NULL))
    return NULL;

  std::unique_ptr<RSAPrivateKey> result(new RSAPrivateKey);
  result->key_ = EVP_PKEY_new();
  if (!result->key_ || !EVP_PKEY_set1_RSA(result->key_, rsa_key.get()))
    return NULL;

  return result.release();
}

// static
RSAPrivateKey* RSAPrivateKey::CreateFromPrivateKeyInfo(
    const std::vector<uint8_t>& input) {
  OpenSSLErrStackTracer err_tracer(FROM_HERE);

  CBS cbs;
  CBS_init(&cbs, input.data(), input.size());
  ScopedEVP_PKEY pkey(EVP_parse_private_key(&cbs));
  if (!pkey || CBS_len(&cbs) != 0 || EVP_PKEY_id(pkey.get()) != EVP_PKEY_RSA)
    return nullptr;

  std::unique_ptr<RSAPrivateKey> result(new RSAPrivateKey);
  result->key_ = pkey.release();
  return result.release();
}

// static
RSAPrivateKey* RSAPrivateKey::CreateFromKey(EVP_PKEY* key) {
  DCHECK(key);
  if (EVP_PKEY_type(key->type) != EVP_PKEY_RSA)
    return NULL;
  RSAPrivateKey* copy = new RSAPrivateKey();
  copy->key_ = EVP_PKEY_up_ref(key);
  return copy;
}

RSAPrivateKey::RSAPrivateKey()
    : key_(NULL) {
}

RSAPrivateKey::~RSAPrivateKey() {
  if (key_)
    EVP_PKEY_free(key_);
}

RSAPrivateKey* RSAPrivateKey::Copy() const {
  std::unique_ptr<RSAPrivateKey> copy(new RSAPrivateKey());
  ScopedRSA rsa(EVP_PKEY_get1_RSA(key_));
  if (!rsa)
    return NULL;
  copy->key_ = EVP_PKEY_new();
  if (!EVP_PKEY_set1_RSA(copy->key_, rsa.get()))
    return NULL;
  return copy.release();
}

bool RSAPrivateKey::ExportPrivateKey(std::vector<uint8_t>* output) const {
  uint8_t *der;
  size_t der_len;
  AutoCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      !EVP_marshal_private_key(cbb.get(), key_) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  output->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

bool RSAPrivateKey::ExportPublicKey(std::vector<uint8_t>* output) const {
  uint8_t *der;
  size_t der_len;
  AutoCBB cbb;
  if (!CBB_init(cbb.get(), 0) ||
      !EVP_marshal_public_key(cbb.get(), key_) ||
      !CBB_finish(cbb.get(), &der, &der_len)) {
    return false;
  }
  output->assign(der, der + der_len);
  OPENSSL_free(der);
  return true;
}

}  // namespace crypto
