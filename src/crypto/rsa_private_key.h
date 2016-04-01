// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_RSA_PRIVATE_KEY_H_
#define CRYPTO_RSA_PRIVATE_KEY_H_

#include <stddef.h>
#include <stdint.h>

#include <list>
#include <vector>

#include "base/macros.h"
#include "build/build_config.h"
#include "crypto/crypto_export.h"

#if defined(USE_OPENSSL)
// Forward declaration for openssl/*.h
typedef struct evp_pkey_st EVP_PKEY;
#else
// Forward declaration.
typedef struct PK11SlotInfoStr PK11SlotInfo;
typedef struct SECKEYPrivateKeyStr SECKEYPrivateKey;
typedef struct SECKEYPublicKeyStr SECKEYPublicKey;
#endif

namespace crypto {

// Encapsulates an RSA private key. Can be used to generate new keys, export
// keys to other formats, or to extract a public key.
// TODO(hclam): This class should be ref-counted so it can be reused easily.
class CRYPTO_EXPORT RSAPrivateKey {
 public:
  ~RSAPrivateKey();

  // Create a new random instance. Can return NULL if initialization fails.
  static RSAPrivateKey* Create(uint16_t num_bits);

  // Create a new instance by importing an existing private key. The format is
  // an ASN.1-encoded PrivateKeyInfo block from PKCS #8. This can return NULL if
  // initialization fails.
  static RSAPrivateKey* CreateFromPrivateKeyInfo(
      const std::vector<uint8_t>& input);

#if defined(USE_OPENSSL)
  // Create a new instance from an existing EVP_PKEY, taking a
  // reference to it. |key| must be an RSA key. Returns NULL on
  // failure.
  static RSAPrivateKey* CreateFromKey(EVP_PKEY* key);
#else
  // Create a new instance by referencing an existing private key
  // structure.  Does not import the key.
  static RSAPrivateKey* CreateFromKey(SECKEYPrivateKey* key);
#endif

#if defined(USE_OPENSSL)
  EVP_PKEY* key() { return key_; }
#else
  SECKEYPrivateKey* key() { return key_; }
  SECKEYPublicKey* public_key() { return public_key_; }
#endif

  // Creates a copy of the object.
  RSAPrivateKey* Copy() const;

  // Exports the private key to a PKCS #8 PrivateKeyInfo block.
  bool ExportPrivateKey(std::vector<uint8_t>* output) const;

  // Exports the public key to an X509 SubjectPublicKeyInfo block.
  bool ExportPublicKey(std::vector<uint8_t>* output) const;

 private:
  // Constructor is private. Use one of the Create*() methods above instead.
  RSAPrivateKey();

#if defined(USE_OPENSSL)
  EVP_PKEY* key_;
#else
  SECKEYPrivateKey* key_;
  SECKEYPublicKey* public_key_;
#endif

  DISALLOW_COPY_AND_ASSIGN(RSAPrivateKey);
};

}  // namespace crypto

#endif  // CRYPTO_RSA_PRIVATE_KEY_H_
