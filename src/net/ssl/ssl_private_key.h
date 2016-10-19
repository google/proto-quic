// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_PRIVATE_KEY_H_
#define NET_SSL_SSL_PRIVATE_KEY_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/net_errors.h"

namespace net {

// An interface for a private key for use with SSL client authentication.
class SSLPrivateKey : public base::RefCountedThreadSafe<SSLPrivateKey> {
 public:
  using SignCallback = base::Callback<void(Error, const std::vector<uint8_t>&)>;

  enum class Type {
    RSA,
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
  };

  // Returns true if |type| is an ECDSA key type.
  static bool IsECDSAType(Type type) {
    return type == Type::ECDSA_P256 || type == Type::ECDSA_P384 ||
           type == Type::ECDSA_P521;
  }

  enum class Hash {
    MD5_SHA1,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
  };

  SSLPrivateKey() {}

  // Returns whether the key is an RSA key or an ECDSA key. Although the signing
  // interface is type-agnositic and type tags in interfaces are discouraged,
  // TLS has key-specific logic in selecting which hashes to sign. Exposing the
  // key type avoids replicating BoringSSL's TLS-specific logic in SSLPrivateKey
  // implementations and complicating the interface between Chromium and
  // BoringSSL.
  virtual Type GetType() = 0;

  // Returns the digests that are supported by the key in decreasing preference.
  virtual std::vector<SSLPrivateKey::Hash> GetDigestPreferences() = 0;

  // Returns the maximum size of a signature, in bytes. For an RSA key, this
  // must be the size of the modulus.
  virtual size_t GetMaxSignatureLengthInBytes() = 0;

  // Asynchronously signs an |input| which was computed with the hash |hash|. On
  // completion, it calls |callback| with the signature or an error code if the
  // operation failed. For an RSA key, the signature is a PKCS#1 signature. The
  // SSLPrivateKey implementation is responsible for prepending the DigestInfo
  // prefix and adding PKCS#1 padding.
  virtual void SignDigest(Hash hash,
                          const base::StringPiece& input,
                          const SignCallback& callback) = 0;

 protected:
  virtual ~SSLPrivateKey() {}

 private:
  friend class base::RefCountedThreadSafe<SSLPrivateKey>;
  DISALLOW_COPY_AND_ASSIGN(SSLPrivateKey);
};

}  // namespace net

#endif  // NET_SSL_SSL_PRIVATE_KEY_H_
