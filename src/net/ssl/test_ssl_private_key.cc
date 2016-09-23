// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/test_ssl_private_key.h"

#include <openssl/digest.h>
#include <openssl/evp.h>

#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "crypto/scoped_openssl_types.h"
#include "net/base/net_errors.h"
#include "net/ssl/ssl_platform_key_task_runner.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/threaded_ssl_private_key.h"

namespace net {

namespace {

class TestSSLPlatformKey : public ThreadedSSLPrivateKey::Delegate {
 public:
  TestSSLPlatformKey(crypto::ScopedEVP_PKEY key, SSLPrivateKey::Type type)
      : key_(std::move(key)), type_(type) {}

  ~TestSSLPlatformKey() override {}

  SSLPrivateKey::Type GetType() override { return type_; }

  std::vector<SSLPrivateKey::Hash> GetDigestPreferences() override {
    static const SSLPrivateKey::Hash kHashes[] = {
        SSLPrivateKey::Hash::SHA512, SSLPrivateKey::Hash::SHA384,
        SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1};
    return std::vector<SSLPrivateKey::Hash>(kHashes,
                                            kHashes + arraysize(kHashes));
  }

  size_t GetMaxSignatureLengthInBytes() override {
    return EVP_PKEY_size(key_.get());
  }

  Error SignDigest(SSLPrivateKey::Hash hash,
                   const base::StringPiece& input,
                   std::vector<uint8_t>* signature) override {
    crypto::ScopedEVP_PKEY_CTX ctx =
        crypto::ScopedEVP_PKEY_CTX(EVP_PKEY_CTX_new(key_.get(), NULL));
    if (!ctx)
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    if (!EVP_PKEY_sign_init(ctx.get()))
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;

    if (type_ == SSLPrivateKey::Type::RSA) {
      const EVP_MD* digest = nullptr;
      switch (hash) {
        case SSLPrivateKey::Hash::MD5_SHA1:
          digest = EVP_md5_sha1();
          break;
        case SSLPrivateKey::Hash::SHA1:
          digest = EVP_sha1();
          break;
        case SSLPrivateKey::Hash::SHA256:
          digest = EVP_sha256();
          break;
        case SSLPrivateKey::Hash::SHA384:
          digest = EVP_sha384();
          break;
        case SSLPrivateKey::Hash::SHA512:
          digest = EVP_sha512();
          break;
        default:
          return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }
      DCHECK(digest);
      if (!EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING))
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      if (!EVP_PKEY_CTX_set_signature_md(ctx.get(), digest))
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }

    const uint8_t* input_ptr = reinterpret_cast<const uint8_t*>(input.data());
    size_t input_len = input.size();
    size_t sig_len = 0;
    if (!EVP_PKEY_sign(ctx.get(), NULL, &sig_len, input_ptr, input_len))
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    signature->resize(sig_len);
    if (!EVP_PKEY_sign(ctx.get(), signature->data(), &sig_len, input_ptr,
                       input_len)) {
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }

    signature->resize(sig_len);

    return OK;
  }

 private:
  crypto::ScopedEVP_PKEY key_;
  SSLPrivateKey::Type type_;

  DISALLOW_COPY_AND_ASSIGN(TestSSLPlatformKey);
};

}  // namespace

scoped_refptr<SSLPrivateKey> WrapOpenSSLPrivateKey(crypto::ScopedEVP_PKEY key) {
  if (!key)
    return nullptr;

  SSLPrivateKey::Type type;
  switch (EVP_PKEY_id(key.get())) {
    case EVP_PKEY_RSA:
      type = SSLPrivateKey::Type::RSA;
      break;
    case EVP_PKEY_EC:
      type = SSLPrivateKey::Type::ECDSA;
      break;
    default:
      LOG(ERROR) << "Unknown key type: " << EVP_PKEY_id(key.get());
      return nullptr;
  }
  return make_scoped_refptr(new ThreadedSSLPrivateKey(
      base::MakeUnique<TestSSLPlatformKey>(std::move(key), type),
      GetSSLPlatformKeyTaskRunner()));
}

}  // namespace net
