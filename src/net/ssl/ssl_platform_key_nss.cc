// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyhi.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <pk11pub.h>
#include <prerror.h>

#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/sequenced_task_runner.h"
#include "crypto/scoped_nss_types.h"
#include "crypto/scoped_openssl_types.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/client_key_store.h"
#include "net/ssl/ssl_platform_key.h"
#include "net/ssl/ssl_platform_key_task_runner.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/threaded_ssl_private_key.h"

namespace net {

namespace {

void LogPRError() {
  PRErrorCode err = PR_GetError();
  const char* err_name = PR_ErrorToName(err);
  if (err_name == nullptr)
    err_name = "";
  LOG(ERROR) << "Could not sign digest: " << err << " (" << err_name << ")";
}

class SSLPlatformKeyNSS : public ThreadedSSLPrivateKey::Delegate {
 public:
  SSLPlatformKeyNSS(SSLPrivateKey::Type type,
                    crypto::ScopedSECKEYPrivateKey key)
      : type_(type), key_(std::move(key)) {}
  ~SSLPlatformKeyNSS() override {}

  SSLPrivateKey::Type GetType() override { return type_; }

  std::vector<SSLPrivateKey::Hash> GetDigestPreferences() override {
    static const SSLPrivateKey::Hash kHashes[] = {
        SSLPrivateKey::Hash::SHA512, SSLPrivateKey::Hash::SHA384,
        SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1};
    return std::vector<SSLPrivateKey::Hash>(kHashes,
                                            kHashes + arraysize(kHashes));
  }

  size_t GetMaxSignatureLengthInBytes() override {
    int len = PK11_SignatureLen(key_.get());
    if (len <= 0)
      return 0;
    // NSS signs raw ECDSA signatures rather than a DER-encoded ECDSA-Sig-Value.
    if (type_ == SSLPrivateKey::Type::ECDSA)
      return ECDSA_SIG_max_len(static_cast<size_t>(len) / 2);
    return static_cast<size_t>(len);
  }

  Error SignDigest(SSLPrivateKey::Hash hash,
                   const base::StringPiece& input,
                   std::vector<uint8_t>* signature) override {
    SECItem digest_item;
    digest_item.data =
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(input.data()));
    digest_item.len = input.size();

    crypto::ScopedOpenSSLBytes free_digest_info;
    if (type_ == SSLPrivateKey::Type::RSA) {
      // PK11_Sign expects the caller to prepend the DigestInfo.
      int hash_nid = NID_undef;
      switch (hash) {
        case SSLPrivateKey::Hash::MD5_SHA1:
          hash_nid = NID_md5_sha1;
          break;
        case SSLPrivateKey::Hash::SHA1:
          hash_nid = NID_sha1;
          break;
        case SSLPrivateKey::Hash::SHA256:
          hash_nid = NID_sha256;
          break;
        case SSLPrivateKey::Hash::SHA384:
          hash_nid = NID_sha384;
          break;
        case SSLPrivateKey::Hash::SHA512:
          hash_nid = NID_sha512;
          break;
      }
      DCHECK_NE(NID_undef, hash_nid);
      int is_alloced;
      size_t prefix_len;
      if (!RSA_add_pkcs1_prefix(&digest_item.data, &prefix_len, &is_alloced,
                                hash_nid, digest_item.data, digest_item.len)) {
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }
      digest_item.len = prefix_len;
      if (is_alloced)
        free_digest_info.reset(digest_item.data);
    }

    int len = PK11_SignatureLen(key_.get());
    if (len <= 0) {
      LogPRError();
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(len);
    SECItem signature_item;
    signature_item.data = signature->data();
    signature_item.len = signature->size();

    SECStatus rv = PK11_Sign(key_.get(), &signature_item, &digest_item);
    if (rv != SECSuccess) {
      LogPRError();
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(signature_item.len);

    // NSS emits raw ECDSA signatures, but BoringSSL expects a DER-encoded
    // ECDSA-Sig-Value.
    if (type_ == SSLPrivateKey::Type::ECDSA) {
      if (signature->size() % 2 != 0) {
        LOG(ERROR) << "Bad signature length";
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }
      size_t order_len = signature->size() / 2;

      // Convert the RAW ECDSA signature to a DER-encoded ECDSA-Sig-Value.
      crypto::ScopedECDSA_SIG sig(ECDSA_SIG_new());
      if (!sig || !BN_bin2bn(signature->data(), order_len, sig->r) ||
          !BN_bin2bn(signature->data() + order_len, order_len, sig->s)) {
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }

      int len = i2d_ECDSA_SIG(sig.get(), nullptr);
      if (len <= 0)
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      signature->resize(len);
      uint8_t* ptr = signature->data();
      len = i2d_ECDSA_SIG(sig.get(), &ptr);
      if (len <= 0)
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      signature->resize(len);
    }

    return OK;
  }

 private:
  SSLPrivateKey::Type type_;
  crypto::ScopedSECKEYPrivateKey key_;

  DISALLOW_COPY_AND_ASSIGN(SSLPlatformKeyNSS);
};

}  // namespace

scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
    X509Certificate* certificate) {
  crypto::ScopedSECKEYPrivateKey key(
      PK11_FindKeyByAnyCert(certificate->os_cert_handle(), nullptr));
  if (!key) {
    return ClientKeyStore::GetInstance()->FetchClientCertPrivateKey(
        *certificate);
  }

  KeyType nss_type = SECKEY_GetPrivateKeyType(key.get());
  SSLPrivateKey::Type type;
  switch (nss_type) {
    case rsaKey:
      type = SSLPrivateKey::Type::RSA;
      break;
    case ecKey:
      type = SSLPrivateKey::Type::ECDSA;
      break;
    default:
      LOG(ERROR) << "Unknown key type: " << nss_type;
      return nullptr;
  }
  return make_scoped_refptr(new ThreadedSSLPrivateKey(
      base::MakeUnique<SSLPlatformKeyNSS>(type, std::move(key)),
      GetSSLPlatformKeyTaskRunner()));
}

}  // namespace net
