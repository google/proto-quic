// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "crypto/scoped_nss_types.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/client_key_store.h"
#include "net/ssl/ssl_platform_key.h"
#include "net/ssl/ssl_platform_key_util.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/threaded_ssl_private_key.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/nid.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"

namespace net {

namespace {

void LogPRError() {
  PRErrorCode err = PR_GetError();
  const char* err_name = PR_ErrorToName(err);
  if (err_name == nullptr)
    err_name = "";
  LOG(ERROR) << "Could not sign digest: " << err << " (" << err_name << ")";
}

class SSLPlatformKeyChromecast : public ThreadedSSLPrivateKey::Delegate {
 public:
  SSLPlatformKeyChromecast(crypto::ScopedSECKEYPrivateKey key)
      : key_(std::move(key)) {}
  ~SSLPlatformKeyChromecast() override {}

  std::vector<SSLPrivateKey::Hash> GetDigestPreferences() override {
    return std::vector<SSLPrivateKey::Hash>{SSLPrivateKey::Hash::SHA256,
                                            SSLPrivateKey::Hash::SHA1};
  }

  Error SignDigest(SSLPrivateKey::Hash hash,
                   const base::StringPiece& input,
                   std::vector<uint8_t>* signature) override {
    SECItem digest_item;
    digest_item.data =
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(input.data()));
    digest_item.len = input.size();

    bssl::UniquePtr<uint8_t> free_digest_info;
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
      default:
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
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

    return OK;
  }

 private:
  crypto::ScopedSECKEYPrivateKey key_;

  DISALLOW_COPY_AND_ASSIGN(SSLPlatformKeyChromecast);
};

}  // namespace

scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
    const X509Certificate* certificate) {
  crypto::ScopedSECKEYPrivateKey key(
      PK11_FindKeyByAnyCert(certificate->os_cert_handle(), nullptr));
  if (!key) {
    return ClientKeyStore::GetInstance()->FetchClientCertPrivateKey(
        *certificate);
  }

  return make_scoped_refptr(new ThreadedSSLPrivateKey(
      base::MakeUnique<SSLPlatformKeyChromecast>(std::move(key)),
      GetSSLPlatformKeyTaskRunner()));
}

}  // namespace net
