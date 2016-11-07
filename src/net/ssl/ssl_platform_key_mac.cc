// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_platform_key.h"

#include <Security/cssm.h>
#include <Security/SecBase.h>
#include <Security/SecCertificate.h>
#include <Security/SecIdentity.h>
#include <Security/SecKey.h>

#include <memory>

#include "base/location.h"
#include "base/logging.h"
#include "base/mac/mac_logging.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/scoped_policy.h"
#include "base/synchronization/lock.h"
#include "crypto/mac_security_services_lock.h"
#include "crypto/openssl_util.h"
#include "net/base/net_errors.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_platform_key_util.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/threaded_ssl_private_key.h"
#include "third_party/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/nid.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"

namespace net {

// CSSM functions are deprecated as of OSX 10.7, but have no replacement.
// https://bugs.chromium.org/p/chromium/issues/detail?id=590914#c1
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

namespace {

class ScopedCSSM_CC_HANDLE {
 public:
  ScopedCSSM_CC_HANDLE() : handle_(0) {}
  explicit ScopedCSSM_CC_HANDLE(CSSM_CC_HANDLE handle) : handle_(handle) {}

  ~ScopedCSSM_CC_HANDLE() { reset(); }

  CSSM_CC_HANDLE get() const { return handle_; }

  void reset() {
    if (handle_)
      CSSM_DeleteContext(handle_);
    handle_ = 0;
  }

 private:
  CSSM_CC_HANDLE handle_;

  DISALLOW_COPY_AND_ASSIGN(ScopedCSSM_CC_HANDLE);
};

// Looks up the private key for |certificate| in KeyChain and returns
// a SecKeyRef or nullptr on failure. The caller takes ownership of the
// result.
SecKeyRef FetchSecKeyRefForCertificate(const X509Certificate* certificate) {
  OSStatus status;
  base::ScopedCFTypeRef<SecIdentityRef> identity;
  {
    base::AutoLock lock(crypto::GetMacSecurityServicesLock());
    status = SecIdentityCreateWithCertificate(
        nullptr, certificate->os_cert_handle(), identity.InitializeInto());
  }
  if (status != noErr) {
    OSSTATUS_LOG(WARNING, status);
    return nullptr;
  }

  base::ScopedCFTypeRef<SecKeyRef> private_key;
  status = SecIdentityCopyPrivateKey(identity, private_key.InitializeInto());
  if (status != noErr) {
    OSSTATUS_LOG(WARNING, status);
    return nullptr;
  }

  return private_key.release();
}

class SSLPlatformKeyMac : public ThreadedSSLPrivateKey::Delegate {
 public:
  SSLPlatformKeyMac(SSLPrivateKey::Type type,
                    size_t max_length,
                    SecKeyRef key,
                    const CSSM_KEY* cssm_key)
      : type_(type),
        max_length_(max_length),
        key_(key, base::scoped_policy::RETAIN),
        cssm_key_(cssm_key) {}

  ~SSLPlatformKeyMac() override {}

  SSLPrivateKey::Type GetType() override { return type_; }

  std::vector<SSLPrivateKey::Hash> GetDigestPreferences() override {
    static const SSLPrivateKey::Hash kHashes[] = {
        SSLPrivateKey::Hash::SHA512, SSLPrivateKey::Hash::SHA384,
        SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1};
    return std::vector<SSLPrivateKey::Hash>(kHashes,
                                            kHashes + arraysize(kHashes));
  }

  size_t GetMaxSignatureLengthInBytes() override { return max_length_; }

  Error SignDigest(SSLPrivateKey::Hash hash,
                   const base::StringPiece& input,
                   std::vector<uint8_t>* signature) override {
    crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

    CSSM_CSP_HANDLE csp_handle;
    OSStatus status = SecKeyGetCSPHandle(key_.get(), &csp_handle);
    if (status != noErr) {
      OSSTATUS_LOG(WARNING, status);
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }

    const CSSM_ACCESS_CREDENTIALS* cssm_creds = nullptr;
    status = SecKeyGetCredentials(key_.get(), CSSM_ACL_AUTHORIZATION_SIGN,
                                  kSecCredentialTypeDefault, &cssm_creds);
    if (status != noErr) {
      OSSTATUS_LOG(WARNING, status);
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }

    CSSM_CC_HANDLE cssm_signature_raw = 0;
    if (CSSM_CSP_CreateSignatureContext(
            csp_handle, cssm_key_->KeyHeader.AlgorithmId, cssm_creds, cssm_key_,
            &cssm_signature_raw) != CSSM_OK) {
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    ScopedCSSM_CC_HANDLE cssm_signature(cssm_signature_raw);

    CSSM_DATA hash_data;
    hash_data.Length = input.size();
    hash_data.Data =
        const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(input.data()));

    bssl::UniquePtr<uint8_t> free_digest_info;
    if (cssm_key_->KeyHeader.AlgorithmId == CSSM_ALGID_RSA) {
      // CSSM expects the caller to prepend the DigestInfo.
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
      if (!RSA_add_pkcs1_prefix(&hash_data.Data, &hash_data.Length, &is_alloced,
                                hash_nid, hash_data.Data, hash_data.Length)) {
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }
      if (is_alloced)
        free_digest_info.reset(hash_data.Data);

      // Set RSA blinding.
      CSSM_CONTEXT_ATTRIBUTE blinding_attr;
      blinding_attr.AttributeType = CSSM_ATTRIBUTE_RSA_BLINDING;
      blinding_attr.AttributeLength = sizeof(uint32_t);
      blinding_attr.Attribute.Uint32 = 1;
      if (CSSM_UpdateContextAttributes(cssm_signature.get(), 1,
                                       &blinding_attr) != CSSM_OK) {
        return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
      }
    }

    signature->resize(max_length_);
    CSSM_DATA signature_data;
    signature_data.Length = signature->size();
    signature_data.Data = signature->data();

    if (CSSM_SignData(cssm_signature.get(), &hash_data, 1, CSSM_ALGID_NONE,
                      &signature_data) != CSSM_OK) {
      return ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED;
    }
    signature->resize(signature_data.Length);
    return OK;
  }

 private:
  SSLPrivateKey::Type type_;
  size_t max_length_;
  base::ScopedCFTypeRef<SecKeyRef> key_;
  const CSSM_KEY* cssm_key_;

  DISALLOW_COPY_AND_ASSIGN(SSLPlatformKeyMac);
};

}  // namespace

scoped_refptr<SSLPrivateKey> FetchClientCertPrivateKey(
    X509Certificate* certificate) {
  // Look up the private key.
  base::ScopedCFTypeRef<SecKeyRef> private_key(
      FetchSecKeyRefForCertificate(certificate));
  if (!private_key)
    return nullptr;

  const CSSM_KEY* cssm_key;
  OSStatus status = SecKeyGetCSSMKey(private_key.get(), &cssm_key);
  if (status != noErr)
    return nullptr;

  SSLPrivateKey::Type key_type;
  size_t max_length;
  if (!GetClientCertInfo(certificate, &key_type, &max_length))
    return nullptr;

  return make_scoped_refptr(new ThreadedSSLPrivateKey(
      base::MakeUnique<SSLPlatformKeyMac>(key_type, max_length,
                                          private_key.get(), cssm_key),
      GetSSLPlatformKeyTaskRunner()));
}

#pragma clang diagnostic pop  // "-Wdeprecated-declarations"

}  // namespace net
