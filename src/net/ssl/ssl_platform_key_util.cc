// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_platform_key_util.h"

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/threading/thread.h"
#include "crypto/openssl_util.h"
#include "net/cert/asn1_util.h"
#include "net/cert/x509_certificate.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/ec_key.h"
#include "third_party/boringssl/src/include/openssl/evp.h"

namespace net {

namespace {

class SSLPlatformKeyTaskRunner {
 public:
  SSLPlatformKeyTaskRunner() : worker_thread_("Platform Key Thread") {
    base::Thread::Options options;
    options.joinable = false;
    worker_thread_.StartWithOptions(options);
  }

  ~SSLPlatformKeyTaskRunner() {}

  scoped_refptr<base::SingleThreadTaskRunner> task_runner() {
    return worker_thread_.task_runner();
  }

 private:
  base::Thread worker_thread_;

  DISALLOW_COPY_AND_ASSIGN(SSLPlatformKeyTaskRunner);
};

base::LazyInstance<SSLPlatformKeyTaskRunner>::Leaky g_platform_key_task_runner =
    LAZY_INSTANCE_INITIALIZER;

}  // namespace

scoped_refptr<base::SingleThreadTaskRunner> GetSSLPlatformKeyTaskRunner() {
  return g_platform_key_task_runner.Get().task_runner();
}

bool GetClientCertInfo(const X509Certificate* certificate,
                       SSLPrivateKey::Type* out_type,
                       size_t* out_max_length) {
  crypto::OpenSSLErrStackTracer tracker(FROM_HERE);

  std::string der_encoded;
  base::StringPiece spki;
  if (!X509Certificate::GetDEREncoded(certificate->os_cert_handle(),
                                      &der_encoded) ||
      !asn1::ExtractSPKIFromDERCert(der_encoded, &spki)) {
    LOG(ERROR) << "Could not extract SPKI from certificate.";
    return false;
  }

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(spki.data()), spki.size());
  bssl::UniquePtr<EVP_PKEY> key(EVP_parse_public_key(&cbs));
  if (!key || CBS_len(&cbs) != 0) {
    LOG(ERROR) << "Could not parse public key.";
    return false;
  }

  int key_type = EVP_PKEY_id(key.get());
  switch (key_type) {
    case EVP_PKEY_RSA:
      *out_type = SSLPrivateKey::Type::RSA;
      break;

    case EVP_PKEY_EC: {
      EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(key.get());
      int curve = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
      switch (curve) {
        case NID_X9_62_prime256v1:
          *out_type = SSLPrivateKey::Type::ECDSA_P256;
          break;
        case NID_secp384r1:
          *out_type = SSLPrivateKey::Type::ECDSA_P384;
          break;
        case NID_secp521r1:
          *out_type = SSLPrivateKey::Type::ECDSA_P521;
          break;
        default:
          LOG(ERROR) << "Unsupported curve type " << curve;
          return false;
      }
      break;
    }

    default:
      LOG(ERROR) << "Unsupported key type " << key_type;
      return false;
  }

  *out_max_length = EVP_PKEY_size(key.get());
  return true;
}

}  // namespace net
