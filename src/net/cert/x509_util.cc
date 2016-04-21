// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/x509_util.h"

#include <memory>

#include "base/time/time.h"
#include "crypto/ec_private_key.h"
#include "crypto/rsa_private_key.h"
#include "net/base/hash_value.h"
#include "net/cert/internal/parse_certificate.h"
#include "net/cert/internal/signature_algorithm.h"
#include "net/cert/x509_certificate.h"

namespace net {

namespace x509_util {

// RSA keys created by CreateKeyAndSelfSignedCert will be of this length.
static const uint16_t kRSAKeyLength = 1024;

// Certificates made by CreateKeyAndSelfSignedCert and
//  CreateKeyAndChannelIDEC will be signed using this digest algorithm.
static const DigestAlgorithm kSignatureDigestAlgorithm = DIGEST_SHA256;

ClientCertSorter::ClientCertSorter() : now_(base::Time::Now()) {}

bool ClientCertSorter::operator()(
    const scoped_refptr<X509Certificate>& a,
    const scoped_refptr<X509Certificate>& b) const {
  // Certificates that are null are sorted last.
  if (!a.get() || !b.get())
    return a.get() && !b.get();

  // Certificates that are expired/not-yet-valid are sorted last.
  bool a_is_valid = now_ >= a->valid_start() && now_ <= a->valid_expiry();
  bool b_is_valid = now_ >= b->valid_start() && now_ <= b->valid_expiry();
  if (a_is_valid != b_is_valid)
    return a_is_valid && !b_is_valid;

  // Certificates with longer expirations appear as higher priority (less
  // than) certificates with shorter expirations.
  if (a->valid_expiry() != b->valid_expiry())
    return a->valid_expiry() > b->valid_expiry();

  // If the expiration dates are equivalent, certificates that were issued
  // more recently should be prioritized over older certificates.
  if (a->valid_start() != b->valid_start())
    return a->valid_start() > b->valid_start();

  // Otherwise, prefer client certificates with shorter chains.
  const X509Certificate::OSCertHandles& a_intermediates =
      a->GetIntermediateCertificates();
  const X509Certificate::OSCertHandles& b_intermediates =
      b->GetIntermediateCertificates();
  return a_intermediates.size() < b_intermediates.size();
}

bool CreateKeyAndSelfSignedCert(const std::string& subject,
                                uint32_t serial_number,
                                base::Time not_valid_before,
                                base::Time not_valid_after,
                                std::unique_ptr<crypto::RSAPrivateKey>* key,
                                std::string* der_cert) {
  std::unique_ptr<crypto::RSAPrivateKey> new_key(
      crypto::RSAPrivateKey::Create(kRSAKeyLength));
  if (!new_key.get())
    return false;

  bool success = CreateSelfSignedCert(new_key.get(),
                                      kSignatureDigestAlgorithm,
                                      subject,
                                      serial_number,
                                      not_valid_before,
                                      not_valid_after,
                                      der_cert);
  if (success)
    key->reset(new_key.release());

  return success;
}

}  // namespace x509_util

}  // namespace net
