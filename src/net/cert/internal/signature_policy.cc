// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/signature_policy.h"

#include "base/logging.h"

#if defined(USE_OPENSSL)
#include <openssl/obj.h>
#endif

namespace net {

bool SignaturePolicy::IsAcceptableSignatureAlgorithm(
    const SignatureAlgorithm& algorithm) const {
  return true;
}

bool SignaturePolicy::IsAcceptableCurveForEcdsa(int curve_nid) const {
#if defined(USE_OPENSSL)
  switch (curve_nid) {
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
      return true;
  }
#endif
  return false;
}

bool SignaturePolicy::IsAcceptableModulusLengthForRsa(
    size_t modulus_length_bits) const {
  return modulus_length_bits >= 2048;
}

SimpleSignaturePolicy::SimpleSignaturePolicy(size_t min_rsa_modulus_length_bits)
    : min_rsa_modulus_length_bits_(min_rsa_modulus_length_bits) {}

bool SimpleSignaturePolicy::IsAcceptableModulusLengthForRsa(
    size_t modulus_length_bits) const {
  return modulus_length_bits >= min_rsa_modulus_length_bits_;
}

}  // namespace net
