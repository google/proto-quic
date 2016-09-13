// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/signature_policy.h"

#include "base/logging.h"
#include "net/cert/internal/cert_errors.h"

#include <openssl/obj.h>

namespace net {

namespace {

DEFINE_CERT_ERROR_TYPE(kUnacceptableCurveForEcdsa,
                       "Only P-256, P-384, P-521 are supported for ECDSA");
DEFINE_CERT_ERROR_TYPE(kRsaModulusLessThan2048,
                       "RSA modulus must be at least 2048 bits");
DEFINE_CERT_ERROR_TYPE(kRsaModulusTooSmall, "RSA modulus too small");

}  // namespace

bool SignaturePolicy::IsAcceptableSignatureAlgorithm(
    const SignatureAlgorithm& algorithm,
    CertErrors* errors) const {
  return true;
}

bool SignaturePolicy::IsAcceptableCurveForEcdsa(int curve_nid,
                                                CertErrors* errors) const {
  switch (curve_nid) {
    case NID_X9_62_prime256v1:
    case NID_secp384r1:
    case NID_secp521r1:
      return true;
  }

  errors->Add(kUnacceptableCurveForEcdsa);
  return false;
}

bool SignaturePolicy::IsAcceptableModulusLengthForRsa(
    size_t modulus_length_bits,
    CertErrors* errors) const {
  if (modulus_length_bits < 2048) {
    // TODO(crbug.com/634443): Add a parameter for actual modulus size.
    errors->Add(kRsaModulusLessThan2048);
    return false;
  }

  return true;
}

SimpleSignaturePolicy::SimpleSignaturePolicy(size_t min_rsa_modulus_length_bits)
    : min_rsa_modulus_length_bits_(min_rsa_modulus_length_bits) {}

bool SimpleSignaturePolicy::IsAcceptableModulusLengthForRsa(
    size_t modulus_length_bits,
    CertErrors* errors) const {
  if (modulus_length_bits < min_rsa_modulus_length_bits_) {
    // TODO(crbug.com/634443): Add parameters for actual and expected modulus
    //                         size.
    errors->Add(kRsaModulusTooSmall);
    return false;
  }

  return true;
}

}  // namespace net
