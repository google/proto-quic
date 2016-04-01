// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_SIGNATURE_POLICY_H_
#define NET_CERT_INTERNAL_SIGNATURE_POLICY_H_

#include <stddef.h>

#include "base/compiler_specific.h"
#include "net/base/net_export.h"
#include "net/cert/internal/signature_algorithm.h"

namespace net {

class SignatureAlgorithm;

// SignaturePolicy is an interface (and base implementation) for applying
// policies when verifying signed data. It lets callers override which
// algorithms, named curves, and key sizes to allow.
class NET_EXPORT SignaturePolicy {
 public:
  virtual ~SignaturePolicy() {}

  // Implementations should return true if |algorithm| is acceptable. For
  // instance, implementations could reject any signature algorithms that used
  // SHA-1.
  //
  // The default implementation accepts all signature algorithms.
  virtual bool IsAcceptableSignatureAlgorithm(
      const SignatureAlgorithm& algorithm) const;

  // Implementations should return true if |curve_nid| is an allowed
  // elliptical curve. |curve_nid| is an object ID from BoringSSL (for example
  // NID_secp384r1).
  //
  // The default implementation accepts secp256r1, secp384r1, secp521r1 only.
  virtual bool IsAcceptableCurveForEcdsa(int curve_nid) const;

  // Implementations should return true if |modulus_length_bits| is an allowed
  // RSA key size in bits.
  //
  // The default implementation accepts any modulus length >= 2048 bits.
  virtual bool IsAcceptableModulusLengthForRsa(
      size_t modulus_length_bits) const;
};

// SimpleSignaturePolicy modifies the base SignaturePolicy by allowing the
// minimum RSA key length to be specified (rather than hard coded to 2048).
//
// TODO(eroman): This is currently just used by a test. If it ends up being
// only useful for the unit-test then move it directly to that test file.
class NET_EXPORT SimpleSignaturePolicy : public SignaturePolicy {
 public:
  explicit SimpleSignaturePolicy(size_t min_rsa_modulus_length_bits);

  bool IsAcceptableModulusLengthForRsa(
      size_t modulus_length_bits) const override;

 private:
  const size_t min_rsa_modulus_length_bits_;
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_SIGNATURE_POLICY_H_
