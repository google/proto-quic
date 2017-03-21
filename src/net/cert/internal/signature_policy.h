// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_SIGNATURE_POLICY_H_
#define NET_CERT_INTERNAL_SIGNATURE_POLICY_H_

#include <stddef.h>

#include "base/compiler_specific.h"
#include "net/base/net_export.h"
#include "net/cert/internal/cert_errors.h"
#include "net/cert/internal/signature_algorithm.h"

namespace net {

class CertErrors;
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
      const SignatureAlgorithm& algorithm,
      CertErrors* errors) const;

  // Implementations should return true if |curve_nid| is an allowed
  // elliptical curve. |curve_nid| is an object ID from BoringSSL (for example
  // NID_secp384r1).
  //
  // The default implementation accepts secp256r1, secp384r1, secp521r1 only.
  virtual bool IsAcceptableCurveForEcdsa(int curve_nid,
                                         CertErrors* errors) const;

  // Implementations should return true if |modulus_length_bits| is an allowed
  // RSA key size in bits.
  //
  // The default implementation accepts any modulus length >= 2048 bits.
  virtual bool IsAcceptableModulusLengthForRsa(size_t modulus_length_bits,
                                               CertErrors* errors) const;
};

// SimpleSignaturePolicy modifies the base SignaturePolicy by allowing the
// minimum RSA key length to be specified (rather than hard coded to 2048).
class NET_EXPORT SimpleSignaturePolicy : public SignaturePolicy {
 public:
  explicit SimpleSignaturePolicy(size_t min_rsa_modulus_length_bits);

  bool IsAcceptableModulusLengthForRsa(size_t modulus_length_bits,
                                       CertErrors* errors) const override;

 private:
  const size_t min_rsa_modulus_length_bits_;
};

// TODO(crbug.com/634443): Move exported errors to a central location?
extern CertErrorId kRsaModulusTooSmall;

}  // namespace net

#endif  // NET_CERT_INTERNAL_SIGNATURE_POLICY_H_
