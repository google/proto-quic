// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_SIGNED_DATA_H_
#define NET_CERT_INTERNAL_VERIFY_SIGNED_DATA_H_

#include "base/compiler_specific.h"
#include "net/base/net_export.h"

namespace net {

namespace der {
class BitString;
class Input;
}  // namespace der

class CertErrors;
class SignatureAlgorithm;
class SignaturePolicy;

// Verifies that |signature_value| is a valid signature of |signed_data| using
// the algorithm |signature_algorithm| and the public key |public_key|.
//
//   |signature_algorithm| - The parsed AlgorithmIdentifier
//   |signed_data| - The blob of data to verify
//   |signature_value| - The BIT STRING for the signature's value
//   |public_key| - A DER-encoded SubjectPublicKeyInfo.
//   |policy| - Instance of the policy to use. This will be queried to
//       determine if:
//          * The parsed RSA key is an adequate size.
//          * The parsed EC key is for an allowed curve.
//          * The signature algorithm and its parameters are acceptable.
//   |errors| - Non-null destination for errors/warnings information.
//
// Returns true if verification was successful.
NET_EXPORT bool VerifySignedData(const SignatureAlgorithm& signature_algorithm,
                                 const der::Input& signed_data,
                                 const der::BitString& signature_value,
                                 const der::Input& public_key,
                                 const SignaturePolicy* policy,
                                 CertErrors* errors) WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_SIGNED_DATA_H_
