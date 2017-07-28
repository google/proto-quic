// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_VERIFY_SIGNED_DATA_H_
#define NET_CERT_INTERNAL_VERIFY_SIGNED_DATA_H_

#include "base/compiler_specific.h"
#include "crypto/openssl_util.h"
#include "net/base/net_export.h"
#include "third_party/boringssl/src/include/openssl/evp.h"

namespace net {

namespace der {
class BitString;
class Input;
}  // namespace der

class SignatureAlgorithm;

// Verifies that |signature_value| is a valid signature of |signed_data| using
// the algorithm |algorithm| and the public key |public_key|.
//
//   |algorithm| - The parsed AlgorithmIdentifier
//   |signed_data| - The blob of data to verify
//   |signature_value| - The BIT STRING for the signature's value
//   |public_key| - The parsed (non-null) public key.
//
// Returns true if verification was successful.
NET_EXPORT bool VerifySignedData(const SignatureAlgorithm& algorithm,
                                 const der::Input& signed_data,
                                 const der::BitString& signature_value,
                                 EVP_PKEY* public_key) WARN_UNUSED_RESULT;

// Same as above overload, only the public key is inputted as an SPKI and will
// be parsed internally.
NET_EXPORT bool VerifySignedData(const SignatureAlgorithm& algorithm,
                                 const der::Input& signed_data,
                                 const der::BitString& signature_value,
                                 const der::Input& public_key_spki)
    WARN_UNUSED_RESULT;

NET_EXPORT bool ParsePublicKey(const der::Input& public_key_spki,
                               bssl::UniquePtr<EVP_PKEY>* public_key)
    WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_VERIFY_SIGNED_DATA_H_
