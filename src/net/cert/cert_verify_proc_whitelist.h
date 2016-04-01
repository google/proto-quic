// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CERT_VERIFY_PROC_WHITELIST_H_
#define NET_CERT_CERT_VERIFY_PROC_WHITELIST_H_

#include <stddef.h>
#include <stdint.h>

#include "crypto/sha2.h"
#include "net/base/hash_value.h"
#include "net/base/net_export.h"

namespace net {

class X509Certificate;

// PublicKeyWhitelist contains a SHA-256 SPKI hash and a pointer to an array
// of SHA-256 certificate hashes that have been publicly disclosed and
// whitelisted.
struct PublicKeyWhitelist {
  uint8_t public_key[crypto::kSHA256Length];
  const uint8_t (*whitelist)[crypto::kSHA256Length];
  size_t whitelist_size;
};

// Returns true if |cert| has been issued by a CA that is constrained from
// issuing new certificates and |cert| is not within the whitelist of
// existing certificates. Returns false if |cert| was issued by an
// unconstrained CA or if it was in the whitelist for that
// CA.
// |cert| should be the verified certificate chain, with |public_key_hashes|
// being the set of hashes of the SPKIs within the verified chain.
bool NET_EXPORT_PRIVATE
IsNonWhitelistedCertificate(const X509Certificate& cert,
                            const HashValueVector& public_key_hashes);

// Sets the certificate whitelist for testing. Supply nullptr/0 to reset to
// the built-in whitelist.
void NET_EXPORT_PRIVATE
SetCertificateWhitelistForTesting(const PublicKeyWhitelist* whitelist,
                                  size_t whitelist_size);

}  // namespace net

#endif  // NET_CERT_CERT_VERIFY_PROC_WHITELIST
