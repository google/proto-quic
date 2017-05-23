// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_CERTIFICATE_POLICIES_H_
#define NET_CERT_INTERNAL_CERTIFICATE_POLICIES_H_

#include <stdint.h>

#include <vector>

#include "base/compiler_specific.h"
#include "net/base/net_export.h"

namespace net {

namespace der {
class Input;
}  // namespace der

// Returns the DER-encoded OID, without tag or length, of the anyPolicy
// certificate policy defined in RFC 5280 section 4.2.1.4.
NET_EXPORT const der::Input AnyPolicy();

// From RFC 5280:
//
//     id-ce-inhibitAnyPolicy OBJECT IDENTIFIER ::=  { id-ce 54 }
//
// In dotted notation: 2.5.29.54
NET_EXPORT der::Input InhibitAnyPolicyOid();

// Parses a certificatePolicies extension and stores the policy OIDs in
// |*policies|, in sorted order. If policyQualifiers are present,
// they are ignored. (RFC 5280 section 4.2.1.4 says "optional qualifiers, which
// MAY be present, are not expected to change the definition of the policy.",
// furthermore policyQualifiers do not affect the success or failure of the
// section 6 Certification Path Validation algorithm.)
//
// The returned values is only valid as long as |extension_value| is.
NET_EXPORT bool ParseCertificatePoliciesExtension(
    const der::Input& extension_value,
    std::vector<der::Input>* policies);

struct ParsedPolicyConstraints {
  bool has_require_explicit_policy = false;
  uint8_t require_explicit_policy = 0;

  bool has_inhibit_policy_mapping = false;
  uint8_t inhibit_policy_mapping = 0;
};

// Parses a PolicyConstraints SEQUENCE as defined by RFC 5280. Returns true on
// success, and sets |out|.
NET_EXPORT bool ParsePolicyConstraints(const der::Input& policy_constraints_tlv,
                                       ParsedPolicyConstraints* out)
    WARN_UNUSED_RESULT;

// Parses an InhibitAnyPolicy as defined by RFC 5280. Returns true on success,
// and sets |out|.
NET_EXPORT bool ParseInhibitAnyPolicy(const der::Input& inhibit_any_policy_tlv,
                                      uint8_t* num_certs) WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERTIFICATE_POLICIES_H_
