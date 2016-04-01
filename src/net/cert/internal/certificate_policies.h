// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_CERTIFICATE_POLICIES_H_
#define NET_CERT_INTERNAL_CERTIFICATE_POLICIES_H_

#include <vector>

#include "net/base/net_export.h"

namespace net {

namespace der {
class Input;
}  // namespace der

// Returns the DER-encoded OID, without tag or length, of the anyPolicy
// certificate policy defined in RFC 5280 section 4.2.1.4.
NET_EXPORT const der::Input AnyPolicy();

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

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERTIFICATE_POLICIES_H_
