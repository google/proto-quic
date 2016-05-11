// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_POLICY_ENFORCER_H
#define NET_CERT_CT_POLICY_ENFORCER_H

#include <stddef.h>
#include <vector>

#include "net/base/net_export.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "net/log/net_log.h"

namespace net {

namespace ct {

class EVCertsWhitelist;
enum class CertPolicyCompliance;
enum class EVPolicyCompliance;

}  // namespace ct

class X509Certificate;

using SCTList = std::vector<scoped_refptr<ct::SignedCertificateTimestamp>>;

// Class for checking that a given certificate conforms to
// Certificate Transparency-related policies.
//
// Each method can be called independently, to determine whether
// or not it complies with a given policy.
//
// For example, to determine if a certificate complies with the
// EV certificate policy, callers need only to call
// DoesConformToEVPolicy() - it is not necessary to first check
// whether or not DoesConformToCertPolicy().
//
// However, consider the case where a given certificate is desired
// to be EV, but, if it does not conform to the EV policy, will
// be downgraded to DV. In this case, it's necessary to check if
// it complies with either policy. This can be done one of two
// ways, reflected in pseudo-code below:
//
// Recommended:
// // Checks EV certificates against the EV policy. If the
// // certificate fails, it will be downgraded to DV, in which
// // case, the DV policy will apply.
// bool is_valid_cert_policy = DoesConformToCertPolicy(...);
// bool is_valid_ev_policy = is_ev && DoesConformToEVPolicy(...);
// if (!is_valid_ev_policy)
//   is_ev = false;
// is_valid_ct = is_valid_ev_policy || is_valid_cert_policy;
//
// NOT recommended:
// // Checks all certificates against the basic policy, and only
// // if they meet the baseline policy, check EV.
// bool conforms_to_cert_policy = DoesConformToCertPolicy(...);
// if (conforms_to_cert_policy && is_ev) {
//   conforms_to_cert_policy = DoesConformToEVPolicy(...);
// }
//
// The reason the second form is NOT recommended is that the EV and Cert
// policies may be completely independent: a certificate might fail the
// cert policy but pass the EV policy (because, for example, the EV
// policy supports whitelisting certificates). Or, conversely, the EV
// policy might have stricter SCT requirements, so that a certificate
// passes the certificate policy but fails the EV policy. For this
// reason, callers are encouraged to check the policy specific to the
// certificate type being validated, and only call other methods if they
// are changing the type of certificate because it failed one or more
// policies.
class NET_EXPORT CTPolicyEnforcer {
 public:
  CTPolicyEnforcer() {}
  virtual ~CTPolicyEnforcer() {}

  // Returns the CT certificate policy compliance status for a given
  // certificate and collection of SCTs.
  // |cert| is the certificate for which to check compliance, and
  // ||verified_scts| contains any/all SCTs associated with |cert| that
  // |have been verified (well-formed, issued by known logs, and
  // |applying to |cert|).
  virtual ct::CertPolicyCompliance DoesConformToCertPolicy(
      X509Certificate* cert,
      const SCTList& verified_scts,
      const BoundNetLog& net_log);

  // Returns the CT/EV policy compliance status for a given certificate
  // and collection of SCTs.
  // |cert| is the certificate for which to check compliance, and
  // ||verified_scts| contains any/all SCTs associated with |cert| that
  // |have been verified (well-formed, issued by known logs, and
  // |applying to |cert|).
  // Note: |ev_whitelist| is an optional whitelist of certificates considered
  // to be conforming.
  virtual ct::EVPolicyCompliance DoesConformToCTEVPolicy(
      X509Certificate* cert,
      const ct::EVCertsWhitelist* ev_whitelist,
      const SCTList& verified_scts,
      const BoundNetLog& net_log);
};

}  // namespace net

#endif  // NET_CERT_CT_POLICY_ENFORCER_H
