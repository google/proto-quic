// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_VERIFY_RESULT_H_
#define NET_CERT_CT_VERIFY_RESULT_H_

#include <vector>

#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/signed_certificate_timestamp.h"

namespace net {

namespace ct {

enum class CertPolicyCompliance;
enum class EVPolicyCompliance;

typedef std::vector<scoped_refptr<SignedCertificateTimestamp> > SCTList;

// Holds Signed Certificate Timestamps, depending on their verification
// results, and information about CT policies that were applied on the
// connection.
struct NET_EXPORT CTVerifyResult {
  CTVerifyResult();
  CTVerifyResult(const CTVerifyResult& other);
  ~CTVerifyResult();

  // SCTs from known logs where the signature verified correctly.
  SCTList verified_scts;
  // SCTs from known logs where the signature failed to verify.
  SCTList invalid_scts;
  // SCTs from unknown logs and as such are unverifiable.
  SCTList unknown_logs_scts;

  // True if any CT policies were applied on this connection.
  bool ct_policies_applied;
  // The result of evaluating whether the connection complies with the
  // CT certificate policy.
  CertPolicyCompliance cert_policy_compliance;
  // The result of evaluating whether the connection complies with the
  // EV CT policy.
  EVPolicyCompliance ev_policy_compliance;
};

}  // namespace ct

}  // namespace net

#endif  // NET_CERT_CT_VERIFY_RESULT_H_
