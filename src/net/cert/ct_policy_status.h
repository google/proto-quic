// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_CT_POLICY_STATUS_H_
#define NET_CERT_CT_POLICY_STATUS_H_

namespace net {

namespace ct {

// Information about the connection's compliance with the CT
// certificate policy.
enum class CertPolicyCompliance {
  // The connection complied with the certificate policy by
  // including SCTs that satisfy the policy.
  CERT_POLICY_COMPLIES_VIA_SCTS = 0,
  // The connection did not have enough SCTs to comply.
  CERT_POLICY_NOT_ENOUGH_SCTS,
  // The connection did not have diverse enough SCTs to comply.
  CERT_POLICY_NOT_DIVERSE_SCTS,
  // The connection cannot be considered compliant because the build
  // isn't timely and therefore log information might be out of date
  // (for example a log might no longer be considered trustworthy).
  CERT_POLICY_BUILD_NOT_TIMELY,
};

}  // namespace ct

}  // namespace net

#endif  // NET_CERT_CT_POLICY_STATUS_H_
