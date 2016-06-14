// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_verify_result.h"

#include "net/cert/ct_policy_status.h"

namespace net {

namespace ct {

CTVerifyResult::CTVerifyResult()
    : ct_policies_applied(false),
      cert_policy_compliance(
          ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS),
      ev_policy_compliance(ct::EVPolicyCompliance::EV_POLICY_DOES_NOT_APPLY) {}

CTVerifyResult::CTVerifyResult(const CTVerifyResult& other) = default;

CTVerifyResult::~CTVerifyResult() {}

}  // namespace ct

}  // namespace net
