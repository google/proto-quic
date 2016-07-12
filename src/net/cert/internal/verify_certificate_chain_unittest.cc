// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_certificate_chain.h"

#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_certificate_chain_typed_unittest.h"

namespace net {

namespace {

class VerifyCertificateChainAssumingTrustedRootDelegate {
 public:
  static void Verify(const ParsedCertificateList& chain,
                     const ParsedCertificateList& roots,
                     const der::GeneralizedTime& time,
                     bool expected_result) {
    TrustStore trust_store;
    ASSERT_EQ(1U, roots.size());
    trust_store.AddTrustedCertificate(roots[0]);

    ParsedCertificateList full_chain(chain);
    full_chain.push_back(roots[0]);

    SimpleSignaturePolicy signature_policy(1024);

    bool result = VerifyCertificateChainAssumingTrustedRoot(
        full_chain, trust_store, &signature_policy, time);

    ASSERT_EQ(expected_result, result);
  }
};

}  // namespace

INSTANTIATE_TYPED_TEST_CASE_P(
    VerifyCertificateChainAssumingTrustedRoot,
    VerifyCertificateChainSingleRootTest,
    VerifyCertificateChainAssumingTrustedRootDelegate);

}  // namespace net
