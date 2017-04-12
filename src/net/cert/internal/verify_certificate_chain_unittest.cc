// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_certificate_chain.h"

#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store.h"
#include "net/cert/internal/verify_certificate_chain_typed_unittest.h"

namespace net {

namespace {

class VerifyCertificateChainDelegate {
 public:
  static void Verify(const VerifyCertChainTest& test,
                     const std::string& test_file_path) {
    ASSERT_TRUE(test.trust_anchor);

    SimpleSignaturePolicy signature_policy(1024);

    CertPathErrors errors;
    bool result = VerifyCertificateChain(test.chain, test.trust_anchor.get(),
                                         &signature_policy, test.time, &errors);
    EXPECT_EQ(test.expected_result, result);
    EXPECT_EQ(test.expected_errors, errors.ToDebugString(test.chain))
        << "Test file: " << test_file_path;
    EXPECT_EQ(result, !errors.ContainsHighSeverityErrors());
  }
};

}  // namespace

INSTANTIATE_TYPED_TEST_CASE_P(VerifyCertificateChain,
                              VerifyCertificateChainSingleRootTest,
                              VerifyCertificateChainDelegate);

}  // namespace net
