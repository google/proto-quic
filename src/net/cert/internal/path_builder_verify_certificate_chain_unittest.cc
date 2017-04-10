// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/path_builder.h"

#include "net/cert/internal/cert_issuer_source_static.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/trust_store_in_memory.h"
#include "net/cert/internal/verify_certificate_chain_typed_unittest.h"

namespace net {

namespace {

class PathBuilderDelegate {
 public:
  static void Verify(const VerifyCertChainTest& test,
                     const std::string& test_file_path) {
    SimpleSignaturePolicy signature_policy(1024);
    ASSERT_FALSE(test.chain.empty());

    TrustStoreInMemory trust_store;
    trust_store.AddTrustAnchor(test.trust_anchor);

    CertIssuerSourceStatic intermediate_cert_issuer_source;
    for (size_t i = 1; i < test.chain.size(); ++i)
      intermediate_cert_issuer_source.AddCert(test.chain[i]);

    CertPathBuilder::Result result;
    // First cert in the |chain| is the target.
    CertPathBuilder path_builder(test.chain.front(), &trust_store,
                                 &signature_policy, test.time, &result);
    path_builder.AddCertIssuerSource(&intermediate_cert_issuer_source);

    path_builder.Run();
    EXPECT_EQ(test.expected_result, result.HasValidPath());
  }
};

}  // namespace

INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              VerifyCertificateChainSingleRootTest,
                              PathBuilderDelegate);

}  // namespace net
