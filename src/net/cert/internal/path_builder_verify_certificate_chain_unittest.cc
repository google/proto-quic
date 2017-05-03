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

    switch (test.last_cert_trust.type) {
      case CertificateTrustType::TRUSTED_ANCHOR:
        trust_store.AddTrustAnchor(test.chain.back());
        break;
      case CertificateTrustType::TRUSTED_ANCHOR_WITH_CONSTRAINTS:
        trust_store.AddTrustAnchorWithConstraints(test.chain.back());
        break;
      case CertificateTrustType::UNSPECIFIED:
        LOG(ERROR) << "Unexpected CertificateTrustType";
        break;
      case CertificateTrustType::DISTRUSTED:
        trust_store.AddDistrustedCertificateForTest(test.chain.back());
        break;
    }

    CertIssuerSourceStatic intermediate_cert_issuer_source;
    for (size_t i = 1; i < test.chain.size(); ++i)
      intermediate_cert_issuer_source.AddCert(test.chain[i]);

    CertPathBuilder::Result result;
    // First cert in the |chain| is the target.
    CertPathBuilder path_builder(test.chain.front(), &trust_store,
                                 &signature_policy, test.time, test.key_purpose,
                                 &result);
    path_builder.AddCertIssuerSource(&intermediate_cert_issuer_source);

    path_builder.Run();
    EXPECT_EQ(!test.HasHighSeverityErrors(), result.HasValidPath());
  }
};

}  // namespace

INSTANTIATE_TYPED_TEST_CASE_P(PathBuilder,
                              VerifyCertificateChainSingleRootTest,
                              PathBuilderDelegate);

}  // namespace net
