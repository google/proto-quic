// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/path_builder.h"

#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "net/cert/internal/cert_issuer_source_static.h"
#include "net/cert/internal/parsed_certificate.h"
#include "net/cert/internal/signature_policy.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/internal/trust_store_collection.h"
#include "net/cert/internal/trust_store_in_memory.h"
#include "net/cert/internal/verify_certificate_chain.h"
#include "net/cert/pem_tokenizer.h"
#include "net/der/input.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_certificate_data.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/pool.h"

namespace net {

// TODO(crbug.com/634443): Assert the errors for each ResultPath.

namespace {

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

// AsyncCertIssuerSourceStatic always returns its certs asynchronously.
class AsyncCertIssuerSourceStatic : public CertIssuerSource {
 public:
  class StaticAsyncRequest : public Request {
   public:
    StaticAsyncRequest(ParsedCertificateList&& issuers) {
      issuers_.swap(issuers);
      issuers_iter_ = issuers_.begin();
    }
    ~StaticAsyncRequest() override {}

    void GetNext(ParsedCertificateList* out_certs) override {
      if (issuers_iter_ != issuers_.end())
        out_certs->push_back(std::move(*issuers_iter_++));
    }

    ParsedCertificateList issuers_;
    ParsedCertificateList::iterator issuers_iter_;

    DISALLOW_COPY_AND_ASSIGN(StaticAsyncRequest);
  };

  ~AsyncCertIssuerSourceStatic() override {}

  void AddCert(scoped_refptr<ParsedCertificate> cert) {
    static_cert_issuer_source_.AddCert(std::move(cert));
  }

  void SyncGetIssuersOf(const ParsedCertificate* cert,
                        ParsedCertificateList* issuers) override {}
  void AsyncGetIssuersOf(const ParsedCertificate* cert,
                         std::unique_ptr<Request>* out_req) override {
    num_async_gets_++;
    ParsedCertificateList issuers;
    static_cert_issuer_source_.SyncGetIssuersOf(cert, &issuers);
    std::unique_ptr<StaticAsyncRequest> req(
        new StaticAsyncRequest(std::move(issuers)));
    *out_req = std::move(req);
  }
  int num_async_gets() const { return num_async_gets_; }

 private:
  CertIssuerSourceStatic static_cert_issuer_source_;

  int num_async_gets_ = 0;
};

::testing::AssertionResult ReadTestPem(const std::string& file_name,
                                       const std::string& block_name,
                                       std::string* result) {
  const PemBlockMapping mappings[] = {
      {block_name.c_str(), result},
  };

  return ReadTestDataFromPemFile(file_name, mappings);
}

::testing::AssertionResult ReadTestCert(
    const std::string& file_name,
    scoped_refptr<ParsedCertificate>* result) {
  std::string der;
  ::testing::AssertionResult r = ReadTestPem(
      "net/data/ssl/certificates/" + file_name, "CERTIFICATE", &der);
  if (!r)
    return r;
  CertErrors errors;
  *result = ParsedCertificate::Create(
      bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(
          reinterpret_cast<const uint8_t*>(der.data()), der.size(), nullptr)),
      {}, &errors);
  if (!*result) {
    return ::testing::AssertionFailure()
           << "ParseCertificate::Create() failed:\n"
           << errors.ToDebugString();
  }
  return ::testing::AssertionSuccess();
}

class PathBuilderMultiRootTest : public ::testing::Test {
 public:
  PathBuilderMultiRootTest() : signature_policy_(1024) {}

  void SetUp() override {
    ASSERT_TRUE(ReadTestCert("multi-root-A-by-B.pem", &a_by_b_));
    ASSERT_TRUE(ReadTestCert("multi-root-B-by-C.pem", &b_by_c_));
    ASSERT_TRUE(ReadTestCert("multi-root-B-by-F.pem", &b_by_f_));
    ASSERT_TRUE(ReadTestCert("multi-root-C-by-D.pem", &c_by_d_));
    ASSERT_TRUE(ReadTestCert("multi-root-C-by-E.pem", &c_by_e_));
    ASSERT_TRUE(ReadTestCert("multi-root-D-by-D.pem", &d_by_d_));
    ASSERT_TRUE(ReadTestCert("multi-root-E-by-E.pem", &e_by_e_));
    ASSERT_TRUE(ReadTestCert("multi-root-F-by-E.pem", &f_by_e_));
  }

 protected:
  scoped_refptr<ParsedCertificate> a_by_b_, b_by_c_, b_by_f_, c_by_d_, c_by_e_,
      d_by_d_, e_by_e_, f_by_e_;

  SimpleSignaturePolicy signature_policy_;
  der::GeneralizedTime time_ = {2017, 3, 1, 0, 0, 0};
};

void AddTrustedCertificate(scoped_refptr<ParsedCertificate> cert,
                           TrustStoreInMemory* trust_store) {
  ASSERT_TRUE(cert.get());
  scoped_refptr<TrustAnchor> anchor =
      TrustAnchor::CreateFromCertificateNoConstraints(std::move(cert));
  ASSERT_TRUE(anchor.get());
  trust_store->AddTrustAnchor(std::move(anchor));
}

// If the target cert is has the same name and key as a trust anchor, however
// is signed but a different trust anchor. This should successfully build a
// path, however the trust anchor will be the signer of this cert.
//
// (This test is very similar to TestEndEntityHasSameNameAndSpkiAsTrustAnchor
// but with different data; also in this test the target cert itself is in the
// trust store).
TEST_F(PathBuilderMultiRootTest, TargetHasNameAndSpkiOfTrustAnchor) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(a_by_b_, &trust_store);
  AddTrustedCertificate(b_by_f_, &trust_store);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);

  path_builder.Run();

  ASSERT_TRUE(result.HasValidPath());
  const auto& path = result.GetBestValidPath()->path;
  ASSERT_EQ(1U, path.certs.size());
  EXPECT_EQ(a_by_b_, path.certs[0]);
  EXPECT_EQ(b_by_f_, path.trust_anchor->cert());
}

// If the target cert is has the same name and key as a trust anchor, however
// is NOT itself signed by a trust anchor, it fails. Although the provided SPKI
// is trusted, the certificate contents cannot be verified.
TEST_F(PathBuilderMultiRootTest, TargetWithSameNameAsTrustAnchorFails) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(a_by_b_, &trust_store);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);

  path_builder.Run();

  EXPECT_FALSE(result.HasValidPath());
}

// Test a failed path building when the trust anchor is provided as a
// supplemental certificate. Conceptually the following paths can be built:
//
//   B(C) <- C(D) <- [Trust anchor D]
//   B(C) <- C(D) <- D(D) <- [Trust anchor D]
//
// The second one is extraneous given the shorter one, however path building
// will enumerate it if the shorter one failed validation.
TEST_F(PathBuilderMultiRootTest, SelfSignedTrustAnchorSupplementalCert) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(d_by_d_, &trust_store);

  // The (extraneous) trust anchor D(D) is supplied as a certificate, as is the
  // intermediate needed for path building C(D).
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(d_by_d_);
  sync_certs.AddCert(c_by_d_);

  // C(D) is not valid at this time, so path building will fail.
  der::GeneralizedTime expired_time = {2016, 1, 1, 0, 0, 0};

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(b_by_c_, &trust_store, &signature_policy_,
                               expired_time, &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_FALSE(result.HasValidPath());
  ASSERT_EQ(2U, result.paths.size());

  EXPECT_FALSE(result.paths[0]->valid);
  const auto& path0 = result.paths[0]->path;
  ASSERT_EQ(2U, path0.certs.size());
  EXPECT_EQ(b_by_c_, path0.certs[0]);
  EXPECT_EQ(c_by_d_, path0.certs[1]);
  EXPECT_EQ(d_by_d_, path0.trust_anchor->cert());

  const auto& path1 = result.paths[1]->path;
  ASSERT_EQ(3U, path1.certs.size());
  EXPECT_EQ(b_by_c_, path1.certs[0]);
  EXPECT_EQ(c_by_d_, path1.certs[1]);
  EXPECT_EQ(d_by_d_, path1.certs[2]);
  EXPECT_EQ(d_by_d_, path1.trust_anchor->cert());
}

// If the target cert is a self-signed cert whose key is a trust anchor, it
// should verify.
TEST_F(PathBuilderMultiRootTest, TargetIsSelfSignedTrustAnchor) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(e_by_e_, &trust_store);
  // This is not necessary for the test, just an extra...
  AddTrustedCertificate(f_by_e_, &trust_store);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(e_by_e_, &trust_store, &signature_policy_, time_,
                               &result);

  path_builder.Run();

  ASSERT_TRUE(result.HasValidPath());
  const auto& path = result.GetBestValidPath()->path;
  ASSERT_EQ(1U, path.certs.size());
  EXPECT_EQ(e_by_e_, path.certs[0]);
  EXPECT_EQ(e_by_e_, path.trust_anchor->cert());
}

// If the target cert is directly issued by a trust anchor, it should verify
// without any intermediate certs being provided.
TEST_F(PathBuilderMultiRootTest, TargetDirectlySignedByTrustAnchor) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(b_by_f_, &trust_store);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);

  path_builder.Run();

  ASSERT_TRUE(result.HasValidPath());
  const auto& path = result.GetBestValidPath()->path;
  ASSERT_EQ(1U, path.certs.size());
  EXPECT_EQ(a_by_b_, path.certs[0]);
  EXPECT_EQ(b_by_f_, path.trust_anchor->cert());
}

// Test that async cert queries are not made if the path can be successfully
// built with synchronously available certs.
TEST_F(PathBuilderMultiRootTest, TriesSyncFirst) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(e_by_e_, &trust_store);

  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(b_by_f_);
  sync_certs.AddCert(f_by_e_);

  AsyncCertIssuerSourceStatic async_certs;
  async_certs.AddCert(b_by_c_);
  async_certs.AddCert(c_by_e_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&async_certs);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());
  EXPECT_EQ(0, async_certs.num_async_gets());
}

// If async queries are needed, all async sources will be queried
// simultaneously.
TEST_F(PathBuilderMultiRootTest, TestAsyncSimultaneous) {
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(e_by_e_, &trust_store);

  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(b_by_c_);
  sync_certs.AddCert(b_by_f_);

  AsyncCertIssuerSourceStatic async_certs1;
  async_certs1.AddCert(c_by_e_);

  AsyncCertIssuerSourceStatic async_certs2;
  async_certs2.AddCert(f_by_e_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&async_certs1);
  path_builder.AddCertIssuerSource(&async_certs2);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());
  EXPECT_EQ(1, async_certs1.num_async_gets());
  EXPECT_EQ(1, async_certs2.num_async_gets());
}

// Test that PathBuilder does not generate longer paths than necessary if one of
// the supplied certs is itself a trust anchor.
TEST_F(PathBuilderMultiRootTest, TestLongChain) {
  // Both D(D) and C(D) are trusted roots.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(d_by_d_, &trust_store);
  AddTrustedCertificate(c_by_d_, &trust_store);

  // Certs B(C), and C(D) are all supplied.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(b_by_c_);
  sync_certs.AddCert(c_by_d_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  ASSERT_TRUE(result.HasValidPath());

  // The result path should be A(B) <- B(C) <- C(D)
  // not the longer but also valid A(B) <- B(C) <- C(D) <- D(D)
  EXPECT_EQ(2U, result.GetBestValidPath()->path.certs.size());
}

// Test that PathBuilder will backtrack and try a different path if the first
// one doesn't work out.
TEST_F(PathBuilderMultiRootTest, TestBacktracking) {
  // Only D(D) is a trusted root.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(d_by_d_, &trust_store);

  // Certs B(F) and F(E) are supplied synchronously, thus the path
  // A(B) <- B(F) <- F(E) should be built first, though it won't verify.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(b_by_f_);
  sync_certs.AddCert(f_by_e_);

  // Certs B(C), and C(D) are supplied asynchronously, so the path
  // A(B) <- B(C) <- C(D) <- D(D) should be tried second.
  AsyncCertIssuerSourceStatic async_certs;
  async_certs.AddCert(b_by_c_);
  async_certs.AddCert(c_by_d_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs);
  path_builder.AddCertIssuerSource(&async_certs);

  path_builder.Run();

  ASSERT_TRUE(result.HasValidPath());

  // The result path should be A(B) <- B(C) <- C(D) <- D(D)
  const auto& path = result.GetBestValidPath()->path;
  ASSERT_EQ(3U, path.certs.size());
  EXPECT_EQ(a_by_b_, path.certs[0]);
  EXPECT_EQ(b_by_c_, path.certs[1]);
  EXPECT_EQ(c_by_d_, path.certs[2]);
  EXPECT_EQ(d_by_d_, path.trust_anchor->cert());
}

// Test that whichever order CertIssuerSource returns the issuers, the path
// building still succeeds.
TEST_F(PathBuilderMultiRootTest, TestCertIssuerOrdering) {
  // Only D(D) is a trusted root.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(d_by_d_, &trust_store);

  for (bool reverse_order : {false, true}) {
    SCOPED_TRACE(reverse_order);
    std::vector<scoped_refptr<ParsedCertificate>> certs = {
        b_by_c_, b_by_f_, f_by_e_, c_by_d_, c_by_e_};
    CertIssuerSourceStatic sync_certs;
    if (reverse_order) {
      for (auto it = certs.rbegin(); it != certs.rend(); ++it)
        sync_certs.AddCert(*it);
    } else {
      for (const auto& cert : certs)
        sync_certs.AddCert(cert);
    }

    CertPathBuilder::Result result;
    CertPathBuilder path_builder(a_by_b_, &trust_store, &signature_policy_,
                                 time_, &result);
    path_builder.AddCertIssuerSource(&sync_certs);

    path_builder.Run();

    ASSERT_TRUE(result.HasValidPath());

    // The result path should be A(B) <- B(C) <- C(D) <- D(D)
    const auto& path = result.GetBestValidPath()->path;
    ASSERT_EQ(3U, path.certs.size());
    EXPECT_EQ(a_by_b_, path.certs[0]);
    EXPECT_EQ(b_by_c_, path.certs[1]);
    EXPECT_EQ(c_by_d_, path.certs[2]);
    EXPECT_EQ(d_by_d_, path.trust_anchor->cert());
  }
}

class PathBuilderKeyRolloverTest : public ::testing::Test {
 public:
  PathBuilderKeyRolloverTest() : signature_policy_(1024) {}

  void SetUp() override {
    ParsedCertificateList path;
    bool unused_result;
    std::string unused_errors;

    ReadVerifyCertChainTestFromFile(
        "net/data/verify_certificate_chain_unittest/key-rollover-oldchain.pem",
        &path, &oldroot_, &time_, &unused_result, &unused_errors);
    ASSERT_EQ(2U, path.size());
    target_ = path[0];
    oldintermediate_ = path[1];
    ASSERT_TRUE(target_);
    ASSERT_TRUE(oldintermediate_);

    ReadVerifyCertChainTestFromFile(
        "net/data/verify_certificate_chain_unittest/"
        "key-rollover-longrolloverchain.pem",
        &path, &oldroot_, &time_, &unused_result, &unused_errors);
    ASSERT_EQ(4U, path.size());
    newintermediate_ = path[1];
    newroot_ = path[2];
    newrootrollover_ = path[3];
    ASSERT_TRUE(newintermediate_);
    ASSERT_TRUE(newroot_);
    ASSERT_TRUE(newrootrollover_);
  }

 protected:
  //    oldroot-------->newrootrollover  newroot
  //       |                      |        |
  //       v                      v        v
  // oldintermediate           newintermediate
  //       |                          |
  //       +------------+-------------+
  //                    |
  //                    v
  //                  target
  scoped_refptr<ParsedCertificate> target_;
  scoped_refptr<ParsedCertificate> oldintermediate_;
  scoped_refptr<ParsedCertificate> newintermediate_;
  scoped_refptr<TrustAnchor> oldroot_;
  scoped_refptr<ParsedCertificate> newroot_;
  scoped_refptr<ParsedCertificate> newrootrollover_;

  SimpleSignaturePolicy signature_policy_;
  der::GeneralizedTime time_;
};

// Tests that if only the old root cert is trusted, the path builder can build a
// path through the new intermediate and rollover cert to the old root.
TEST_F(PathBuilderKeyRolloverTest, TestRolloverOnlyOldRootTrusted) {
  // Only oldroot is trusted.
  TrustStoreInMemory trust_store;
  trust_store.AddTrustAnchor(oldroot_);

  // Old intermediate cert is not provided, so the pathbuilder will need to go
  // through the rollover cert.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(newintermediate_);
  sync_certs.AddCert(newrootrollover_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());

  // Path builder will first attempt: target <- newintermediate <- oldroot
  // but it will fail since newintermediate is signed by newroot.
  ASSERT_EQ(2U, result.paths.size());
  const auto& path0 = result.paths[0]->path;
  EXPECT_FALSE(result.paths[0]->valid);
  ASSERT_EQ(2U, path0.certs.size());
  EXPECT_EQ(target_, path0.certs[0]);
  EXPECT_EQ(newintermediate_, path0.certs[1]);
  EXPECT_EQ(oldroot_, path0.trust_anchor);

  // Path builder will next attempt:
  // target <- newintermediate <- newrootrollover <- oldroot
  // which will succeed.
  const auto& path1 = result.paths[1]->path;
  EXPECT_EQ(1U, result.best_result_index);
  EXPECT_TRUE(result.paths[1]->valid);
  ASSERT_EQ(3U, path1.certs.size());
  EXPECT_EQ(target_, path1.certs[0]);
  EXPECT_EQ(newintermediate_, path1.certs[1]);
  EXPECT_EQ(newrootrollover_, path1.certs[2]);
  EXPECT_EQ(oldroot_, path1.trust_anchor);
}

// Tests that if both old and new roots are trusted it can build a path through
// either.
// TODO(mattm): Once prioritization is implemented, it should test that it
// always builds the path through the new intermediate and new root.
TEST_F(PathBuilderKeyRolloverTest, TestRolloverBothRootsTrusted) {
  // Both oldroot and newroot are trusted.
  TrustStoreInMemory trust_store;
  trust_store.AddTrustAnchor(oldroot_);
  AddTrustedCertificate(newroot_, &trust_store);

  // Both old and new intermediates + rollover cert are provided.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(oldintermediate_);
  sync_certs.AddCert(newintermediate_);
  sync_certs.AddCert(newrootrollover_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());

  // Path builder willattempt one of:
  // target <- oldintermediate <- oldroot
  // target <- newintermediate <- newroot
  // either will succeed.
  ASSERT_EQ(1U, result.paths.size());
  const auto& path = result.paths[0]->path;
  EXPECT_TRUE(result.paths[0]->valid);
  ASSERT_EQ(2U, path.certs.size());
  EXPECT_EQ(target_, path.certs[0]);
  if (path.certs[1] != newintermediate_) {
    DVLOG(1) << "USED OLD";
    EXPECT_EQ(oldintermediate_, path.certs[1]);
    EXPECT_EQ(oldroot_, path.trust_anchor);
  } else {
    DVLOG(1) << "USED NEW";
    EXPECT_EQ(newintermediate_, path.certs[1]);
    EXPECT_EQ(newroot_, path.trust_anchor->cert());
  }
}

// If trust anchor query returned no results, and there are no issuer
// sources, path building should fail at that point.
TEST_F(PathBuilderKeyRolloverTest, TestAnchorsNoMatchAndNoIssuerSources) {
  TrustStoreInMemory trust_store;
  trust_store.AddTrustAnchor(
      TrustAnchor::CreateFromCertificateNoConstraints(newroot_));

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);

  path_builder.Run();

  EXPECT_FALSE(result.HasValidPath());

  ASSERT_EQ(0U, result.paths.size());
}

// Tests that multiple trust root matches on a single path will be considered.
// Both roots have the same subject but different keys. Only one of them will
// verify.
TEST_F(PathBuilderKeyRolloverTest, TestMultipleRootMatchesOnlyOneWorks) {
  TrustStoreCollection trust_store_collection;
  TrustStoreInMemory trust_store1;
  TrustStoreInMemory trust_store2;
  trust_store_collection.AddTrustStore(&trust_store1);
  trust_store_collection.AddTrustStore(&trust_store2);
  // Add two trust anchors (newroot_ and oldroot_). Path building will attempt
  // them in this same order, as trust_store1 was added to
  // trust_store_collection first.
  trust_store1.AddTrustAnchor(
      TrustAnchor::CreateFromCertificateNoConstraints(newroot_));
  trust_store2.AddTrustAnchor(oldroot_);

  // Only oldintermediate is supplied, so the path with newroot should fail,
  // oldroot should succeed.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(oldintermediate_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store_collection,
                               &signature_policy_, time_, &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());
  ASSERT_EQ(2U, result.paths.size());

  {
    // Path builder may first attempt: target <- oldintermediate <- newroot
    // but it will fail since oldintermediate is signed by oldroot.
    EXPECT_FALSE(result.paths[0]->valid);
    const auto& path = result.paths[0]->path;
    ASSERT_EQ(2U, path.certs.size());
    EXPECT_EQ(target_, path.certs[0]);
    EXPECT_EQ(oldintermediate_, path.certs[1]);
    EXPECT_EQ(newroot_, path.trust_anchor->cert());
  }

  {
    // Path builder will next attempt:
    // target <- old intermediate <- oldroot
    // which should succeed.
    EXPECT_TRUE(result.paths[result.best_result_index]->valid);
    const auto& path = result.paths[result.best_result_index]->path;
    ASSERT_EQ(2U, path.certs.size());
    EXPECT_EQ(target_, path.certs[0]);
    EXPECT_EQ(oldintermediate_, path.certs[1]);
    EXPECT_EQ(oldroot_, path.trust_anchor);
  }
}

// Tests that the path builder doesn't build longer than necessary paths.
TEST_F(PathBuilderKeyRolloverTest, TestRolloverLongChain) {
  // Only oldroot is trusted.
  TrustStoreInMemory trust_store;
  trust_store.AddTrustAnchor(oldroot_);

  // New intermediate and new root are provided synchronously.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(newintermediate_);
  sync_certs.AddCert(newroot_);

  // Rollover cert is only provided asynchronously. This will force the
  // pathbuilder to first try building a longer than necessary path.
  AsyncCertIssuerSourceStatic async_certs;
  async_certs.AddCert(newrootrollover_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs);
  path_builder.AddCertIssuerSource(&async_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());
  ASSERT_EQ(3U, result.paths.size());

  // Path builder will first attempt: target <- newintermediate <- oldroot
  // but it will fail since newintermediate is signed by newroot.
  EXPECT_FALSE(result.paths[0]->valid);
  const auto& path0 = result.paths[0]->path;
  ASSERT_EQ(2U, path0.certs.size());
  EXPECT_EQ(target_, path0.certs[0]);
  EXPECT_EQ(newintermediate_, path0.certs[1]);
  EXPECT_EQ(oldroot_, path0.trust_anchor);

  // Path builder will next attempt:
  // target <- newintermediate <- newroot <- oldroot
  // but it will fail since newroot is self-signed.
  EXPECT_FALSE(result.paths[1]->valid);
  const auto& path1 = result.paths[1]->path;
  ASSERT_EQ(3U, path1.certs.size());
  EXPECT_EQ(target_, path1.certs[0]);
  EXPECT_EQ(newintermediate_, path1.certs[1]);
  EXPECT_EQ(newroot_, path1.certs[2]);
  EXPECT_EQ(oldroot_, path1.trust_anchor);

  // Path builder will skip:
  // target <- newintermediate <- newroot <- newrootrollover <- ...
  // Since newroot and newrootrollover have the same Name+SAN+SPKI.

  // Finally path builder will use:
  // target <- newintermediate <- newrootrollover <- oldroot
  EXPECT_EQ(2U, result.best_result_index);
  EXPECT_TRUE(result.paths[2]->valid);
  const auto& path2 = result.paths[2]->path;
  ASSERT_EQ(3U, path2.certs.size());
  EXPECT_EQ(target_, path2.certs[0]);
  EXPECT_EQ(newintermediate_, path2.certs[1]);
  EXPECT_EQ(newrootrollover_, path2.certs[2]);
  EXPECT_EQ(oldroot_, path2.trust_anchor);
}

// If the target cert is a trust anchor, however is not itself *signed* by a
// trust anchor, then it is not considered valid (the SPKI and name of the
// trust anchor matches the SPKI and subject of the targe certificate, but the
// rest of the certificate cannot be verified).
TEST_F(PathBuilderKeyRolloverTest, TestEndEntityIsTrustRoot) {
  // Trust newintermediate.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(newintermediate_, &trust_store);

  CertPathBuilder::Result result;
  // Newintermediate is also the target cert.
  CertPathBuilder path_builder(newintermediate_, &trust_store,
                               &signature_policy_, time_, &result);

  path_builder.Run();

  EXPECT_FALSE(result.HasValidPath());
}

// If target has same Name+SAN+SPKI as a necessary intermediate, test if a path
// can still be built.
// Since LoopChecker will prevent the intermediate from being included, this
// currently does NOT verify. This case shouldn't occur in the web PKI.
TEST_F(PathBuilderKeyRolloverTest,
       TestEndEntityHasSameNameAndSpkiAsIntermediate) {
  // Trust oldroot.
  TrustStoreInMemory trust_store;
  trust_store.AddTrustAnchor(oldroot_);

  // New root rollover is provided synchronously.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(newrootrollover_);

  CertPathBuilder::Result result;
  // Newroot is the target cert.
  CertPathBuilder path_builder(newroot_, &trust_store, &signature_policy_,
                               time_, &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  // This could actually be OK, but CertPathBuilder does not build the
  // newroot <- newrootrollover <- oldroot path.
  EXPECT_FALSE(result.HasValidPath());
}

// If target has same Name+SAN+SPKI as the trust root, test that a (trivial)
// path can still be built.
TEST_F(PathBuilderKeyRolloverTest,
       TestEndEntityHasSameNameAndSpkiAsTrustAnchor) {
  // Trust newrootrollover.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(newrootrollover_, &trust_store);

  CertPathBuilder::Result result;
  // Newroot is the target cert.
  CertPathBuilder path_builder(newroot_, &trust_store, &signature_policy_,
                               time_, &result);

  path_builder.Run();

  ASSERT_TRUE(result.HasValidPath());

  const CertPathBuilder::ResultPath* best_result = result.GetBestValidPath();

  // Newroot has same name+SPKI as newrootrollover, thus the path is valid and
  // only contains newroot.
  EXPECT_TRUE(best_result->valid);
  ASSERT_EQ(1U, best_result->path.certs.size());
  EXPECT_EQ(newroot_, best_result->path.certs[0]);
  EXPECT_EQ(newrootrollover_, best_result->path.trust_anchor->cert());
}

// Test that PathBuilder will not try the same path twice if multiple
// CertIssuerSources provide the same certificate.
TEST_F(PathBuilderKeyRolloverTest, TestDuplicateIntermediates) {
  // Create a separate copy of oldintermediate.
  scoped_refptr<ParsedCertificate> oldintermediate_dupe(
      ParsedCertificate::Create(
          bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(
              oldintermediate_->der_cert().UnsafeData(),
              oldintermediate_->der_cert().Length(), nullptr)),
          {}, nullptr));

  // Only newroot is a trusted root.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(newroot_, &trust_store);

  // The oldintermediate is supplied synchronously by |sync_certs1| and
  // another copy of oldintermediate is supplied synchronously by |sync_certs2|.
  // The path target <- oldintermediate <- newroot  should be built first,
  // though it won't verify. It should not be attempted again even though
  // oldintermediate was supplied twice.
  CertIssuerSourceStatic sync_certs1;
  sync_certs1.AddCert(oldintermediate_);
  CertIssuerSourceStatic sync_certs2;
  sync_certs2.AddCert(oldintermediate_dupe);

  // The newintermediate is supplied asynchronously, so the path
  // target <- newintermediate <- newroot should be tried second.
  AsyncCertIssuerSourceStatic async_certs;
  async_certs.AddCert(newintermediate_);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs1);
  path_builder.AddCertIssuerSource(&sync_certs2);
  path_builder.AddCertIssuerSource(&async_certs);

  path_builder.Run();

  EXPECT_TRUE(result.HasValidPath());
  ASSERT_EQ(2U, result.paths.size());

  // Path builder will first attempt: target <- oldintermediate <- newroot
  // but it will fail since oldintermediate is signed by oldroot.
  EXPECT_FALSE(result.paths[0]->valid);
  const auto& path0 = result.paths[0]->path;

  ASSERT_EQ(2U, path0.certs.size());
  EXPECT_EQ(target_, path0.certs[0]);
  // Compare the DER instead of ParsedCertificate pointer, don't care which copy
  // of oldintermediate was used in the path.
  EXPECT_EQ(oldintermediate_->der_cert(), path0.certs[1]->der_cert());
  EXPECT_EQ(newroot_, path0.trust_anchor->cert());

  // Path builder will next attempt: target <- newintermediate <- newroot
  // which will succeed.
  EXPECT_EQ(1U, result.best_result_index);
  EXPECT_TRUE(result.paths[1]->valid);
  const auto& path1 = result.paths[1]->path;
  ASSERT_EQ(2U, path1.certs.size());
  EXPECT_EQ(target_, path1.certs[0]);
  EXPECT_EQ(newintermediate_, path1.certs[1]);
  EXPECT_EQ(newroot_, path1.trust_anchor->cert());
}

// Test when PathBuilder is given a cert CertIssuerSources that has the same
// SPKI as a TrustAnchor.
TEST_F(PathBuilderKeyRolloverTest, TestDuplicateIntermediateAndRoot) {
  // Create a separate copy of newroot.
  scoped_refptr<ParsedCertificate> newroot_dupe(ParsedCertificate::Create(
      bssl::UniquePtr<CRYPTO_BUFFER>(
          CRYPTO_BUFFER_new(newroot_->der_cert().UnsafeData(),
                            newroot_->der_cert().Length(), nullptr)),
      {}, nullptr));

  // Only newroot is a trusted root.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(newroot_, &trust_store);

  // The oldintermediate and newroot are supplied synchronously by |sync_certs|.
  CertIssuerSourceStatic sync_certs;
  sync_certs.AddCert(oldintermediate_);
  sync_certs.AddCert(newroot_dupe);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&sync_certs);

  path_builder.Run();

  EXPECT_FALSE(result.HasValidPath());
  ASSERT_EQ(2U, result.paths.size());
  // TODO(eroman): Is this right?

  // Path builder attempt: target <- oldintermediate <- newroot
  // but it will fail since oldintermediate is signed by oldroot.
  EXPECT_FALSE(result.paths[0]->valid);
  const auto& path = result.paths[0]->path;
  ASSERT_EQ(2U, path.certs.size());
  EXPECT_EQ(target_, path.certs[0]);
  EXPECT_EQ(oldintermediate_, path.certs[1]);
  // Compare the DER instead of ParsedCertificate pointer, don't care which copy
  // of newroot was used in the path.
  EXPECT_EQ(newroot_->der_cert(), path.trust_anchor->cert()->der_cert());
}

class MockCertIssuerSourceRequest : public CertIssuerSource::Request {
 public:
  MOCK_METHOD1(GetNext, void(ParsedCertificateList*));
};

class MockCertIssuerSource : public CertIssuerSource {
 public:
  MOCK_METHOD2(SyncGetIssuersOf,
               void(const ParsedCertificate*, ParsedCertificateList*));
  MOCK_METHOD2(AsyncGetIssuersOf,
               void(const ParsedCertificate*, std::unique_ptr<Request>*));
};

// Helper class to pass the Request to the PathBuilder when it calls
// AsyncGetIssuersOf. (GoogleMock has a ByMove helper, but it apparently can
// only be used with Return, not SetArgPointee.)
class CertIssuerSourceRequestMover {
 public:
  CertIssuerSourceRequestMover(std::unique_ptr<CertIssuerSource::Request> req)
      : request_(std::move(req)) {}
  void MoveIt(const ParsedCertificate* cert,
              std::unique_ptr<CertIssuerSource::Request>* out_req) {
    *out_req = std::move(request_);
  }

 private:
  std::unique_ptr<CertIssuerSource::Request> request_;
};

// Functor that when called with a ParsedCertificateList* will append the
// specified certificate.
class AppendCertToList {
 public:
  explicit AppendCertToList(const scoped_refptr<ParsedCertificate>& cert)
      : cert_(cert) {}

  void operator()(ParsedCertificateList* out) { out->push_back(cert_); }

 private:
  scoped_refptr<ParsedCertificate> cert_;
};

// Test that a single CertIssuerSource returning multiple async batches of
// issuers is handled correctly. Due to the StrictMocks, it also tests that path
// builder does not request issuers of certs that it shouldn't.
TEST_F(PathBuilderKeyRolloverTest, TestMultipleAsyncIssuersFromSingleSource) {
  StrictMock<MockCertIssuerSource> cert_issuer_source;

  // Only newroot is a trusted root.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(newroot_, &trust_store);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&cert_issuer_source);

  // Create the mock CertIssuerSource::Request...
  std::unique_ptr<StrictMock<MockCertIssuerSourceRequest>>
      target_issuers_req_owner(new StrictMock<MockCertIssuerSourceRequest>());
  // Keep a raw pointer to the Request...
  StrictMock<MockCertIssuerSourceRequest>* target_issuers_req =
      target_issuers_req_owner.get();
  // Setup helper class to pass ownership of the Request to the PathBuilder when
  // it calls AsyncGetIssuersOf.
  CertIssuerSourceRequestMover req_mover(std::move(target_issuers_req_owner));
  {
    ::testing::InSequence s;
    EXPECT_CALL(cert_issuer_source, SyncGetIssuersOf(target_.get(), _));
    EXPECT_CALL(cert_issuer_source, AsyncGetIssuersOf(target_.get(), _))
        .WillOnce(Invoke(&req_mover, &CertIssuerSourceRequestMover::MoveIt));
  }

  EXPECT_CALL(*target_issuers_req, GetNext(_))
      // First async batch: return oldintermediate_.
      .WillOnce(Invoke(AppendCertToList(oldintermediate_)))
      // Second async batch: return newintermediate_.
      .WillOnce(Invoke(AppendCertToList(newintermediate_)));
  {
    ::testing::InSequence s;
    // oldintermediate_ does not create a valid path, so both sync and async
    // lookups are expected.
    EXPECT_CALL(cert_issuer_source,
                SyncGetIssuersOf(oldintermediate_.get(), _));
    EXPECT_CALL(cert_issuer_source,
                AsyncGetIssuersOf(oldintermediate_.get(), _));
  }

  // newroot_ is in the trust store, so this path will be completed
  // synchronously. AsyncGetIssuersOf will not be called on newintermediate_.
  EXPECT_CALL(cert_issuer_source, SyncGetIssuersOf(newintermediate_.get(), _));

  // Ensure pathbuilder finished and filled result.
  path_builder.Run();

  // Note that VerifyAndClearExpectations(target_issuers_req) is not called
  // here. PathBuilder could have destroyed it already, so just let the
  // expectations get checked by the destructor.
  ::testing::Mock::VerifyAndClearExpectations(&cert_issuer_source);

  EXPECT_TRUE(result.HasValidPath());
  ASSERT_EQ(2U, result.paths.size());

  // Path builder first attempts: target <- oldintermediate <- newroot
  // but it will fail since oldintermediate is signed by oldroot.
  EXPECT_FALSE(result.paths[0]->valid);
  const auto& path0 = result.paths[0]->path;
  ASSERT_EQ(2U, path0.certs.size());
  EXPECT_EQ(target_, path0.certs[0]);
  EXPECT_EQ(oldintermediate_, path0.certs[1]);
  EXPECT_EQ(newroot_, path0.trust_anchor->cert());

  // After the second batch of async results, path builder will attempt:
  // target <- newintermediate <- newroot which will succeed.
  EXPECT_TRUE(result.paths[1]->valid);
  const auto& path1 = result.paths[1]->path;
  ASSERT_EQ(2U, path1.certs.size());
  EXPECT_EQ(target_, path1.certs[0]);
  EXPECT_EQ(newintermediate_, path1.certs[1]);
  EXPECT_EQ(newroot_, path1.trust_anchor->cert());
}

// Test that PathBuilder will not try the same path twice if CertIssuerSources
// asynchronously provide the same certificate multiple times.
TEST_F(PathBuilderKeyRolloverTest, TestDuplicateAsyncIntermediates) {
  StrictMock<MockCertIssuerSource> cert_issuer_source;

  // Only newroot is a trusted root.
  TrustStoreInMemory trust_store;
  AddTrustedCertificate(newroot_, &trust_store);

  CertPathBuilder::Result result;
  CertPathBuilder path_builder(target_, &trust_store, &signature_policy_, time_,
                               &result);
  path_builder.AddCertIssuerSource(&cert_issuer_source);

  // Create the mock CertIssuerSource::Request...
  std::unique_ptr<StrictMock<MockCertIssuerSourceRequest>>
      target_issuers_req_owner(new StrictMock<MockCertIssuerSourceRequest>());
  // Keep a raw pointer to the Request...
  StrictMock<MockCertIssuerSourceRequest>* target_issuers_req =
      target_issuers_req_owner.get();
  // Setup helper class to pass ownership of the Request to the PathBuilder when
  // it calls AsyncGetIssuersOf.
  CertIssuerSourceRequestMover req_mover(std::move(target_issuers_req_owner));
  {
    ::testing::InSequence s;
    EXPECT_CALL(cert_issuer_source, SyncGetIssuersOf(target_.get(), _));
    EXPECT_CALL(cert_issuer_source, AsyncGetIssuersOf(target_.get(), _))
        .WillOnce(Invoke(&req_mover, &CertIssuerSourceRequestMover::MoveIt));
  }

  scoped_refptr<ParsedCertificate> oldintermediate_dupe(
      ParsedCertificate::Create(
          bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(
              oldintermediate_->der_cert().UnsafeData(),
              oldintermediate_->der_cert().Length(), nullptr)),
          {}, nullptr));

  EXPECT_CALL(*target_issuers_req, GetNext(_))
      // First async batch: return oldintermediate_.
      .WillOnce(Invoke(AppendCertToList(oldintermediate_)))
      // Second async batch: return a different copy of oldintermediate_ again.
      .WillOnce(Invoke(AppendCertToList(oldintermediate_dupe)))
      // Third async batch: return newintermediate_.
      .WillOnce(Invoke(AppendCertToList(newintermediate_)));

  {
    ::testing::InSequence s;
    // oldintermediate_ does not create a valid path, so both sync and async
    // lookups are expected.
    EXPECT_CALL(cert_issuer_source,
                SyncGetIssuersOf(oldintermediate_.get(), _));
    EXPECT_CALL(cert_issuer_source,
                AsyncGetIssuersOf(oldintermediate_.get(), _));
  }

  // newroot_ is in the trust store, so this path will be completed
  // synchronously. AsyncGetIssuersOf will not be called on newintermediate_.
  EXPECT_CALL(cert_issuer_source, SyncGetIssuersOf(newintermediate_.get(), _));

  // Ensure pathbuilder finished and filled result.
  path_builder.Run();

  ::testing::Mock::VerifyAndClearExpectations(&cert_issuer_source);

  EXPECT_TRUE(result.HasValidPath());
  ASSERT_EQ(2U, result.paths.size());

  // Path builder first attempts: target <- oldintermediate <- newroot
  // but it will fail since oldintermediate is signed by oldroot.
  EXPECT_FALSE(result.paths[0]->valid);
  const auto& path0 = result.paths[0]->path;
  ASSERT_EQ(2U, path0.certs.size());
  EXPECT_EQ(target_, path0.certs[0]);
  EXPECT_EQ(oldintermediate_, path0.certs[1]);
  EXPECT_EQ(newroot_, path0.trust_anchor->cert());

  // The second async result does not generate any path.

  // After the third batch of async results, path builder will attempt:
  // target <- newintermediate <- newroot which will succeed.
  EXPECT_TRUE(result.paths[1]->valid);
  const auto& path1 = result.paths[1]->path;
  ASSERT_EQ(2U, path1.certs.size());
  EXPECT_EQ(target_, path1.certs[0]);
  EXPECT_EQ(newintermediate_, path1.certs[1]);
  EXPECT_EQ(newroot_, path1.trust_anchor->cert());
}

}  // namespace

}  // namespace net
