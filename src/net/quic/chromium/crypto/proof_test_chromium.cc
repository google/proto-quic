// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "base/files/file_path.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/quic/core/crypto/proof_source.h"
#include "net/quic/core/crypto/proof_verifier.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {
namespace {

// TestProofVerifierCallback is a simple callback for a ProofVerifier that
// signals a TestCompletionCallback when called and stores the results from the
// ProofVerifier in pointers passed to the constructor.
class TestProofVerifierCallback : public ProofVerifierCallback {
 public:
  TestProofVerifierCallback(TestCompletionCallback* comp_callback,
                            bool* ok,
                            string* error_details)
      : comp_callback_(comp_callback), ok_(ok), error_details_(error_details) {}

  void Run(bool ok,
           const string& error_details,
           std::unique_ptr<ProofVerifyDetails>* details) override {
    *ok_ = ok;
    *error_details_ = error_details;

    comp_callback_->callback().Run(0);
  }

 private:
  TestCompletionCallback* const comp_callback_;
  bool* const ok_;
  string* const error_details_;
};

// RunVerification runs |verifier->VerifyProof| and asserts that the result
// matches |expected_ok|.
void RunVerification(ProofVerifier* verifier,
                     const string& hostname,
                     const uint16_t port,
                     const string& server_config,
                     QuicVersion quic_version,
                     QuicStringPiece chlo_hash,
                     const std::vector<string>& certs,
                     const string& proof,
                     bool expected_ok) {
  std::unique_ptr<ProofVerifyDetails> details;
  TestCompletionCallback comp_callback;
  bool ok;
  string error_details;
  std::unique_ptr<ProofVerifyContext> verify_context(
      crypto_test_utils::ProofVerifyContextForTesting());
  std::unique_ptr<TestProofVerifierCallback> callback(
      new TestProofVerifierCallback(&comp_callback, &ok, &error_details));

  QuicAsyncStatus status = verifier->VerifyProof(
      hostname, port, server_config, quic_version, chlo_hash, certs, "", proof,
      verify_context.get(), &error_details, &details, std::move(callback));

  switch (status) {
    case QUIC_FAILURE:
      ASSERT_FALSE(expected_ok);
      ASSERT_NE("", error_details);
      return;
    case QUIC_SUCCESS:
      ASSERT_TRUE(expected_ok);
      ASSERT_EQ("", error_details);
      return;
    case QUIC_PENDING:
      comp_callback.WaitForResult();
      ASSERT_EQ(expected_ok, ok);
      break;
  }
}

class TestCallback : public ProofSource::Callback {
 public:
  explicit TestCallback(bool* called,
                        bool* ok,
                        QuicReferenceCountedPointer<ProofSource::Chain>* chain,
                        QuicCryptoProof* proof)
      : called_(called), ok_(ok), chain_(chain), proof_(proof) {}

  void Run(bool ok,
           const QuicReferenceCountedPointer<ProofSource::Chain>& chain,
           const QuicCryptoProof& proof,
           std::unique_ptr<ProofSource::Details> /* details */) override {
    *ok_ = ok;
    *chain_ = chain;
    *proof_ = proof;
    *called_ = true;
  }

 private:
  bool* called_;
  bool* ok_;
  QuicReferenceCountedPointer<ProofSource::Chain>* chain_;
  QuicCryptoProof* proof_;
};

class ProofTest : public ::testing::TestWithParam<QuicVersion> {};

}  // namespace

INSTANTIATE_TEST_CASE_P(QuicVersion,
                        ProofTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

// TODO(rtenneti): Enable testing of ProofVerifier. See http://crbug.com/514468.
TEST_P(ProofTest, DISABLED_Verify) {
  std::unique_ptr<ProofSource> source(
      crypto_test_utils::ProofSourceForTesting());
  std::unique_ptr<ProofVerifier> verifier(
      crypto_test_utils::ProofVerifierForTesting());

  const string server_config = "server config bytes";
  const string hostname = "test.example.com";
  const uint16_t port = 8443;
  const string first_chlo_hash = "first chlo hash bytes";
  const string second_chlo_hash = "first chlo hash bytes";
  const QuicVersion quic_version = GetParam();

  bool called = false;
  bool first_called = false;
  bool ok, first_ok;
  QuicReferenceCountedPointer<ProofSource::Chain> chain;
  QuicReferenceCountedPointer<ProofSource::Chain> first_chain;
  string error_details;
  QuicCryptoProof proof, first_proof;
  QuicSocketAddress server_addr;

  std::unique_ptr<ProofSource::Callback> cb(
      new TestCallback(&called, &ok, &chain, &proof));
  std::unique_ptr<ProofSource::Callback> first_cb(
      new TestCallback(&first_called, &first_ok, &first_chain, &first_proof));

  // GetProof here expects the async method to invoke the callback
  // synchronously.
  source->GetProof(server_addr, hostname, server_config, quic_version,
                   first_chlo_hash, QuicTagVector(), std::move(first_cb));
  source->GetProof(server_addr, hostname, server_config, quic_version,
                   second_chlo_hash, QuicTagVector(), std::move(cb));
  ASSERT_TRUE(called);
  ASSERT_TRUE(first_called);
  ASSERT_TRUE(ok);
  ASSERT_TRUE(first_ok);

  // Check that the proof source is caching correctly:
  ASSERT_EQ(first_chain->certs, chain->certs);
  ASSERT_NE(proof.signature, first_proof.signature);
  ASSERT_EQ(first_proof.leaf_cert_scts, proof.leaf_cert_scts);

  RunVerification(verifier.get(), hostname, port, server_config, quic_version,
                  first_chlo_hash, chain->certs, proof.signature, true);

  RunVerification(verifier.get(), "foo.com", port, server_config, quic_version,
                  first_chlo_hash, chain->certs, proof.signature, false);

  RunVerification(verifier.get(), server_config.substr(1, string::npos), port,
                  server_config, quic_version, first_chlo_hash, chain->certs,
                  proof.signature, false);

  const string corrupt_signature = "1" + proof.signature;
  RunVerification(verifier.get(), hostname, port, server_config, quic_version,
                  first_chlo_hash, chain->certs, corrupt_signature, false);

  std::vector<string> wrong_certs;
  for (size_t i = 1; i < chain->certs.size(); i++) {
    wrong_certs.push_back(chain->certs[i]);
  }

  RunVerification(verifier.get(), "foo.com", port, server_config, quic_version,
                  first_chlo_hash, wrong_certs, corrupt_signature, false);
}

TEST_P(ProofTest, UseAfterFree) {
  std::unique_ptr<ProofSource> source(
      crypto_test_utils::ProofSourceForTesting());

  const string server_config = "server config bytes";
  const string hostname = "test.example.com";
  const string chlo_hash = "proof nonce bytes";
  bool called = false;
  bool ok;
  QuicReferenceCountedPointer<ProofSource::Chain> chain;
  string error_details;
  QuicCryptoProof proof;
  QuicSocketAddress server_addr;
  std::unique_ptr<ProofSource::Callback> cb(
      new TestCallback(&called, &ok, &chain, &proof));

  // GetProof here expects the async method to invoke the callback
  // synchronously.
  source->GetProof(server_addr, hostname, server_config, GetParam(), chlo_hash,
                   QuicTagVector(), std::move(cb));
  ASSERT_TRUE(called);
  ASSERT_TRUE(ok);

  // Make sure we can safely access results after deleting where they came from.
  EXPECT_FALSE(chain->HasOneRef());
  source = nullptr;
  EXPECT_TRUE(chain->HasOneRef());

  EXPECT_FALSE(chain->certs.empty());
  for (const string& cert : chain->certs) {
    EXPECT_FALSE(cert.empty());
  }
}

}  // namespace test
}  // namespace net
