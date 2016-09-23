// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_log_verifier.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "crypto/secure_hash.h"
#include "net/base/hash_value.h"
#include "net/cert/ct_log_verifier_util.h"
#include "net/cert/merkle_consistency_proof.h"
#include "net/cert/signed_certificate_timestamp.h"
#include "net/cert/signed_tree_head.h"
#include "net/test/ct_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Calculate the power of two nearest to, but less than, |n|.
// |n| must be at least 2.
uint64_t CalculateNearestPowerOfTwo(uint64_t n) {
  DCHECK_GT(n, 1u);

  uint64_t ret = UINT64_C(1) << 63;
  while (ret >= n)
    ret >>= 1;

  return ret;
}

// A single consistency proof. Contains the old and new tree sizes
// (snapshot1 and snapshot2), the length of the proof (proof_length) and
// at most 3 proof nodes (all test proofs will be for a tree of size 8).
struct ProofTestVector {
  uint64_t snapshot1;
  uint64_t snapshot2;
  size_t proof_length;
  const char* const proof[3];
};

// All test data replicated from
// https://github.com/google/certificate-transparency/blob/c41b090ecc14ddd6b3531dc7e5ce36b21e253fdd/cpp/merkletree/merkle_tree_test.cc
// A hash of the empty string.
const uint8_t kSHA256EmptyTreeHash[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

// Root hashes from building the sample tree of size 8 leaf-by-leaf.
// The first entry is the root at size 0, the last is the root at size 8.
const char* const kSHA256Roots[8] = {
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"};

// A collection of consistency proofs between various sub-trees of the tree
// defined by |kSHA256Roots|.
const ProofTestVector kSHA256Proofs[4] = {
    // Empty consistency proof between trees of the same size (1).
    {1, 1, 0, {"", "", ""}},
    // Consistency proof between tree of size 1 and tree of size 8, with 3
    // nodes in the proof.
    {1,
     8,
     3,
     {"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
      "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
      "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"}},
    // Consistency proof between tree of size 6 and tree of size 8, with 3
    // nodes in the proof.
    {6,
     8,
     3,
     {"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
      "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
      "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"}},
    // Consistency proof between tree of size 2 and tree of size 5, with 2
    // nodes in the proof.
    {2,
     5,
     2,
     {"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
      "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", ""}}};

// Decodes a hexadecimal string into the binary data it represents.
std::string HexToBytes(const std::string& hex_data) {
  std::vector<uint8_t> output;
  std::string result;
  if (base::HexStringToBytes(hex_data, &output))
    result.assign(output.begin(), output.end());
  return result;
}

std::string GetEmptyTreeHash() {
  return std::string(std::begin(kSHA256EmptyTreeHash),
                     std::end(kSHA256EmptyTreeHash));
}

// Creates a ct::MerkleConsistencyProof and returns the result of
// calling log->VerifyConsistencyProof with that proof and snapshots.
bool VerifyConsistencyProof(scoped_refptr<const CTLogVerifier> log,
                            uint64_t old_tree_size,
                            const std::string& old_tree_root,
                            uint64_t new_tree_size,
                            const std::string& new_tree_root,
                            const std::vector<std::string>& proof) {
  return log->VerifyConsistencyProof(
      ct::MerkleConsistencyProof(log->key_id(), proof, old_tree_size,
                                 new_tree_size),
      old_tree_root, new_tree_root);
}

class CTLogVerifierTest : public ::testing::Test {
 public:
  CTLogVerifierTest() {}

  void SetUp() override {
    log_ = CTLogVerifier::Create(ct::GetTestPublicKey(), "testlog",
                                 "https://ct.example.com", "ct.example.com");

    ASSERT_TRUE(log_);
    ASSERT_EQ(ct::GetTestPublicKeyId(), log_->key_id());
    ASSERT_EQ("ct.example.com", log_->dns_domain());
  }

  // Given a consistency proof between two snapshots of the tree, asserts that
  // it verifies and no other combination of snapshots and proof nodes verifies.
  void VerifierConsistencyCheck(int snapshot1,
                                int snapshot2,
                                const std::string& root1,
                                const std::string& root2,
                                const std::vector<std::string>& proof) {
    // Verify the original consistency proof.
    EXPECT_TRUE(
        VerifyConsistencyProof(log_, snapshot1, root1, snapshot2, root2, proof))
        << " " << snapshot1 << " " << snapshot2;

    if (proof.empty()) {
      // For simplicity test only non-trivial proofs that have root1 != root2
      // snapshot1 != 0 and snapshot1 != snapshot2.
      return;
    }

    // Wrong snapshot index: The proof checking code should not accept
    // as a valid proof a proof for a tree size different than the original
    // size it was produced for.
    // Test that this is not the case for off-by-one changes.
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1 - 1, root1, snapshot2,
                                        root2, proof));
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1 + 1, root1, snapshot2,
                                        root2, proof));
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1 ^ 2, root1, snapshot2,
                                        root2, proof));

    // Test that the proof is not accepted for trees with wrong tree height.
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2 * 2,
                                        root2, proof));
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2 / 2,
                                        root2, proof));

    // Test that providing the wrong input root fails checking an
    // otherwise-valid proof.
    const std::string wrong_root("WrongRoot");
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        wrong_root, proof));
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, wrong_root, snapshot2,
                                        root2, proof));
    // Test that swapping roots fails checking an otherwise-valid proof (that
    // the right root is used for each calculation).
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root2, snapshot2,
                                        root1, proof));

    // Variations of wrong proofs, all of which should be rejected.
    std::vector<std::string> wrong_proof;
    // Empty proof.
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        root2, wrong_proof));

    // Modify a single element in the proof.
    for (size_t j = 0; j < proof.size(); ++j) {
      wrong_proof = proof;
      wrong_proof[j] = GetEmptyTreeHash();
      EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                          root2, wrong_proof));
    }

    // Add garbage at the end of the proof.
    wrong_proof = proof;
    wrong_proof.push_back(std::string());
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        root2, wrong_proof));
    wrong_proof.pop_back();

    wrong_proof.push_back(proof.back());
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        root2, wrong_proof));
    wrong_proof.pop_back();

    // Remove a node from the end.
    wrong_proof.pop_back();
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        root2, wrong_proof));

    // Add garbage in the beginning of the proof.
    wrong_proof.clear();
    wrong_proof.push_back(std::string());
    wrong_proof.insert(wrong_proof.end(), proof.begin(), proof.end());
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        root2, wrong_proof));

    wrong_proof[0] = proof[0];
    EXPECT_FALSE(VerifyConsistencyProof(log_, snapshot1, root1, snapshot2,
                                        root2, wrong_proof));
  }

 protected:
  scoped_refptr<const CTLogVerifier> log_;
};

TEST_F(CTLogVerifierTest, VerifiesCertSCT) {
  ct::LogEntry cert_entry;
  ct::GetX509CertLogEntry(&cert_entry);

  scoped_refptr<ct::SignedCertificateTimestamp> cert_sct;
  ct::GetX509CertSCT(&cert_sct);

  EXPECT_TRUE(log_->Verify(cert_entry, *cert_sct.get()));
}

TEST_F(CTLogVerifierTest, VerifiesPrecertSCT) {
  ct::LogEntry precert_entry;
  ct::GetPrecertLogEntry(&precert_entry);

  scoped_refptr<ct::SignedCertificateTimestamp> precert_sct;
  ct::GetPrecertSCT(&precert_sct);

  EXPECT_TRUE(log_->Verify(precert_entry, *precert_sct.get()));
}

TEST_F(CTLogVerifierTest, FailsInvalidTimestamp) {
  ct::LogEntry cert_entry;
  ct::GetX509CertLogEntry(&cert_entry);

  scoped_refptr<ct::SignedCertificateTimestamp> cert_sct;
  ct::GetX509CertSCT(&cert_sct);

  // Mangle the timestamp, so that it should fail signature validation.
  cert_sct->timestamp = base::Time::Now();

  EXPECT_FALSE(log_->Verify(cert_entry, *cert_sct.get()));
}

TEST_F(CTLogVerifierTest, FailsInvalidLogID) {
  ct::LogEntry cert_entry;
  ct::GetX509CertLogEntry(&cert_entry);

  scoped_refptr<ct::SignedCertificateTimestamp> cert_sct;
  ct::GetX509CertSCT(&cert_sct);

  // Mangle the log ID, which should cause it to match a different log before
  // attempting signature validation.
  cert_sct->log_id.assign(cert_sct->log_id.size(), '\0');

  EXPECT_FALSE(log_->Verify(cert_entry, *cert_sct.get()));
}

TEST_F(CTLogVerifierTest, VerifiesValidSTH) {
  ct::SignedTreeHead sth;
  ASSERT_TRUE(ct::GetSampleSignedTreeHead(&sth));
  EXPECT_TRUE(log_->VerifySignedTreeHead(sth));
}

TEST_F(CTLogVerifierTest, DoesNotVerifyInvalidSTH) {
  ct::SignedTreeHead sth;
  ASSERT_TRUE(ct::GetSampleSignedTreeHead(&sth));
  sth.sha256_root_hash[0] = '\x0';
  EXPECT_FALSE(log_->VerifySignedTreeHead(sth));
}

TEST_F(CTLogVerifierTest, VerifiesValidEmptySTH) {
  ct::SignedTreeHead sth;
  ASSERT_TRUE(ct::GetSampleEmptySignedTreeHead(&sth));
  EXPECT_TRUE(log_->VerifySignedTreeHead(sth));
}

TEST_F(CTLogVerifierTest, DoesNotVerifyInvalidEmptySTH) {
  ct::SignedTreeHead sth;
  ASSERT_TRUE(ct::GetBadEmptySignedTreeHead(&sth));
  EXPECT_FALSE(log_->VerifySignedTreeHead(sth));
}

// Test that excess data after the public key is rejected.
TEST_F(CTLogVerifierTest, ExcessDataInPublicKey) {
  std::string key = ct::GetTestPublicKey();
  key += "extra";

  scoped_refptr<const CTLogVerifier> log = CTLogVerifier::Create(
      key, "testlog", "https://ct.example.com", "ct.example.com");
  EXPECT_FALSE(log);
}

TEST_F(CTLogVerifierTest, VerifiesConsistencyProofEdgeCases_EmptyProof) {
  std::vector<std::string> empty_proof;
  std::string root1(GetEmptyTreeHash()), root2(GetEmptyTreeHash());

  // Snapshots that are always consistent, because they are either
  // from an empty tree to a non-empty one or for trees of the same
  // size.
  EXPECT_TRUE(VerifyConsistencyProof(log_, 0, root1, 0, root2, empty_proof));
  EXPECT_TRUE(VerifyConsistencyProof(log_, 0, root1, 1, root2, empty_proof));
  EXPECT_TRUE(VerifyConsistencyProof(log_, 1, root1, 1, root2, empty_proof));

  // Invalid consistency proofs.
  // Time travel to the past.
  EXPECT_FALSE(VerifyConsistencyProof(log_, 1, root1, 0, root2, empty_proof));
  EXPECT_FALSE(VerifyConsistencyProof(log_, 2, root1, 1, root2, empty_proof));
  // Proof between two trees of different size can never be empty.
  EXPECT_FALSE(VerifyConsistencyProof(log_, 1, root1, 2, root2, empty_proof));
}

TEST_F(CTLogVerifierTest, VerifiesConsistencyProofEdgeCases_MismatchingRoots) {
  std::vector<std::string> empty_proof;
  std::string root2;
  const std::string empty_tree_hash(GetEmptyTreeHash());

  // Roots don't match.
  EXPECT_FALSE(
      VerifyConsistencyProof(log_, 0, empty_tree_hash, 0, root2, empty_proof));
  EXPECT_FALSE(
      VerifyConsistencyProof(log_, 1, empty_tree_hash, 1, root2, empty_proof));
}

TEST_F(CTLogVerifierTest,
       VerifiesConsistencyProofEdgeCases_MatchingRootsNonEmptyProof) {
  const std::string empty_tree_hash(GetEmptyTreeHash());

  std::vector<std::string> proof;
  proof.push_back(empty_tree_hash);

  // Roots match and the tree size is either the same or the old tree size is 0,
  // but the proof is not empty (the verification code should not accept
  // proofs with redundant nodes in this case).
  proof.push_back(empty_tree_hash);
  EXPECT_FALSE(VerifyConsistencyProof(log_, 0, empty_tree_hash, 0,
                                      empty_tree_hash, proof));
  EXPECT_FALSE(VerifyConsistencyProof(log_, 0, empty_tree_hash, 1,
                                      empty_tree_hash, proof));
  EXPECT_FALSE(VerifyConsistencyProof(log_, 1, empty_tree_hash, 1,
                                      empty_tree_hash, proof));
}

TEST_F(CTLogVerifierTest, VerifiesValidConsistencyProofs) {
  std::vector<std::string> proof;
  std::string root1, root2;

  // Known good proofs.
  for (size_t i = 0; i < arraysize(kSHA256Proofs); ++i) {
    SCOPED_TRACE(i);
    proof.clear();
    for (size_t j = 0; j < kSHA256Proofs[i].proof_length; ++j) {
      const char* const v = kSHA256Proofs[i].proof[j];
      proof.push_back(HexToBytes(v));
    }
    const uint64_t snapshot1 = kSHA256Proofs[i].snapshot1;
    const uint64_t snapshot2 = kSHA256Proofs[i].snapshot2;
    const char* const old_root = kSHA256Roots[snapshot1 - 1];
    const char* const new_root = kSHA256Roots[snapshot2 - 1];
    VerifierConsistencyCheck(snapshot1, snapshot2, HexToBytes(old_root),
                             HexToBytes(new_root), proof);
  }
}

const char kLeafPrefix[] = {'\x00'};

// Reference implementation of RFC6962.
// This allows generation of arbitrary-sized Merkle trees and consistency
// proofs between them for testing the consistency proof validation
// code.
class TreeHasher {
 public:
  static std::string HashLeaf(const std::string& leaf) {
    SHA256HashValue sha256;
    memset(sha256.data, 0, sizeof(sha256.data));

    std::unique_ptr<crypto::SecureHash> hash(
        crypto::SecureHash::Create(crypto::SecureHash::SHA256));
    hash->Update(kLeafPrefix, 1);
    hash->Update(leaf.data(), leaf.size());
    hash->Finish(sha256.data, sizeof(sha256.data));

    return std::string(reinterpret_cast<const char*>(sha256.data),
                       sizeof(sha256.data));
  }
};

// Reference implementation of Merkle hash, for cross-checking.
// Recursively calculates the hash of the root given the leaf data
// specified in |inputs|.
std::string ReferenceMerkleTreeHash(std::string* inputs, uint64_t input_size) {
  if (!input_size)
    return GetEmptyTreeHash();
  if (input_size == 1)
    return TreeHasher::HashLeaf(inputs[0]);

  const uint64_t split = CalculateNearestPowerOfTwo(input_size);

  return ct::internal::HashNodes(
      ReferenceMerkleTreeHash(&inputs[0], split),
      ReferenceMerkleTreeHash(&inputs[split], input_size - split));
}

// Reference implementation of snapshot consistency. Returns a
// consistency proof between two snapshots of the tree designated
// by |inputs|.
// Call with have_root1 = true.
std::vector<std::string> ReferenceSnapshotConsistency(std::string* inputs,
                                                      uint64_t snapshot2,
                                                      uint64_t snapshot1,
                                                      bool have_root1) {
  std::vector<std::string> proof;
  if (snapshot1 == 0 || snapshot1 > snapshot2)
    return proof;
  if (snapshot1 == snapshot2) {
    // Consistency proof for two equal subtrees is empty.
    if (!have_root1) {
      // Record the hash of this subtree unless it's the root for which
      // the proof was originally requested. (This happens when the snapshot1
      // tree is balanced.)
      proof.push_back(ReferenceMerkleTreeHash(inputs, snapshot1));
    }
    return proof;
  }

  // 0 < snapshot1 < snapshot2
  const uint64_t split = CalculateNearestPowerOfTwo(snapshot2);

  std::vector<std::string> subproof;
  if (snapshot1 <= split) {
    // Root of snapshot1 is in the left subtree of snapshot2.
    // Prove that the left subtrees are consistent.
    subproof =
        ReferenceSnapshotConsistency(inputs, split, snapshot1, have_root1);
    proof.insert(proof.end(), subproof.begin(), subproof.end());
    // Record the hash of the right subtree (only present in snapshot2).
    proof.push_back(ReferenceMerkleTreeHash(&inputs[split], snapshot2 - split));
  } else {
    // Snapshot1 root is at the same level as snapshot2 root.
    // Prove that the right subtrees are consistent. The right subtree
    // doesn't contain the root of snapshot1, so set have_root1 = false.
    subproof = ReferenceSnapshotConsistency(&inputs[split], snapshot2 - split,
                                            snapshot1 - split, false);
    proof.insert(proof.end(), subproof.begin(), subproof.end());
    // Record the hash of the left subtree (equal in both trees).
    proof.push_back(ReferenceMerkleTreeHash(&inputs[0], split));
  }
  return proof;
}

class CTLogVerifierTestUsingReferenceGenerator
    : public CTLogVerifierTest,
      public ::testing::WithParamInterface<uint64_t> {};

const uint64_t kReferenceTreeSize = 256;

// Tests that every possible valid consistency proof for a tree of a given size
// verifies correctly. Also checks that invalid variations of each proof fail to
// verify (see VerifierConsistencyCheck).
TEST_P(CTLogVerifierTestUsingReferenceGenerator,
       VerifiesValidConsistencyProof) {
  std::vector<std::string> data;
  for (uint64_t i = 0; i < kReferenceTreeSize; ++i)
    data.push_back(std::string(1, static_cast<char>(i)));

  const uint64_t tree_size = GetParam();
  const std::string tree_root = ReferenceMerkleTreeHash(data.data(), tree_size);

  for (uint64_t snapshot = 1; snapshot <= tree_size; ++snapshot) {
    SCOPED_TRACE(snapshot);
    const std::string snapshot_root =
        ReferenceMerkleTreeHash(data.data(), snapshot);
    const std::vector<std::string> proof =
        ReferenceSnapshotConsistency(data.data(), tree_size, snapshot, true);
    VerifierConsistencyCheck(snapshot, tree_size, snapshot_root, tree_root,
                             proof);
  }
}

// Test verification of consistency proofs between all tree sizes from 1 to 128.
INSTANTIATE_TEST_CASE_P(RangeOfTreeSizesAndSnapshots,
                        CTLogVerifierTestUsingReferenceGenerator,
                        testing::Range(UINT64_C(1),
                                       (kReferenceTreeSize / 2) + 1));

}  // namespace

}  // namespace net
