// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/cert_compressor.h"

#include <memory>

#include "base/strings/string_number_conversions.h"
#include "net/quic/quic_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;
using std::vector;

namespace net {
namespace test {

TEST(CertCompressor, EmptyChain) {
  vector<string> chain;
  const string compressed = CertCompressor::CompressChain(
      chain, StringPiece(), StringPiece(), nullptr);
  EXPECT_EQ("00", base::HexEncode(compressed.data(), compressed.size()));

  vector<string> chain2, cached_certs;
  ASSERT_TRUE(CertCompressor::DecompressChain(compressed, cached_certs, nullptr,
                                              &chain2));
  EXPECT_EQ(chain.size(), chain2.size());
}

TEST(CertCompressor, Compressed) {
  vector<string> chain;
  chain.push_back("testcert");
  const string compressed = CertCompressor::CompressChain(
      chain, StringPiece(), StringPiece(), nullptr);
  ASSERT_GE(compressed.size(), 2u);
  EXPECT_EQ("0100", base::HexEncode(compressed.substr(0, 2).data(), 2));

  vector<string> chain2, cached_certs;
  ASSERT_TRUE(CertCompressor::DecompressChain(compressed, cached_certs, nullptr,
                                              &chain2));
  EXPECT_EQ(chain.size(), chain2.size());
  EXPECT_EQ(chain[0], chain2[0]);
}

TEST(CertCompressor, Common) {
  vector<string> chain;
  chain.push_back("testcert");
  static const uint64_t set_hash = 42;
  std::unique_ptr<CommonCertSets> common_sets(
      CryptoTestUtils::MockCommonCertSets(chain[0], set_hash, 1));
  const string compressed = CertCompressor::CompressChain(
      chain,
      StringPiece(reinterpret_cast<const char*>(&set_hash), sizeof(set_hash)),
      StringPiece(), common_sets.get());
  const string common(
      "03"               /* common */
      "2A00000000000000" /* set hash 42 */
      "01000000"         /* index 1 */
      "00" /* end of list */);
  EXPECT_EQ(common.data(),
            base::HexEncode(compressed.data(), compressed.size()));

  vector<string> chain2, cached_certs;
  ASSERT_TRUE(CertCompressor::DecompressChain(compressed, cached_certs,
                                              common_sets.get(), &chain2));
  EXPECT_EQ(chain.size(), chain2.size());
  EXPECT_EQ(chain[0], chain2[0]);
}

TEST(CertCompressor, Cached) {
  vector<string> chain;
  chain.push_back("testcert");
  uint64_t hash = QuicUtils::FNV1a_64_Hash(chain[0].data(), chain[0].size());
  StringPiece hash_bytes(reinterpret_cast<char*>(&hash), sizeof(hash));
  const string compressed =
      CertCompressor::CompressChain(chain, StringPiece(), hash_bytes, nullptr);

  EXPECT_EQ("02" /* cached */ +
                base::HexEncode(hash_bytes.data(), hash_bytes.size()) +
                "00" /* end of list */,
            base::HexEncode(compressed.data(), compressed.size()));

  vector<string> cached_certs, chain2;
  cached_certs.push_back(chain[0]);
  ASSERT_TRUE(CertCompressor::DecompressChain(compressed, cached_certs, nullptr,
                                              &chain2));
  EXPECT_EQ(chain.size(), chain2.size());
  EXPECT_EQ(chain[0], chain2[0]);
}

TEST(CertCompressor, BadInputs) {
  vector<string> cached_certs, chain;

  /* bad entry type */
  const string bad_entry("04");
  EXPECT_FALSE(CertCompressor::DecompressChain(
      base::HexEncode(bad_entry.data(), bad_entry.size()), cached_certs,
      nullptr, &chain));

  /* no terminator */
  const string no_terminator("01");
  EXPECT_FALSE(CertCompressor::DecompressChain(
      base::HexEncode(no_terminator.data(), no_terminator.size()), cached_certs,
      nullptr, &chain));

  /* hash truncated */
  const string hash_truncated("0200");
  EXPECT_FALSE(CertCompressor::DecompressChain(
      base::HexEncode(hash_truncated.data(), hash_truncated.size()),
      cached_certs, nullptr, &chain));

  /* hash and index truncated */
  const string hash_and_index_truncated("0300");
  EXPECT_FALSE(CertCompressor::DecompressChain(
      base::HexEncode(hash_and_index_truncated.data(),
                      hash_and_index_truncated.size()),
      cached_certs, nullptr, &chain));

  /* without a CommonCertSets */
  const string without_a_common_cert_set(
      "03"
      "0000000000000000"
      "00000000");
  EXPECT_FALSE(CertCompressor::DecompressChain(
      base::HexEncode(without_a_common_cert_set.data(),
                      without_a_common_cert_set.size()),
      cached_certs, nullptr, &chain));

  std::unique_ptr<CommonCertSets> common_sets(
      CryptoTestUtils::MockCommonCertSets("foo", 42, 1));

  /* incorrect hash and index */
  const string incorrect_hash_and_index(
      "03"
      "a200000000000000"
      "00000000");
  EXPECT_FALSE(CertCompressor::DecompressChain(
      base::HexEncode(incorrect_hash_and_index.data(),
                      incorrect_hash_and_index.size()),
      cached_certs, nullptr, &chain));
}

}  // namespace test
}  // namespace net
