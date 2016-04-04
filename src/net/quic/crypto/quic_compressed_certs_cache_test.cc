// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_compressed_certs_cache.h"

#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/crypto/cert_compressor.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;
using std::vector;

namespace net {

namespace test {

namespace {

class QuicCompressedCertsCacheTest : public testing::Test {
 public:
  QuicCompressedCertsCacheTest()
      : certs_cache_(QuicCompressedCertsCache::kQuicCompressedCertsCacheSize) {}

 protected:
  QuicCompressedCertsCache certs_cache_;
};

TEST_F(QuicCompressedCertsCacheTest, CacheHit) {
  vector<string> certs = {"leaf cert", "intermediate cert", "root cert"};
  scoped_refptr<ProofSource::Chain> chain(new ProofSource::Chain(certs));
  string common_certs = "common certs";
  string cached_certs = "cached certs";
  string compressed = "compressed cert";

  certs_cache_.Insert(chain, common_certs, cached_certs, compressed);

  const string* cached_value =
      certs_cache_.GetCompressedCert(chain, common_certs, cached_certs);
  ASSERT_NE(nullptr, cached_value);
  EXPECT_EQ(*cached_value, compressed);
}

TEST_F(QuicCompressedCertsCacheTest, CacheMiss) {
  vector<string> certs = {"leaf cert", "intermediate cert", "root cert"};
  scoped_refptr<ProofSource::Chain> chain(new ProofSource::Chain(certs));
  string common_certs = "common certs";
  string cached_certs = "cached certs";
  string compressed = "compressed cert";

  certs_cache_.Insert(chain, common_certs, cached_certs, compressed);

  EXPECT_EQ(nullptr, certs_cache_.GetCompressedCert(
                         chain, "mismatched common certs", cached_certs));
  EXPECT_EQ(nullptr, certs_cache_.GetCompressedCert(chain, common_certs,
                                                    "mismatched cached certs"));
  scoped_refptr<ProofSource::Chain> chain2(new ProofSource::Chain(certs));
  EXPECT_EQ(nullptr,
            certs_cache_.GetCompressedCert(chain2, common_certs, cached_certs));
}

TEST_F(QuicCompressedCertsCacheTest, CacheMissDueToEviction) {
  // Test cache returns a miss when a queried uncompressed certs was cached but
  // then evicted.
  vector<string> certs = {"leaf cert", "intermediate cert", "root cert"};
  scoped_refptr<ProofSource::Chain> chain(new ProofSource::Chain(certs));

  string common_certs = "common certs";
  string cached_certs = "cached certs";
  string compressed = "compressed cert";
  certs_cache_.Insert(chain, common_certs, cached_certs, compressed);

  // Insert another kQuicCompressedCertsCacheSize certs to evict the first
  // cached cert.
  for (unsigned int i = 0;
       i < QuicCompressedCertsCache::kQuicCompressedCertsCacheSize; i++) {
    EXPECT_EQ(certs_cache_.Size(), i + 1);
    certs_cache_.Insert(chain, base::IntToString(i), "", base::IntToString(i));
  }
  EXPECT_EQ(certs_cache_.MaxSize(), certs_cache_.Size());

  EXPECT_EQ(nullptr,
            certs_cache_.GetCompressedCert(chain, common_certs, cached_certs));
}

}  // namespace
}  // namespace test
}  // namespace net
