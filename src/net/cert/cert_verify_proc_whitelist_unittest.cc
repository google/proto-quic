// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/cert_verify_proc_whitelist.h"

#include "base/memory/ref_counted.h"
#include "net/cert/x509_certificate.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

HashValue GetTestHashValue(uint8_t label, HashValueTag tag) {
  HashValue hash_value(tag);
  memset(hash_value.data(), label, hash_value.size());
  return hash_value;
}

HashValueVector GetFakeHashValues() {
  HashValueVector public_key_hashes;

  // Fake "root" hash
  public_key_hashes.push_back(GetTestHashValue(0x00, HASH_VALUE_SHA256));
  public_key_hashes.push_back(GetTestHashValue(0x01, HASH_VALUE_SHA1));
  // Fake "intermediate" hash
  public_key_hashes.push_back(GetTestHashValue(0x02, HASH_VALUE_SHA256));
  public_key_hashes.push_back(GetTestHashValue(0x03, HASH_VALUE_SHA1));
  // Fake "leaf" hash
  public_key_hashes.push_back(GetTestHashValue(0x04, HASH_VALUE_SHA256));
  public_key_hashes.push_back(GetTestHashValue(0x05, HASH_VALUE_SHA1));

  return public_key_hashes;
}

// The SHA-256 hash of the leaf cert "ok_cert.pem"; obtainable either
// via X509Certificate::CalculateFingerprint256 or
// openssl x509 -inform pem -in ok_cert.pem -outform der | openssl
//   dgst -sha256 -c
const uint8_t kWhitelistCerts[][crypto::kSHA256Length] = {
    /* clang-format off */
  { 0xf4, 0x42, 0xdd, 0x66, 0xfa, 0x10, 0x70, 0x65,
    0xd1, 0x7e, 0xd9, 0xbb, 0x7c, 0xa9, 0x3c, 0x79,
    0x63, 0xbe, 0x01, 0xa7, 0x54, 0x18, 0xab, 0x2f,
    0xc3, 0x9a, 0x14, 0x53, 0xc3, 0x83, 0xa0, 0x5a },
    /* clang-format on */
};

TEST(CertVerifyProcWhitelistTest, AcceptsWhitelistedEEByRoot) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(cert);

  // clang-format off
  const PublicKeyWhitelist kWhitelist[] = {
      { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        kWhitelistCerts, arraysize(kWhitelistCerts)
      },
  };
  // clang-format on

  SetCertificateWhitelistForTesting(kWhitelist, arraysize(kWhitelist));

  HashValueVector public_key_hashes = GetFakeHashValues();

  // Should return false, indicating this cert is acceptable because of
  // it being whitelisted.
  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes));

  SetCertificateWhitelistForTesting(nullptr, 0);
}

TEST(CertVerifyProcWhitelistTest, AcceptsWhitelistedEEByIntermediate) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(cert);

  // clang-format off
  const PublicKeyWhitelist kWhitelist[] = {
      { { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 },
        kWhitelistCerts, arraysize(kWhitelistCerts)
      },
  };
  // clang-format on

  SetCertificateWhitelistForTesting(kWhitelist, arraysize(kWhitelist));

  HashValueVector public_key_hashes = GetFakeHashValues();

  // Should return false, indicating this cert is acceptable because of
  // it being whitelisted.
  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes));

  SetCertificateWhitelistForTesting(nullptr, 0);
}

TEST(CertVerifyProcWhitelistTest, RejectsNonWhitelistedEE) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  ASSERT_TRUE(cert);

  // clang-format off
  const PublicKeyWhitelist kWhitelist[] = {
      { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        kWhitelistCerts, arraysize(kWhitelistCerts)
      },
  };
  // clang-format on

  SetCertificateWhitelistForTesting(kWhitelist, arraysize(kWhitelist));

  HashValueVector public_key_hashes = GetFakeHashValues();

  // Should return true, indicating this certificate chains to a constrained
  // root and is not whitelisted.
  EXPECT_TRUE(IsNonWhitelistedCertificate(*cert, public_key_hashes));

  SetCertificateWhitelistForTesting(nullptr, 0);
}

TEST(CertVerifyProcWhitelistTest, RejectsNonWhitelistedEEByIntermediate) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  ASSERT_TRUE(cert);

  // clang-format off
  const PublicKeyWhitelist kWhitelist[] = {
      { { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 },
        kWhitelistCerts, arraysize(kWhitelistCerts)
      },
  };
  // clang-format on

  SetCertificateWhitelistForTesting(kWhitelist, arraysize(kWhitelist));

  HashValueVector public_key_hashes = GetFakeHashValues();

  // Should return true, indicating this certificate chains to a constrained
  // root and is not whitelisted.
  EXPECT_TRUE(IsNonWhitelistedCertificate(*cert, public_key_hashes));

  SetCertificateWhitelistForTesting(nullptr, 0);
}

TEST(CertVerifyProcWhitelistTest, AcceptsUnconstrainedLeaf) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(cert);

  // clang-format off
  const PublicKeyWhitelist kWhitelist[] = {
      { { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
          0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
          0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
          0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 },
        kWhitelistCerts, arraysize(kWhitelistCerts)
      },
  };
  // clang-format on

  SetCertificateWhitelistForTesting(kWhitelist, arraysize(kWhitelist));

  HashValueVector public_key_hashes = GetFakeHashValues();

  // Should return false, because the chain (as indicated by
  // public_key_hashes) is not constrained.
  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes));

  SetCertificateWhitelistForTesting(nullptr, 0);
}

}  // namespace

}  // namespace net
