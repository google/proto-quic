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

TEST(CertVerifyProcWhitelistTest, HandlesWosignCerts) {
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wosign_before_oct_21.pem");
  ASSERT_TRUE(cert);

  HashValueVector public_key_hashes;
  public_key_hashes.emplace_back(SHA256HashValue{
      {0x15, 0x28, 0x39, 0x7d, 0xa2, 0x12, 0x89, 0x0a, 0x83, 0x0b, 0x0b,
       0x95, 0xa5, 0x99, 0x68, 0xce, 0xf2, 0x34, 0x77, 0x37, 0x79, 0xdf,
       0x51, 0x81, 0xcf, 0x10, 0xfa, 0x64, 0x75, 0x34, 0xbb, 0x65}});

  EXPECT_FALSE(IsNonWhitelistedCertificate(*cert, public_key_hashes));

  cert = ImportCertFromFile(GetTestCertsDirectory(), "wosign_after_oct_21.pem");
  ASSERT_TRUE(cert);

  EXPECT_TRUE(IsNonWhitelistedCertificate(*cert, public_key_hashes));
}

}  // namespace

}  // namespace net
