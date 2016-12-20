// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_platform_key.h"

#include <pk11pub.h>
#include <stdint.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/memory/ref_counted.h"
#include "crypto/scoped_test_nss_db.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_private_key_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

TEST(SSLPlatformKeyChromecastTest, KeyMatches) {
  std::string pkcs8;
  base::FilePath pkcs8_path =
      GetTestCertsDirectory().AppendASCII("client_1.pk8");
  ASSERT_TRUE(base::ReadFileToString(pkcs8_path, &pkcs8));

  // Import the key into a test NSS database.
  crypto::ScopedTestNSSDB test_db;
  scoped_refptr<X509Certificate> cert = ImportClientCertAndKeyFromFile(
      GetTestCertsDirectory(), "client_1.pem", "client_1.pk8", test_db.slot());
  ASSERT_TRUE(cert);

  // Look up the key.
  scoped_refptr<SSLPrivateKey> key = FetchClientCertPrivateKey(cert.get());
  ASSERT_TRUE(key);

  // Only support SHA-256 and SHA-1.
  std::vector<SSLPrivateKey::Hash> expected_hashes = {
      SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1,
  };
  EXPECT_EQ(expected_hashes, key->GetDigestPreferences());

  TestSSLPrivateKeyMatches(key.get(), pkcs8);
}

}  // namespace net
