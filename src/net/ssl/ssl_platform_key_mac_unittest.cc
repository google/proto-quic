// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_platform_key_mac.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCertificate.h>
#include <Security/SecImportExport.h>
#include <Security/SecKeychain.h>

#include <string>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/mac/scoped_cftyperef.h"
#include "base/memory/ref_counted.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_private_key_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/ec_key.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/mem.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"

namespace net {

namespace {

struct TestKey {
  const char* cert_file;
  const char* key_file;
  SSLPrivateKey::Type key_type;
};

const TestKey kTestKeys[] = {
    {"client_1.pem", "client_1.pk8", SSLPrivateKey::Type::RSA},
    {"client_4.pem", "client_4.pk8", SSLPrivateKey::Type::ECDSA_P256},
    {"client_5.pem", "client_5.pk8", SSLPrivateKey::Type::ECDSA_P384},
    {"client_6.pem", "client_6.pk8", SSLPrivateKey::Type::ECDSA_P521},
};

std::string TestKeyToString(const testing::TestParamInfo<TestKey>& params) {
  return SSLPrivateKeyTypeToString(params.param.key_type);
}

}  // namespace

class SSLPlatformKeyMacTest : public testing::TestWithParam<TestKey> {};

TEST_P(SSLPlatformKeyMacTest, KeyMatches) {
  const TestKey& test_key = GetParam();

  // Load test data.
  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), test_key.cert_file);
  ASSERT_TRUE(cert);

  std::string pkcs8;
  base::FilePath pkcs8_path =
      GetTestCertsDirectory().AppendASCII(test_key.key_file);
  ASSERT_TRUE(base::ReadFileToString(pkcs8_path, &pkcs8));

  // Create a temporary keychain.
  base::ScopedTempDir keychain_dir;
  ASSERT_TRUE(keychain_dir.CreateUniqueTempDir());
  base::FilePath keychain_path =
      keychain_dir.GetPath().AppendASCII("test_keychain.keychain");
  base::ScopedCFTypeRef<SecKeychainRef> keychain;
  ASSERT_EQ(noErr,
            SecKeychainCreate(keychain_path.value().c_str(), 0, "", FALSE,
                              nullptr, keychain.InitializeInto()));

  // Insert the certificate into the keychain.
  ASSERT_EQ(noErr,
            SecCertificateAddToKeychain(cert->os_cert_handle(), keychain));

  // Import the key into the keychain. Apple doesn't accept unencrypted PKCS#8,
  // but it accepts the low-level RSAPrivateKey and ECPrivateKey types as
  // "kSecFormatOpenSSL", so produce those. There doesn't appear to be a way to
  // tell it which key type we have, so leave this unspecified and have it
  // guess.
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(pkcs8.data()), pkcs8.size());
  bssl::UniquePtr<EVP_PKEY> openssl_key(EVP_parse_private_key(&cbs));
  ASSERT_TRUE(openssl_key);
  EXPECT_EQ(0u, CBS_len(&cbs));

  bssl::ScopedCBB cbb;
  ASSERT_TRUE(CBB_init(cbb.get(), 0));
  if (EVP_PKEY_id(openssl_key.get()) == EVP_PKEY_RSA) {
    ASSERT_TRUE(RSA_marshal_private_key(cbb.get(),
                                        EVP_PKEY_get0_RSA(openssl_key.get())));
  } else if (EVP_PKEY_id(openssl_key.get()) == EVP_PKEY_EC) {
    ASSERT_TRUE(EC_KEY_marshal_private_key(
        cbb.get(), EVP_PKEY_get0_EC_KEY(openssl_key.get()), 0));
  } else {
    ASSERT_TRUE(false);
  }

  uint8_t* encoded;
  size_t encoded_len;
  ASSERT_TRUE(CBB_finish(cbb.get(), &encoded, &encoded_len));
  bssl::UniquePtr<uint8_t> scoped_encoded(encoded);

  base::ScopedCFTypeRef<CFDataRef> encoded_ref(CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault, encoded, encoded_len, kCFAllocatorNull));
  SecExternalFormat format = kSecFormatOpenSSL;
  SecExternalItemType item_type = kSecItemTypePrivateKey;
  ASSERT_EQ(noErr, SecItemImport(encoded_ref, nullptr, &format, &item_type, 0,
                                 nullptr, keychain, nullptr));

  // Finally, test the code to look up the key.
  scoped_refptr<SSLPrivateKey> key =
      FetchClientCertPrivateKeyFromKeychain(cert.get(), keychain);
  ASSERT_TRUE(key);

  // All Mac keys are expected to have the same hash preferences.
  std::vector<SSLPrivateKey::Hash> expected_hashes = {
      SSLPrivateKey::Hash::SHA512, SSLPrivateKey::Hash::SHA384,
      SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1,
  };
  EXPECT_EQ(expected_hashes, key->GetDigestPreferences());

  TestSSLPrivateKeyMatches(key.get(), pkcs8);
}

INSTANTIATE_TEST_CASE_P(,
                        SSLPlatformKeyMacTest,
                        testing::ValuesIn(kTestKeys),
                        TestKeyToString);

}  // namespace net
