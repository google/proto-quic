// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_platform_key_android.h"

#include <string>

#include "base/android/jni_android.h"
#include "base/android/jni_array.h"
#include "base/android/scoped_java_ref.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "net/android/keystore.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_private_key_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/jni/AndroidKeyStoreTestUtil_jni.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

typedef base::android::ScopedJavaLocalRef<jobject> ScopedJava;

bool ReadTestFile(const char* filename, std::string* pkcs8) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  base::FilePath file_path = certs_dir.AppendASCII(filename);
  return base::ReadFileToString(file_path, pkcs8);
}

// Retrieve a JNI local ref from encoded PKCS#8 data.
ScopedJava GetPKCS8PrivateKeyJava(android::PrivateKeyType key_type,
                                  const std::string& pkcs8_key) {
  JNIEnv* env = base::android::AttachCurrentThread();
  base::android::ScopedJavaLocalRef<jbyteArray> bytes(
      base::android::ToJavaByteArray(
          env, reinterpret_cast<const uint8_t*>(pkcs8_key.data()),
          pkcs8_key.size()));

  ScopedJava key(Java_AndroidKeyStoreTestUtil_createPrivateKeyFromPKCS8(
      env, key_type, bytes));

  return key;
}

struct TestKey {
  const char* cert_file;
  const char* key_file;
  android::PrivateKeyType android_key_type;
  SSLPrivateKey::Type key_type;
};

const TestKey kTestKeys[] = {
    {"client_1.pem", "client_1.pk8", android::PRIVATE_KEY_TYPE_RSA,
     SSLPrivateKey::Type::RSA},
    {"client_4.pem", "client_4.pk8", android::PRIVATE_KEY_TYPE_ECDSA,
     SSLPrivateKey::Type::ECDSA_P256},
    {"client_5.pem", "client_5.pk8", android::PRIVATE_KEY_TYPE_ECDSA,
     SSLPrivateKey::Type::ECDSA_P384},
    {"client_6.pem", "client_6.pk8", android::PRIVATE_KEY_TYPE_ECDSA,
     SSLPrivateKey::Type::ECDSA_P521},
};

std::string TestKeyToString(const testing::TestParamInfo<TestKey>& params) {
  return SSLPrivateKeyTypeToString(params.param.key_type);
}

}  // namespace

class SSLPlatformKeyAndroidTest : public testing::TestWithParam<TestKey> {};

TEST_P(SSLPlatformKeyAndroidTest, Matches) {
  const TestKey& test_key = GetParam();

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), test_key.cert_file);
  ASSERT_TRUE(cert);

  std::string key_bytes;
  ASSERT_TRUE(ReadTestFile(test_key.key_file, &key_bytes));
  ScopedJava java_key =
      GetPKCS8PrivateKeyJava(test_key.android_key_type, key_bytes);
  ASSERT_FALSE(java_key.is_null());

  scoped_refptr<SSLPrivateKey> key = WrapJavaPrivateKey(cert.get(), java_key);
  ASSERT_TRUE(key);

  // All Android keys are expected to have the same hash preferences.
  std::vector<SSLPrivateKey::Hash> expected_hashes = {
      SSLPrivateKey::Hash::SHA512, SSLPrivateKey::Hash::SHA384,
      SSLPrivateKey::Hash::SHA256, SSLPrivateKey::Hash::SHA1,
  };
  EXPECT_EQ(expected_hashes, key->GetDigestPreferences());

  TestSSLPrivateKeyMatches(key.get(), key_bytes);
}

INSTANTIATE_TEST_CASE_P(,
                        SSLPlatformKeyAndroidTest,
                        testing::ValuesIn(kTestKeys),
                        TestKeyToString);

}  // namespace net
