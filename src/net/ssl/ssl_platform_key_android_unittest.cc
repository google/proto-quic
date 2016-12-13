// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/jni_android.h"
#include "base/android/jni_array.h"
#include "base/android/scoped_java_ref.h"
#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "crypto/openssl_util.h"
#include "net/android/keystore.h"
#include "net/cert/x509_certificate.h"
#include "net/ssl/ssl_platform_key_android.h"
#include "net/ssl/ssl_private_key.h"
#include "net/test/cert_test_util.h"
#include "net/test/jni/AndroidKeyStoreTestUtil_jni.h"
#include "net/test/test_data_directory.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/bytestring.h"
#include "third_party/boringssl/src/include/openssl/digest.h"
#include "third_party/boringssl/src/include/openssl/ecdsa.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/pem.h"
#include "third_party/boringssl/src/include/openssl/rsa.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

namespace net {

namespace {

typedef base::android::ScopedJavaLocalRef<jobject> ScopedJava;

// Resize a string to |size| bytes of data, then return its data buffer address
// cast as an 'uint8_t*', as expected by OpenSSL functions.
// |str| the target string.
// |size| the number of bytes to write into the string.
// Return the string's new buffer in memory, as an 'uint8_t*' pointer.
uint8_t* OpenSSLWriteInto(std::string* str, size_t size) {
  return reinterpret_cast<uint8_t*>(base::WriteInto(str, size + 1));
}

bool ReadTestFile(const char* filename, std::string* pkcs8) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  base::FilePath file_path = certs_dir.AppendASCII(filename);
  return base::ReadFileToString(file_path, pkcs8);
}

// Parses a PKCS#8 key into an OpenSSL private key object.
bssl::UniquePtr<EVP_PKEY> ImportPrivateKeyOpenSSL(const std::string& pkcs8) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(pkcs8.data()), pkcs8.size());
  return bssl::UniquePtr<EVP_PKEY>(EVP_parse_private_key(&cbs));
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

bool VerifyWithOpenSSL(const EVP_MD* md,
                       const base::StringPiece& digest,
                       EVP_PKEY* key,
                       const base::StringPiece& signature) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key, nullptr));
  if (!ctx || !EVP_PKEY_verify_init(ctx.get()) ||
      !EVP_PKEY_CTX_set_signature_md(ctx.get(), md) ||
      !EVP_PKEY_verify(
          ctx.get(), reinterpret_cast<const uint8_t*>(signature.data()),
          signature.size(), reinterpret_cast<const uint8_t*>(digest.data()),
          digest.size())) {
    return false;
  }

  return true;
}

bool SignWithOpenSSL(const EVP_MD* md,
                     const base::StringPiece& digest,
                     EVP_PKEY* key,
                     std::string* result) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  size_t sig_len;
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key, nullptr));
  if (!ctx || !EVP_PKEY_sign_init(ctx.get()) ||
      !EVP_PKEY_CTX_set_signature_md(ctx.get(), md) ||
      !EVP_PKEY_sign(ctx.get(), OpenSSLWriteInto(result, EVP_PKEY_size(key)),
                     &sig_len, reinterpret_cast<const uint8_t*>(digest.data()),
                     digest.size())) {
    return false;
  }

  result->resize(sig_len);
  return true;
}

void OnSignComplete(base::RunLoop* loop,
                    Error* out_error,
                    std::string* out_signature,
                    Error error,
                    const std::vector<uint8_t>& signature) {
  *out_error = error;
  out_signature->assign(signature.begin(), signature.end());
  loop->Quit();
}

void DoKeySigningWithWrapper(SSLPrivateKey* key,
                             SSLPrivateKey::Hash hash,
                             const base::StringPiece& message,
                             std::string* result) {
  Error error;
  base::RunLoop loop;

  key->SignDigest(
      hash, message,
      base::Bind(OnSignComplete, base::Unretained(&loop),
                 base::Unretained(&error), base::Unretained(result)));
  loop.Run();

  ASSERT_EQ(OK, error);
}

static const struct {
  const char* name;
  int nid;
  SSLPrivateKey::Hash hash;
} kHashes[] = {
    {"MD5-SHA1", NID_md5_sha1, SSLPrivateKey::Hash::MD5_SHA1},
    {"SHA-1", NID_sha1, SSLPrivateKey::Hash::SHA1},
    {"SHA-256", NID_sha256, SSLPrivateKey::Hash::SHA256},
    {"SHA-384", NID_sha384, SSLPrivateKey::Hash::SHA384},
    {"SHA-512", NID_sha512, SSLPrivateKey::Hash::SHA512},
};

struct TestKey {
  const char* cert_file;
  const char* key_file;
  android::PrivateKeyType android_key_type;
  SSLPrivateKey::Type key_type;
};

static const TestKey kTestKeys[] = {
    {"client_1.pem", "client_1.pk8", android::PRIVATE_KEY_TYPE_RSA,
     SSLPrivateKey::Type::RSA},
    {"client_4.pem", "client_4.pk8", android::PRIVATE_KEY_TYPE_ECDSA,
     SSLPrivateKey::Type::ECDSA_P256},
    {"client_5.pem", "client_5.pk8", android::PRIVATE_KEY_TYPE_ECDSA,
     SSLPrivateKey::Type::ECDSA_P384},
    {"client_6.pem", "client_6.pk8", android::PRIVATE_KEY_TYPE_ECDSA,
     SSLPrivateKey::Type::ECDSA_P521},
};

}  // namespace

class SSLPlatformKeyAndroidTest : public testing::TestWithParam<TestKey> {};

TEST_P(SSLPlatformKeyAndroidTest, SignHashes) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  const TestKey& test_key = GetParam();

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), test_key.cert_file);
  ASSERT_TRUE(cert);

  std::string key_bytes;
  ASSERT_TRUE(ReadTestFile(test_key.key_file, &key_bytes));
  ScopedJava java_key =
      GetPKCS8PrivateKeyJava(test_key.android_key_type, key_bytes);
  ASSERT_FALSE(java_key.is_null());

  scoped_refptr<SSLPrivateKey> wrapper_key =
      WrapJavaPrivateKey(cert.get(), java_key);
  ASSERT_TRUE(wrapper_key);

  bssl::UniquePtr<EVP_PKEY> openssl_key = ImportPrivateKeyOpenSSL(key_bytes);
  ASSERT_TRUE(openssl_key);

  // Check that the wrapper key returns the correct length and type.
  EXPECT_EQ(test_key.key_type, wrapper_key->GetType());
  EXPECT_EQ(static_cast<size_t>(EVP_PKEY_size(openssl_key.get())),
            wrapper_key->GetMaxSignatureLengthInBytes());

  // Test signing against each hash.
  for (const auto& hash : kHashes) {
    // Only RSA signs MD5-SHA1.
    if (test_key.key_type != SSLPrivateKey::Type::RSA &&
        hash.nid == NID_md5_sha1) {
      continue;
    }

    SCOPED_TRACE(hash.name);

    const EVP_MD* md = EVP_get_digestbynid(hash.nid);
    ASSERT_TRUE(md);
    std::string digest(EVP_MD_size(md), 'a');

    std::string signature;
    DoKeySigningWithWrapper(wrapper_key.get(), hash.hash, digest, &signature);
    EXPECT_TRUE(VerifyWithOpenSSL(md, digest, openssl_key.get(), signature));

    // RSA signing is deterministic, so further check the signature matches.
    if (test_key.key_type == SSLPrivateKey::Type::RSA) {
      std::string openssl_signature;
      ASSERT_TRUE(
          SignWithOpenSSL(md, digest, openssl_key.get(), &openssl_signature));
      EXPECT_EQ(openssl_signature, signature);
    }
  }
}

INSTANTIATE_TEST_CASE_P(,
                        SSLPlatformKeyAndroidTest,
                        testing::ValuesIn(kTestKeys));

}  // namespace net
