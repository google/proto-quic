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

// Resize a string to |size| bytes of data, then return its data buffer
// address cast as an 'unsigned char*', as expected by OpenSSL functions.
// |str| the target string.
// |size| the number of bytes to write into the string.
// Return the string's new buffer in memory, as an 'unsigned char*'
// pointer.
unsigned char* OpenSSLWriteInto(std::string* str, size_t size) {
  return reinterpret_cast<unsigned char*>(base::WriteInto(str, size + 1));
}

bool ReadTestFile(const char* filename, std::string* pkcs8) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  base::FilePath file_path = certs_dir.AppendASCII(filename);
  return base::ReadFileToString(file_path, pkcs8);
}

// Load a given private key file into an EVP_PKEY.
// |filename| is the key file path.
// Returns a new EVP_PKEY on success, NULL on failure.
bssl::UniquePtr<EVP_PKEY> ImportPrivateKeyFile(const char* filename) {
  std::string pkcs8;
  if (!ReadTestFile(filename, &pkcs8))
    return nullptr;

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(pkcs8.data()), pkcs8.size());
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_parse_private_key(&cbs));
  if (!pkey) {
    LOG(ERROR) << "Could not load private key file: " << filename;
    return nullptr;
  }

  return pkey;
}

// Imports the public key from the specified test certificate.
bssl::UniquePtr<EVP_PKEY> ImportPublicKeyFromCertificateFile(
    const char* filename) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), filename);
  if (!cert) {
    LOG(ERROR) << "Could not open certificate file: " << filename;
    return nullptr;
  }

  bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(cert->os_cert_handle()));
  if (!pkey) {
    LOG(ERROR) << "Could not load public key from certificate: " << filename;
    return nullptr;
  }

  return pkey;
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

const char kTestRsaKeyFile[] = "client_1.pk8";
const char kTestRsaCertificateFile[] = "client_1.pem";

// Retrieve a JNI local ref for our test RSA key.
ScopedJava GetRSATestKeyJava() {
  std::string key;
  if (!ReadTestFile(kTestRsaKeyFile, &key))
    return ScopedJava();
  return GetPKCS8PrivateKeyJava(android::PRIVATE_KEY_TYPE_RSA, key);
}

const char kTestEcdsaKeyFile[] = "client_4.pk8";
const char kTestEcdsaCertificateFile[] = "client_4.pem";

// Retrieve a JNI local ref for our test ECDSA key.
ScopedJava GetECDSATestKeyJava() {
  std::string key;
  if (!ReadTestFile(kTestEcdsaKeyFile, &key))
    return ScopedJava();
  return GetPKCS8PrivateKeyJava(android::PRIVATE_KEY_TYPE_ECDSA, key);
}

// Call this function to verify that one message signed with our
// test ECDSA private key is correct. Since ECDSA signing introduces
// random elements in the signature, it is not possible to compare
// signature bits directly. However, one can use the public key
// to do the check.
bool VerifyTestECDSASignature(const base::StringPiece& message,
                              const base::StringPiece& signature) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  bssl::UniquePtr<EVP_PKEY> pkey =
      ImportPublicKeyFromCertificateFile(kTestEcdsaCertificateFile);
  if (!pkey)
    return false;

  EC_KEY* pub_key = EVP_PKEY_get0_EC_KEY(pkey.get());
  if (!pub_key) {
    LOG(ERROR) << "Could not get ECDSA public key";
    return false;
  }

  const unsigned char* digest =
      reinterpret_cast<const unsigned char*>(message.data());
  int digest_len = static_cast<int>(message.size());
  const unsigned char* sigbuf =
      reinterpret_cast<const unsigned char*>(signature.data());
  int siglen = static_cast<int>(signature.size());

  if (!ECDSA_verify(0, digest, digest_len, sigbuf, siglen, pub_key)) {
    LOG(ERROR) << "ECDSA_verify() failed";
    return false;
  }
  return true;
}

// Sign a message with OpenSSL, return the result as a string.
// |message| is the message to be signed.
// |openssl_key| is an OpenSSL EVP_PKEY to use.
// |result| receives the result.
// Returns true on success, false otherwise.
bool SignWithOpenSSL(int hash_nid,
                     const base::StringPiece& message,
                     EVP_PKEY* openssl_key,
                     std::string* result) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  RSA* rsa = EVP_PKEY_get0_RSA(openssl_key);
  if (!rsa) {
    LOG(ERROR) << "Could not get RSA from EVP_PKEY";
    return false;
  }

  const unsigned char* digest =
      reinterpret_cast<const unsigned char*>(message.data());
  unsigned int digest_len = static_cast<unsigned int>(message.size());

  // With RSA, the signature will always be RSA_size() bytes.
  size_t max_signature_size = static_cast<size_t>(RSA_size(rsa));
  std::string signature;
  unsigned char* p = OpenSSLWriteInto(&signature, max_signature_size);
  unsigned int p_len = 0;
  if (!RSA_sign(hash_nid, digest, digest_len, p, &p_len, rsa)) {
    LOG(ERROR) << "RSA_sign() failed";
    return false;
  }

  size_t signature_size = static_cast<size_t>(p_len);
  if (signature_size == 0) {
    LOG(ERROR) << "Signature is empty!";
    return false;
  }
  if (signature_size > max_signature_size) {
    LOG(ERROR) << "Signature size mismatch, actual " << signature_size
               << ", expected <= " << max_signature_size;
    return false;
  }
  signature.resize(signature_size);
  result->swap(signature);
  return true;
}

// Check that a generated signature for a given message matches
// OpenSSL output byte-by-byte.
// |message| is the input message.
// |signature| is the generated signature for the message.
// |openssl_key| is a raw EVP_PKEY for the same private key than the
// one which was used to generate the signature.
// Returns true on success, false otherwise.
bool CompareSignatureWithOpenSSL(int hash_nid,
                                 const base::StringPiece& message,
                                 const base::StringPiece& signature,
                                 EVP_PKEY* openssl_key) {
  std::string openssl_signature;
  if (!SignWithOpenSSL(hash_nid, message, openssl_key, &openssl_signature))
    return false;

  if (signature.size() != openssl_signature.size()) {
    LOG(ERROR) << "Signature size mismatch, actual " << signature.size()
               << ", expected " << openssl_signature.size();
    return false;
  }
  for (size_t n = 0; n < signature.size(); ++n) {
    if (openssl_signature[n] != signature[n]) {
      LOG(ERROR) << "Signature byte mismatch at index " << n << "actual "
                 << signature[n] << ", expected " << openssl_signature[n];
      LOG(ERROR) << "Actual signature  : "
                 << base::HexEncode(signature.data(), signature.size());
      LOG(ERROR) << "Expected signature: "
                 << base::HexEncode(openssl_signature.data(),
                                    openssl_signature.size());
      return false;
    }
  }
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

}  // namespace

TEST(SSLPlatformKeyAndroid, RSA) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), kTestRsaCertificateFile);
  ASSERT_TRUE(cert);
  ScopedJava rsa_key = GetRSATestKeyJava();
  ASSERT_FALSE(rsa_key.is_null());

  scoped_refptr<SSLPrivateKey> wrapper_key =
      WrapJavaPrivateKey(cert.get(), rsa_key);
  ASSERT_TRUE(wrapper_key);

  bssl::UniquePtr<EVP_PKEY> openssl_key = ImportPrivateKeyFile(kTestRsaKeyFile);
  ASSERT_TRUE(openssl_key);

  // Check that the wrapper key returns the correct length and type.
  EXPECT_EQ(SSLPrivateKey::Type::RSA, wrapper_key->GetType());
  EXPECT_EQ(static_cast<size_t>(EVP_PKEY_size(openssl_key.get())),
            wrapper_key->GetMaxSignatureLengthInBytes());

  // Test signing against each hash.
  for (const auto& hash : kHashes) {
    SCOPED_TRACE(hash.name);

    const EVP_MD* md = EVP_get_digestbynid(hash.nid);
    ASSERT_TRUE(md);
    std::string digest(EVP_MD_size(md), 'a');

    std::string signature;
    DoKeySigningWithWrapper(wrapper_key.get(), hash.hash, digest, &signature);
    ASSERT_TRUE(CompareSignatureWithOpenSSL(hash.nid, digest, signature,
                                            openssl_key.get()));
  }
}

TEST(SSLPlatformKeyAndroid, ECDSA) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), kTestEcdsaCertificateFile);
  ASSERT_TRUE(cert);
  ScopedJava ecdsa_key = GetECDSATestKeyJava();
  ASSERT_FALSE(ecdsa_key.is_null());

  scoped_refptr<SSLPrivateKey> wrapper_key =
      WrapJavaPrivateKey(cert.get(), ecdsa_key);
  ASSERT_TRUE(wrapper_key);

  bssl::UniquePtr<EVP_PKEY> openssl_key =
      ImportPrivateKeyFile(kTestEcdsaKeyFile);
  ASSERT_TRUE(openssl_key);

  // Check that the wrapper key returns the correct length and type.
  EXPECT_EQ(SSLPrivateKey::Type::ECDSA_P256, wrapper_key->GetType());
  EXPECT_EQ(static_cast<size_t>(EVP_PKEY_size(openssl_key.get())),
            wrapper_key->GetMaxSignatureLengthInBytes());

  // Test signing against each hash.
  for (const auto& hash : kHashes) {
    // ECDSA does not sign MD5-SHA1.
    if (hash.nid == NID_md5_sha1)
      continue;

    SCOPED_TRACE(hash.name);
    const EVP_MD* md = EVP_get_digestbynid(hash.nid);
    ASSERT_TRUE(md);
    std::string digest(EVP_MD_size(md), 'a');

    std::string signature;
    DoKeySigningWithWrapper(wrapper_key.get(), hash.hash, digest, &signature);
    ASSERT_TRUE(VerifyTestECDSASignature(digest, signature));
  }
}

}  // namespace net
