// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_encrypter.h"

#include "net/quic/test_tools/quic_test_utils.h"

using base::StringPiece;
using std::string;

namespace {

// The test vectors come from draft-agl-tls-chacha20poly1305-04 Section 7.

// Each test vector consists of five strings of lowercase hexadecimal digits.
// The strings may be empty (zero length). A test vector with a nullptr |key|
// marks the end of an array of test vectors.
struct TestVector {
  const char* key;
  const char* pt;
  const char* iv;
  const char* aad;
  const char* ct;
};

const TestVector test_vectors[] = {
    {
        "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd110"
        "0a1007",
        "86d09974840bded2a5ca", "cd7cf67be39c794a", "87e229d4500845a079c0",
        "e3e446f7ede9a19b62a4677dabf4e3d24b876bb28475"  // "3896e1d6" truncated.
    },
    {nullptr}};

}  // namespace

namespace net {
namespace test {

// EncryptWithNonce wraps the |Encrypt| method of |encrypter| to allow passing
// in an nonce and also to allocate the buffer needed for the ciphertext.
QuicData* EncryptWithNonce(ChaCha20Poly1305Encrypter* encrypter,
                           StringPiece nonce,
                           StringPiece associated_data,
                           StringPiece plaintext) {
  size_t ciphertext_size = encrypter->GetCiphertextSize(plaintext.length());
  scoped_ptr<char[]> ciphertext(new char[ciphertext_size]);

  if (!encrypter->Encrypt(nonce, associated_data, plaintext,
                          reinterpret_cast<unsigned char*>(ciphertext.get()))) {
    return nullptr;
  }

  return new QuicData(ciphertext.release(), ciphertext_size, true);
}

TEST(ChaCha20Poly1305EncrypterTest, Encrypt) {
  for (size_t i = 0; test_vectors[i].key != nullptr; i++) {
    // Decode the test vector.
    string key;
    string pt;
    string iv;
    string aad;
    string ct;
    ASSERT_TRUE(DecodeHexString(test_vectors[i].key, &key));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].pt, &pt));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].iv, &iv));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].aad, &aad));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].ct, &ct));

    ChaCha20Poly1305Encrypter encrypter;
    ASSERT_TRUE(encrypter.SetKey(key));
    scoped_ptr<QuicData> encrypted(EncryptWithNonce(
        &encrypter, iv,
        // This deliberately tests that the encrypter can handle an AAD that
        // is set to nullptr, as opposed to a zero-length, non-nullptr pointer.
        StringPiece(aad.length() ? aad.data() : nullptr, aad.length()), pt));
    ASSERT_TRUE(encrypted.get());

    test::CompareCharArraysWithHexError("ciphertext", encrypted->data(),
                                        encrypted->length(), ct.data(),
                                        ct.length());
  }
}

TEST(ChaCha20Poly1305EncrypterTest, GetMaxPlaintextSize) {
  ChaCha20Poly1305Encrypter encrypter;
  EXPECT_EQ(1000u, encrypter.GetMaxPlaintextSize(1012));
  EXPECT_EQ(100u, encrypter.GetMaxPlaintextSize(112));
  EXPECT_EQ(10u, encrypter.GetMaxPlaintextSize(22));
}

TEST(ChaCha20Poly1305EncrypterTest, GetCiphertextSize) {
  ChaCha20Poly1305Encrypter encrypter;
  EXPECT_EQ(1012u, encrypter.GetCiphertextSize(1000));
  EXPECT_EQ(112u, encrypter.GetCiphertextSize(100));
  EXPECT_EQ(22u, encrypter.GetCiphertextSize(10));
}

}  // namespace test
}  // namespace net
