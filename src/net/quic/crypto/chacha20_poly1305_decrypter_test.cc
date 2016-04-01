// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/chacha20_poly1305_decrypter.h"

#include "net/quic/quic_flags.h"
#include "net/quic/test_tools/quic_test_utils.h"

using base::StringPiece;
using std::string;

namespace {

// The test vectors come from draft-agl-tls-chacha20poly1305-04 Section 7.

// Each test vector consists of six strings of lowercase hexadecimal digits.
// The strings may be empty (zero length). A test vector with a nullptr |key|
// marks the end of an array of test vectors.
struct TestVector {
  // Input:
  const char* key;
  const char* iv;
  const char* aad;
  const char* ct;

  // Expected output:
  const char* pt;  // An empty string "" means decryption succeeded and
                   // the plaintext is zero-length. NULL means decryption
                   // failed.
};

const TestVector test_vectors[] = {
    {"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd110"
     "0a1007",
     "cd7cf67be39c794a", "87e229d4500845a079c0",
     "e3e446f7ede9a19b62a4677dabf4e3d24b876bb28475",  // "3896e1d6" truncated.
     "86d09974840bded2a5ca"},
    // Modify the ciphertext (ChaCha20 encryption output).
    {
        "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd110"
        "0a1007",
        "cd7cf67be39c794a", "87e229d4500845a079c0",
        "f3e446f7ede9a19b62a4677dabf4e3d24b876bb28475",  // "3896e1d6"
                                                         // truncated.
        nullptr                                          // FAIL
    },
    // Modify the ciphertext (Poly1305 authenticator).
    {
        "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd110"
        "0a1007",
        "cd7cf67be39c794a", "87e229d4500845a079c0",
        "e3e446f7ede9a19b62a4677dabf4e3d24b876bb28476",  // "3896e1d6"
                                                         // truncated.
        nullptr                                          // FAIL
    },
    // Modify the associated data.
    {
        "4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd110"
        "0a1007",
        "dd7cf67be39c794a", "87e229d4500845a079c0",
        "e3e446f7ede9a19b62a4677dabf4e3d24b876bb28475",  // "3896e1d6"
                                                         // truncated.
        nullptr                                          // FAIL
    },
    {nullptr}};

}  // namespace

namespace net {
namespace test {

// DecryptWithNonce wraps the |Decrypt| method of |decrypter| to allow passing
// in an nonce and also to allocate the buffer needed for the plaintext.
QuicData* DecryptWithNonce(ChaCha20Poly1305Decrypter* decrypter,
                           StringPiece nonce,
                           StringPiece associated_data,
                           StringPiece ciphertext) {
  QuicPathId path_id = kDefaultPathId;
  QuicPacketNumber packet_number;
  StringPiece nonce_prefix(nonce.data(), nonce.size() - sizeof(packet_number));
  decrypter->SetNoncePrefix(nonce_prefix);
  memcpy(&packet_number, nonce.data() + nonce_prefix.size(),
         sizeof(packet_number));
  path_id = static_cast<QuicPathId>(
      packet_number >> 8 * (sizeof(packet_number) - sizeof(path_id)));
  packet_number &= UINT64_C(0x00FFFFFFFFFFFFFF);
  scoped_ptr<char[]> output(new char[ciphertext.length()]);
  size_t output_length = 0;
  const bool success = decrypter->DecryptPacket(
      path_id, packet_number, associated_data, ciphertext, output.get(),
      &output_length, ciphertext.length());
  if (!success) {
    return nullptr;
  }
  return new QuicData(output.release(), output_length, true);
}

TEST(ChaCha20Poly1305DecrypterTest, Decrypt) {
  for (size_t i = 0; test_vectors[i].key != nullptr; i++) {
    // If not present then decryption is expected to fail.
    bool has_pt = test_vectors[i].pt;

    // Decode the test vector.
    string key;
    string iv;
    string aad;
    string ct;
    string pt;
    ASSERT_TRUE(DecodeHexString(test_vectors[i].key, &key));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].iv, &iv));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].aad, &aad));
    ASSERT_TRUE(DecodeHexString(test_vectors[i].ct, &ct));
    if (has_pt) {
      ASSERT_TRUE(DecodeHexString(test_vectors[i].pt, &pt));
    }

    ChaCha20Poly1305Decrypter decrypter;
    ASSERT_TRUE(decrypter.SetKey(key));
    scoped_ptr<QuicData> decrypted(DecryptWithNonce(
        &decrypter, iv,
        // This deliberately tests that the decrypter can handle an AAD that
        // is set to nullptr, as opposed to a zero-length, non-nullptr pointer.
        StringPiece(aad.length() ? aad.data() : nullptr, aad.length()), ct));
    if (!decrypted.get()) {
      EXPECT_FALSE(has_pt);
      continue;
    }
    EXPECT_TRUE(has_pt);

    ASSERT_EQ(pt.length(), decrypted->length());
    test::CompareCharArraysWithHexError("plaintext", decrypted->data(),
                                        pt.length(), pt.data(), pt.length());
  }
}

}  // namespace test
}  // namespace net
