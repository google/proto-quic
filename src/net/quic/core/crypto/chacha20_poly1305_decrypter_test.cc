// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/crypto/chacha20_poly1305_decrypter.h"

#include <memory>

#include "net/quic/core/quic_utils.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"

using std::string;

namespace {

// The test vectors come from RFC 7539 Section 2.8.2.

// Each test vector consists of six strings of lowercase hexadecimal digits.
// The strings may be empty (zero length). A test vector with a nullptr |key|
// marks the end of an array of test vectors.
struct TestVector {
  // Input:
  const char* key;
  const char* iv;
  const char* fixed;
  const char* aad;
  const char* ct;

  // Expected output:
  const char* pt;  // An empty string "" means decryption succeeded and
                   // the plaintext is zero-length. nullptr means decryption
                   // failed.
};

const TestVector test_vectors[] = {
    {"808182838485868788898a8b8c8d8e8f"
     "909192939495969798999a9b9c9d9e9f",

     "4041424344454647",

     "07000000",

     "50515253c0c1c2c3c4c5c6c7",

     "d31a8d34648e60db7b86afbc53ef7ec2"
     "a4aded51296e08fea9e2b5a736ee62d6"
     "3dbea45e8ca9671282fafb69da92728b"
     "1a71de0a9e060b2905d6a5b67ecd3b36"
     "92ddbd7f2d778b8c9803aee328091b58"
     "fab324e4fad675945585808b4831d7bc"
     "3ff4def08e4b7a9de576d26586cec64b"
     "6116"
     "1ae10b594f09e26a7e902ecb",  // "d0600691" truncated

     "4c616469657320616e642047656e746c"
     "656d656e206f662074686520636c6173"
     "73206f66202739393a20496620492063"
     "6f756c64206f6666657220796f75206f"
     "6e6c79206f6e652074697020666f7220"
     "746865206675747572652c2073756e73"
     "637265656e20776f756c642062652069"
     "742e"},
    // Modify the ciphertext (Poly1305 authenticator).
    {"808182838485868788898a8b8c8d8e8f"
     "909192939495969798999a9b9c9d9e9f",

     "4041424344454647",

     "07000000",

     "50515253c0c1c2c3c4c5c6c7",

     "d31a8d34648e60db7b86afbc53ef7ec2"
     "a4aded51296e08fea9e2b5a736ee62d6"
     "3dbea45e8ca9671282fafb69da92728b"
     "1a71de0a9e060b2905d6a5b67ecd3b36"
     "92ddbd7f2d778b8c9803aee328091b58"
     "fab324e4fad675945585808b4831d7bc"
     "3ff4def08e4b7a9de576d26586cec64b"
     "6116"
     "1ae10b594f09e26a7e902ecc",  // "d0600691" truncated

     nullptr},
    // Modify the associated data.
    {"808182838485868788898a8b8c8d8e8f"
     "909192939495969798999a9b9c9d9e9f",

     "4041424344454647",

     "07000000",

     "60515253c0c1c2c3c4c5c6c7",

     "d31a8d34648e60db7b86afbc53ef7ec2"
     "a4aded51296e08fea9e2b5a736ee62d6"
     "3dbea45e8ca9671282fafb69da92728b"
     "1a71de0a9e060b2905d6a5b67ecd3b36"
     "92ddbd7f2d778b8c9803aee328091b58"
     "fab324e4fad675945585808b4831d7bc"
     "3ff4def08e4b7a9de576d26586cec64b"
     "6116"
     "1ae10b594f09e26a7e902ecb",  // "d0600691" truncated

     nullptr},
    {nullptr}};

}  // namespace

namespace net {
namespace test {

// DecryptWithNonce wraps the |Decrypt| method of |decrypter| to allow passing
// in an nonce and also to allocate the buffer needed for the plaintext.
QuicData* DecryptWithNonce(ChaCha20Poly1305Decrypter* decrypter,
                           QuicStringPiece nonce,
                           QuicStringPiece associated_data,
                           QuicStringPiece ciphertext) {
  QuicPacketNumber packet_number;
  QuicStringPiece nonce_prefix(nonce.data(),
                               nonce.size() - sizeof(packet_number));
  decrypter->SetNoncePrefix(nonce_prefix);
  memcpy(&packet_number, nonce.data() + nonce_prefix.size(),
         sizeof(packet_number));
  std::unique_ptr<char[]> output(new char[ciphertext.length()]);
  size_t output_length = 0;
  const bool success = decrypter->DecryptPacket(
      QuicVersionMax(), packet_number, associated_data, ciphertext,
      output.get(), &output_length, ciphertext.length());
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
    string key = QuicTextUtils::HexDecode(test_vectors[i].key);
    string iv = QuicTextUtils::HexDecode(test_vectors[i].iv);
    string fixed = QuicTextUtils::HexDecode(test_vectors[i].fixed);
    string aad = QuicTextUtils::HexDecode(test_vectors[i].aad);
    string ct = QuicTextUtils::HexDecode(test_vectors[i].ct);
    string pt;
    if (has_pt) {
      pt = QuicTextUtils::HexDecode(test_vectors[i].pt);
    }

    ChaCha20Poly1305Decrypter decrypter;
    ASSERT_TRUE(decrypter.SetKey(key));
    std::unique_ptr<QuicData> decrypted(DecryptWithNonce(
        &decrypter, fixed + iv,
        // This deliberately tests that the decrypter can handle an AAD that
        // is set to nullptr, as opposed to a zero-length, non-nullptr pointer.
        QuicStringPiece(aad.length() ? aad.data() : nullptr, aad.length()),
        ct));
    if (!decrypted.get()) {
      EXPECT_FALSE(has_pt);
      continue;
    }
    EXPECT_TRUE(has_pt);

    EXPECT_EQ(12u, ct.size() - decrypted->length());
    ASSERT_EQ(pt.length(), decrypted->length());
    test::CompareCharArraysWithHexError("plaintext", decrypted->data(),
                                        pt.length(), pt.data(), pt.length());
  }
}

}  // namespace test
}  // namespace net
