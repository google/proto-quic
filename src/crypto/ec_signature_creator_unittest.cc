// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/ec_signature_creator.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "crypto/ec_private_key.h"
#include "crypto/signature_verifier.h"
#include "testing/gtest/include/gtest/gtest.h"

// TODO(rch): Add some exported keys from each to
// test interop between NSS and OpenSSL.

TEST(ECSignatureCreatorTest, BasicTest) {
  // Do a verify round trip.
  std::unique_ptr<crypto::ECPrivateKey> key_original(
      crypto::ECPrivateKey::Create());
  ASSERT_TRUE(key_original.get());

  std::vector<uint8_t> key_info;
  ASSERT_TRUE(
      key_original->ExportEncryptedPrivateKey(std::string(), 1000, &key_info));
  std::vector<uint8_t> pubkey_info;
  ASSERT_TRUE(key_original->ExportPublicKey(&pubkey_info));

  std::unique_ptr<crypto::ECPrivateKey> key(
      crypto::ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
          std::string(), key_info, pubkey_info));
  ASSERT_TRUE(key.get());
  ASSERT_TRUE(key->key() != NULL);

  std::unique_ptr<crypto::ECSignatureCreator> signer(
      crypto::ECSignatureCreator::Create(key.get()));
  ASSERT_TRUE(signer.get());

  std::string data("Hello, World!");
  std::vector<uint8_t> signature;
  ASSERT_TRUE(signer->Sign(reinterpret_cast<const uint8_t*>(data.c_str()),
                           data.size(), &signature));

  std::vector<uint8_t> public_key_info;
  ASSERT_TRUE(key_original->ExportPublicKey(&public_key_info));

  crypto::SignatureVerifier verifier;
  ASSERT_TRUE(verifier.VerifyInit(
      crypto::SignatureVerifier::ECDSA_SHA256, &signature[0], signature.size(),
      &public_key_info.front(), public_key_info.size()));

  verifier.VerifyUpdate(reinterpret_cast<const uint8_t*>(data.c_str()),
                        data.size());
  ASSERT_TRUE(verifier.VerifyFinal());
}
