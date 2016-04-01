// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/curve25519_key_exchange.h"

#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "net/quic/crypto/quic_random.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {

// SharedKey just tests that the basic key exchange identity holds: that both
// parties end up with the same key.
TEST(Curve25519KeyExchange, SharedKey) {
  QuicRandom* const rand = QuicRandom::GetInstance();

  for (int i = 0; i < 5; i++) {
    const string alice_key(Curve25519KeyExchange::NewPrivateKey(rand));
    const string bob_key(Curve25519KeyExchange::NewPrivateKey(rand));

    scoped_ptr<Curve25519KeyExchange> alice(
        Curve25519KeyExchange::New(alice_key));
    scoped_ptr<Curve25519KeyExchange> bob(Curve25519KeyExchange::New(bob_key));

    const StringPiece alice_public(alice->public_value());
    const StringPiece bob_public(bob->public_value());

    string alice_shared, bob_shared;
    ASSERT_TRUE(alice->CalculateSharedKey(bob_public, &alice_shared));
    ASSERT_TRUE(bob->CalculateSharedKey(alice_public, &bob_shared));
    ASSERT_EQ(alice_shared, bob_shared);
  }
}

}  // namespace test
}  // namespace net
