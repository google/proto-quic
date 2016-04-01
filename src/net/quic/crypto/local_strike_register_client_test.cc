// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/local_strike_register_client.h"

#include <memory>

#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "base/sys_byteorder.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_time.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {
namespace {

class RecordResultCallback : public StrikeRegisterClient::ResultCallback {
 public:
  // RecordResultCallback stores the argument to RunImpl in
  // |*saved_value| and sets |*called| to true.  The callback is self
  // deleting.
  RecordResultCallback(bool* called,
                       bool* saved_value,
                       InsertStatus* saved_nonce_error)
      : called_(called),
        saved_value_(saved_value),
        saved_nonce_error_(saved_nonce_error) {
    *called_ = false;
  }

 protected:
  void RunImpl(bool nonce_is_valid_and_unique,
               InsertStatus nonce_error) override {
    *called_ = true;
    *saved_value_ = nonce_is_valid_and_unique;
    *saved_nonce_error_ = nonce_error;
  }

 private:
  bool* called_;
  bool* saved_value_;
  InsertStatus* saved_nonce_error_;

  DISALLOW_COPY_AND_ASSIGN(RecordResultCallback);
};

const uint8_t kOrbit[] = "\x12\x34\x56\x78\x9A\xBC\xDE\xF0";
const uint32_t kCurrentTimeExternalSecs = 12345678;
size_t kMaxEntries = 100;
uint32_t kWindowSecs = 60;

class LocalStrikeRegisterClientTest : public ::testing::Test {
 protected:
  LocalStrikeRegisterClientTest() {}

  void SetUp() override {
    strike_register_.reset(new LocalStrikeRegisterClient(
        kMaxEntries, kCurrentTimeExternalSecs, kWindowSecs, kOrbit,
        StrikeRegister::NO_STARTUP_PERIOD_NEEDED));
  }

  scoped_ptr<LocalStrikeRegisterClient> strike_register_;
};

TEST_F(LocalStrikeRegisterClientTest, CheckOrbit) {
  EXPECT_TRUE(strike_register_->IsKnownOrbit(
      StringPiece(reinterpret_cast<const char*>(kOrbit), kOrbitSize)));
  EXPECT_FALSE(strike_register_->IsKnownOrbit(
      StringPiece(reinterpret_cast<const char*>(kOrbit), kOrbitSize - 1)));
  EXPECT_FALSE(strike_register_->IsKnownOrbit(
      StringPiece(reinterpret_cast<const char*>(kOrbit), kOrbitSize + 1)));
  EXPECT_FALSE(strike_register_->IsKnownOrbit(
      StringPiece(reinterpret_cast<const char*>(kOrbit) + 1, kOrbitSize)));
}

TEST_F(LocalStrikeRegisterClientTest, IncorrectNonceLength) {
  string valid_nonce;
  uint32_t norder = htonl(kCurrentTimeExternalSecs);
  valid_nonce.assign(reinterpret_cast<const char*>(&norder), sizeof(norder));
  valid_nonce.append(string(reinterpret_cast<const char*>(kOrbit), kOrbitSize));
  valid_nonce.append(string(20, '\x17'));  // 20 'random' bytes.

  {
    // Validation fails if you remove a byte from the nonce.
    bool called = false;
    bool is_valid = false;
    InsertStatus nonce_error = NONCE_UNKNOWN_FAILURE;
    string short_nonce = valid_nonce.substr(0, valid_nonce.length() - 1);
    strike_register_->VerifyNonceIsValidAndUnique(
        short_nonce, QuicWallTime::FromUNIXSeconds(kCurrentTimeExternalSecs),
        new RecordResultCallback(&called, &is_valid, &nonce_error));
    EXPECT_TRUE(called);
    EXPECT_FALSE(is_valid);
    EXPECT_EQ(NONCE_INVALID_FAILURE, nonce_error);
  }

  {
    // Validation fails if you add a byte to the nonce.
    bool called = false;
    bool is_valid = false;
    InsertStatus nonce_error = NONCE_UNKNOWN_FAILURE;
    string long_nonce(valid_nonce);
    long_nonce.append("a");
    strike_register_->VerifyNonceIsValidAndUnique(
        long_nonce, QuicWallTime::FromUNIXSeconds(kCurrentTimeExternalSecs),
        new RecordResultCallback(&called, &is_valid, &nonce_error));
    EXPECT_TRUE(called);
    EXPECT_FALSE(is_valid);
    EXPECT_EQ(NONCE_INVALID_FAILURE, nonce_error);
  }

  {
    // Verify that the base nonce validates was valid.
    bool called = false;
    bool is_valid = false;
    InsertStatus nonce_error = NONCE_UNKNOWN_FAILURE;
    strike_register_->VerifyNonceIsValidAndUnique(
        valid_nonce, QuicWallTime::FromUNIXSeconds(kCurrentTimeExternalSecs),
        new RecordResultCallback(&called, &is_valid, &nonce_error));
    EXPECT_TRUE(called);
    EXPECT_TRUE(is_valid);
    EXPECT_EQ(NONCE_OK, nonce_error);
  }
}

}  // namespace
}  // namespace test
}  // namespace net
