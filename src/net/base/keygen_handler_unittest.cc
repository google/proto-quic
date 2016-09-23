// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/keygen_handler.h"

#include <openssl/bytestring.h>
#include <openssl/evp.h>
#include <stdint.h>

#include <string>
#include <utility>

#include "base/base64.h"
#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/worker_pool.h"
#include "build/build_config.h"
#include "crypto/scoped_openssl_types.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(USE_NSS_CERTS)
#include <private/pprthred.h>  // PR_DetachThread
#include "crypto/nss_crypto_module_delegate.h"
#include "crypto/scoped_test_nss_db.h"
#endif

namespace net {

namespace {

#if defined(USE_NSS_CERTS)
class StubCryptoModuleDelegate : public crypto::NSSCryptoModuleDelegate {
  public:
   explicit StubCryptoModuleDelegate(crypto::ScopedPK11Slot slot)
       : slot_(std::move(slot)) {}

   std::string RequestPassword(const std::string& slot_name,
                               bool retry,
                               bool* cancelled) override {
     return std::string();
   }

   crypto::ScopedPK11Slot RequestSlot() override {
     return crypto::ScopedPK11Slot(PK11_ReferenceSlot(slot_.get()));
   }

  private:
   crypto::ScopedPK11Slot slot_;
};
#endif

const char kChallenge[] = "some challenge";

class KeygenHandlerTest : public ::testing::Test {
 public:
  KeygenHandlerTest() {}
  ~KeygenHandlerTest() override {}

  std::unique_ptr<KeygenHandler> CreateKeygenHandler() {
    std::unique_ptr<KeygenHandler> handler(
        new KeygenHandler(768, kChallenge, GURL("http://www.example.com")));
#if defined(USE_NSS_CERTS)
    handler->set_crypto_module_delegate(
        std::unique_ptr<crypto::NSSCryptoModuleDelegate>(
            new StubCryptoModuleDelegate(crypto::ScopedPK11Slot(
                PK11_ReferenceSlot(test_nss_db_.slot())))));
#endif
    return handler;
  }

 private:
#if defined(USE_NSS_CERTS)
  crypto::ScopedTestNSSDB test_nss_db_;
#endif
};

base::StringPiece StringPieceFromCBS(const CBS& cbs) {
  return base::StringPiece(reinterpret_cast<const char*>(CBS_data(&cbs)),
                           CBS_len(&cbs));
}

// Assert that |result| is a valid output for KeygenHandler given challenge
// string of |challenge|.
void AssertValidSignedPublicKeyAndChallenge(const std::string& result,
                                            const std::string& challenge) {
  // Verify it's valid base64:
  std::string spkac;
  ASSERT_TRUE(base::Base64Decode(result, &spkac));

  // Parse the following structure:
  //
  //   PublicKeyAndChallenge ::= SEQUENCE {
  //     spki SubjectPublicKeyInfo,
  //     challenge IA5STRING
  //   }
  //   SignedPublicKeyAndChallenge ::= SEQUENCE {
  //     publicKeyAndChallenge PublicKeyAndChallenge,
  //     signatureAlgorithm AlgorithmIdentifier,
  //     signature BIT STRING
  //   }

  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(spkac.data()), spkac.size());

  // The input should consist of a SEQUENCE.
  CBS child;
  ASSERT_TRUE(CBS_get_asn1(&cbs, &child, CBS_ASN1_SEQUENCE));
  ASSERT_EQ(0u, CBS_len(&cbs));

  // Extract the raw PublicKeyAndChallenge.
  CBS public_key_and_challenge_raw;
  ASSERT_TRUE(CBS_get_asn1_element(&child, &public_key_and_challenge_raw,
                                   CBS_ASN1_SEQUENCE));

  // Parse out the PublicKeyAndChallenge.
  CBS copy = public_key_and_challenge_raw;
  CBS public_key_and_challenge;
  ASSERT_TRUE(
      CBS_get_asn1(&copy, &public_key_and_challenge, CBS_ASN1_SEQUENCE));
  ASSERT_EQ(0u, CBS_len(&copy));
  crypto::ScopedEVP_PKEY key(EVP_parse_public_key(&public_key_and_challenge));
  ASSERT_TRUE(key);
  CBS challenge_spkac;
  ASSERT_TRUE(CBS_get_asn1(&public_key_and_challenge, &challenge_spkac,
                           CBS_ASN1_IA5STRING));
  ASSERT_EQ(0u, CBS_len(&public_key_and_challenge));

  // The challenge must match.
  ASSERT_EQ(challenge, StringPieceFromCBS(challenge_spkac));

  // The next element must be the AlgorithmIdentifier for MD5 with RSA.
  static const uint8_t kMd5WithRsaEncryption[] = {
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
      0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00,
  };
  CBS algorithm;
  ASSERT_TRUE(CBS_get_bytes(&child, &algorithm, sizeof(kMd5WithRsaEncryption)));
  ASSERT_EQ(
      base::StringPiece(reinterpret_cast<const char*>(kMd5WithRsaEncryption),
                        sizeof(kMd5WithRsaEncryption)),
      StringPieceFromCBS(algorithm));

  // Finally, parse the signature.
  CBS signature;
  ASSERT_TRUE(CBS_get_asn1(&child, &signature, CBS_ASN1_BITSTRING));
  ASSERT_EQ(0u, CBS_len(&child));
  uint8_t pad;
  ASSERT_TRUE(CBS_get_u8(&signature, &pad));
  ASSERT_EQ(0u, pad);

  // Check the signature.
  crypto::ScopedEVP_MD_CTX ctx(EVP_MD_CTX_create());
  ASSERT_TRUE(
      EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_md5(), nullptr, key.get()));
  ASSERT_TRUE(EVP_DigestVerifyUpdate(ctx.get(),
                                     CBS_data(&public_key_and_challenge_raw),
                                     CBS_len(&public_key_and_challenge_raw)));
  ASSERT_TRUE(EVP_DigestVerifyFinal(ctx.get(), CBS_data(&signature),
                                    CBS_len(&signature)));
}

TEST_F(KeygenHandlerTest, SmokeTest) {
  std::unique_ptr<KeygenHandler> handler(CreateKeygenHandler());
  handler->set_stores_key(false);  // Don't leave the key-pair behind
  std::string result = handler->GenKeyAndSignChallenge();
  VLOG(1) << "KeygenHandler produced: " << result;
  AssertValidSignedPublicKeyAndChallenge(result, kChallenge);
}

void ConcurrencyTestCallback(const std::string& challenge,
                             base::WaitableEvent* event,
                             std::unique_ptr<KeygenHandler> handler,
                             std::string* result) {
  // We allow Singleton use on the worker thread here since we use a
  // WaitableEvent to synchronize, so it's safe.
  base::ThreadRestrictions::ScopedAllowSingleton scoped_allow_singleton;
  handler->set_stores_key(false);  // Don't leave the key-pair behind.
  *result = handler->GenKeyAndSignChallenge();
  event->Signal();
#if defined(USE_NSS_CERTS)
  // Detach the thread from NSPR.
  // Calling NSS functions attaches the thread to NSPR, which stores
  // the NSPR thread ID in thread-specific data.
  // The threads in our thread pool terminate after we have called
  // PR_Cleanup.  Unless we detach them from NSPR, net_unittests gets
  // segfaults on shutdown when the threads' thread-specific data
  // destructors run.
  PR_DetachThread();
#endif
}

// We asynchronously generate the keys so as not to hang up the IO thread. This
// test tries to catch concurrency problems in the keygen implementation.
TEST_F(KeygenHandlerTest, ConcurrencyTest) {
  const int NUM_HANDLERS = 5;
  base::WaitableEvent* events[NUM_HANDLERS] = { NULL };
  std::string results[NUM_HANDLERS];
  for (int i = 0; i < NUM_HANDLERS; i++) {
    std::unique_ptr<KeygenHandler> handler(CreateKeygenHandler());
    events[i] = new base::WaitableEvent(
        base::WaitableEvent::ResetPolicy::AUTOMATIC,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    base::WorkerPool::PostTask(FROM_HERE,
                               base::Bind(ConcurrencyTestCallback,
                                          "some challenge",
                                          events[i],
                                          base::Passed(&handler),
                                          &results[i]),
                               true);
  }

  for (int i = 0; i < NUM_HANDLERS; i++) {
    // Make sure the job completed
    events[i]->Wait();
    delete events[i];
    events[i] = NULL;

    VLOG(1) << "KeygenHandler " << i << " produced: " << results[i];
    AssertValidSignedPublicKeyAndChallenge(results[i], "some challenge");
  }
}

}  // namespace

}  // namespace net
