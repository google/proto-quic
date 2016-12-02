// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_collection.h"

#include "net/cert/internal/test_helpers.h"
#include "net/cert/internal/trust_store_in_memory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class TrustStoreCollectionTest : public testing::Test {
 public:
  void SetUp() override {
    ParsedCertificateList chain;
    bool unused_verify_result;
    der::GeneralizedTime unused_time;
    std::string unused_errors;

    ReadVerifyCertChainTestFromFile(
        "net/data/verify_certificate_chain_unittest/key-rollover-oldchain.pem",
        &chain, &oldroot_, &unused_time, &unused_verify_result, &unused_errors);
    ASSERT_EQ(2U, chain.size());
    target_ = chain[0];
    oldintermediate_ = chain[1];
    ASSERT_TRUE(target_);
    ASSERT_TRUE(oldintermediate_);
    ASSERT_TRUE(oldroot_);

    scoped_refptr<TrustAnchor> unused_root;
    ReadVerifyCertChainTestFromFile(
        "net/data/verify_certificate_chain_unittest/"
        "key-rollover-longrolloverchain.pem",
        &chain, &unused_root, &unused_time, &unused_verify_result,
        &unused_errors);
    ASSERT_EQ(4U, chain.size());
    newintermediate_ = chain[1];
    newroot_ = TrustAnchor::CreateFromCertificateNoConstraints(chain[2]);
    newrootrollover_ =
        TrustAnchor::CreateFromCertificateNoConstraints(chain[3]);
    ASSERT_TRUE(newintermediate_);
    ASSERT_TRUE(newroot_);
    ASSERT_TRUE(newrootrollover_);
  }

 protected:
  scoped_refptr<TrustAnchor> oldroot_;
  scoped_refptr<TrustAnchor> newroot_;
  scoped_refptr<TrustAnchor> newrootrollover_;

  scoped_refptr<ParsedCertificate> target_;
  scoped_refptr<ParsedCertificate> oldintermediate_;
  scoped_refptr<ParsedCertificate> newintermediate_;
};

// Collection contains no stores, should return no results.
TEST_F(TrustStoreCollectionTest, NoStores) {
  TrustAnchors matches;

  TrustStoreCollection collection;
  collection.FindTrustAnchorsForCert(target_, &matches);

  EXPECT_TRUE(matches.empty());
}

// Collection contains only one store.
TEST_F(TrustStoreCollectionTest, OneStore) {
  TrustAnchors matches;

  TrustStoreCollection collection;
  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(newroot_);
  collection.AddTrustStore(&in_memory);
  collection.FindTrustAnchorsForCert(newintermediate_, &matches);

  ASSERT_EQ(1U, matches.size());
  EXPECT_EQ(newroot_, matches[0]);
}

// Collection contains two stores.
TEST_F(TrustStoreCollectionTest, TwoStores) {
  TrustAnchors matches;

  TrustStoreCollection collection;
  TrustStoreInMemory in_memory1;
  TrustStoreInMemory in_memory2;
  in_memory1.AddTrustAnchor(newroot_);
  in_memory2.AddTrustAnchor(oldroot_);
  collection.AddTrustStore(&in_memory1);
  collection.AddTrustStore(&in_memory2);
  collection.FindTrustAnchorsForCert(newintermediate_, &matches);

  ASSERT_EQ(2U, matches.size());
  EXPECT_EQ(newroot_, matches[0]);
  EXPECT_EQ(oldroot_, matches[1]);
}

}  // namespace

}  // namespace net
