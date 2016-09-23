// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/trust_store_collection.h"

#include "base/bind.h"
#include "net/cert/internal/test_helpers.h"
#include "net/cert/internal/trust_store_test_helpers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

using ::testing::_;
using ::testing::Property;
using ::testing::StrictMock;

void NotCalled(TrustAnchors anchors) {
  ADD_FAILURE() << "NotCalled was called";
}

class MockTrustStore : public TrustStore {
 public:
  MOCK_CONST_METHOD4(FindTrustAnchorsForCert,
                     void(const scoped_refptr<ParsedCertificate>&,
                          const TrustAnchorsCallback&,
                          TrustAnchors*,
                          std::unique_ptr<Request>*));
};

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

// Collection contains no stores, should return no results and complete
// synchronously.
TEST_F(TrustStoreCollectionTest, NoStores) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreCollection collection;
  collection.FindTrustAnchorsForCert(target_, base::Bind(&NotCalled),
                                     &sync_matches, &req);

  EXPECT_FALSE(req);
  EXPECT_TRUE(sync_matches.empty());
}

// Collection contains only one synchronous store, should complete
// synchronously.
TEST_F(TrustStoreCollectionTest, NoPrimaryStoreOneSyncStore) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreCollection collection;
  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(newroot_);
  collection.AddTrustStoreSynchronousOnly(&in_memory);
  collection.FindTrustAnchorsForCert(newintermediate_, base::Bind(&NotCalled),
                                     &sync_matches, &req);

  EXPECT_FALSE(req);
  ASSERT_EQ(1U, sync_matches.size());
  EXPECT_EQ(newroot_, sync_matches[0]);
}

// Collection contains two synchronous stores, should complete synchronously.
TEST_F(TrustStoreCollectionTest, NoPrimaryStoreTwoSyncStores) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreCollection collection;
  TrustStoreInMemory in_memory1;
  TrustStoreInMemory in_memory2;
  in_memory1.AddTrustAnchor(newroot_);
  in_memory2.AddTrustAnchor(oldroot_);
  collection.AddTrustStoreSynchronousOnly(&in_memory1);
  collection.AddTrustStoreSynchronousOnly(&in_memory2);
  collection.FindTrustAnchorsForCert(newintermediate_, base::Bind(&NotCalled),
                                     &sync_matches, &req);

  EXPECT_FALSE(req);
  ASSERT_EQ(2U, sync_matches.size());
  EXPECT_EQ(newroot_, sync_matches[0]);
  EXPECT_EQ(oldroot_, sync_matches[1]);
}

// The secondary stores in the collection should not be passed a callback to
// their FindTrustAnchorsForCert call.
TEST_F(TrustStoreCollectionTest, SyncStoresAreQueriedSynchronously) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreCollection collection;
  StrictMock<MockTrustStore> store;
  collection.AddTrustStoreSynchronousOnly(&store);

  EXPECT_CALL(
      store,
      FindTrustAnchorsForCert(
          _, Property(&TrustStore::TrustAnchorsCallback::is_null, true), _, _));

  collection.FindTrustAnchorsForCert(newintermediate_, base::Bind(&NotCalled),
                                     &sync_matches, &req);

  EXPECT_FALSE(req);
  EXPECT_TRUE(sync_matches.empty());
}

// If the primary store completes synchronously, TrustStoreCollection should
// complete synchronously also.
TEST_F(TrustStoreCollectionTest, AllStoresAreSynchronous) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreCollection collection;
  TrustStoreInMemory in_memory1;
  TrustStoreInMemory in_memory2;
  in_memory1.AddTrustAnchor(newroot_);
  in_memory2.AddTrustAnchor(oldroot_);
  collection.SetPrimaryTrustStore(&in_memory1);
  collection.AddTrustStoreSynchronousOnly(&in_memory2);
  collection.FindTrustAnchorsForCert(newintermediate_, base::Bind(&NotCalled),
                                     &sync_matches, &req);

  EXPECT_FALSE(req);
  ASSERT_EQ(2U, sync_matches.size());
  EXPECT_EQ(newroot_, sync_matches[0]);
  EXPECT_EQ(oldroot_, sync_matches[1]);
}

// Primary store returns results asynchronously. No secondary stores registered.
TEST_F(TrustStoreCollectionTest, AsyncPrimaryStore) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreInMemoryAsync in_memory_async;
  in_memory_async.AddAsyncTrustAnchor(newroot_);

  TrustStoreCollection collection;
  collection.SetPrimaryTrustStore(&in_memory_async);

  TrustAnchorResultRecorder anchor_results;
  collection.FindTrustAnchorsForCert(
      newintermediate_, anchor_results.Callback(), &sync_matches, &req);

  ASSERT_TRUE(req);
  EXPECT_TRUE(sync_matches.empty());

  anchor_results.Run();
  ASSERT_EQ(1U, anchor_results.matches().size());
  EXPECT_EQ(newroot_, anchor_results.matches()[0]);
}

// Primary store returns results both synchronously and asynchronously, and
// a secondary store returns results synchronously as well.
TEST_F(TrustStoreCollectionTest, SyncAndAsyncPrimaryStoreAndSyncStore) {
  std::unique_ptr<TrustStore::Request> req;
  TrustAnchors sync_matches;

  TrustStoreInMemoryAsync in_memory_async;
  in_memory_async.AddAsyncTrustAnchor(newroot_);
  in_memory_async.AddSyncTrustAnchor(newrootrollover_);

  TrustStoreInMemory in_memory;
  in_memory.AddTrustAnchor(oldroot_);

  TrustStoreCollection collection;
  collection.SetPrimaryTrustStore(&in_memory_async);
  collection.AddTrustStoreSynchronousOnly(&in_memory);

  TrustAnchorResultRecorder anchor_results;
  collection.FindTrustAnchorsForCert(
      newintermediate_, anchor_results.Callback(), &sync_matches, &req);

  ASSERT_TRUE(req);
  ASSERT_EQ(2U, sync_matches.size());
  EXPECT_EQ(newrootrollover_, sync_matches[0]);
  EXPECT_EQ(oldroot_, sync_matches[1]);

  anchor_results.Run();
  ASSERT_EQ(1U, anchor_results.matches().size());
  EXPECT_EQ(newroot_, anchor_results.matches()[0]);
}

}  // namespace

}  // namespace net
