// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/disk_cache_based_quic_server_info.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "net/base/net_errors.h"
#include "net/http/mock_http_cache.h"
#include "net/quic/chromium/quic_server_info.h"
#include "net/quic/core/quic_server_id.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

using std::string;

namespace net {
namespace {

// This is an empty transaction, needed to register the URL and the test mode.
const MockTransaction kHostInfoTransaction1 = {
    "quicserverinfo:https://www.google.com:443",
    "",
    base::Time(),
    "",
    LOAD_NORMAL,
    "",
    "",
    base::Time(),
    "",
    TEST_MODE_NORMAL,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    OK,
};

const MockTransaction kHostInfoTransaction2 = {
    "quicserverinfo:https://www.google.com:80",
    "",
    base::Time(),
    "",
    LOAD_NORMAL,
    "",
    "",
    base::Time(),
    "",
    TEST_MODE_NORMAL,
    nullptr,
    nullptr,
    nullptr,
    0,
    0,
    OK,
};

class DeleteCacheCompletionCallback : public TestCompletionCallbackBase {
 public:
  explicit DeleteCacheCompletionCallback(QuicServerInfo* server_info)
      : server_info_(server_info),
        callback_(base::Bind(&DeleteCacheCompletionCallback::OnComplete,
                             base::Unretained(this))) {}

  const CompletionCallback& callback() const { return callback_; }

 private:
  void OnComplete(int result) {
    delete server_info_;
    SetResult(result);
  }

  QuicServerInfo* server_info_;
  CompletionCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(DeleteCacheCompletionCallback);
};

}  // namespace

// Tests that we can delete a DiskCacheBasedQuicServerInfo object in a
// completion callback for DiskCacheBasedQuicServerInfo::WaitForDataReady.
TEST(DiskCacheBasedQuicServerInfo, DeleteInCallback) {
  // Use the blocking mock backend factory to force asynchronous completion
  // of quic_server_info->WaitForDataReady(), so that the callback will run.
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache cache(base::WrapUnique(factory), true);
  QuicServerId server_id("www.verisign.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  TestCompletionCallback callback;
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Now complete the backend creation and let the callback run.
  factory->FinishCreation();
  EXPECT_THAT(callback.GetResult(rv), IsOk());
}

// Tests the basic logic of storing, retrieving and updating data.
TEST(DiskCacheBasedQuicServerInfo, Update) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);
  TestCompletionCallback callback;

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  QuicServerInfo::State* state = quic_server_info->mutable_state();
  EXPECT_TRUE(state->certs.empty());
  const string server_config_a = "server_config_a";
  const string source_address_token_a = "source_address_token_a";
  const string cert_sct_a = "cert_sct_a";
  const string chlo_hash_a = "chlo_hash_a";
  const string server_config_sig_a = "server_config_sig_a";
  const string cert_a = "cert_a";
  const string cert_b = "cert_b";

  state->server_config = server_config_a;
  state->source_address_token = source_address_token_a;
  state->cert_sct = cert_sct_a;
  state->chlo_hash = chlo_hash_a;
  state->server_config_sig = server_config_sig_a;
  state->certs.push_back(cert_a);
  quic_server_info->Persist();

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  // Open the stored QuicServerInfo.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  // And now update the data.
  state = quic_server_info->mutable_state();
  state->certs.push_back(cert_b);

  // Fail instead of DCHECKing double creates.
  cache.disk_cache()->set_double_create_check(false);
  quic_server_info->Persist();
  base::RunLoop().RunUntilIdle();

  // Verify that the state was updated.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state1 = quic_server_info->state();
  EXPECT_EQ(server_config_a, state1.server_config);
  EXPECT_EQ(source_address_token_a, state1.source_address_token);
  EXPECT_EQ(cert_sct_a, state1.cert_sct);
  EXPECT_EQ(chlo_hash_a, state1.chlo_hash);
  EXPECT_EQ(server_config_sig_a, state1.server_config_sig);
  EXPECT_EQ(2U, state1.certs.size());
  EXPECT_EQ(cert_a, state1.certs[0]);
  EXPECT_EQ(cert_b, state1.certs[1]);

  RemoveMockTransaction(&kHostInfoTransaction1);
}

// Test that demonstrates different info is returned when the ports differ.
TEST(DiskCacheBasedQuicServerInfo, UpdateDifferentPorts) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);
  AddMockTransaction(&kHostInfoTransaction2);
  TestCompletionCallback callback;

  // Persist data for port 443.
  QuicServerId server_id1("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info1(
      new DiskCacheBasedQuicServerInfo(server_id1, cache.http_cache()));
  quic_server_info1->Start();
  int rv = quic_server_info1->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  QuicServerInfo::State* state1 = quic_server_info1->mutable_state();
  EXPECT_TRUE(state1->certs.empty());
  const string server_config_a = "server_config_a";
  const string source_address_token_a = "source_address_token_a";
  const string cert_sct_a = "cert_sct_a";
  const string chlo_hash_a = "chlo_hash_a";
  const string server_config_sig_a = "server_config_sig_a";
  const string cert_a = "cert_a";

  state1->server_config = server_config_a;
  state1->source_address_token = source_address_token_a;
  state1->cert_sct = cert_sct_a;
  state1->chlo_hash = chlo_hash_a;
  state1->server_config_sig = server_config_sig_a;
  state1->certs.push_back(cert_a);
  quic_server_info1->Persist();

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  // Persist data for port 80.
  QuicServerId server_id2("www.google.com", 80, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info2(
      new DiskCacheBasedQuicServerInfo(server_id2, cache.http_cache()));
  quic_server_info2->Start();
  rv = quic_server_info2->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  QuicServerInfo::State* state2 = quic_server_info2->mutable_state();
  EXPECT_TRUE(state2->certs.empty());
  const string server_config_b = "server_config_b";
  const string source_address_token_b = "source_address_token_b";
  const string cert_sct_b = "cert_sct_b";
  const string chlo_hash_b = "chlo_hash_b";
  const string server_config_sig_b = "server_config_sig_b";
  const string cert_b = "cert_b";

  state2->server_config = server_config_b;
  state2->source_address_token = source_address_token_b;
  state2->cert_sct = cert_sct_b;
  state2->chlo_hash = chlo_hash_b;
  state2->server_config_sig = server_config_sig_b;
  state2->certs.push_back(cert_b);
  quic_server_info2->Persist();

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  // Verify the stored QuicServerInfo for port 443.
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id1, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state_a = quic_server_info->state();
  EXPECT_EQ(server_config_a, state_a.server_config);
  EXPECT_EQ(source_address_token_a, state_a.source_address_token);
  EXPECT_EQ(cert_sct_a, state_a.cert_sct);
  EXPECT_EQ(chlo_hash_a, state_a.chlo_hash);
  EXPECT_EQ(server_config_sig_a, state_a.server_config_sig);
  EXPECT_EQ(1U, state_a.certs.size());
  EXPECT_EQ(cert_a, state_a.certs[0]);

  // Verify the stored QuicServerInfo for port 80.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id2, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state_b = quic_server_info->state();
  EXPECT_EQ(server_config_b, state_b.server_config);
  EXPECT_EQ(source_address_token_b, state_b.source_address_token);
  EXPECT_EQ(cert_sct_b, state_b.cert_sct);
  EXPECT_EQ(chlo_hash_b, state_b.chlo_hash);
  EXPECT_EQ(server_config_sig_b, state_b.server_config_sig);
  EXPECT_EQ(1U, state_b.certs.size());
  EXPECT_EQ(cert_b, state_b.certs[0]);

  RemoveMockTransaction(&kHostInfoTransaction2);
  RemoveMockTransaction(&kHostInfoTransaction1);
}

// Test IsReadyToPersist when there is a pending write.
TEST(DiskCacheBasedQuicServerInfo, IsReadyToPersist) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);
  TestCompletionCallback callback;

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  QuicServerInfo::State* state = quic_server_info->mutable_state();
  EXPECT_TRUE(state->certs.empty());
  const string server_config_a = "server_config_a";
  const string source_address_token_a = "source_address_token_a";
  const string cert_sct_a = "cert_sct_a";
  const string chlo_hash_a = "chlo_hash_a";
  const string server_config_sig_a = "server_config_sig_a";
  const string cert_a = "cert_a";

  state->server_config = server_config_a;
  state->source_address_token = source_address_token_a;
  state->cert_sct = cert_sct_a;
  state->chlo_hash = chlo_hash_a;
  state->server_config_sig = server_config_sig_a;
  state->certs.push_back(cert_a);
  EXPECT_TRUE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();

  // Once we call Persist, IsReadyToPersist should return false until Persist
  // has completed.
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(quic_server_info->IsReadyToPersist());

  // Verify that the state was updated.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state1 = quic_server_info->state();
  EXPECT_EQ(server_config_a, state1.server_config);
  EXPECT_EQ(source_address_token_a, state1.source_address_token);
  EXPECT_EQ(cert_sct_a, state1.cert_sct);
  EXPECT_EQ(chlo_hash_a, state1.chlo_hash);
  EXPECT_EQ(server_config_sig_a, state1.server_config_sig);
  EXPECT_EQ(1U, state1.certs.size());
  EXPECT_EQ(cert_a, state1.certs[0]);

  RemoveMockTransaction(&kHostInfoTransaction1);
}

// Test multiple calls to Persist.
TEST(DiskCacheBasedQuicServerInfo, MultiplePersist) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);
  TestCompletionCallback callback;

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  // Persist data once.
  QuicServerInfo::State* state = quic_server_info->mutable_state();
  EXPECT_TRUE(state->certs.empty());
  const string server_config_init = "server_config_init";
  const string source_address_token_init = "source_address_token_init";
  const string cert_sct_init = "cert_sct_init";
  const string chlo_hash_init = "chlo_hash_init";
  const string server_config_sig_init = "server_config_sig_init";
  const string cert_init = "cert_init";

  state->server_config = server_config_init;
  state->source_address_token = source_address_token_init;
  state->cert_sct = cert_sct_init;
  state->chlo_hash = chlo_hash_init;
  state->server_config_sig = server_config_sig_init;
  state->certs.push_back(cert_init);
  EXPECT_TRUE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();

  // Once we call Persist, IsReadyToPersist should return false until Persist
  // has completed.
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(quic_server_info->IsReadyToPersist());

  // Persist one more time using the same |quic_server_info| object and without
  // doing another Start() and WaitForDataReady.
  const string server_config_a = "server_config_a";
  const string source_address_token_a = "source_address_token_a";
  const string cert_sct_a = "cert_sct_a";
  const string chlo_hash_a = "chlo_hash_a";
  const string server_config_sig_a = "server_config_sig_a";
  const string cert_a = "cert_a";

  state->server_config = server_config_a;
  state->source_address_token = source_address_token_a;
  state->cert_sct = cert_sct_a;
  state->chlo_hash = chlo_hash_a;
  state->server_config_sig = server_config_sig_a;
  state->certs.push_back(cert_a);
  EXPECT_TRUE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();

  // Once we call Persist, IsReadyToPersist should return false until Persist
  // has completed.
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(quic_server_info->IsReadyToPersist());

  // Verify that the state was updated.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state1 = quic_server_info->state();
  EXPECT_EQ(server_config_a, state1.server_config);
  EXPECT_EQ(source_address_token_a, state1.source_address_token);
  EXPECT_EQ(cert_sct_a, state1.cert_sct);
  EXPECT_EQ(chlo_hash_a, state1.chlo_hash);
  EXPECT_EQ(server_config_sig_a, state1.server_config_sig);
  EXPECT_EQ(1U, state1.certs.size());
  EXPECT_EQ(cert_a, state1.certs[0]);

  RemoveMockTransaction(&kHostInfoTransaction1);
}

TEST(DiskCacheBasedQuicServerInfo, CancelWaitForDataReady) {
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache cache(base::WrapUnique(factory), true);
  TestCompletionCallback callback;
  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Now cancel the callback.
  quic_server_info->CancelWaitForDataReadyCallback();
  EXPECT_FALSE(quic_server_info->IsDataReady());
  // Now complete the backend creation and let the callback run.
  factory->FinishCreation();
  EXPECT_TRUE(quic_server_info->IsDataReady());
}

TEST(DiskCacheBasedQuicServerInfo, CancelWaitForDataReadyButDataIsReady) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);
  TestCompletionCallback callback;

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  quic_server_info->CancelWaitForDataReadyCallback();
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());
  RemoveMockTransaction(&kHostInfoTransaction1);
}

TEST(DiskCacheBasedQuicServerInfo, CancelWaitForDataReadyAfterDeleteCache) {
  std::unique_ptr<QuicServerInfo> quic_server_info;
  {
    MockHttpCache cache(true);
    AddMockTransaction(&kHostInfoTransaction1);
    TestCompletionCallback callback;

    QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
    quic_server_info.reset(
        new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
    EXPECT_FALSE(quic_server_info->IsDataReady());
    quic_server_info->Start();
    int rv = quic_server_info->WaitForDataReady(callback.callback());
    quic_server_info->CancelWaitForDataReadyCallback();
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    EXPECT_TRUE(quic_server_info->IsDataReady());
    RemoveMockTransaction(&kHostInfoTransaction1);
  }
  // Cancel the callback after Cache is deleted.
  quic_server_info->ResetWaitForDataReadyCallback();
}

// Test Start() followed by Persist() without calling WaitForDataReady.
TEST(DiskCacheBasedQuicServerInfo, StartAndPersist) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  quic_server_info->Start();
  // Wait until Start() does the work.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(quic_server_info->IsDataReady());

  QuicServerInfo::State* state = quic_server_info->mutable_state();
  EXPECT_TRUE(state->certs.empty());
  const string server_config_a = "server_config_a";
  const string source_address_token_a = "source_address_token_a";
  const string cert_sct_a = "cert_sct_a";
  const string chlo_hash_a = "chlo_hash_a";
  const string server_config_sig_a = "server_config_sig_a";
  const string cert_a = "cert_a";

  state->server_config = server_config_a;
  state->source_address_token = source_address_token_a;
  state->cert_sct = cert_sct_a;
  state->chlo_hash = chlo_hash_a;
  state->server_config_sig = server_config_sig_a;
  state->certs.push_back(cert_a);
  EXPECT_TRUE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();
  quic_server_info->OnExternalCacheHit();

  // Once we call Persist, IsReadyToPersist should return false until Persist
  // has completed.
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(quic_server_info->IsReadyToPersist());

  // Verify that the state was updated.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  TestCompletionCallback callback;
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state1 = quic_server_info->state();
  EXPECT_EQ(server_config_a, state1.server_config);
  EXPECT_EQ(source_address_token_a, state1.source_address_token);
  EXPECT_EQ(cert_sct_a, state1.cert_sct);
  EXPECT_EQ(chlo_hash_a, state1.chlo_hash);
  EXPECT_EQ(server_config_sig_a, state1.server_config_sig);
  EXPECT_EQ(1U, state1.certs.size());
  EXPECT_EQ(cert_a, state1.certs[0]);

  RemoveMockTransaction(&kHostInfoTransaction1);
}

// Test Persisting data when we are not ready to persist and then verify it
// persists the data when Start() finishes.
TEST(DiskCacheBasedQuicServerInfo, PersistWhenNotReadyToPersist) {
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache cache(base::WrapUnique(factory), true);
  AddMockTransaction(&kHostInfoTransaction1);
  TestCompletionCallback callback;

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  // We do a Start(), but don't call WaitForDataReady(). Because we haven't
  // created the backend, we will wait and data wouldn't be ready.
  quic_server_info->Start();
  EXPECT_FALSE(quic_server_info->IsDataReady());

  // Persist data once, even though the backend is not ready.
  QuicServerInfo::State* state = quic_server_info->mutable_state();
  EXPECT_TRUE(state->certs.empty());
  const string server_config_init = "server_config_init";
  const string source_address_token_init = "source_address_token_init";
  const string cert_sct_init = "cert_sct_init";
  const string chlo_hash_init = "chlo_hash_init";
  const string server_config_sig_init = "server_config_sig_init";
  const string cert_init = "cert_init";

  state->server_config = server_config_init;
  state->source_address_token = source_address_token_init;
  state->cert_sct = cert_sct_init;
  state->chlo_hash = chlo_hash_init;
  state->server_config_sig = server_config_sig_init;
  state->certs.push_back(cert_init);
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());

  // Now complete the backend creation and let the callback run.
  factory->FinishCreation();
  EXPECT_TRUE(quic_server_info->IsDataReady());

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  // Verify that the state was updated.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  const QuicServerInfo::State& state1 = quic_server_info->state();
  EXPECT_EQ(server_config_init, state1.server_config);
  EXPECT_EQ(source_address_token_init, state1.source_address_token);
  EXPECT_EQ(cert_sct_init, state1.cert_sct);
  EXPECT_EQ(chlo_hash_init, state1.chlo_hash);
  EXPECT_EQ(server_config_sig_init, state1.server_config_sig);
  EXPECT_EQ(1U, state1.certs.size());
  EXPECT_EQ(cert_init, state1.certs[0]);
  RemoveMockTransaction(&kHostInfoTransaction1);
}

// Test multiple calls to Persist without waiting for the data to be written.
TEST(DiskCacheBasedQuicServerInfo, MultiplePersistsWithoutWaiting) {
  MockHttpCache cache(true);
  AddMockTransaction(&kHostInfoTransaction1);
  TestCompletionCallback callback;

  QuicServerId server_id("www.google.com", 443, PRIVACY_MODE_DISABLED);
  std::unique_ptr<QuicServerInfo> quic_server_info(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  EXPECT_FALSE(quic_server_info->IsDataReady());
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  // Persist data once.
  QuicServerInfo::State* state = quic_server_info->mutable_state();
  EXPECT_TRUE(state->certs.empty());
  const string server_config_init = "server_config_init";
  const string source_address_token_init = "source_address_token_init";
  const string cert_sct_init = "cert_sct_init";
  const string chlo_hash_init = "chlo_hash_init";
  const string server_config_sig_init = "server_config_sig_init";
  const string cert_init = "cert_init";

  state->server_config = server_config_init;
  state->source_address_token = source_address_token_init;
  state->cert_sct = cert_sct_init;
  state->chlo_hash = chlo_hash_init;
  state->server_config_sig = server_config_sig_init;
  state->certs.push_back(cert_init);
  EXPECT_TRUE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();

  // Once we call Persist, IsReadyToPersist should return false until Persist
  // has completed.
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());

  // Persist one more time using the same |quic_server_info| object and without
  // doing another Start() and WaitForDataReady.
  const string server_config_a = "server_config_a";
  const string source_address_token_a = "source_address_token_a";
  const string cert_sct_a = "cert_sct_a";
  const string chlo_hash_a = "chlo_hash_a";
  const string server_config_sig_a = "server_config_sig_a";
  const string cert_a = "cert_a";

  state->server_config = server_config_a;
  state->source_address_token = source_address_token_a;
  state->cert_sct = cert_sct_a;
  state->chlo_hash = chlo_hash_a;
  state->server_config_sig = server_config_sig_a;
  state->certs.push_back(cert_a);
  EXPECT_FALSE(quic_server_info->IsReadyToPersist());
  quic_server_info->Persist();

  // Wait until Persist() does the work.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(quic_server_info->IsReadyToPersist());

  // Verify that the state was updated.
  quic_server_info.reset(
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache()));
  quic_server_info->Start();
  rv = quic_server_info->WaitForDataReady(callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(quic_server_info->IsDataReady());

  // Verify the second time persisted data is persisted.
  const QuicServerInfo::State& state1 = quic_server_info->state();
  EXPECT_EQ(server_config_a, state1.server_config);
  EXPECT_EQ(source_address_token_a, state1.source_address_token);
  EXPECT_EQ(cert_sct_a, state1.cert_sct);
  EXPECT_EQ(chlo_hash_a, state1.chlo_hash);
  EXPECT_EQ(server_config_sig_a, state1.server_config_sig);
  EXPECT_EQ(1U, state1.certs.size());
  EXPECT_EQ(cert_a, state1.certs[0]);

  RemoveMockTransaction(&kHostInfoTransaction1);
}

// crbug.com/439209: test deletion of QuicServerInfo object in the callback
// doesn't crash.
TEST(DiskCacheBasedQuicServerInfo, DeleteServerInfoInCallback) {
  // Use the blocking mock backend factory to force asynchronous completion
  // of quic_server_info->WaitForDataReady(), so that the callback will run.
  MockBlockingBackendFactory* factory = new MockBlockingBackendFactory();
  MockHttpCache cache(base::WrapUnique(factory), true);
  QuicServerId server_id("www.verisign.com", 443, PRIVACY_MODE_DISABLED);
  QuicServerInfo* quic_server_info =
      new DiskCacheBasedQuicServerInfo(server_id, cache.http_cache());
  // |cb| takes owndership and deletes |quic_server_info| when it is called.
  DeleteCacheCompletionCallback cb(quic_server_info);
  quic_server_info->Start();
  int rv = quic_server_info->WaitForDataReady(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Now complete the backend creation and let the callback run.
  factory->FinishCreation();
  EXPECT_THAT(cb.GetResult(rv), IsOk());
}

}  // namespace net
