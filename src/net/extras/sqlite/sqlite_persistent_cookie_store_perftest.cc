// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_cookie_store.h"

#include <vector>

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/files/scoped_temp_dir.h"
#include "base/message_loop/message_loop.h"
#include "base/sequenced_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/perf_time_logger.h"
#include "base/test/sequenced_worker_pool_owner.h"
#include "base/threading/sequenced_worker_pool.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/extras/sqlite/cookie_crypto_delegate.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

const base::FilePath::CharType cookie_filename[] = FILE_PATH_LITERAL("Cookies");

}  // namespace

class SQLitePersistentCookieStorePerfTest : public testing::Test {
 public:
  SQLitePersistentCookieStorePerfTest()
      : pool_owner_(new base::SequencedWorkerPoolOwner(2, "SetupPool")),
        loaded_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                      base::WaitableEvent::InitialState::NOT_SIGNALED),
        key_loaded_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                          base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  void OnLoaded(std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
    cookies_.swap(cookies);
    loaded_event_.Signal();
  }

  void OnKeyLoaded(std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
    cookies_.swap(cookies);
    key_loaded_event_.Signal();
  }

  void Load() {
    store_->Load(base::Bind(&SQLitePersistentCookieStorePerfTest::OnLoaded,
                            base::Unretained(this)));
    loaded_event_.Wait();
  }

  scoped_refptr<base::SequencedTaskRunner> background_task_runner() {
    return pool_owner_->pool()->GetSequencedTaskRunner(
        pool_owner_->pool()->GetNamedSequenceToken("background"));
  }

  scoped_refptr<base::SequencedTaskRunner> client_task_runner() {
    return pool_owner_->pool()->GetSequencedTaskRunner(
        pool_owner_->pool()->GetNamedSequenceToken("client"));
  }

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    store_ = new SQLitePersistentCookieStore(
        temp_dir_.GetPath().Append(cookie_filename), client_task_runner(),
        background_task_runner(), false, NULL);
    std::vector<CanonicalCookie*> cookies;
    Load();
    ASSERT_EQ(0u, cookies_.size());
    // Creates 15000 cookies from 300 eTLD+1s.
    base::Time t = base::Time::Now();
    for (int domain_num = 0; domain_num < 300; domain_num++) {
      std::string domain_name(base::StringPrintf(".domain_%d.com", domain_num));
      GURL gurl("http://www" + domain_name);
      for (int cookie_num = 0; cookie_num < 50; ++cookie_num) {
        t += base::TimeDelta::FromInternalValue(10);
        store_->AddCookie(*CanonicalCookie::Create(
            gurl, base::StringPrintf("Cookie_%d", cookie_num), "1", domain_name,
            "/", t, t, false, false, CookieSameSite::DEFAULT_MODE,
            COOKIE_PRIORITY_DEFAULT));
      }
    }
    // Replace the store effectively destroying the current one and forcing it
    // to write its data to disk.
    store_ = NULL;

    // Shut down the pool, causing deferred (no-op) commits to be discarded.
    pool_owner_->pool()->Shutdown();
    // ~SequencedWorkerPoolOwner blocks on pool shutdown.
    pool_owner_.reset(new base::SequencedWorkerPoolOwner(2, "TestPool"));

    store_ = new SQLitePersistentCookieStore(
        temp_dir_.GetPath().Append(cookie_filename), client_task_runner(),
        background_task_runner(), false, NULL);
  }

  void TearDown() override {
    store_ = NULL;
  }

 protected:
  base::MessageLoop main_loop_;
  std::unique_ptr<base::SequencedWorkerPoolOwner> pool_owner_;
  base::WaitableEvent loaded_event_;
  base::WaitableEvent key_loaded_event_;
  std::vector<std::unique_ptr<CanonicalCookie>> cookies_;
  base::ScopedTempDir temp_dir_;
  scoped_refptr<SQLitePersistentCookieStore> store_;
};

// Test the performance of priority load of cookies for a specific domain key
TEST_F(SQLitePersistentCookieStorePerfTest, TestLoadForKeyPerformance) {
  for (int domain_num = 0; domain_num < 3; ++domain_num) {
    std::string domain_name(base::StringPrintf("domain_%d.com", domain_num));
    base::PerfTimeLogger timer(
        ("Load cookies for the eTLD+1 " + domain_name).c_str());
    store_->LoadCookiesForKey(
        domain_name,
        base::Bind(&SQLitePersistentCookieStorePerfTest::OnKeyLoaded,
                   base::Unretained(this)));
    key_loaded_event_.Wait();
    timer.Done();

    ASSERT_EQ(50U, cookies_.size());
  }
}

// Test the performance of load
TEST_F(SQLitePersistentCookieStorePerfTest, TestLoadPerformance) {
  base::PerfTimeLogger timer("Load all cookies");
  Load();
  timer.Done();

  ASSERT_EQ(15000U, cookies_.size());
}

}  // namespace net
