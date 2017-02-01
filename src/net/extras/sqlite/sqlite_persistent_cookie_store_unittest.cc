// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/extras/sqlite/sqlite_persistent_cookie_store.h"

#include <map>
#include <memory>
#include <set>

#include "base/bind.h"
#include "base/callback.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/sequenced_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/sequenced_worker_pool_owner.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/time/time.h"
#include "crypto/encryptor.h"
#include "crypto/symmetric_key.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/extras/sqlite/cookie_crypto_delegate.h"
#include "sql/connection.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

const base::FilePath::CharType kCookieFilename[] = FILE_PATH_LITERAL("Cookies");

class CookieCryptor : public CookieCryptoDelegate {
 public:
  CookieCryptor();
  bool ShouldEncrypt() override;
  bool EncryptString(const std::string& plaintext,
                     std::string* ciphertext) override;
  bool DecryptString(const std::string& ciphertext,
                     std::string* plaintext) override;

  bool should_encrypt_;

 private:
  std::unique_ptr<crypto::SymmetricKey> key_;
  crypto::Encryptor encryptor_;
};

CookieCryptor::CookieCryptor()
    : should_encrypt_(true),
      key_(
          crypto::SymmetricKey::DeriveKeyFromPassword(crypto::SymmetricKey::AES,
                                                      "password",
                                                      "saltiest",
                                                      1000,
                                                      256)) {
  std::string iv("the iv: 16 bytes");
  encryptor_.Init(key_.get(), crypto::Encryptor::CBC, iv);
}

bool CookieCryptor::ShouldEncrypt() {
  return should_encrypt_;
}

bool CookieCryptor::EncryptString(const std::string& plaintext,
                                  std::string* ciphertext) {
  return encryptor_.Encrypt(plaintext, ciphertext);
}

bool CookieCryptor::DecryptString(const std::string& ciphertext,
                                  std::string* plaintext) {
  return encryptor_.Decrypt(ciphertext, plaintext);
}

}  // namespace

typedef std::vector<std::unique_ptr<CanonicalCookie>> CanonicalCookieVector;

class SQLitePersistentCookieStoreTest : public testing::Test {
 public:
  SQLitePersistentCookieStoreTest()
      : pool_owner_(new base::SequencedWorkerPoolOwner(3, "Background Pool")),
        loaded_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                      base::WaitableEvent::InitialState::NOT_SIGNALED),
        key_loaded_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                          base::WaitableEvent::InitialState::NOT_SIGNALED),
        db_thread_event_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                         base::WaitableEvent::InitialState::NOT_SIGNALED) {}

  void OnLoaded(CanonicalCookieVector cookies) {
    cookies_.swap(cookies);
    loaded_event_.Signal();
  }

  void OnKeyLoaded(CanonicalCookieVector cookies) {
    cookies_.swap(cookies);
    key_loaded_event_.Signal();
  }

  void Load(CanonicalCookieVector* cookies) {
    EXPECT_FALSE(loaded_event_.IsSignaled());
    store_->Load(base::Bind(&SQLitePersistentCookieStoreTest::OnLoaded,
                            base::Unretained(this)));
    loaded_event_.Wait();
    cookies->swap(cookies_);
  }

  void Flush() {
    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);
    store_->Flush(
        base::Bind(&base::WaitableEvent::Signal, base::Unretained(&event)));
    event.Wait();
  }

  scoped_refptr<base::SequencedTaskRunner> background_task_runner() {
    return pool_owner_->pool()->GetSequencedTaskRunner(
        pool_owner_->pool()->GetNamedSequenceToken("background"));
  }

  scoped_refptr<base::SequencedTaskRunner> client_task_runner() {
    return pool_owner_->pool()->GetSequencedTaskRunner(
        pool_owner_->pool()->GetNamedSequenceToken("client"));
  }

  void DestroyStore() {
    store_ = nullptr;
    // Make sure we wait until the destructor has run by shutting down the pool
    // resetting the owner (whose destructor blocks on the pool completion).
    pool_owner_->pool()->Shutdown();
    // Create a new pool for the few tests that create multiple stores. In other
    // cases this is wasted but harmless.
    pool_owner_.reset(new base::SequencedWorkerPoolOwner(3, "Background Pool"));
  }

  void Create(bool crypt_cookies, bool restore_old_session_cookies) {
    if (crypt_cookies)
      cookie_crypto_delegate_.reset(new CookieCryptor());

    store_ = new SQLitePersistentCookieStore(
        temp_dir_.GetPath().Append(kCookieFilename), client_task_runner(),
        background_task_runner(), restore_old_session_cookies,
        cookie_crypto_delegate_.get());
  }

  void CreateAndLoad(bool crypt_cookies,
                     bool restore_old_session_cookies,
                     CanonicalCookieVector* cookies) {
    Create(crypt_cookies, restore_old_session_cookies);
    Load(cookies);
  }

  void InitializeStore(bool crypt, bool restore_old_session_cookies) {
    CanonicalCookieVector cookies;
    CreateAndLoad(crypt, restore_old_session_cookies, &cookies);
    EXPECT_EQ(0U, cookies.size());
  }

  // We have to create this method to wrap WaitableEvent::Wait, since we cannot
  // bind a non-void returning method as a Closure.
  void WaitOnDBEvent() { db_thread_event_.Wait(); }

  // Adds a persistent cookie to store_.
  void AddCookie(const GURL& url,
                 const std::string& name,
                 const std::string& value,
                 const std::string& domain,
                 const std::string& path,
                 const base::Time& creation) {
    store_->AddCookie(*CanonicalCookie::Create(
        url, name, value, domain, path, creation, creation, false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  }

  void AddCookieWithExpiration(const GURL& url,
                               const std::string& name,
                               const std::string& value,
                               const std::string& domain,
                               const std::string& path,
                               const base::Time& creation,
                               const base::Time& expiration) {
    store_->AddCookie(*CanonicalCookie::Create(
        url, name, value, domain, path, creation, expiration, false, false,
        CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  }

  std::string ReadRawDBContents() {
    std::string contents;
    if (!base::ReadFileToString(temp_dir_.GetPath().Append(kCookieFilename),
                                &contents))
      return std::string();
    return contents;
  }

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void TearDown() override {
    DestroyStore();
  }

 protected:
  std::unique_ptr<base::SequencedWorkerPoolOwner> pool_owner_;
  base::WaitableEvent loaded_event_;
  base::WaitableEvent key_loaded_event_;
  base::WaitableEvent db_thread_event_;
  CanonicalCookieVector cookies_;
  base::ScopedTempDir temp_dir_;
  scoped_refptr<SQLitePersistentCookieStore> store_;
  std::unique_ptr<CookieCryptor> cookie_crypto_delegate_;
};

TEST_F(SQLitePersistentCookieStoreTest, TestInvalidMetaTableRecovery) {
  InitializeStore(false, false);
  AddCookie(GURL("http://foo.bar"), "A", "B", std::string(), "/",
            base::Time::Now());
  DestroyStore();

  // Load up the store and verify that it has good data in it.
  CanonicalCookieVector cookies;
  CreateAndLoad(false, false, &cookies);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("A", cookies[0]->Name().c_str());
  ASSERT_STREQ("B", cookies[0]->Value().c_str());
  DestroyStore();
  cookies.clear();

  // Now corrupt the meta table.
  {
    sql::Connection db;
    ASSERT_TRUE(db.Open(temp_dir_.GetPath().Append(kCookieFilename)));
    sql::MetaTable meta_table_;
    meta_table_.Init(&db, 1, 1);
    ASSERT_TRUE(db.Execute("DELETE FROM meta"));
    db.Close();
  }

  // Upon loading, the database should be reset to a good, blank state.
  CreateAndLoad(false, false, &cookies);
  ASSERT_EQ(0U, cookies.size());

  // Verify that, after, recovery, the database persists properly.
  AddCookie(GURL("http://foo.bar"), "X", "Y", std::string(), "/",
            base::Time::Now());
  DestroyStore();
  CreateAndLoad(false, false, &cookies);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("X", cookies[0]->Name().c_str());
  ASSERT_STREQ("Y", cookies[0]->Value().c_str());
  cookies.clear();
}

// Test if data is stored as expected in the SQLite database.
TEST_F(SQLitePersistentCookieStoreTest, TestPersistance) {
  InitializeStore(false, false);
  AddCookie(GURL("http://foo.bar"), "A", "B", std::string(), "/",
            base::Time::Now());
  // Replace the store effectively destroying the current one and forcing it
  // to write its data to disk. Then we can see if after loading it again it
  // is still there.
  DestroyStore();
  // Reload and test for persistence
  CanonicalCookieVector cookies;
  CreateAndLoad(false, false, &cookies);
  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("foo.bar", cookies[0]->Domain().c_str());
  ASSERT_STREQ("A", cookies[0]->Name().c_str());
  ASSERT_STREQ("B", cookies[0]->Value().c_str());

  // Now delete the cookie and check persistence again.
  store_->DeleteCookie(*cookies[0]);
  DestroyStore();
  cookies.clear();

  // Reload and check if the cookie has been removed.
  CreateAndLoad(false, false, &cookies);
  ASSERT_EQ(0U, cookies.size());
}

TEST_F(SQLitePersistentCookieStoreTest, TestSessionCookiesDeletedOnStartup) {
  // Initialize the cookie store with 3 persistent cookies, 5 transient
  // cookies.
  InitializeStore(false, false);

  // Add persistent cookies.
  base::Time t = base::Time::Now();
  AddCookie(GURL("http://a1.com"), "A", "B", std::string(), "/", t);
  t += base::TimeDelta::FromInternalValue(10);
  AddCookie(GURL("http://a2.com"), "A", "B", std::string(), "/", t);
  t += base::TimeDelta::FromInternalValue(10);
  AddCookie(GURL("http://a3.com"), "A", "B", std::string(), "/", t);

  // Add transient cookies.
  t += base::TimeDelta::FromInternalValue(10);
  AddCookieWithExpiration(GURL("http://b1.com"), "A", "B", std::string(), "/",
                          t, base::Time());
  t += base::TimeDelta::FromInternalValue(10);
  AddCookieWithExpiration(GURL("http://b2.com"), "A", "B", std::string(), "/",
                          t, base::Time());
  t += base::TimeDelta::FromInternalValue(10);
  AddCookieWithExpiration(GURL("http://b3.com"), "A", "B", std::string(), "/",
                          t, base::Time());
  t += base::TimeDelta::FromInternalValue(10);
  AddCookieWithExpiration(GURL("http://b4.com"), "A", "B", std::string(), "/",
                          t, base::Time());
  t += base::TimeDelta::FromInternalValue(10);
  AddCookieWithExpiration(GURL("http://b5.com"), "A", "B", std::string(), "/",
                          t, base::Time());
  DestroyStore();

  // Load the store a second time. Before the store finishes loading, add a
  // transient cookie and flush it to disk.
  store_ = new SQLitePersistentCookieStore(
      temp_dir_.GetPath().Append(kCookieFilename), client_task_runner(),
      background_task_runner(), false, nullptr);

  // Posting a blocking task to db_thread_ makes sure that the DB thread waits
  // until both Load and Flush have been posted to its task queue.
  background_task_runner()->PostTask(
      FROM_HERE, base::Bind(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                            base::Unretained(this)));
  store_->Load(base::Bind(&SQLitePersistentCookieStoreTest::OnLoaded,
                          base::Unretained(this)));
  t += base::TimeDelta::FromInternalValue(10);
  AddCookieWithExpiration(GURL("http://c.com"), "A", "B", std::string(), "/", t,
                          base::Time());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  store_->Flush(
      base::Bind(&base::WaitableEvent::Signal, base::Unretained(&event)));

  // Now the DB-thread queue contains:
  // (active:)
  // 1. Wait (on db_event)
  // (pending:)
  // 2. "Init And Chain-Load First Domain"
  // 3. Add Cookie (c.com)
  // 4. Flush Cookie (c.com)
  db_thread_event_.Signal();
  event.Wait();
  loaded_event_.Wait();
  cookies_.clear();
  DestroyStore();

  // Load the store a third time, this time restoring session cookies. The
  // store should contain exactly 4 cookies: the 3 persistent, and "c.com",
  // which was added during the second cookie store load.
  store_ = new SQLitePersistentCookieStore(
      temp_dir_.GetPath().Append(kCookieFilename), client_task_runner(),
      background_task_runner(), true, nullptr);
  store_->Load(base::Bind(&SQLitePersistentCookieStoreTest::OnLoaded,
                          base::Unretained(this)));
  loaded_event_.Wait();
  ASSERT_EQ(4u, cookies_.size());
  cookies_.clear();
}

// Test that priority load of cookies for a specfic domain key could be
// completed before the entire store is loaded
TEST_F(SQLitePersistentCookieStoreTest, TestLoadCookiesForKey) {
  InitializeStore(false, false);
  base::Time t = base::Time::Now();
  AddCookie(GURL("http://foo.bar"), "A", "B", std::string(), "/", t);
  t += base::TimeDelta::FromInternalValue(10);
  AddCookie(GURL("http://www.aaa.com"), "A", "B", std::string(), "/", t);
  t += base::TimeDelta::FromInternalValue(10);
  AddCookie(GURL("http://travel.aaa.com"), "A", "B", std::string(), "/", t);
  t += base::TimeDelta::FromInternalValue(10);
  AddCookie(GURL("http://www.bbb.com"), "A", "B", std::string(), "/", t);
  DestroyStore();

  store_ = new SQLitePersistentCookieStore(
      temp_dir_.GetPath().Append(kCookieFilename), client_task_runner(),
      background_task_runner(), false, nullptr);

  // Posting a blocking task to db_thread_ makes sure that the DB thread waits
  // until both Load and LoadCookiesForKey have been posted to its task queue.
  background_task_runner()->PostTask(
      FROM_HERE, base::Bind(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                            base::Unretained(this)));
  store_->Load(base::Bind(&SQLitePersistentCookieStoreTest::OnLoaded,
                          base::Unretained(this)));
  store_->LoadCookiesForKey(
      "aaa.com", base::Bind(&SQLitePersistentCookieStoreTest::OnKeyLoaded,
                            base::Unretained(this)));
  background_task_runner()->PostTask(
      FROM_HERE, base::Bind(&SQLitePersistentCookieStoreTest::WaitOnDBEvent,
                            base::Unretained(this)));

  // Now the DB-thread queue contains:
  // (active:)
  // 1. Wait (on db_event)
  // (pending:)
  // 2. "Init And Chain-Load First Domain"
  // 3. Priority Load (aaa.com)
  // 4. Wait (on db_event)
  db_thread_event_.Signal();
  key_loaded_event_.Wait();
  ASSERT_EQ(loaded_event_.IsSignaled(), false);
  std::set<std::string> cookies_loaded;
  for (CanonicalCookieVector::const_iterator it = cookies_.begin();
       it != cookies_.end(); ++it) {
    cookies_loaded.insert((*it)->Domain().c_str());
  }
  cookies_.clear();
  ASSERT_GT(4U, cookies_loaded.size());
  ASSERT_EQ(true, cookies_loaded.find("www.aaa.com") != cookies_loaded.end());
  ASSERT_EQ(true,
            cookies_loaded.find("travel.aaa.com") != cookies_loaded.end());

  db_thread_event_.Signal();
  loaded_event_.Wait();
  for (CanonicalCookieVector::const_iterator it = cookies_.begin();
       it != cookies_.end(); ++it) {
    cookies_loaded.insert((*it)->Domain().c_str());
  }
  ASSERT_EQ(4U, cookies_loaded.size());
  ASSERT_EQ(cookies_loaded.find("foo.bar") != cookies_loaded.end(), true);
  ASSERT_EQ(cookies_loaded.find("www.bbb.com") != cookies_loaded.end(), true);
  cookies_.clear();
}

// Test that we can force the database to be written by calling Flush().
TEST_F(SQLitePersistentCookieStoreTest, TestFlush) {
  InitializeStore(false, false);
  // File timestamps don't work well on all platforms, so we'll determine
  // whether the DB file has been modified by checking its size.
  base::FilePath path = temp_dir_.GetPath().Append(kCookieFilename);
  base::File::Info info;
  ASSERT_TRUE(base::GetFileInfo(path, &info));
  int64_t base_size = info.size;

  // Write some large cookies, so the DB will have to expand by several KB.
  for (char c = 'a'; c < 'z'; ++c) {
    // Each cookie needs a unique timestamp for creation_utc (see DB schema).
    base::Time t = base::Time::Now() + base::TimeDelta::FromMicroseconds(c);
    std::string name(1, c);
    std::string value(1000, c);
    AddCookie(GURL("http://foo.bar"), name, value, std::string(), "/", t);
  }

  Flush();

  // We forced a write, so now the file will be bigger.
  ASSERT_TRUE(base::GetFileInfo(path, &info));
  ASSERT_GT(info.size, base_size);
}

// Test loading old session cookies from the disk.
TEST_F(SQLitePersistentCookieStoreTest, TestLoadOldSessionCookies) {
  InitializeStore(false, true);

  // Add a session cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL("http://sessioncookie.com"), "C", "D", std::string(), "/",
      base::Time::Now(), base::Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookies and test that the session cookie
  // was loaded.
  CanonicalCookieVector cookies;
  CreateAndLoad(false, true, &cookies);

  ASSERT_EQ(1U, cookies.size());
  ASSERT_STREQ("sessioncookie.com", cookies[0]->Domain().c_str());
  ASSERT_STREQ("C", cookies[0]->Name().c_str());
  ASSERT_STREQ("D", cookies[0]->Value().c_str());
  ASSERT_EQ(COOKIE_PRIORITY_DEFAULT, cookies[0]->Priority());

  cookies.clear();
}

// Test loading old session cookies from the disk.
TEST_F(SQLitePersistentCookieStoreTest, TestDontLoadOldSessionCookies) {
  InitializeStore(false, true);

  // Add a session cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL("http://sessioncookie.com"), "C", "D", std::string(), "/",
      base::Time::Now(), base::Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that doesn't load old session cookies and test that the
  // session cookie was not loaded.
  CanonicalCookieVector cookies;
  CreateAndLoad(false, false, &cookies);
  ASSERT_EQ(0U, cookies.size());

  // The store should also delete the session cookie. Wait until that has been
  // done.
  DestroyStore();

  // Create a store that loads old session cookies and test that the session
  // cookie is gone.
  CreateAndLoad(false, true, &cookies);
  ASSERT_EQ(0U, cookies.size());
}

TEST_F(SQLitePersistentCookieStoreTest, PersistIsPersistent) {
  InitializeStore(false, true);
  static const char kSessionName[] = "session";
  static const char kPersistentName[] = "persistent";

  // Add a session cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL("http://sessioncookie.com"), kSessionName, "val", std::string(), "/",
      base::Time::Now(), base::Time(), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));
  // Add a persistent cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL("http://sessioncookie.com"), kPersistentName, "val", std::string(),
      "/", base::Time::Now() - base::TimeDelta::FromDays(1),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the IsPersistent
  // attribute is restored.
  CanonicalCookieVector cookies;
  CreateAndLoad(false, true, &cookies);
  ASSERT_EQ(2U, cookies.size());

  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  auto it = cookie_map.find(kSessionName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_FALSE(cookie_map[kSessionName]->IsPersistent());

  it = cookie_map.find(kPersistentName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_TRUE(cookie_map[kPersistentName]->IsPersistent());

  cookies.clear();
}

TEST_F(SQLitePersistentCookieStoreTest, PriorityIsPersistent) {
  static const char kURL[] = "http://sessioncookie.com";
  static const char kLowName[] = "low";
  static const char kMediumName[] = "medium";
  static const char kHighName[] = "high";
  static const char kCookieValue[] = "value";
  static const char kCookiePath[] = "/";

  InitializeStore(false, true);

  // Add a low-priority persistent cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL(kURL), kLowName, kCookieValue, std::string(), kCookiePath,
      base::Time::Now() - base::TimeDelta::FromMinutes(1),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_LOW));

  // Add a medium-priority persistent cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL(kURL), kMediumName, kCookieValue, std::string(), kCookiePath,
      base::Time::Now() - base::TimeDelta::FromMinutes(2),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_MEDIUM));

  // Add a high-priority peristent cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL(kURL), kHighName, kCookieValue, std::string(), kCookiePath,
      base::Time::Now() - base::TimeDelta::FromMinutes(3),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::DEFAULT_MODE, COOKIE_PRIORITY_HIGH));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the priority
  // attribute values are restored.
  CanonicalCookieVector cookies;
  CreateAndLoad(false, true, &cookies);
  ASSERT_EQ(3U, cookies.size());

  // Put the cookies into a map, by name, so we can easily find them.
  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  // Validate that each cookie has the correct priority.
  auto it = cookie_map.find(kLowName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_EQ(COOKIE_PRIORITY_LOW, cookie_map[kLowName]->Priority());

  it = cookie_map.find(kMediumName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_EQ(COOKIE_PRIORITY_MEDIUM, cookie_map[kMediumName]->Priority());

  it = cookie_map.find(kHighName);
  ASSERT_TRUE(it != cookie_map.end());
  EXPECT_EQ(COOKIE_PRIORITY_HIGH, cookie_map[kHighName]->Priority());

  cookies.clear();
}

TEST_F(SQLitePersistentCookieStoreTest, SameSiteIsPersistent) {
  const char kURL[] = "http://sessioncookie.com";
  const char kNoneName[] = "none";
  const char kLaxName[] = "lax";
  const char kStrictName[] = "strict";
  const char kCookieValue[] = "value";
  const char kCookiePath[] = "/";

  InitializeStore(false, true);

  // Add a non-samesite cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL(kURL), kNoneName, kCookieValue, std::string(), kCookiePath,
      base::Time::Now() - base::TimeDelta::FromMinutes(1),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::NO_RESTRICTION, COOKIE_PRIORITY_DEFAULT));

  // Add a lax-samesite persistent cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL(kURL), kLaxName, kCookieValue, std::string(), kCookiePath,
      base::Time::Now() - base::TimeDelta::FromMinutes(2),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::LAX_MODE, COOKIE_PRIORITY_DEFAULT));

  // Add a strict-samesite persistent cookie.
  store_->AddCookie(*CanonicalCookie::Create(
      GURL(kURL), kStrictName, kCookieValue, std::string(), kCookiePath,
      base::Time::Now() - base::TimeDelta::FromMinutes(3),
      base::Time::Now() + base::TimeDelta::FromDays(1), false, false,
      CookieSameSite::STRICT_MODE, COOKIE_PRIORITY_DEFAULT));

  // Force the store to write its data to the disk.
  DestroyStore();

  // Create a store that loads session cookie and test that the priority
  // attribute values are restored.
  CanonicalCookieVector cookies;
  CreateAndLoad(false, true, &cookies);
  ASSERT_EQ(3U, cookies.size());

  // Put the cookies into a map, by name, for comparison below.
  std::map<std::string, CanonicalCookie*> cookie_map;
  for (const auto& cookie : cookies)
    cookie_map[cookie->Name()] = cookie.get();

  // Validate that each cookie has the correct SameSite.
  ASSERT_EQ(1u, cookie_map.count(kNoneName));
  EXPECT_EQ(CookieSameSite::NO_RESTRICTION, cookie_map[kNoneName]->SameSite());

  ASSERT_EQ(1u, cookie_map.count(kLaxName));
  EXPECT_EQ(CookieSameSite::LAX_MODE, cookie_map[kLaxName]->SameSite());

  ASSERT_EQ(1u, cookie_map.count(kStrictName));
  EXPECT_EQ(CookieSameSite::STRICT_MODE, cookie_map[kStrictName]->SameSite());

  cookies.clear();
}

TEST_F(SQLitePersistentCookieStoreTest, UpdateToEncryption) {
  CanonicalCookieVector cookies;

  // Create unencrypted cookie store and write something to it.
  InitializeStore(false, false);
  AddCookie(GURL("http://foo.bar"), "name", "value123XYZ", std::string(), "/",
            base::Time::Now());
  DestroyStore();

  // Verify that "value" is visible in the file.  This is necessary in order to
  // have confidence in a later test that "encrypted_value" is not visible.
  std::string contents = ReadRawDBContents();
  EXPECT_NE(0U, contents.length());
  EXPECT_NE(contents.find("value123XYZ"), std::string::npos);

  // Create encrypted cookie store and ensure old cookie still reads.
  cookies.clear();
  EXPECT_EQ(0U, cookies.size());
  CreateAndLoad(true, false, &cookies);
  EXPECT_EQ(1U, cookies.size());
  EXPECT_EQ("name", cookies[0]->Name());
  EXPECT_EQ("value123XYZ", cookies[0]->Value());

  // Make sure we can update existing cookie and add new cookie as encrypted.
  store_->DeleteCookie(*(cookies[0]));
  AddCookie(GURL("http://foo.bar"), "name", "encrypted_value123XYZ",
            std::string(), "/", base::Time::Now());
  AddCookie(GURL("http://foo.bar"), "other", "something456ABC", std::string(),
            "/", base::Time::Now() + base::TimeDelta::FromInternalValue(10));
  DestroyStore();
  cookies.clear();
  CreateAndLoad(true, false, &cookies);
  EXPECT_EQ(2U, cookies.size());
  CanonicalCookie* cookie_name = nullptr;
  CanonicalCookie* cookie_other = nullptr;
  if (cookies[0]->Name() == "name") {
    cookie_name = cookies[0].get();
    cookie_other = cookies[1].get();
  } else {
    cookie_name = cookies[1].get();
    cookie_other = cookies[0].get();
  }
  EXPECT_EQ("encrypted_value123XYZ", cookie_name->Value());
  EXPECT_EQ("something456ABC", cookie_other->Value());
  DestroyStore();
  cookies.clear();

  // Examine the real record to make sure plaintext version doesn't exist.
  sql::Connection db;
  sql::Statement smt;
  int resultcount = 0;
  ASSERT_TRUE(db.Open(temp_dir_.GetPath().Append(kCookieFilename)));
  smt.Assign(db.GetCachedStatement(SQL_FROM_HERE,
                                   "SELECT * "
                                   "FROM cookies "
                                   "WHERE host_key = 'foo.bar'"));
  while (smt.Step()) {
    resultcount++;
    for (int i = 0; i < smt.ColumnCount(); i++) {
      EXPECT_EQ(smt.ColumnString(i).find("value"), std::string::npos);
      EXPECT_EQ(smt.ColumnString(i).find("something"), std::string::npos);
    }
  }
  EXPECT_EQ(2, resultcount);

  // Verify that "encrypted_value" is NOT visible in the file.
  contents = ReadRawDBContents();
  EXPECT_NE(0U, contents.length());
  EXPECT_EQ(contents.find("encrypted_value123XYZ"), std::string::npos);
  EXPECT_EQ(contents.find("something456ABC"), std::string::npos);
}

TEST_F(SQLitePersistentCookieStoreTest, UpdateFromEncryption) {
  CanonicalCookieVector cookies;

  // Create unencrypted cookie store and write something to it.
  InitializeStore(true, false);
  AddCookie(GURL("http://foo.bar"), "name", "value123XYZ", std::string(), "/",
            base::Time::Now());
  DestroyStore();

  // Verify that "value" is not visible in the file.
  std::string contents = ReadRawDBContents();
  EXPECT_NE(0U, contents.length());
  EXPECT_EQ(contents.find("value123XYZ"), std::string::npos);

  // Create encrypted cookie store and ensure old cookie still reads.
  cookies.clear();
  EXPECT_EQ(0U, cookies.size());
  CreateAndLoad(true, false, &cookies);
  EXPECT_EQ(1U, cookies.size());
  EXPECT_EQ("name", cookies[0]->Name());
  EXPECT_EQ("value123XYZ", cookies[0]->Value());

  // Make sure we can update existing cookie and it writes unencrypted.
  cookie_crypto_delegate_->should_encrypt_ = false;
  store_->DeleteCookie(*(cookies[0]));
  AddCookie(GURL("http://foo.bar"), "name", "plaintext_value123XYZ",
            std::string(), "/", base::Time::Now());
  AddCookie(GURL("http://foo.bar"), "other", "something456ABC", std::string(),
            "/", base::Time::Now() + base::TimeDelta::FromInternalValue(10));
  DestroyStore();
  cookies.clear();
  CreateAndLoad(true, false, &cookies);
  EXPECT_EQ(2U, cookies.size());
  CanonicalCookie* cookie_name = nullptr;
  CanonicalCookie* cookie_other = nullptr;
  if (cookies[0]->Name() == "name") {
    cookie_name = cookies[0].get();
    cookie_other = cookies[1].get();
  } else {
    cookie_name = cookies[1].get();
    cookie_other = cookies[0].get();
  }
  EXPECT_EQ("plaintext_value123XYZ", cookie_name->Value());
  EXPECT_EQ("something456ABC", cookie_other->Value());
  DestroyStore();
  cookies.clear();

  // Verify that "value" is now visible in the file.
  contents = ReadRawDBContents();
  EXPECT_NE(0U, contents.length());
  EXPECT_NE(contents.find("value123XYZ"), std::string::npos);
}

namespace {
void WasCalledWithNoCookies(
    bool* was_called_with_no_cookies,
    std::vector<std::unique_ptr<CanonicalCookie>> cookies) {
  *was_called_with_no_cookies = cookies.empty();
}
}

TEST_F(SQLitePersistentCookieStoreTest, EmptyLoadAfterClose) {
  // Create unencrypted cookie store and write something to it.
  InitializeStore(false, false);
  AddCookie(GURL("http://foo.bar"), "name", "value123XYZ", std::string(), "/",
            base::Time::Now());
  DestroyStore();

  // Create the cookie store, but immediately close it.
  Create(false, false);
  store_->Close(base::Closure());

  // Expect any attempt to call Load() to synchronously respond with an empty
  // vector of cookies after we've Close()d the database.
  bool was_called_with_no_cookies = false;
  store_->Load(base::Bind(WasCalledWithNoCookies, &was_called_with_no_cookies));
  EXPECT_TRUE(was_called_with_no_cookies);

  // Same with trying to load a specific cookie.
  was_called_with_no_cookies = false;
  store_->LoadCookiesForKey("foo.bar", base::Bind(WasCalledWithNoCookies,
                                                  &was_called_with_no_cookies));
  EXPECT_TRUE(was_called_with_no_cookies);
}

}  // namespace net
