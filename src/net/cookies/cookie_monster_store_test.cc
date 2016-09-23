// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_monster_store_test.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/parsed_cookie.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

LoadedCallbackTask::LoadedCallbackTask(LoadedCallback loaded_callback,
                                       std::vector<CanonicalCookie*> cookies)
    : loaded_callback_(loaded_callback), cookies_(cookies) {
}

LoadedCallbackTask::~LoadedCallbackTask() {
}

CookieStoreCommand::CookieStoreCommand(
    Type type,
    const CookieMonster::PersistentCookieStore::LoadedCallback& loaded_callback,
    const std::string& key)
    : type(type), loaded_callback(loaded_callback), key(key) {}

CookieStoreCommand::CookieStoreCommand(Type type, const CanonicalCookie& cookie)
    : type(type), cookie(cookie) {}

CookieStoreCommand::CookieStoreCommand(const CookieStoreCommand& other) =
    default;

CookieStoreCommand::~CookieStoreCommand() {}

MockPersistentCookieStore::MockPersistentCookieStore()
    : store_load_commands_(false), load_return_value_(true), loaded_(false) {}

void MockPersistentCookieStore::SetLoadExpectation(
    bool return_value,
    const std::vector<CanonicalCookie*>& result) {
  load_return_value_ = return_value;
  load_result_ = result;
}

void MockPersistentCookieStore::Load(const LoadedCallback& loaded_callback) {
  if (store_load_commands_) {
    commands_.push_back(
        CookieStoreCommand(CookieStoreCommand::LOAD, loaded_callback, ""));
    return;
  }
  std::vector<CanonicalCookie*> out_cookies;
  if (load_return_value_) {
    out_cookies = load_result_;
    loaded_ = true;
  }
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&LoadedCallbackTask::Run,
                 new LoadedCallbackTask(loaded_callback, out_cookies)));
}

void MockPersistentCookieStore::LoadCookiesForKey(
    const std::string& key,
    const LoadedCallback& loaded_callback) {
  if (store_load_commands_) {
    commands_.push_back(CookieStoreCommand(
        CookieStoreCommand::LOAD_COOKIES_FOR_KEY, loaded_callback, key));
    return;
  }
  if (!loaded_) {
    Load(loaded_callback);
  } else {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&LoadedCallbackTask::Run,
                   new LoadedCallbackTask(loaded_callback,
                                          std::vector<CanonicalCookie*>())));
  }
}

void MockPersistentCookieStore::AddCookie(const CanonicalCookie& cookie) {
  commands_.push_back(CookieStoreCommand(CookieStoreCommand::ADD, cookie));
}

void MockPersistentCookieStore::UpdateCookieAccessTime(
    const CanonicalCookie& cookie) {
}

void MockPersistentCookieStore::DeleteCookie(const CanonicalCookie& cookie) {
  commands_.push_back(CookieStoreCommand(CookieStoreCommand::REMOVE, cookie));
}

void MockPersistentCookieStore::Flush(const base::Closure& callback) {
  if (!callback.is_null())
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, callback);
}

void MockPersistentCookieStore::SetForceKeepSessionState() {
}

MockPersistentCookieStore::~MockPersistentCookieStore() {
}

MockCookieMonsterDelegate::MockCookieMonsterDelegate() {
}

void MockCookieMonsterDelegate::OnCookieChanged(
    const CanonicalCookie& cookie,
    bool removed,
    CookieMonsterDelegate::ChangeCause cause) {
  CookieNotification notification(cookie, removed);
  changes_.push_back(notification);
}

MockCookieMonsterDelegate::~MockCookieMonsterDelegate() {
}

std::unique_ptr<CanonicalCookie> BuildCanonicalCookie(
    const GURL& url,
    const std::string& cookie_line,
    const base::Time& creation_time) {
  // Parse the cookie line.
  ParsedCookie pc(cookie_line);
  EXPECT_TRUE(pc.IsValid());

  // This helper is simplistic in interpreting a parsed cookie, in order to
  // avoid duplicated CookieMonster's CanonPath() and CanonExpiration()
  // functions. Would be nice to export them, and re-use here.
  EXPECT_FALSE(pc.HasMaxAge());
  EXPECT_TRUE(pc.HasPath());
  base::Time cookie_expires = pc.HasExpires()
                                  ? cookie_util::ParseCookieTime(pc.Expires())
                                  : base::Time();
  std::string cookie_path = pc.Path();

  return CanonicalCookie::Create(url, pc.Name(), pc.Value(), url.host(),
                                 cookie_path, creation_time, cookie_expires,
                                 pc.IsSecure(), pc.IsHttpOnly(), pc.SameSite(),
                                 false, pc.Priority());
}

void AddCookieToList(const GURL& url,
                     const std::string& cookie_line,
                     const base::Time& creation_time,
                     std::vector<CanonicalCookie*>* out_list) {
  std::unique_ptr<CanonicalCookie> cookie(
      BuildCanonicalCookie(url, cookie_line, creation_time));

  out_list->push_back(cookie.release());
}

MockSimplePersistentCookieStore::MockSimplePersistentCookieStore()
    : loaded_(false) {
}

void MockSimplePersistentCookieStore::Load(
    const LoadedCallback& loaded_callback) {
  std::vector<CanonicalCookie*> out_cookies;

  for (CanonicalCookieMap::const_iterator it = cookies_.begin();
       it != cookies_.end(); it++)
    out_cookies.push_back(new CanonicalCookie(it->second));

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&LoadedCallbackTask::Run,
                 new LoadedCallbackTask(loaded_callback, out_cookies)));
  loaded_ = true;
}

void MockSimplePersistentCookieStore::LoadCookiesForKey(
    const std::string& key,
    const LoadedCallback& loaded_callback) {
  if (!loaded_) {
    Load(loaded_callback);
  } else {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&LoadedCallbackTask::Run,
                   new LoadedCallbackTask(loaded_callback,
                                          std::vector<CanonicalCookie*>())));
  }
}

void MockSimplePersistentCookieStore::AddCookie(const CanonicalCookie& cookie) {
  int64_t creation_time = cookie.CreationDate().ToInternalValue();
  EXPECT_TRUE(cookies_.find(creation_time) == cookies_.end());
  cookies_[creation_time] = cookie;
}

void MockSimplePersistentCookieStore::UpdateCookieAccessTime(
    const CanonicalCookie& cookie) {
  int64_t creation_time = cookie.CreationDate().ToInternalValue();
  ASSERT_TRUE(cookies_.find(creation_time) != cookies_.end());
  cookies_[creation_time].SetLastAccessDate(base::Time::Now());
}

void MockSimplePersistentCookieStore::DeleteCookie(
    const CanonicalCookie& cookie) {
  int64_t creation_time = cookie.CreationDate().ToInternalValue();
  CanonicalCookieMap::iterator it = cookies_.find(creation_time);
  ASSERT_TRUE(it != cookies_.end());
  cookies_.erase(it);
}

void MockSimplePersistentCookieStore::Flush(const base::Closure& callback) {
  if (!callback.is_null())
    base::ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, callback);
}

void MockSimplePersistentCookieStore::SetForceKeepSessionState() {
}

std::unique_ptr<CookieMonster> CreateMonsterFromStoreForGC(
    int num_secure_cookies,
    int num_old_secure_cookies,
    int num_non_secure_cookies,
    int num_old_non_secure_cookies,
    int days_old) {
  base::Time current(base::Time::Now());
  base::Time past_creation(base::Time::Now() - base::TimeDelta::FromDays(1000));
  scoped_refptr<MockSimplePersistentCookieStore> store(
      new MockSimplePersistentCookieStore);
  int total_cookies = num_secure_cookies + num_non_secure_cookies;
  int base = 0;
  // Must expire to be persistent
  for (int i = 0; i < total_cookies; i++) {
    int num_old_cookies;
    bool secure;
    if (i < num_secure_cookies) {
      num_old_cookies = num_old_secure_cookies;
      secure = true;
    } else {
      base = num_secure_cookies;
      num_old_cookies = num_old_non_secure_cookies;
      secure = false;
    }
    base::Time creation_time =
        past_creation + base::TimeDelta::FromMicroseconds(i);
    base::Time expiration_time = current + base::TimeDelta::FromDays(30);
    base::Time last_access_time =
        ((i - base) < num_old_cookies)
            ? current - base::TimeDelta::FromDays(days_old)
            : current;

    std::unique_ptr<CanonicalCookie> cc(CanonicalCookie::Create(
        GURL(base::StringPrintf("http://h%05d.izzle/", i)), "a", "1",
        std::string(), "/path", creation_time, expiration_time, secure, false,
        CookieSameSite::DEFAULT_MODE, false, COOKIE_PRIORITY_DEFAULT));
    cc->SetLastAccessDate(last_access_time);
    store->AddCookie(*cc);
  }

  return base::MakeUnique<CookieMonster>(store.get(), nullptr);
}

MockSimplePersistentCookieStore::~MockSimplePersistentCookieStore() {
}

}  // namespace net
