// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains test infrastructure for multiple files
// (current cookie_monster_unittest.cc and cookie_monster_perftest.cc)
// that need to test out CookieMonster interactions with the backing store.
// It should only be included by test code.

#ifndef NET_COOKIES_COOKIE_MONSTER_STORE_TEST_H_
#define NET_COOKIES_COOKIE_MONSTER_STORE_TEST_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_monster.h"

class GURL;

namespace base {
class Time;
}

namespace net {

// Wrapper class for posting a loaded callback. Since the Callback class is not
// reference counted, we cannot post a callback to the message loop directly,
// instead we post a LoadedCallbackTask.
class LoadedCallbackTask
    : public base::RefCountedThreadSafe<LoadedCallbackTask> {
 public:
  typedef CookieMonster::PersistentCookieStore::LoadedCallback LoadedCallback;

  LoadedCallbackTask(LoadedCallback loaded_callback,
                     std::vector<CanonicalCookie*> cookies);

  void Run() { loaded_callback_.Run(cookies_); }

 private:
  friend class base::RefCountedThreadSafe<LoadedCallbackTask>;
  ~LoadedCallbackTask();

  LoadedCallback loaded_callback_;
  std::vector<CanonicalCookie*> cookies_;

  DISALLOW_COPY_AND_ASSIGN(LoadedCallbackTask);
};  // Wrapper class LoadedCallbackTask

// Describes a call to one of the 5 functions of PersistentCookieStore.
struct CookieStoreCommand {
  enum Type {
    LOAD,
    LOAD_COOKIES_FOR_KEY,
    // UPDATE_ACCESS_TIME is not included in this list, because get cookie
    // commands may or may not end updating the access time, unless they have
    // the option set not to do so.
    ADD,
    REMOVE,
  };

  // Constructor for LOAD and LOAD_COOKIES_FOR_KEY calls.  |key| should be empty
  // for LOAD_COOKIES_FOR_KEY.
  CookieStoreCommand(Type type,
                     const CookieMonster::PersistentCookieStore::LoadedCallback&
                         loaded_callback,
                     const std::string& key);

  // Constructor for ADD, UPDATE_ACCESS_TIME, and REMOVE calls.
  CookieStoreCommand(Type type, const CanonicalCookie& cookie);

  CookieStoreCommand(const CookieStoreCommand& other);

  ~CookieStoreCommand();

  Type type;

  // Only non-null for LOAD and LOAD_COOKIES_FOR_KEY.
  CookieMonster::PersistentCookieStore::LoadedCallback loaded_callback;

  // Only non-empty for LOAD_COOKIES_FOR_KEY.
  std::string key;

  // Only non-null for ADD, UPDATE_ACCESS_TIME, and REMOVE.
  CanonicalCookie cookie;
};

// Implementation of PersistentCookieStore that captures the
// received commands and saves them to a list.
// The result of calls to Load() can be configured using SetLoadExpectation().
class MockPersistentCookieStore : public CookieMonster::PersistentCookieStore {
 public:
  typedef std::vector<CookieStoreCommand> CommandList;

  MockPersistentCookieStore();

  // When set, Load() and LoadCookiesForKey() calls are store in the command
  // list, rather than being automatically executed. Defaults to false.
  void set_store_load_commands(bool store_load_commands) {
    store_load_commands_ = store_load_commands;
  }

  void SetLoadExpectation(bool return_value,
                          const std::vector<CanonicalCookie*>& result);

  const CommandList& commands() const { return commands_; }

  void Load(const LoadedCallback& loaded_callback) override;

  void LoadCookiesForKey(const std::string& key,
                         const LoadedCallback& loaded_callback) override;

  void AddCookie(const CanonicalCookie& cookie) override;

  void UpdateCookieAccessTime(const CanonicalCookie& cookie) override;

  void DeleteCookie(const CanonicalCookie& cookie) override;

  void Flush(const base::Closure& callback) override;

  void SetForceKeepSessionState() override;

 protected:
  ~MockPersistentCookieStore() override;

 private:
  CommandList commands_;

  bool store_load_commands_;

  // Deferred result to use when Load() is called.
  bool load_return_value_;
  std::vector<CanonicalCookie*> load_result_;
  // Indicates if the store has been fully loaded to avoid returning duplicate
  // cookies.
  bool loaded_;

  DISALLOW_COPY_AND_ASSIGN(MockPersistentCookieStore);
};

// Mock for CookieMonsterDelegate
class MockCookieMonsterDelegate : public CookieMonsterDelegate {
 public:
  typedef std::pair<CanonicalCookie, bool> CookieNotification;

  MockCookieMonsterDelegate();

  const std::vector<CookieNotification>& changes() const { return changes_; }

  void reset() { changes_.clear(); }

  void OnCookieChanged(const CanonicalCookie& cookie,
                       bool removed,
                       CookieMonsterDelegate::ChangeCause cause) override;

 private:
  ~MockCookieMonsterDelegate() override;

  std::vector<CookieNotification> changes_;

  DISALLOW_COPY_AND_ASSIGN(MockCookieMonsterDelegate);
};

// Helper to build a single CanonicalCookie.
std::unique_ptr<CanonicalCookie> BuildCanonicalCookie(
    const GURL& url,
    const std::string& cookie_line,
    const base::Time& creation_time);

// Helper to build a list of CanonicalCookie*s.
void AddCookieToList(const GURL& url,
                     const std::string& cookie_line,
                     const base::Time& creation_time,
                     std::vector<CanonicalCookie*>* out_list);

// Just act like a backing database.  Keep cookie information from
// Add/Update/Delete and regurgitate it when Load is called.
class MockSimplePersistentCookieStore
    : public CookieMonster::PersistentCookieStore {
 public:
  MockSimplePersistentCookieStore();

  void Load(const LoadedCallback& loaded_callback) override;

  void LoadCookiesForKey(const std::string& key,
                         const LoadedCallback& loaded_callback) override;

  void AddCookie(const CanonicalCookie& cookie) override;

  void UpdateCookieAccessTime(const CanonicalCookie& cookie) override;

  void DeleteCookie(const CanonicalCookie& cookie) override;

  void Flush(const base::Closure& callback) override;

  void SetForceKeepSessionState() override;

 protected:
  ~MockSimplePersistentCookieStore() override;

 private:
  typedef std::map<int64_t, CanonicalCookie> CanonicalCookieMap;

  CanonicalCookieMap cookies_;

  // Indicates if the store has been fully loaded to avoid return duplicate
  // cookies in subsequent load requests
  bool loaded_;
};

// Helper function for creating a CookieMonster backed by a
// MockSimplePersistentCookieStore for garbage collection testing.
//
// Fill the store through import with |num_*_cookies| cookies,
// |num_old_*_cookies| with access time Now()-days_old, the rest with access
// time Now(). Cookies made by |num_secure_cookies| and |num_non_secure_cookies|
// will be marked secure and non-secure, respectively. Do two SetCookies().
// Return whether each of the two SetCookies() took longer than |gc_perf_micros|
// to complete, and how many cookie were left in the store afterwards.
std::unique_ptr<CookieMonster> CreateMonsterFromStoreForGC(
    int num_secure_cookies,
    int num_old_secure_cookies,
    int num_non_secure_cookies,
    int num_old_non_secure_cookies,
    int days_old);

}  // namespace net

#endif  // NET_COOKIES_COOKIE_MONSTER_STORE_TEST_H_
