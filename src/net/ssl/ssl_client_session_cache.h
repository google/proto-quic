// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_CLIENT_SESSION_CACHE_H
#define NET_SSL_SSL_CLIENT_SESSION_CACHE_H

#include <openssl/ssl.h>
#include <stddef.h>

#include <memory>
#include <string>

#include "base/containers/mru_cache.h"
#include "base/macros.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/ssl/scoped_openssl_types.h"

namespace base {
class Clock;
}

namespace net {

class NET_EXPORT SSLClientSessionCache {
 public:
  struct Config {
    // The maximum number of entries in the cache.
    size_t max_entries = 1024;
    // The number of calls to Lookup before a new check for expired sessions.
    size_t expiration_check_count = 256;
    // How long each session should last.
    base::TimeDelta timeout = base::TimeDelta::FromHours(1);
  };

  explicit SSLClientSessionCache(const Config& config);
  ~SSLClientSessionCache();

  size_t size() const;

  // Returns the session associated with |cache_key| and moves it to the front
  // of the MRU list. Returns nullptr if there is none.
  ScopedSSL_SESSION Lookup(const std::string& cache_key);

  // Inserts |session| into the cache at |cache_key|. If there is an existing
  // one, it is released. Every |expiration_check_count| calls, the cache is
  // checked for stale entries.
  void Insert(const std::string& cache_key, SSL_SESSION* session);

  // Removes all entries from the cache.
  void Flush();

  void SetClockForTesting(std::unique_ptr<base::Clock> clock);

 private:
  struct CacheEntry {
    CacheEntry();
    ~CacheEntry();

    ScopedSSL_SESSION session;
    // The time at which this entry was created.
    base::Time creation_time;
  };

  using CacheEntryMap =
      base::HashingMRUCache<std::string, std::unique_ptr<CacheEntry>>;

  // Returns true if |entry| is expired as of |now|.
  bool IsExpired(CacheEntry* entry, const base::Time& now);

  // Removes all expired sessions from the cache.
  void FlushExpiredSessions();

  std::unique_ptr<base::Clock> clock_;
  Config config_;
  CacheEntryMap cache_;
  size_t lookups_since_flush_;

  // TODO(davidben): After https://crbug.com/458365 is fixed, replace this with
  // a ThreadChecker. The session cache should be single-threaded like other
  // classes in net.
  base::Lock lock_;

  DISALLOW_COPY_AND_ASSIGN(SSLClientSessionCache);
};

}  // namespace net

#endif  // NET_SSL_SSL_CLIENT_SESSION_CACHE_H
