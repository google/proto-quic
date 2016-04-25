// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_client_session_cache_openssl.h"

#include <utility>

#include "base/time/clock.h"
#include "base/time/default_clock.h"

namespace net {

SSLClientSessionCacheOpenSSL::SSLClientSessionCacheOpenSSL(const Config& config)
    : clock_(new base::DefaultClock),
      config_(config),
      cache_(config.max_entries),
      lookups_since_flush_(0) {
}

SSLClientSessionCacheOpenSSL::~SSLClientSessionCacheOpenSSL() {
  Flush();
}

size_t SSLClientSessionCacheOpenSSL::size() const {
  return cache_.size();
}

ScopedSSL_SESSION SSLClientSessionCacheOpenSSL::Lookup(
    const std::string& cache_key) {
  base::AutoLock lock(lock_);

  // Expire stale sessions.
  lookups_since_flush_++;
  if (lookups_since_flush_ >= config_.expiration_check_count) {
    lookups_since_flush_ = 0;
    FlushExpiredSessions();
  }

  CacheEntryMap::iterator iter = cache_.Get(cache_key);
  if (iter == cache_.end())
    return nullptr;
  if (IsExpired(iter->second.get(), clock_->Now())) {
    cache_.Erase(iter);
    return nullptr;
  }
  return ScopedSSL_SESSION(SSL_SESSION_up_ref(iter->second->session.get()));
}

void SSLClientSessionCacheOpenSSL::Insert(const std::string& cache_key,
                                          SSL_SESSION* session) {
  base::AutoLock lock(lock_);

  // Make a new entry.
  std::unique_ptr<CacheEntry> entry(new CacheEntry);
  entry->session.reset(SSL_SESSION_up_ref(session));
  entry->creation_time = clock_->Now();

  // Takes ownership.
  cache_.Put(cache_key, std::move(entry));
}

void SSLClientSessionCacheOpenSSL::Flush() {
  base::AutoLock lock(lock_);

  cache_.Clear();
}

void SSLClientSessionCacheOpenSSL::SetClockForTesting(
    std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

SSLClientSessionCacheOpenSSL::CacheEntry::CacheEntry() {
}

SSLClientSessionCacheOpenSSL::CacheEntry::~CacheEntry() {
}

bool SSLClientSessionCacheOpenSSL::IsExpired(
    SSLClientSessionCacheOpenSSL::CacheEntry* entry,
    const base::Time& now) {
  return now < entry->creation_time ||
         entry->creation_time + config_.timeout < now;
}

void SSLClientSessionCacheOpenSSL::FlushExpiredSessions() {
  base::Time now = clock_->Now();
  CacheEntryMap::iterator iter = cache_.begin();
  while (iter != cache_.end()) {
    if (IsExpired(iter->second.get(), now)) {
      iter = cache_.Erase(iter);
    } else {
      ++iter;
    }
  }
}

}  // namespace net
