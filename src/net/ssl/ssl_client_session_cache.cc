// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_client_session_cache.h"

#include <utility>

#include "base/memory/memory_coordinator_client_registry.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"

namespace net {

SSLClientSessionCache::SSLClientSessionCache(const Config& config)
    : clock_(new base::DefaultClock),
      config_(config),
      cache_(config.max_entries),
      lookups_since_flush_(0) {
  memory_pressure_listener_.reset(new base::MemoryPressureListener(base::Bind(
      &SSLClientSessionCache::OnMemoryPressure, base::Unretained(this))));
  base::MemoryCoordinatorClientRegistry::GetInstance()->Register(this);
}

SSLClientSessionCache::~SSLClientSessionCache() {
  Flush();
  base::MemoryCoordinatorClientRegistry::GetInstance()->Unregister(this);
}

size_t SSLClientSessionCache::size() const {
  return cache_.size();
}

ScopedSSL_SESSION SSLClientSessionCache::Lookup(const std::string& cache_key) {
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

  SSL_SESSION* session = iter->second->session.get();
  SSL_SESSION_up_ref(session);
  return ScopedSSL_SESSION(session);
}

void SSLClientSessionCache::Insert(const std::string& cache_key,
                                   SSL_SESSION* session) {
  base::AutoLock lock(lock_);

  // Make a new entry.
  std::unique_ptr<CacheEntry> entry(new CacheEntry);
  SSL_SESSION_up_ref(session);
  entry->session.reset(session);
  entry->creation_time = clock_->Now();

  // Takes ownership.
  cache_.Put(cache_key, std::move(entry));
}

void SSLClientSessionCache::Flush() {
  base::AutoLock lock(lock_);

  cache_.Clear();
}

void SSLClientSessionCache::SetClockForTesting(
    std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

SSLClientSessionCache::CacheEntry::CacheEntry() {}

SSLClientSessionCache::CacheEntry::~CacheEntry() {}

bool SSLClientSessionCache::IsExpired(SSLClientSessionCache::CacheEntry* entry,
                                      const base::Time& now) {
  return now < entry->creation_time ||
         entry->creation_time + config_.timeout < now;
}

void SSLClientSessionCache::FlushExpiredSessions() {
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

void SSLClientSessionCache::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level) {
  switch (memory_pressure_level) {
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE:
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE:
      FlushExpiredSessions();
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL:
      Flush();
      break;
  }
}

void SSLClientSessionCache::OnMemoryStateChange(base::MemoryState state) {
  // TODO(hajimehoshi): When the state changes, adjust the sizes of the caches
  // to reduce the limits. SSLClientSessionCache doesn't have the ability to
  // limit at present.
  switch (state) {
    case base::MemoryState::NORMAL:
      break;
    case base::MemoryState::THROTTLED:
      Flush();
      break;
    case base::MemoryState::SUSPENDED:
    // Note: Not supported at present. Fall through.
    case base::MemoryState::UNKNOWN:
      NOTREACHED();
      break;
  }
}

}  // namespace net
