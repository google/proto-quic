// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_client_session_cache.h"

#include <utility>

#include "base/memory/memory_coordinator_client_registry.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

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

bssl::UniquePtr<SSL_SESSION> SSLClientSessionCache::Lookup(
    const std::string& cache_key) {
  base::AutoLock lock(lock_);

  // Expire stale sessions.
  lookups_since_flush_++;
  if (lookups_since_flush_ >= config_.expiration_check_count) {
    lookups_since_flush_ = 0;
    FlushExpiredSessions();
  }

  auto iter = cache_.Get(cache_key);
  if (iter == cache_.end())
    return nullptr;

  SSL_SESSION* session = iter->second.get();
  if (IsExpired(session, clock_->Now().ToTimeT())) {
    cache_.Erase(iter);
    return nullptr;
  }

  SSL_SESSION_up_ref(session);
  return bssl::UniquePtr<SSL_SESSION>(session);
}

void SSLClientSessionCache::Insert(const std::string& cache_key,
                                   SSL_SESSION* session) {
  base::AutoLock lock(lock_);

  SSL_SESSION_up_ref(session);
  cache_.Put(cache_key, bssl::UniquePtr<SSL_SESSION>(session));
}

void SSLClientSessionCache::Flush() {
  base::AutoLock lock(lock_);

  cache_.Clear();
}

void SSLClientSessionCache::SetClockForTesting(
    std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

bool SSLClientSessionCache::IsExpired(SSL_SESSION* session, time_t now) {
  return now < SSL_SESSION_get_time(session) ||
         now >=
             SSL_SESSION_get_time(session) + SSL_SESSION_get_timeout(session);
}

void SSLClientSessionCache::FlushExpiredSessions() {
  time_t now = clock_->Now().ToTimeT();
  auto iter = cache_.begin();
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
