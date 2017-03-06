// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_client_session_cache.h"

#include <utility>

#include "base/containers/flat_set.h"
#include "base/memory/memory_coordinator_client_registry.h"
#include "base/strings/stringprintf.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"
#include "base/trace_event/process_memory_dump.h"
#include "net/cert/x509_util_openssl.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "third_party/boringssl/src/include/openssl/x509.h"

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
    const std::string& cache_key,
    int* count) {
  base::AutoLock lock(lock_);

  // Expire stale sessions.
  lookups_since_flush_++;
  if (lookups_since_flush_ >= config_.expiration_check_count) {
    lookups_since_flush_ = 0;
    FlushExpiredSessions();
  }

  // Set count to 0 if there's no session in the cache.
  if (count != nullptr)
    *count = 0;

  auto iter = cache_.Get(cache_key);
  if (iter == cache_.end())
    return nullptr;

  SSL_SESSION* session = iter->second.session.get();
  if (IsExpired(session, clock_->Now().ToTimeT())) {
    cache_.Erase(iter);
    return nullptr;
  }

  iter->second.lookups++;
  if (count != nullptr) {
    *count = iter->second.lookups;
  }

  SSL_SESSION_up_ref(session);
  return bssl::UniquePtr<SSL_SESSION>(session);
}

void SSLClientSessionCache::ResetLookupCount(const std::string& cache_key) {
  base::AutoLock lock(lock_);

  // It's possible that the cached session for this key was deleted after the
  // Lookup. If that's the case, don't do anything.
  auto iter = cache_.Get(cache_key);
  if (iter == cache_.end())
    return;

  iter->second.lookups = 0;
}

void SSLClientSessionCache::Insert(const std::string& cache_key,
                                   SSL_SESSION* session) {
  base::AutoLock lock(lock_);

  SSL_SESSION_up_ref(session);
  Entry entry;
  entry.session = bssl::UniquePtr<SSL_SESSION>(session);
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

bool SSLClientSessionCache::IsExpired(SSL_SESSION* session, time_t now) {
  return now < SSL_SESSION_get_time(session) ||
         now >=
             SSL_SESSION_get_time(session) + SSL_SESSION_get_timeout(session);
}

void SSLClientSessionCache::DumpMemoryStats(
    base::trace_event::ProcessMemoryDump* pmd) {
  std::string absolute_name = "net/ssl_session_cache";
  base::trace_event::MemoryAllocatorDump* cache_dump =
      pmd->GetAllocatorDump(absolute_name);
  // This method can be reached from different URLRequestContexts. Since this is
  // a singleton, only log memory stats once.
  // TODO(xunjieli): Change this once crbug.com/458365 is fixed.
  if (cache_dump)
    return;
  cache_dump = pmd->CreateAllocatorDump(absolute_name);
  base::AutoLock lock(lock_);
  size_t cert_size = 0;
  size_t cert_count = 0;
  size_t undeduped_cert_size = 0;
  size_t undeduped_cert_count = 0;
  for (const auto& pair : cache_) {
    undeduped_cert_count +=
        sk_CRYPTO_BUFFER_num(pair.second.session.get()->certs);
  }
  // Use a flat_set here to avoid malloc upon insertion.
  base::flat_set<const CRYPTO_BUFFER*> crypto_buffer_set;
  crypto_buffer_set.reserve(undeduped_cert_count);
  for (const auto& pair : cache_) {
    const SSL_SESSION* session = pair.second.session.get();
    size_t pair_cert_count = sk_CRYPTO_BUFFER_num(session->certs);
    for (size_t i = 0; i < pair_cert_count; ++i) {
      const CRYPTO_BUFFER* cert = sk_CRYPTO_BUFFER_value(session->certs, i);
      // TODO(xunjieli): The multipler is added to account for the difference
      // between the serialized form and real cert allocation. Remove after
      // crbug.com/671420 is done.
      size_t individual_cert_size = 4 * CRYPTO_BUFFER_len(cert);
      undeduped_cert_size += individual_cert_size;
      auto result = crypto_buffer_set.insert(cert);
      if (!result.second)
        continue;
      cert_size += individual_cert_size;
      cert_count++;
    }
  }
  cache_dump->AddScalar(base::trace_event::MemoryAllocatorDump::kNameSize,
                        base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                        cert_size);
  cache_dump->AddScalar("cert_size",
                        base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                        cert_size);
  cache_dump->AddScalar("cert_count",
                        base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                        cert_count);
  cache_dump->AddScalar("undeduped_cert_size",
                        base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                        undeduped_cert_size);
  cache_dump->AddScalar("undeduped_cert_count",
                        base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                        undeduped_cert_count);
}

SSLClientSessionCache::Entry::Entry() : lookups(0) {}
SSLClientSessionCache::Entry::Entry(Entry&&) = default;
SSLClientSessionCache::Entry::~Entry() = default;

void SSLClientSessionCache::FlushExpiredSessions() {
  time_t now = clock_->Now().ToTimeT();
  auto iter = cache_.begin();
  while (iter != cache_.end()) {
    if (IsExpired(iter->second.session.get(), now)) {
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

void SSLClientSessionCache::OnPurgeMemory() {
  Flush();
}

}  // namespace net
