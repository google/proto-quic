// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_client_session_cache.h"

#include <utility>

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
  for (const auto& pair : cache_) {
    auto entry = pair.second.get();
    auto cert_chain = entry->x509_chain;
    size_t cert_count = sk_X509_num(cert_chain);
    base::trace_event::MemoryAllocatorDump* entry_dump =
        pmd->CreateAllocatorDump(
            base::StringPrintf("%s/entry_%p", absolute_name.c_str(), entry));
    int cert_size = 0;
    for (size_t i = 0; i < cert_count; ++i) {
      X509* cert = sk_X509_value(cert_chain, i);
      cert_size += i2d_X509(cert, nullptr);
    }
    // This measures the lower bound of the serialized certificate. It doesn't
    // measure the actual memory used, which is 4x this amount (see
    // crbug.com/671420 for more details).
    entry_dump->AddScalar("cert_size",
                          base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                          cert_size);
    entry_dump->AddScalar("serialized_cert_count",
                          base::trace_event::MemoryAllocatorDump::kUnitsObjects,
                          cert_count);
    entry_dump->AddScalar(base::trace_event::MemoryAllocatorDump::kNameSize,
                          base::trace_event::MemoryAllocatorDump::kUnitsBytes,
                          cert_size);
  }
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
