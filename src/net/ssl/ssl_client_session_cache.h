// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_CLIENT_SESSION_CACHE_H_
#define NET_SSL_SSL_CLIENT_SESSION_CACHE_H_

#include <stddef.h>
#include <time.h>

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/containers/mru_cache.h"
#include "base/macros.h"
#include "base/memory/memory_coordinator_client.h"
#include "base/memory/memory_pressure_monitor.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "third_party/boringssl/src/include/openssl/base.h"

namespace base {
class Clock;
namespace trace_event {
class ProcessMemoryDump;
}
}

namespace net {

class NET_EXPORT SSLClientSessionCache : public base::MemoryCoordinatorClient {
 public:
  struct Config {
    // The maximum number of entries in the cache.
    size_t max_entries = 1024;
    // The number of calls to Lookup before a new check for expired sessions.
    size_t expiration_check_count = 256;
  };

  explicit SSLClientSessionCache(const Config& config);
  ~SSLClientSessionCache() override;

  size_t size() const;

  // Returns the session associated with |cache_key| and moves it to the front
  // of the MRU list. Returns nullptr if there is none. If |count| is non-null,
  // |*count| will contain the number of times this session has been looked up
  // (including this call).
  bssl::UniquePtr<SSL_SESSION> Lookup(const std::string& cache_key, int* count);

  // Resets the count returned by Lookup to 0 for the session associated with
  // |cache_key|.
  void ResetLookupCount(const std::string& cache_key);

  // Inserts |session| into the cache at |cache_key|. If there is an existing
  // one, it is released. Every |expiration_check_count| calls, the cache is
  // checked for stale entries.
  void Insert(const std::string& cache_key, SSL_SESSION* session);

  // Removes all entries from the cache.
  void Flush();

  void SetClockForTesting(std::unique_ptr<base::Clock> clock);

  // Dumps memory allocation stats. |pmd| is the ProcessMemoryDump of the
  // browser process.
  void DumpMemoryStats(base::trace_event::ProcessMemoryDump* pmd);

 private:
  struct Entry {
    Entry();
    Entry(Entry&&);
    ~Entry();

    int lookups;
    bssl::UniquePtr<SSL_SESSION> session;
  };

  // base::MemoryCoordinatorClient implementation:
  void OnPurgeMemory() override;

  // Returns true if |entry| is expired as of |now|.
  bool IsExpired(SSL_SESSION* session, time_t now);

  // Removes all expired sessions from the cache.
  void FlushExpiredSessions();

  // Clear cache on low memory notifications callback.
  void OnMemoryPressure(
      base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level);

  std::unique_ptr<base::Clock> clock_;
  Config config_;
  base::HashingMRUCache<std::string, Entry> cache_;
  size_t lookups_since_flush_;

  // TODO(davidben): After https://crbug.com/458365 is fixed, replace this with
  // a ThreadChecker. The session cache should be single-threaded like other
  // classes in net.
  base::Lock lock_;

  std::unique_ptr<base::MemoryPressureListener> memory_pressure_listener_;

  DISALLOW_COPY_AND_ASSIGN(SSLClientSessionCache);
};

}  // namespace net

#endif  // NET_SSL_SSL_CLIENT_SESSION_CACHE_H_
