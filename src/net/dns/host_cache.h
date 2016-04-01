// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DNS_HOST_CACHE_H_
#define NET_DNS_HOST_CACHE_H_

#include <stddef.h>

#include <functional>
#include <string>
#include <tuple>

#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "base/threading/non_thread_safe.h"
#include "base/time/time.h"
#include "net/base/address_family.h"
#include "net/base/address_list.h"
#include "net/base/expiring_cache.h"
#include "net/base/net_export.h"

namespace net {

// Cache used by HostResolver to map hostnames to their resolved result.
class NET_EXPORT HostCache : NON_EXPORTED_BASE(public base::NonThreadSafe) {
 public:
  // Stores the latest address list that was looked up for a hostname.
  struct NET_EXPORT Entry {
    Entry(int error, const AddressList& addrlist, base::TimeDelta ttl);
    // Use when |ttl| is unknown.
    Entry(int error, const AddressList& addrlist);
    ~Entry();

    bool has_ttl() const { return ttl >= base::TimeDelta(); }

    // The resolve results for this entry.
    int error;
    AddressList addrlist;
    // TTL obtained from the nameserver. Negative if unknown.
    base::TimeDelta ttl;
  };

  struct Key {
    Key(const std::string& hostname, AddressFamily address_family,
        HostResolverFlags host_resolver_flags)
        : hostname(hostname),
          address_family(address_family),
          host_resolver_flags(host_resolver_flags) {}

    bool operator<(const Key& other) const {
      // The order of comparisons of |Key| fields is arbitrary, thus
      // |address_family| and |host_resolver_flags| are compared before
      // |hostname| under assumption that integer comparisons are faster than
      // string comparisons.
      return std::tie(address_family, host_resolver_flags, hostname) <
             std::tie(other.address_family, other.host_resolver_flags,
                      other.hostname);
    }

    std::string hostname;
    AddressFamily address_family;
    HostResolverFlags host_resolver_flags;
  };

  struct EvictionHandler {
    void Handle(const Key& key,
                const Entry& entry,
                const base::TimeTicks& expiration,
                const base::TimeTicks& now,
                bool onGet) const;
  };

  typedef ExpiringCache<Key, Entry, base::TimeTicks,
                        std::less<base::TimeTicks>,
                        EvictionHandler> EntryMap;

  // Constructs a HostCache that stores up to |max_entries|.
  explicit HostCache(size_t max_entries);

  ~HostCache();

  // Returns a pointer to the entry for |key|, which is valid at time
  // |now|. If there is no such entry, returns NULL.
  const Entry* Lookup(const Key& key, base::TimeTicks now);

  // Overwrites or creates an entry for |key|.
  // |entry| is the value to set, |now| is the current time
  // |ttl| is the "time to live".
  void Set(const Key& key,
           const Entry& entry,
           base::TimeTicks now,
           base::TimeDelta ttl);

  // Empties the cache
  void clear();

  // Returns the number of entries in the cache.
  size_t size() const;

  // Following are used by net_internals UI.
  size_t max_entries() const;

  const EntryMap& entries() const;

  // Creates a default cache.
  static scoped_ptr<HostCache> CreateDefaultCache();

 private:
  FRIEND_TEST_ALL_PREFIXES(HostCacheTest, NoCache);

  // Returns true if this HostCache can contain no entries.
  bool caching_is_disabled() const {
    return entries_.max_entries() == 0;
  }

  // Map from hostname (presumably in lowercase canonicalized format) to
  // a resolved result entry.
  EntryMap entries_;

  DISALLOW_COPY_AND_ASSIGN(HostCache);
};

}  // namespace net

#endif  // NET_DNS_HOST_CACHE_H_
