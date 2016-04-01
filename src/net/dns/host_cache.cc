// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_cache.h"

#include "base/logging.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/net_errors.h"

namespace net {

//-----------------------------------------------------------------------------

HostCache::Entry::Entry(int error, const AddressList& addrlist,
                        base::TimeDelta ttl)
    : error(error),
      addrlist(addrlist),
      ttl(ttl) {
  DCHECK(ttl >= base::TimeDelta());
}

HostCache::Entry::Entry(int error, const AddressList& addrlist)
    : error(error),
      addrlist(addrlist),
      ttl(base::TimeDelta::FromSeconds(-1)) {
}

HostCache::Entry::~Entry() {
}

//-----------------------------------------------------------------------------

HostCache::HostCache(size_t max_entries)
    : entries_(max_entries) {
}

HostCache::~HostCache() {
}

const HostCache::Entry* HostCache::Lookup(const Key& key,
                                          base::TimeTicks now) {
  DCHECK(CalledOnValidThread());
  if (caching_is_disabled())
    return NULL;

  return entries_.Get(key, now);
}

void HostCache::Set(const Key& key,
                    const Entry& entry,
                    base::TimeTicks now,
                    base::TimeDelta ttl) {
  DCHECK(CalledOnValidThread());
  if (caching_is_disabled())
    return;

  entries_.Put(key, entry, now, now + ttl);
}

void HostCache::clear() {
  DCHECK(CalledOnValidThread());
  entries_.Clear();
}

size_t HostCache::size() const {
  DCHECK(CalledOnValidThread());
  return entries_.size();
}

size_t HostCache::max_entries() const {
  DCHECK(CalledOnValidThread());
  return entries_.max_entries();
}

// Note that this map may contain expired entries.
const HostCache::EntryMap& HostCache::entries() const {
  DCHECK(CalledOnValidThread());
  return entries_;
}

// static
scoped_ptr<HostCache> HostCache::CreateDefaultCache() {
  // Cache capacity is determined by the field trial.
#if defined(ENABLE_BUILT_IN_DNS)
  const size_t kDefaultMaxEntries = 1000;
#else
  const size_t kDefaultMaxEntries = 100;
#endif
  const size_t kSaneMaxEntries = 1 << 20;
  size_t max_entries = 0;
  base::StringToSizeT(base::FieldTrialList::FindFullName("HostCacheSize"),
                      &max_entries);
  if ((max_entries == 0) || (max_entries > kSaneMaxEntries))
    max_entries = kDefaultMaxEntries;
  return make_scoped_ptr(new HostCache(max_entries));
}

void HostCache::EvictionHandler::Handle(
    const Key& key,
    const Entry& entry,
    const base::TimeTicks& expiration,
    const base::TimeTicks& now,
    bool on_get) const {
  if (on_get) {
    DCHECK(now >= expiration);
    UMA_HISTOGRAM_CUSTOM_TIMES("DNS.CacheExpiredOnGet", now - expiration,
        base::TimeDelta::FromSeconds(1), base::TimeDelta::FromDays(1), 100);
    return;
  }
  if (expiration > now) {
    UMA_HISTOGRAM_CUSTOM_TIMES("DNS.CacheEvicted", expiration - now,
        base::TimeDelta::FromSeconds(1), base::TimeDelta::FromDays(1), 100);
  } else {
    UMA_HISTOGRAM_CUSTOM_TIMES("DNS.CacheExpired", now - expiration,
        base::TimeDelta::FromSeconds(1), base::TimeDelta::FromDays(1), 100);
  }
}

}  // namespace net
