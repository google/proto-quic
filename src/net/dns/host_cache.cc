// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_cache.h"

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/trace_event/trace_event.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/dns/dns_util.h"

namespace net {

namespace {

#define CACHE_HISTOGRAM_TIME(name, time) \
  UMA_HISTOGRAM_LONG_TIMES("DNS.HostCache." name, time)

#define CACHE_HISTOGRAM_COUNT(name, count) \
  UMA_HISTOGRAM_COUNTS_1000("DNS.HostCache." name, count)

#define CACHE_HISTOGRAM_ENUM(name, value, max) \
  UMA_HISTOGRAM_ENUMERATION("DNS.HostCache." name, value, max)

}  // namespace

// Used in histograms; do not modify existing values.
enum HostCache::SetOutcome : int {
  SET_INSERT = 0,
  SET_UPDATE_VALID = 1,
  SET_UPDATE_STALE = 2,
  MAX_SET_OUTCOME
};

// Used in histograms; do not modify existing values.
enum HostCache::LookupOutcome : int {
  LOOKUP_MISS_ABSENT = 0,
  LOOKUP_MISS_STALE = 1,
  LOOKUP_HIT_VALID = 2,
  LOOKUP_HIT_STALE = 3,
  MAX_LOOKUP_OUTCOME
};

// Used in histograms; do not modify existing values.
enum HostCache::EraseReason : int {
  ERASE_EVICT = 0,
  ERASE_CLEAR = 1,
  ERASE_DESTRUCT = 2,
  MAX_ERASE_REASON
};

HostCache::Entry::Entry(int error,
                        const AddressList& addresses,
                        base::TimeDelta ttl)
    : error_(error), addresses_(addresses), ttl_(ttl) {
  DCHECK(ttl >= base::TimeDelta());
}

HostCache::Entry::Entry(int error, const AddressList& addresses)
    : error_(error),
      addresses_(addresses),
      ttl_(base::TimeDelta::FromSeconds(-1)) {}

HostCache::Entry::~Entry() {}

HostCache::Entry::Entry(const HostCache::Entry& entry,
                        base::TimeTicks now,
                        base::TimeDelta ttl,
                        int network_changes)
    : error_(entry.error()),
      addresses_(entry.addresses()),
      ttl_(entry.ttl()),
      expires_(now + ttl),
      network_changes_(network_changes),
      total_hits_(0),
      stale_hits_(0) {}

bool HostCache::Entry::IsStale(base::TimeTicks now, int network_changes) const {
  EntryStaleness stale;
  stale.expired_by = now - expires_;
  stale.network_changes = network_changes - network_changes_;
  stale.stale_hits = stale_hits_;
  return stale.is_stale();
}

void HostCache::Entry::CountHit(bool hit_is_stale) {
  ++total_hits_;
  if (hit_is_stale)
    ++stale_hits_;
}

void HostCache::Entry::GetStaleness(base::TimeTicks now,
                                    int network_changes,
                                    EntryStaleness* out) const {
  DCHECK(out);
  out->expired_by = now - expires_;
  out->network_changes = network_changes - network_changes_;
  out->stale_hits = stale_hits_;
}

HostCache::HostCache(size_t max_entries)
    : max_entries_(max_entries), network_changes_(0) {}

HostCache::~HostCache() {
  RecordEraseAll(ERASE_DESTRUCT, base::TimeTicks::Now());
}

const HostCache::Entry* HostCache::Lookup(const Key& key,
                                          base::TimeTicks now) {
  DCHECK(CalledOnValidThread());
  if (caching_is_disabled())
    return nullptr;

  HostCache::Entry* entry = LookupInternal(key);
  if (!entry) {
    RecordLookup(LOOKUP_MISS_ABSENT, now, nullptr);
    return nullptr;
  }
  if (entry->IsStale(now, network_changes_)) {
    RecordLookup(LOOKUP_MISS_STALE, now, entry);
    return nullptr;
  }

  entry->CountHit(/* hit_is_stale= */ false);
  RecordLookup(LOOKUP_HIT_VALID, now, entry);
  return entry;
}

const HostCache::Entry* HostCache::LookupStale(
    const Key& key,
    base::TimeTicks now,
    HostCache::EntryStaleness* stale_out) {
  DCHECK(CalledOnValidThread());
  if (caching_is_disabled())
    return nullptr;

  HostCache::Entry* entry = LookupInternal(key);
  if (!entry) {
    RecordLookup(LOOKUP_MISS_ABSENT, now, nullptr);
    return nullptr;
  }

  bool is_stale = entry->IsStale(now, network_changes_);
  entry->CountHit(/* hit_is_stale= */ is_stale);
  RecordLookup(is_stale ? LOOKUP_HIT_STALE : LOOKUP_HIT_VALID, now, entry);

  if (stale_out)
    entry->GetStaleness(now, network_changes_, stale_out);
  return entry;
}

HostCache::Entry* HostCache::LookupInternal(const Key& key) {
  auto it = entries_.find(key);
  return (it != entries_.end()) ? &it->second : nullptr;
}

void HostCache::Set(const Key& key,
                    const Entry& entry,
                    base::TimeTicks now,
                    base::TimeDelta ttl) {
  TRACE_EVENT0(kNetTracingCategory, "HostCache::Set");
  DCHECK(CalledOnValidThread());
  if (caching_is_disabled())
    return;

  auto it = entries_.find(key);
  if (it != entries_.end()) {
    bool is_stale = it->second.IsStale(now, network_changes_);
    RecordSet(is_stale ? SET_UPDATE_STALE : SET_UPDATE_VALID, now, &it->second,
              entry);
    // TODO(juliatuttle): Remember some old metadata (hit count or frequency or
    // something like that) if it's useful for better eviction algorithms?
    entries_.erase(it);
  } else {
    if (size() == max_entries_)
      EvictOneEntry(now);
    RecordSet(SET_INSERT, now, nullptr, entry);
  }

  DCHECK_GT(max_entries_, size());
  DCHECK_EQ(0u, entries_.count(key));
  entries_.insert(
      std::make_pair(Key(key), Entry(entry, now, ttl, network_changes_)));
  DCHECK_GE(max_entries_, size());
}

void HostCache::OnNetworkChange() {
  ++network_changes_;
}

void HostCache::clear() {
  DCHECK(CalledOnValidThread());
  RecordEraseAll(ERASE_CLEAR, base::TimeTicks::Now());
  entries_.clear();
}

void HostCache::ClearForHosts(
    const base::Callback<bool(const std::string&)>& host_filter) {
  DCHECK(CalledOnValidThread());

  if (host_filter.is_null()) {
    clear();
    return;
  }

  base::TimeTicks now = base::TimeTicks::Now();
  for (EntryMap::iterator it = entries_.begin(); it != entries_.end();) {
    EntryMap::iterator next_it = std::next(it);

    if (host_filter.Run(it->first.hostname)) {
      RecordErase(ERASE_CLEAR, now, it->second);
      entries_.erase(it);
    }

    it = next_it;
  }
}

size_t HostCache::size() const {
  DCHECK(CalledOnValidThread());
  return entries_.size();
}

size_t HostCache::max_entries() const {
  DCHECK(CalledOnValidThread());
  return max_entries_;
}

// static
std::unique_ptr<HostCache> HostCache::CreateDefaultCache() {
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
  return base::WrapUnique(new HostCache(max_entries));
}

void HostCache::EvictOneEntry(base::TimeTicks now) {
  DCHECK_LT(0u, entries_.size());

  auto oldest_it = entries_.begin();
  for (auto it = entries_.begin(); it != entries_.end(); ++it) {
    if ((it->second.expires() < oldest_it->second.expires()) &&
        (it->second.IsStale(now, network_changes_) ||
         !oldest_it->second.IsStale(now, network_changes_))) {
      oldest_it = it;
    }
  }

  if (!eviction_callback_.is_null())
    eviction_callback_.Run(oldest_it->first, oldest_it->second);
  RecordErase(ERASE_EVICT, now, oldest_it->second);
  entries_.erase(oldest_it);
}

void HostCache::RecordSet(SetOutcome outcome,
                          base::TimeTicks now,
                          const Entry* old_entry,
                          const Entry& new_entry) {
  CACHE_HISTOGRAM_ENUM("Set", outcome, MAX_SET_OUTCOME);
  switch (outcome) {
    case SET_INSERT:
    case SET_UPDATE_VALID:
      // Nothing to log here.
      break;
    case SET_UPDATE_STALE: {
      EntryStaleness stale;
      old_entry->GetStaleness(now, network_changes_, &stale);
      CACHE_HISTOGRAM_TIME("UpdateStale.ExpiredBy", stale.expired_by);
      CACHE_HISTOGRAM_COUNT("UpdateStale.NetworkChanges",
                            stale.network_changes);
      CACHE_HISTOGRAM_COUNT("UpdateStale.StaleHits", stale.stale_hits);
      if (old_entry->error() == OK && new_entry.error() == OK) {
        AddressListDeltaType delta = FindAddressListDeltaType(
            old_entry->addresses(), new_entry.addresses());
        RecordUpdateStale(delta, stale);
      }
      break;
    }
    case MAX_SET_OUTCOME:
      NOTREACHED();
      break;
  }
}

void HostCache::RecordUpdateStale(AddressListDeltaType delta,
                                  const EntryStaleness& stale) {
  CACHE_HISTOGRAM_ENUM("UpdateStale.AddressListDelta", delta, MAX_DELTA_TYPE);
  switch (delta) {
    case DELTA_IDENTICAL:
      CACHE_HISTOGRAM_TIME("UpdateStale.ExpiredBy_Identical", stale.expired_by);
      CACHE_HISTOGRAM_COUNT("UpdateStale.NetworkChanges_Identical",
                            stale.network_changes);
      break;
    case DELTA_REORDERED:
      CACHE_HISTOGRAM_TIME("UpdateStale.ExpiredBy_Reordered", stale.expired_by);
      CACHE_HISTOGRAM_COUNT("UpdateStale.NetworkChanges_Reordered",
                            stale.network_changes);
      break;
    case DELTA_OVERLAP:
      CACHE_HISTOGRAM_TIME("UpdateStale.ExpiredBy_Overlap", stale.expired_by);
      CACHE_HISTOGRAM_COUNT("UpdateStale.NetworkChanges_Overlap",
                            stale.network_changes);
      break;
    case DELTA_DISJOINT:
      CACHE_HISTOGRAM_TIME("UpdateStale.ExpiredBy_Disjoint", stale.expired_by);
      CACHE_HISTOGRAM_COUNT("UpdateStale.NetworkChanges_Disjoint",
                            stale.network_changes);
      break;
    case MAX_DELTA_TYPE:
      NOTREACHED();
      break;
  }
}

void HostCache::RecordLookup(LookupOutcome outcome,
                             base::TimeTicks now,
                             const Entry* entry) {
  CACHE_HISTOGRAM_ENUM("Lookup", outcome, MAX_LOOKUP_OUTCOME);
  switch (outcome) {
    case LOOKUP_MISS_ABSENT:
    case LOOKUP_MISS_STALE:
    case LOOKUP_HIT_VALID:
      // Nothing to log here.
      break;
    case LOOKUP_HIT_STALE:
      CACHE_HISTOGRAM_TIME("LookupStale.ExpiredBy", now - entry->expires());
      CACHE_HISTOGRAM_COUNT("LookupStale.NetworkChanges",
                            network_changes_ - entry->network_changes());
      break;
    case MAX_LOOKUP_OUTCOME:
      NOTREACHED();
      break;
  }
}

void HostCache::RecordErase(EraseReason reason,
                            base::TimeTicks now,
                            const Entry& entry) {
  HostCache::EntryStaleness stale;
  entry.GetStaleness(now, network_changes_, &stale);
  CACHE_HISTOGRAM_ENUM("Erase", reason, MAX_ERASE_REASON);
  if (stale.is_stale()) {
    CACHE_HISTOGRAM_TIME("EraseStale.ExpiredBy", stale.expired_by);
    CACHE_HISTOGRAM_COUNT("EraseStale.NetworkChanges", stale.network_changes);
    CACHE_HISTOGRAM_COUNT("EraseStale.StaleHits", entry.stale_hits());
  } else {
    CACHE_HISTOGRAM_TIME("EraseValid.ValidFor", -stale.expired_by);
  }
}

void HostCache::RecordEraseAll(EraseReason reason, base::TimeTicks now) {
  for (const auto& it : entries_)
    RecordErase(reason, now, it.second);
}

}  // namespace net
