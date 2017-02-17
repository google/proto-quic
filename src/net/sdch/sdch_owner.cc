// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/sdch/sdch_owner.h"

#include <utility>

#include "base/bind.h"
#include "base/debug/alias.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/memory_coordinator_client_registry.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/time/default_clock.h"
#include "base/values.h"
#include "net/base/sdch_manager.h"
#include "net/base/sdch_net_log_params.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"

namespace net {

namespace {

// Dictionaries that haven't been touched in 24 hours may be evicted
// to make room for new dictionaries.
const int kFreshnessLifetimeHours = 24;

// Dictionaries that have never been used only stay fresh for one hour.
const int kNeverUsedFreshnessLifetimeHours = 1;

void RecordPersistenceFailure(
    SdchOwner::PrefStorage::ReadError failure_reason) {
  UMA_HISTOGRAM_ENUMERATION(
      "Sdch3.PersistenceFailureReason", failure_reason,
      SdchOwner::PrefStorage::PERSISTENCE_FAILURE_REASON_MAX);
}

// Schema specifications and access routines.

// The persistent prefs store is conceptually shared with any other network
// stack systems that want to persist data over browser restarts, and so
// use of it must be namespace restricted.
// Schema:
//      pref_store_->GetValue() -> Dictionary {
//          'version' -> 2 [int]
//          'dictionaries' -> Dictionary {
//              server_hash -> {
//                  'url' -> URL [string]
//                  'last_used' -> seconds since unix epoch [double]
//                  'created_time' -> seconds since unix epoch [double]
//                  'use_count' -> use count [int]
//                  'size' -> size [int]
//          }
//      }
const char kVersionKey[] = "version";
const char kDictionariesKey[] = "dictionaries";
const char kDictionaryUrlKey[] = "url";
const char kDictionaryLastUsedKey[] = "last_used";
const char kDictionaryCreatedTimeKey[] = "created_time";
const char kDictionaryUseCountKey[] = "use_count";
const char kDictionarySizeKey[] = "size";

const int kVersion = 2;

// A simple implementation of pref storage that just stores the value in
// memory.
class ValueMapPrefStorage : public SdchOwner::PrefStorage {
 public:
  ValueMapPrefStorage() {}
  ~ValueMapPrefStorage() override {}

  ReadError GetReadError() const override { return PERSISTENCE_FAILURE_NONE; }

  bool GetValue(const base::DictionaryValue** result) const override {
    *result = &storage_;
    return true;
  }
  bool GetMutableValue(base::DictionaryValue** result) override {
    *result = &storage_;
    return true;
  }
  void SetValue(std::unique_ptr<base::DictionaryValue> value) override {
    storage_.Clear();
    storage_.MergeDictionary(value.get());
  }

  void ReportValueChanged() override {}

  // This storage class requires no special initialization.
  bool IsInitializationComplete() override { return true; }
  void StartObservingInit(SdchOwner* observer) override {}
  void StopObservingInit() override {}

 private:
  base::DictionaryValue storage_;

  DISALLOW_COPY_AND_ASSIGN(ValueMapPrefStorage);
};

// This function returns store[kPreferenceName/kDictionariesKey].  The caller
// is responsible for making sure any needed calls to
// |store->ReportValueChanged()| occur.
base::DictionaryValue* GetPersistentStoreDictionaryMap(
    SdchOwner::PrefStorage* store) {
  base::DictionaryValue* preference_dictionary = nullptr;
  bool success = store->GetMutableValue(&preference_dictionary);
  DCHECK(success);

  base::DictionaryValue* dictionary_list_dictionary = nullptr;
  success = preference_dictionary->GetDictionary(kDictionariesKey,
                                                 &dictionary_list_dictionary);
  DCHECK(success);
  DCHECK(dictionary_list_dictionary);

  return dictionary_list_dictionary;
}

// This function initializes a pref store with an empty version of the
// above schema, removing anything previously in the store under
// kPreferenceName.
void InitializePrefStore(SdchOwner::PrefStorage* store) {
  std::unique_ptr<base::DictionaryValue> empty_store(new base::DictionaryValue);
  empty_store->SetInteger(kVersionKey, kVersion);
  empty_store->Set(kDictionariesKey,
                   base::WrapUnique(new base::DictionaryValue));
  store->SetValue(std::move(empty_store));
}

// A class to allow iteration over all dictionaries in the pref store, and
// easy lookup of the information associated with those dictionaries.
// Note that this is an "Iterator" in the same sense (and for the same
// reasons) that base::Dictionary::Iterator is an iterator--it allows
// iterating over all the dictionaries in the preference store, but it
// does not allow use as an STL iterator because the container it
// is iterating over does not export begin()/end() methods. This iterator can
// only be safely used on sanitized pref stores that are known to conform to the
// pref store schema.
class DictionaryPreferenceIterator {
 public:
  explicit DictionaryPreferenceIterator(SdchOwner::PrefStorage* pref_store);

  bool IsAtEnd() const;
  void Advance();

  const std::string& server_hash() const { return server_hash_; }
  const GURL& url() const { return url_; }
  base::Time last_used() const { return last_used_; }
  base::Time created_time() const { return created_time_; }
  int use_count() const { return use_count_; }
  int size() const { return size_; }

 private:
  // Load Dictionary silently skipping any that are malformed.
  void LoadNextDictionary();
  // Try to load Dictionary from current iterator's position. Returns true if
  // succeeded.
  bool TryLoadDictionary();

  std::string server_hash_;
  GURL url_;
  base::Time last_used_;
  base::Time created_time_;
  int use_count_;
  int size_;

  base::DictionaryValue::Iterator dictionary_iterator_;
};

DictionaryPreferenceIterator::DictionaryPreferenceIterator(
    SdchOwner::PrefStorage* pref_store)
    : use_count_(0),
      size_(0),
      dictionary_iterator_(*GetPersistentStoreDictionaryMap(pref_store)) {
  LoadNextDictionary();
}

bool DictionaryPreferenceIterator::IsAtEnd() const {
  return dictionary_iterator_.IsAtEnd();
}

void DictionaryPreferenceIterator::Advance() {
  dictionary_iterator_.Advance();
  LoadNextDictionary();
}

void DictionaryPreferenceIterator::LoadNextDictionary() {
  while (!IsAtEnd()) {
    if (TryLoadDictionary())
      return;
    dictionary_iterator_.Advance();
  }
}

bool DictionaryPreferenceIterator::TryLoadDictionary() {
  const base::DictionaryValue* dict = nullptr;

  bool success = dictionary_iterator_.value().GetAsDictionary(&dict);
  if (!success)
    return false;

  server_hash_ = dictionary_iterator_.key();

  std::string url_spec;
  success = dict->GetString(kDictionaryUrlKey, &url_spec);
  if (!success)
    return false;
  url_ = GURL(url_spec);

  double last_used_seconds_from_epoch = 0;
  success =
      dict->GetDouble(kDictionaryLastUsedKey, &last_used_seconds_from_epoch);
  if (!success)
    return false;
  last_used_ = base::Time::FromDoubleT(last_used_seconds_from_epoch);

  success = dict->GetInteger(kDictionaryUseCountKey, &use_count_);
  if (!success)
    return false;

  success = dict->GetInteger(kDictionarySizeKey, &size_);
  if (!success)
    return false;

  double created_time_seconds = 0;
  success = dict->GetDouble(kDictionaryCreatedTimeKey, &created_time_seconds);
  if (!success)
    return false;
  created_time_ = base::Time::FromDoubleT(created_time_seconds);

  return true;
}

// Triggers a ReportValueChanged() when the object goes out of scope.
class ScopedPrefNotifier {
 public:
  // Caller must guarantee lifetime of |*pref_store| exceeds the
  // lifetime of this object.
  ScopedPrefNotifier(SdchOwner::PrefStorage* pref_store)
      : pref_store_(pref_store) {
    DCHECK(pref_store);
  }
  ~ScopedPrefNotifier() { pref_store_->ReportValueChanged(); }

 private:
  SdchOwner::PrefStorage* pref_store_;

  DISALLOW_COPY_AND_ASSIGN(ScopedPrefNotifier);
};

}  // namespace

// Adjust SDCH limits downwards for mobile.
#if defined(OS_ANDROID) || defined(OS_IOS)
// static
const size_t SdchOwner::kMaxTotalDictionarySize = 2 * 500 * 1000;
#else
// static
const size_t SdchOwner::kMaxTotalDictionarySize = 20 * 1000 * 1000;
#endif

SdchOwner::PrefStorage::~PrefStorage() {}

// Somewhat arbitrary, but we assume a dictionary smaller than
// 50K isn't going to do anyone any good.  Note that this still doesn't
// prevent download and addition unless there is less than this
// amount of space available in storage.
const size_t SdchOwner::kMinSpaceForDictionaryFetch = 50 * 1000;

void SdchOwner::RecordDictionaryFate(enum DictionaryFate fate) {
  UMA_HISTOGRAM_ENUMERATION("Sdch3.DictionaryFate", fate, DICTIONARY_FATE_MAX);
}

void SdchOwner::RecordDictionaryEvictionOrUnload(const std::string& server_hash,
                                                 size_t size,
                                                 int use_count,
                                                 DictionaryFate fate) {
  DCHECK(fate == DICTIONARY_FATE_EVICT_FOR_DICT ||
         fate == DICTIONARY_FATE_EVICT_FOR_MEMORY ||
         fate == DICTIONARY_FATE_EVICT_FOR_DESTRUCTION ||
         fate == DICTIONARY_FATE_UNLOAD_FOR_DESTRUCTION);

  UMA_HISTOGRAM_COUNTS_100("Sdch3.DictionaryUseCount", use_count);
  RecordDictionaryFate(fate);

  DCHECK(load_times_.count(server_hash) == 1);
  base::Time now = clock_->Now();
  base::TimeDelta dict_lifetime = now - load_times_[server_hash];
  consumed_byte_seconds_.push_back(size * dict_lifetime.InMilliseconds());
  load_times_.erase(server_hash);
}

SdchOwner::SdchOwner(SdchManager* sdch_manager, URLRequestContext* context)
    : manager_(sdch_manager),
      fetcher_(new SdchDictionaryFetcher(context)),
      total_dictionary_bytes_(0),
      clock_(new base::DefaultClock),
      max_total_dictionary_size_(kMaxTotalDictionarySize),
      min_space_for_dictionary_fetch_(kMinSpaceForDictionaryFetch),
      memory_pressure_listener_(
          base::Bind(&SdchOwner::OnMemoryPressure,
                     // Because |memory_pressure_listener_| is owned by
                     // SdchOwner, the SdchOwner object will be available
                     // for the lifetime of |memory_pressure_listener_|.
                     base::Unretained(this))),
      in_memory_pref_store_(new ValueMapPrefStorage()),
      external_pref_store_(nullptr),
      pref_store_(in_memory_pref_store_.get()),
      creation_time_(clock_->Now()) {
  manager_->AddObserver(this);
  InitializePrefStore(pref_store_);
  base::MemoryCoordinatorClientRegistry::GetInstance()->Register(this);
}

SdchOwner::~SdchOwner() {
  for (DictionaryPreferenceIterator it(pref_store_); !it.IsAtEnd();
       it.Advance()) {
    int new_uses = it.use_count() - use_counts_at_load_[it.server_hash()];
    DictionaryFate fate = IsPersistingDictionaries() ?
                          DICTIONARY_FATE_UNLOAD_FOR_DESTRUCTION :
                          DICTIONARY_FATE_EVICT_FOR_DESTRUCTION;
    RecordDictionaryEvictionOrUnload(it.server_hash(), it.size(), new_uses,
                                     fate);
  }
  manager_->RemoveObserver(this);

  // This object only observes the external store during loading,
  // i.e. before it's made the default preferences store.
  if (external_pref_store_ && pref_store_ != external_pref_store_.get())
    external_pref_store_->StopObservingInit();

  int64_t object_lifetime = (clock_->Now() - creation_time_).InMilliseconds();
  for (const auto& val : consumed_byte_seconds_) {
    if (object_lifetime > 0) {
      // Objects that are created and immediately destroyed don't add any memory
      // pressure over time (and also cause a crash here).
      UMA_HISTOGRAM_MEMORY_KB("Sdch3.TimeWeightedMemoryUse",
                              val / object_lifetime);
    }
  }
  base::MemoryCoordinatorClientRegistry::GetInstance()->Unregister(this);
}

void SdchOwner::EnablePersistentStorage(
    std::unique_ptr<PrefStorage> pref_store) {
  DCHECK(!external_pref_store_);
  DCHECK(pref_store);
  external_pref_store_ = std::move(pref_store);
  external_pref_store_->StartObservingInit(this);

  if (external_pref_store_->IsInitializationComplete())
    OnPrefStorageInitializationComplete(true);
}

void SdchOwner::SetMaxTotalDictionarySize(size_t max_total_dictionary_size) {
  max_total_dictionary_size_ = max_total_dictionary_size;
}

void SdchOwner::SetMinSpaceForDictionaryFetch(
    size_t min_space_for_dictionary_fetch) {
  min_space_for_dictionary_fetch_ = min_space_for_dictionary_fetch;
}

void SdchOwner::OnDictionaryFetched(base::Time last_used,
                                    base::Time created_time,
                                    int use_count,
                                    const std::string& dictionary_text,
                                    const GURL& dictionary_url,
                                    const NetLogWithSource& net_log,
                                    bool was_from_cache) {
  struct DictionaryItem {
    base::Time last_used;
    std::string server_hash;
    int use_count;
    size_t dictionary_size;

    DictionaryItem() : use_count(0), dictionary_size(0) {}
    DictionaryItem(const base::Time& last_used,
                   const std::string& server_hash,
                   int use_count,
                   size_t dictionary_size)
        : last_used(last_used),
          server_hash(server_hash),
          use_count(use_count),
          dictionary_size(dictionary_size) {}
    DictionaryItem(const DictionaryItem& rhs) = default;
    DictionaryItem& operator=(const DictionaryItem& rhs) = default;
    bool operator<(const DictionaryItem& rhs) const {
      return last_used < rhs.last_used;
    }
  };

  if (!was_from_cache)
    UMA_HISTOGRAM_COUNTS("Sdch3.NetworkBytesSpent", dictionary_text.size());

  // Figure out if there is space for the incoming dictionary; evict
  // stale dictionaries if needed to make space.

  std::vector<DictionaryItem> stale_dictionary_list;
  size_t recoverable_bytes = 0;
  base::Time now(clock_->Now());
  // Dictionaries whose last used time is before |stale_boundary| are candidates
  // for eviction if necessary.
  base::Time stale_boundary(
      now - base::TimeDelta::FromHours(kFreshnessLifetimeHours));
  // Dictionaries that have never been used and are from before
  // |never_used_stale_boundary| are candidates for eviction if necessary.
  base::Time never_used_stale_boundary(
      now - base::TimeDelta::FromHours(kNeverUsedFreshnessLifetimeHours));
  for (DictionaryPreferenceIterator it(pref_store_); !it.IsAtEnd();
       it.Advance()) {
    if (it.last_used() < stale_boundary ||
        (it.use_count() == 0 && it.last_used() < never_used_stale_boundary)) {
      stale_dictionary_list.push_back(DictionaryItem(
          it.last_used(), it.server_hash(), it.use_count(), it.size()));
      recoverable_bytes += it.size();
    }
  }

  if (total_dictionary_bytes_ + dictionary_text.size() - recoverable_bytes >
      max_total_dictionary_size_) {
    RecordDictionaryFate(DICTIONARY_FATE_FETCH_IGNORED_NO_SPACE);
    SdchManager::SdchErrorRecovery(SDCH_DICTIONARY_NO_ROOM);
    net_log.AddEvent(NetLogEventType::SDCH_DICTIONARY_ERROR,
                     base::Bind(&NetLogSdchDictionaryFetchProblemCallback,
                                SDCH_DICTIONARY_NO_ROOM, dictionary_url, true));
    return;
  }

  // Add the new dictionary.  This is done before removing the stale
  // dictionaries so that no state change will occur if dictionary addition
  // fails.
  std::string server_hash;
  SdchProblemCode rv = manager_->AddSdchDictionary(
      dictionary_text, dictionary_url, &server_hash);
  if (rv != SDCH_OK) {
    RecordDictionaryFate(DICTIONARY_FATE_FETCH_MANAGER_REFUSED);
    SdchManager::SdchErrorRecovery(rv);
    net_log.AddEvent(NetLogEventType::SDCH_DICTIONARY_ERROR,
                     base::Bind(&NetLogSdchDictionaryFetchProblemCallback, rv,
                                dictionary_url, true));
    return;
  }

  base::DictionaryValue* pref_dictionary_map =
      GetPersistentStoreDictionaryMap(pref_store_);
  ScopedPrefNotifier scoped_pref_notifier(pref_store_);

  // Remove the old dictionaries.
  std::sort(stale_dictionary_list.begin(), stale_dictionary_list.end());
  size_t avail_bytes = max_total_dictionary_size_ - total_dictionary_bytes_;
  auto stale_it = stale_dictionary_list.begin();
  while (avail_bytes < dictionary_text.size() &&
         stale_it != stale_dictionary_list.end()) {
    manager_->RemoveSdchDictionary(stale_it->server_hash);

    DCHECK(pref_dictionary_map->HasKey(stale_it->server_hash));
    bool success = pref_dictionary_map->RemoveWithoutPathExpansion(
        stale_it->server_hash, nullptr);
    DCHECK(success);

    avail_bytes += stale_it->dictionary_size;

    int new_uses = stale_it->use_count -
        use_counts_at_load_[stale_it->server_hash];
    RecordDictionaryEvictionOrUnload(stale_it->server_hash,
                                     stale_it->dictionary_size,
                                     new_uses,
                                     DICTIONARY_FATE_EVICT_FOR_DICT);

    ++stale_it;
  }
  DCHECK_GE(avail_bytes, dictionary_text.size());

  RecordDictionaryFate(
      // Distinguish between loads triggered by network responses and
      // loads triggered by persistence.
      last_used.is_null() ? DICTIONARY_FATE_ADD_RESPONSE_TRIGGERED
                          : DICTIONARY_FATE_ADD_PERSISTENCE_TRIGGERED);

  // If a dictionary has never been used, its dictionary addition time
  // is recorded as its last used time.  Never used dictionaries are treated
  // specially in the freshness logic.
  if (last_used.is_null())
    last_used = clock_->Now();

  total_dictionary_bytes_ += dictionary_text.size();

  // Record the addition in the pref store.
  std::unique_ptr<base::DictionaryValue> dictionary_description(
      new base::DictionaryValue());
  dictionary_description->SetString(kDictionaryUrlKey, dictionary_url.spec());
  dictionary_description->SetDouble(kDictionaryLastUsedKey,
                                    last_used.ToDoubleT());
  dictionary_description->SetDouble(kDictionaryCreatedTimeKey,
                                    created_time.ToDoubleT());
  dictionary_description->SetInteger(kDictionaryUseCountKey, use_count);
  dictionary_description->SetInteger(kDictionarySizeKey,
                                     dictionary_text.size());
  pref_dictionary_map->Set(server_hash, std::move(dictionary_description));
  load_times_[server_hash] = clock_->Now();
}

void SdchOwner::OnDictionaryAdded(const GURL& dictionary_url,
                                  const std::string& server_hash) { }

void SdchOwner::OnDictionaryRemoved(const std::string& server_hash) { }

void SdchOwner::OnDictionaryUsed(const std::string& server_hash) {
  base::Time now(clock_->Now());
  base::DictionaryValue* pref_dictionary_map =
      GetPersistentStoreDictionaryMap(pref_store_);
  ScopedPrefNotifier scoped_pref_notifier(pref_store_);

  base::Value* value = nullptr;
  bool success = pref_dictionary_map->Get(server_hash, &value);
  if (!success) {
    // SdchManager::GetDictionarySet() pins the referenced dictionaries in
    // memory past a possible deletion.  For this reason, OnDictionaryUsed()
    // notifications may occur after SdchOwner thinks that dictionaries
    // have been deleted.
    SdchManager::SdchErrorRecovery(SDCH_DICTIONARY_USED_AFTER_DELETION);
    return;
  }
  base::DictionaryValue* specific_dictionary_map = nullptr;
  success = value->GetAsDictionary(&specific_dictionary_map);
  DCHECK(success);

  double last_used_seconds_since_epoch = 0.0;
  success = specific_dictionary_map->GetDouble(kDictionaryLastUsedKey,
                                               &last_used_seconds_since_epoch);
  DCHECK(success);
  int use_count = 0;
  success =
      specific_dictionary_map->GetInteger(kDictionaryUseCountKey, &use_count);
  DCHECK(success);

  if (use_counts_at_load_.count(server_hash) == 0) {
    use_counts_at_load_[server_hash] = use_count;
  }

  base::TimeDelta time_since_last_used(now -
      base::Time::FromDoubleT(last_used_seconds_since_epoch));

  if (use_count) {
    UMA_HISTOGRAM_CUSTOM_TIMES("Sdch3.UsageInterval2", time_since_last_used,
                               base::TimeDelta(), base::TimeDelta::FromDays(7),
                               50);
  } else {
    double created_time = 0;
    success = specific_dictionary_map->GetDouble(kDictionaryCreatedTimeKey,
                                                 &created_time);
    DCHECK(success);
    base::TimeDelta time_since_created(now -
                                       base::Time::FromDoubleT(created_time));
    UMA_HISTOGRAM_CUSTOM_TIMES("Sdch3.FirstUseInterval", time_since_created,
                               base::TimeDelta(), base::TimeDelta::FromDays(7),
                               50);
  }

  specific_dictionary_map->SetDouble(kDictionaryLastUsedKey, now.ToDoubleT());
  specific_dictionary_map->SetInteger(kDictionaryUseCountKey, use_count + 1);
}

void SdchOwner::OnGetDictionary(const GURL& request_url,
                                const GURL& dictionary_url) {
  base::Time stale_boundary(clock_->Now() - base::TimeDelta::FromDays(1));
  size_t avail_bytes = 0;
  for (DictionaryPreferenceIterator it(pref_store_); !it.IsAtEnd();
       it.Advance()) {
    if (it.last_used() < stale_boundary)
      avail_bytes += it.size();
  }

  // Don't initiate the fetch if we wouldn't be able to store any
  // reasonable dictionary.
  // TODO(rdsmith): Maybe do a HEAD request to figure out how much
  // storage we'd actually need?
  if (max_total_dictionary_size_ < (total_dictionary_bytes_ - avail_bytes +
                                    min_space_for_dictionary_fetch_)) {
    RecordDictionaryFate(DICTIONARY_FATE_GET_IGNORED);
    // TODO(rdsmith): Log a net-internals error.  This requires
    // SdchManager to forward the URLRequest that detected the
    // Get-Dictionary header to its observers, which is tricky
    // because SdchManager is layered underneath URLRequest.
    return;
  }

  fetcher_->Schedule(
      dictionary_url,
      base::Bind(&SdchOwner::OnDictionaryFetched,
                 // SdchOwner will outlive its member variables.
                 base::Unretained(this), base::Time(), base::Time::Now(), 0));
}

void SdchOwner::OnClearDictionaries() {
  total_dictionary_bytes_ = 0;
  fetcher_->Cancel();

  InitializePrefStore(pref_store_);
}

void SdchOwner::OnPrefStorageInitializationComplete(bool succeeded) {
  PrefStorage::ReadError error = external_pref_store_->GetReadError();
  // Errors on load are self-correcting; if dictionaries were not
  // persisted from the last instance of the browser, they will be
  // faulted in by user action over time.  However, if a load error
  // means that the dictionary information won't be able to be persisted,
  // the in memory pref store is left in place.
  if (!succeeded) {
    // Failure means a write failed, since read failures are recoverable.
    external_pref_store_->StopObservingInit();
    external_pref_store_ = nullptr;
    RecordPersistenceFailure(
        PrefStorage::PERSISTENCE_FAILURE_REASON_WRITE_FAILED);
    return;
  }

  if (error != PrefStorage::PERSISTENCE_FAILURE_NONE)
    RecordPersistenceFailure(error);

  // Load in what was stored before chrome exited previously.
  const base::DictionaryValue* sdch_persistence_dictionary = nullptr;

  // The GetPersistentStore() routine above assumes data formatted
  // according to the schema described at the top of this file.  Since
  // this data comes from disk, to avoid disk corruption resulting in
  // persistent chrome errors this code avoids those assupmtions.
  if (external_pref_store_->GetValue(&sdch_persistence_dictionary))
    SchedulePersistedDictionaryLoads(*sdch_persistence_dictionary);

  // Reset the persistent store and update it with the accumulated
  // information from the local store.
  InitializePrefStore(external_pref_store_.get());

  ScopedPrefNotifier scoped_pref_notifier(external_pref_store_.get());
  GetPersistentStoreDictionaryMap(external_pref_store_.get())
      ->Swap(GetPersistentStoreDictionaryMap(in_memory_pref_store_.get()));

  // This object can stop waiting on (i.e. observing) the external preference
  // store and switch over to using it as the primary preference store.
  pref_store_ = external_pref_store_.get();
  external_pref_store_->StopObservingInit();
  in_memory_pref_store_ = nullptr;
}

void SdchOwner::SetClockForTesting(std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

int SdchOwner::GetDictionaryCountForTesting() const {
  int count = 0;
  for (DictionaryPreferenceIterator it(pref_store_); !it.IsAtEnd();
       it.Advance()) {
    count++;
  }
  return count;
}

bool SdchOwner::HasDictionaryFromURLForTesting(const GURL& url) const {
  for (DictionaryPreferenceIterator it(pref_store_); !it.IsAtEnd();
       it.Advance()) {
    if (it.url() == url)
      return true;
  }
  return false;
}

void SdchOwner::SetFetcherForTesting(
    std::unique_ptr<SdchDictionaryFetcher> fetcher) {
  fetcher_ = std::move(fetcher);
}

void SdchOwner::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel level) {
  DCHECK_NE(base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE, level);
  ClearData();
}

void SdchOwner::OnPurgeMemory() {
  ClearData();
}

void SdchOwner::ClearData() {
  for (DictionaryPreferenceIterator it(pref_store_); !it.IsAtEnd();
       it.Advance()) {
    int new_uses = it.use_count() - use_counts_at_load_[it.server_hash()];
    RecordDictionaryEvictionOrUnload(it.server_hash(),
                                     it.size(),
                                     new_uses,
                                     DICTIONARY_FATE_EVICT_FOR_MEMORY);
  }

  // TODO(rdsmith): Make a distinction between moderate and critical
  // memory pressure.
  manager_->ClearData();
}

bool SdchOwner::SchedulePersistedDictionaryLoads(
    const base::DictionaryValue& persisted_info) {
  // Any schema error will result in dropping the persisted info.
  int version = 0;
  if (!persisted_info.GetInteger(kVersionKey, &version))
    return false;

  // Any version mismatch will result in dropping the persisted info;
  // it will be faulted in at small performance cost as URLs using
  // dictionaries for encoding are visited.
  if (version != kVersion)
    return false;

  const base::DictionaryValue* dictionary_set = nullptr;
  if (!persisted_info.GetDictionary(kDictionariesKey, &dictionary_set))
    return false;

  // Any formatting error will result in skipping that particular
  // dictionary.
  for (base::DictionaryValue::Iterator dict_it(*dictionary_set);
       !dict_it.IsAtEnd(); dict_it.Advance()) {
    const base::DictionaryValue* dict_info = nullptr;
    if (!dict_it.value().GetAsDictionary(&dict_info))
      continue;

    std::string url_string;
    if (!dict_info->GetString(kDictionaryUrlKey, &url_string))
      continue;
    GURL dict_url(url_string);

    double last_used = 0;
    if (!dict_info->GetDouble(kDictionaryLastUsedKey, &last_used))
      continue;

    int use_count = 0;
    if (!dict_info->GetInteger(kDictionaryUseCountKey, &use_count))
      continue;

    double created_time = 0;
    if (!dict_info->GetDouble(kDictionaryCreatedTimeKey, &created_time))
      continue;

    fetcher_->ScheduleReload(
        dict_url,
        base::Bind(&SdchOwner::OnDictionaryFetched,
                   // SdchOwner will outlive its member variables.
                   base::Unretained(this), base::Time::FromDoubleT(last_used),
                   base::Time::FromDoubleT(created_time), use_count));
  }

  return true;
}

bool SdchOwner::IsPersistingDictionaries() const {
  return in_memory_pref_store_.get() != nullptr;
}

}  // namespace net
