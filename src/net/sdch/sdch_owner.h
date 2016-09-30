// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SDCH_SDCH_OWNER_H_
#define NET_SDCH_SDCH_OWNER_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <string>

#include "base/macros.h"
#include "base/memory/memory_pressure_listener.h"
#include "base/memory/ref_counted.h"
#include "net/base/sdch_observer.h"
#include "net/url_request/sdch_dictionary_fetcher.h"

class GURL;

namespace base {
class Clock;
}

namespace net {
class SdchManager;
class URLRequestContext;

// This class owns the SDCH objects not owned as part of URLRequestContext, and
// exposes interface for setting SDCH policy.  It should be instantiated by
// the net/ embedder.
// TODO(rdsmith): Implement dictionary prioritization.
class NET_EXPORT SdchOwner : public SdchObserver {
 public:
  // Abstact storage interface for storing settings that allows the embedder
  // to provide the appropriate storage backend.
  class NET_EXPORT PrefStorage {
   public:
    // Possible values returned by GetReadError. This is a subset of the error
    // values of Chromium's pref storage that we care about.
    //
    // DO NOT CHANGE VALUES. This is logged persistently in a histogram.
    enum ReadError {
      PERSISTENCE_FAILURE_NONE = 0,

      // File didn't exist; is being created.
      PERSISTENCE_FAILURE_REASON_NO_FILE = 1,

      // Error reading in information, but should be able to write.
      PERSISTENCE_FAILURE_REASON_READ_FAILED = 2,

      // Error leading to abort on attempted persistence.
      PERSISTENCE_FAILURE_REASON_WRITE_FAILED = 3,

      // Anything else.
      PERSISTENCE_FAILURE_REASON_OTHER = 4,

      PERSISTENCE_FAILURE_REASON_MAX = 5
      // See RecordPersistenceFailure for UMA logging of this value if
      // adding a value here.
    };

    virtual ~PrefStorage();

    // Returns the read error if any. Valid to be called after initialization
    // is complete (see IsInitializationComplete).
    virtual ReadError GetReadError() const = 0;

    // Gets or sets the value in the preferences store.
    virtual bool GetValue(const base::DictionaryValue** result) const = 0;
    virtual bool GetMutableValue(base::DictionaryValue** result) = 0;
    virtual void SetValue(std::unique_ptr<base::DictionaryValue> value) = 0;

    // Notifies the storage system that a value was changed via mutating the
    // result of GetMutableValue().
    virtual void ReportValueChanged() = 0;

    // Returns true if the store's init is complete. See the Start/Stop
    // functions below for observing changes to this value.
    virtual bool IsInitializationComplete() = 0;

    // Starts and stops observing preferences storage init. There will only
    // be one observer active at a time. The store should call
    // OnPrefStorageInitializationComplete() when it transitions to initialized
    // and there is an observer active. See also IsInitializationComplete().
    virtual void StartObservingInit(SdchOwner* observer) = 0;
    virtual void StopObservingInit() = 0;
  };

  static const size_t kMaxTotalDictionarySize;
  static const size_t kMinSpaceForDictionaryFetch;

  // Consumer must guarantee that |sdch_manager| and |context| outlive
  // this object.
  SdchOwner(SdchManager* sdch_manager, URLRequestContext* context);
  ~SdchOwner() override;

  // Enables use of pref persistence. Ownership of the storage will be passed.
  // This routine may only be called once per SdchOwner instance.
  void EnablePersistentStorage(std::unique_ptr<PrefStorage> pref_store);

  // Defaults to kMaxTotalDictionarySize.
  void SetMaxTotalDictionarySize(size_t max_total_dictionary_size);

  // Defaults to kMinSpaceForDictionaryFetch.
  void SetMinSpaceForDictionaryFetch(size_t min_space_for_dictionary_fetch);

  // SdchObserver implementation.
  void OnDictionaryAdded(const GURL& dictionary_url,
                         const std::string& server_hash) override;
  void OnDictionaryRemoved(const std::string& server_hash) override;
  void OnDictionaryUsed(const std::string& server_hash) override;
  void OnGetDictionary(const GURL& request_url,
                       const GURL& dictionary_url) override;
  void OnClearDictionaries() override;

  // Called by the PrefStorage implementation when initialization is complete.
  // See PrefStorage::StartObservingInit().
  void OnPrefStorageInitializationComplete(bool succeeded);

  // Implementation detail--this is the function callback by the callback passed
  // to the fetcher through which the fetcher informs the SdchOwner that it's
  // gotten the dictionary.  The first two arguments are bound locally.
  // Public for testing.
  void OnDictionaryFetched(base::Time last_used,
                           base::Time created_time,
                           int use_count,
                           const std::string& dictionary_text,
                           const GURL& dictionary_url,
                           const BoundNetLog& net_log,
                           bool was_from_cache);

  void SetClockForTesting(std::unique_ptr<base::Clock> clock);

  // Returns the total number of dictionaries loaded.
  int GetDictionaryCountForTesting() const;

  // Returns whether this SdchOwner has dictionary from |url| loaded.
  bool HasDictionaryFromURLForTesting(const GURL& url) const;

  void SetFetcherForTesting(std::unique_ptr<SdchDictionaryFetcher> fetcher);

 private:
  // For each active dictionary, stores local info.
  // Indexed by the server hash of the dictionary.
  struct DictionaryInfo {
    base::Time last_used;
    int use_count;
    size_t size;

    DictionaryInfo() : use_count(0), size(0) {}
    DictionaryInfo(const base::Time& last_used, size_t size)
        : last_used(last_used), use_count(0), size(size) {}
    DictionaryInfo(const DictionaryInfo& rhs) = default;
    DictionaryInfo& operator=(const DictionaryInfo& rhs) = default;
  };

  void OnMemoryPressure(
      base::MemoryPressureListener::MemoryPressureLevel level);

  // Schedule loading of all dictionaries described in |persisted_info|.
  // Returns false and does not schedule a load if |persisted_info| has an
  // unsupported version or no dictionaries key. Skips any dictionaries that are
  // malformed in |persisted_info|.
  bool SchedulePersistedDictionaryLoads(
      const base::DictionaryValue& persisted_info);

  bool IsPersistingDictionaries() const;

  enum DictionaryFate {
    // A Get-Dictionary header wasn't acted on.
    DICTIONARY_FATE_GET_IGNORED = 1,

    // A fetch was attempted, but failed.
    // TODO(rdsmith): Actually record this case.
    DICTIONARY_FATE_FETCH_FAILED = 2,

    // A successful fetch was dropped on the floor, no space.
    DICTIONARY_FATE_FETCH_IGNORED_NO_SPACE = 3,

    // A successful fetch was refused by the SdchManager.
    DICTIONARY_FATE_FETCH_MANAGER_REFUSED = 4,

    // A dictionary was successfully added based on
    // a Get-Dictionary header in a response.
    DICTIONARY_FATE_ADD_RESPONSE_TRIGGERED = 5,

    // A dictionary was evicted by an incoming dict.
    DICTIONARY_FATE_EVICT_FOR_DICT = 6,

    // A dictionary was evicted by memory pressure.
    DICTIONARY_FATE_EVICT_FOR_MEMORY = 7,

    // A dictionary was evicted on destruction.
    DICTIONARY_FATE_EVICT_FOR_DESTRUCTION = 8,

    // A dictionary was successfully added based on
    // persistence from a previous browser revision.
    DICTIONARY_FATE_ADD_PERSISTENCE_TRIGGERED = 9,

    // A dictionary was unloaded on destruction, but is still present on disk.
    DICTIONARY_FATE_UNLOAD_FOR_DESTRUCTION = 10,

    DICTIONARY_FATE_MAX = 11
  };

  void RecordDictionaryFate(DictionaryFate fate);

  // Record the lifetime memory use of a specified dictionary, identified by
  // server hash.
  void RecordDictionaryEvictionOrUnload(
      const std::string& server_hash,
      size_t size,
      int use_count, DictionaryFate fate);

  net::SdchManager* manager_;
  std::unique_ptr<net::SdchDictionaryFetcher> fetcher_;

  size_t total_dictionary_bytes_;

  std::unique_ptr<base::Clock> clock_;

  size_t max_total_dictionary_size_;
  size_t min_space_for_dictionary_fetch_;

  base::MemoryPressureListener memory_pressure_listener_;

  // Dictionary persistence machinery.
  // * |in_memory_pref_store_| is created on construction and used in the
  //   absence of any call to EnablePersistentStorage().
  // * |external_pref_store_| holds the preference store specified by
  //   EnablePersistentStorage() (if any).
  // * The external pref store is initialized asynchronously. During this time,
  //   both pointers will be value, pref_store_ will point to the in-memory
  //   one, and this class will be observing the initialization of the external
  //   store.
  // * When the external pref store is initialized, the in-memory version will
  //   be freed, and pref_store_ will point to the external one.
  // * |pref_store_| holds an unowned pointer to the currently
  //   active pref store (one of the preceding two).
  std::unique_ptr<PrefStorage> in_memory_pref_store_;
  std::unique_ptr<PrefStorage> external_pref_store_;
  PrefStorage* pref_store_;

  // The use counts of dictionaries when they were loaded from the persistent
  // store, keyed by server hash. These are stored to avoid generating
  // misleading ever-increasing use counts for dictionaries that are persisted,
  // since the UMA histogram for use counts is only supposed to be since last
  // load.
  std::map<std::string, int> use_counts_at_load_;

  // Load times for loaded dictionaries, keyed by server hash. These are used to
  // track the durations that dictionaries are in memory.
  std::map<std::string, base::Time> load_times_;

  // Byte-seconds consumed by dictionaries that have been unloaded. These are
  // stored for later uploading in the SdchOwner destructor.
  std::vector<int64_t> consumed_byte_seconds_;

  // Creation time for this SdchOwner object, used for reporting temporal memory
  // pressure.
  base::Time creation_time_;

  DISALLOW_COPY_AND_ASSIGN(SdchOwner);
};

}  // namespace net

#endif  // NET_SDCH_SDCH_OWNER_H_
