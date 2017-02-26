// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/blockfile/backend_impl.h"

#include <limits>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/hash.h"
#include "base/location.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram.h"
#include "base/rand_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/sys_info.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/blockfile/disk_format.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/errors.h"
#include "net/disk_cache/blockfile/experiments.h"
#include "net/disk_cache/blockfile/file.h"
#include "net/disk_cache/blockfile/histogram_macros.h"
#include "net/disk_cache/blockfile/webfonts_histogram.h"
#include "net/disk_cache/cache_util.h"

// Provide a BackendImpl object to macros from histogram_macros.h.
#define CACHE_UMA_BACKEND_IMPL_OBJ this

using base::Time;
using base::TimeDelta;
using base::TimeTicks;

namespace {

const char kIndexName[] = "index";

// Seems like ~240 MB correspond to less than 50k entries for 99% of the people.
// Note that the actual target is to keep the index table load factor under 55%
// for most users.
const int k64kEntriesStore = 240 * 1000 * 1000;
const int kBaseTableLen = 64 * 1024;

// Avoid trimming the cache for the first 5 minutes (10 timer ticks).
const int kTrimDelay = 10;

int DesiredIndexTableLen(int32_t storage_size) {
  if (storage_size <= k64kEntriesStore)
    return kBaseTableLen;
  if (storage_size <= k64kEntriesStore * 2)
    return kBaseTableLen * 2;
  if (storage_size <= k64kEntriesStore * 4)
    return kBaseTableLen * 4;
  if (storage_size <= k64kEntriesStore * 8)
    return kBaseTableLen * 8;

  // The biggest storage_size for int32_t requires a 4 MB table.
  return kBaseTableLen * 16;
}

int MaxStorageSizeForTable(int table_len) {
  return table_len * (k64kEntriesStore / kBaseTableLen);
}

size_t GetIndexSize(int table_len) {
  size_t table_size = sizeof(disk_cache::CacheAddr) * table_len;
  return sizeof(disk_cache::IndexHeader) + table_size;
}

// ------------------------------------------------------------------------

// Sets group for the current experiment. Returns false if the files should be
// discarded.
bool InitExperiment(disk_cache::IndexHeader* header, bool cache_created) {
  if (header->experiment == disk_cache::EXPERIMENT_OLD_FILE1 ||
      header->experiment == disk_cache::EXPERIMENT_OLD_FILE2) {
    // Discard current cache.
    return false;
  }

  if (base::FieldTrialList::FindFullName("SimpleCacheTrial") ==
          "ExperimentControl") {
    if (cache_created) {
      header->experiment = disk_cache::EXPERIMENT_SIMPLE_CONTROL;
      return true;
    }
    return header->experiment == disk_cache::EXPERIMENT_SIMPLE_CONTROL;
  }

  header->experiment = disk_cache::NO_EXPERIMENT;
  return true;
}

// A callback to perform final cleanup on the background thread.
void FinalCleanupCallback(disk_cache::BackendImpl* backend) {
  backend->CleanupCache();
}

}  // namespace

// ------------------------------------------------------------------------

namespace disk_cache {

BackendImpl::BackendImpl(
    const base::FilePath& path,
    const scoped_refptr<base::SingleThreadTaskRunner>& cache_thread,
    net::NetLog* net_log)
    : background_queue_(this, cache_thread),
      path_(path),
      block_files_(path),
      mask_(0),
      max_size_(0),
      up_ticks_(0),
      cache_type_(net::DISK_CACHE),
      uma_report_(0),
      user_flags_(0),
      init_(false),
      restarted_(false),
      unit_test_(false),
      read_only_(false),
      disabled_(false),
      new_eviction_(false),
      first_timer_(true),
      user_load_(false),
      net_log_(net_log),
      done_(base::WaitableEvent::ResetPolicy::MANUAL,
            base::WaitableEvent::InitialState::NOT_SIGNALED),
      ptr_factory_(this) {}

BackendImpl::BackendImpl(
    const base::FilePath& path,
    uint32_t mask,
    const scoped_refptr<base::SingleThreadTaskRunner>& cache_thread,
    net::NetLog* net_log)
    : background_queue_(this, cache_thread),
      path_(path),
      block_files_(path),
      mask_(mask),
      max_size_(0),
      up_ticks_(0),
      cache_type_(net::DISK_CACHE),
      uma_report_(0),
      user_flags_(kMask),
      init_(false),
      restarted_(false),
      unit_test_(false),
      read_only_(false),
      disabled_(false),
      new_eviction_(false),
      first_timer_(true),
      user_load_(false),
      net_log_(net_log),
      done_(base::WaitableEvent::ResetPolicy::MANUAL,
            base::WaitableEvent::InitialState::NOT_SIGNALED),
      ptr_factory_(this) {}

BackendImpl::~BackendImpl() {
  if (user_flags_ & kNoRandom) {
    // This is a unit test, so we want to be strict about not leaking entries
    // and completing all the work.
    background_queue_.WaitForPendingIO();
  } else {
    // This is most likely not a test, so we want to do as little work as
    // possible at this time, at the price of leaving dirty entries behind.
    background_queue_.DropPendingIO();
  }

  if (background_queue_.BackgroundIsCurrentThread()) {
    // Unit tests may use the same thread for everything.
    CleanupCache();
  } else {
    background_queue_.background_thread()->PostTask(
        FROM_HERE, base::Bind(&FinalCleanupCallback, base::Unretained(this)));
    // http://crbug.com/74623
    base::ThreadRestrictions::ScopedAllowWait allow_wait;
    done_.Wait();
  }
}

int BackendImpl::Init(const CompletionCallback& callback) {
  background_queue_.Init(callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::SyncInit() {
#if defined(NET_BUILD_STRESS_CACHE)
  // Start evictions right away.
  up_ticks_ = kTrimDelay * 2;
#endif
  DCHECK(!init_);
  if (init_)
    return net::ERR_FAILED;

  bool create_files = false;
  if (!InitBackingStore(&create_files)) {
    ReportError(ERR_STORAGE_ERROR);
    return net::ERR_FAILED;
  }

  num_refs_ = num_pending_io_ = max_refs_ = 0;
  entry_count_ = byte_count_ = 0;

  bool should_create_timer = false;
  if (!restarted_) {
    buffer_bytes_ = 0;
    trace_object_ = TraceObject::GetTraceObject();
    should_create_timer = true;
  }

  init_ = true;
  Trace("Init");

  if (data_->header.experiment != NO_EXPERIMENT &&
      cache_type_ != net::DISK_CACHE) {
    // No experiment for other caches.
    return net::ERR_FAILED;
  }

  if (!(user_flags_ & kNoRandom)) {
    // The unit test controls directly what to test.
    new_eviction_ = (cache_type_ == net::DISK_CACHE);
  }

  if (!CheckIndex()) {
    ReportError(ERR_INIT_FAILED);
    return net::ERR_FAILED;
  }

  if (!restarted_ && (create_files || !data_->header.num_entries))
    ReportError(ERR_CACHE_CREATED);

  if (!(user_flags_ & kNoRandom) && cache_type_ == net::DISK_CACHE &&
      !InitExperiment(&data_->header, create_files)) {
    return net::ERR_FAILED;
  }

  // We don't care if the value overflows. The only thing we care about is that
  // the id cannot be zero, because that value is used as "not dirty".
  // Increasing the value once per second gives us many years before we start
  // having collisions.
  data_->header.this_id++;
  if (!data_->header.this_id)
    data_->header.this_id++;

  bool previous_crash = (data_->header.crash != 0);
  data_->header.crash = 1;

  if (!block_files_.Init(create_files))
    return net::ERR_FAILED;

  // We want to minimize the changes to cache for an AppCache.
  if (cache_type() == net::APP_CACHE) {
    DCHECK(!new_eviction_);
    read_only_ = true;
  } else if (cache_type() == net::SHADER_CACHE) {
    DCHECK(!new_eviction_);
  }

  eviction_.Init(this);

  // stats_ and rankings_ may end up calling back to us so we better be enabled.
  disabled_ = false;
  if (!InitStats())
    return net::ERR_FAILED;

  disabled_ = !rankings_.Init(this, new_eviction_);

#if defined(STRESS_CACHE_EXTENDED_VALIDATION)
  trace_object_->EnableTracing(false);
  int sc = SelfCheck();
  if (sc < 0 && sc != ERR_NUM_ENTRIES_MISMATCH)
    NOTREACHED();
  trace_object_->EnableTracing(true);
#endif

  if (previous_crash) {
    ReportError(ERR_PREVIOUS_CRASH);
  } else if (!restarted_) {
    ReportError(ERR_NO_ERROR);
  }

  FlushIndex();

  if (!disabled_ && should_create_timer) {
    // Create a recurrent timer of 30 secs.
    int timer_delay = unit_test_ ? 1000 : 30000;
    timer_.reset(new base::RepeatingTimer());
    timer_->Start(FROM_HERE, TimeDelta::FromMilliseconds(timer_delay), this,
                  &BackendImpl::OnStatsTimer);
  }

  return disabled_ ? net::ERR_FAILED : net::OK;
}

void BackendImpl::CleanupCache() {
  Trace("Backend Cleanup");
  eviction_.Stop();
  timer_.reset();

  if (init_) {
    StoreStats();
    if (data_)
      data_->header.crash = 0;

    if (user_flags_ & kNoRandom) {
      // This is a net_unittest, verify that we are not 'leaking' entries.
      File::WaitForPendingIO(&num_pending_io_);
      DCHECK(!num_refs_);
    } else {
      File::DropPendingIO();
    }
  }
  block_files_.CloseFiles();
  FlushIndex();
  index_ = NULL;
  ptr_factory_.InvalidateWeakPtrs();
  done_.Signal();
}

// ------------------------------------------------------------------------

int BackendImpl::SyncOpenEntry(const std::string& key, Entry** entry) {
  DCHECK(entry);
  *entry = OpenEntryImpl(key);
  return (*entry) ? net::OK : net::ERR_FAILED;
}

int BackendImpl::SyncCreateEntry(const std::string& key, Entry** entry) {
  DCHECK(entry);
  *entry = CreateEntryImpl(key);
  return (*entry) ? net::OK : net::ERR_FAILED;
}

int BackendImpl::SyncDoomEntry(const std::string& key) {
  if (disabled_)
    return net::ERR_FAILED;

  EntryImpl* entry = OpenEntryImpl(key);
  if (!entry)
    return net::ERR_FAILED;

  entry->DoomImpl();
  entry->Release();
  return net::OK;
}

int BackendImpl::SyncDoomAllEntries() {
  if (disabled_)
    return net::ERR_FAILED;

  // This is not really an error, but it is an interesting condition.
  ReportError(ERR_CACHE_DOOMED);
  stats_.OnEvent(Stats::DOOM_CACHE);
  if (!num_refs_) {
    RestartCache(false);
    return disabled_ ? net::ERR_FAILED : net::OK;
  } else {
    if (disabled_)
      return net::ERR_FAILED;

    eviction_.TrimCache(true);
    return net::OK;
  }
}

int BackendImpl::SyncDoomEntriesBetween(const base::Time initial_time,
                                        const base::Time end_time) {
  DCHECK_NE(net::APP_CACHE, cache_type_);
  if (end_time.is_null())
    return SyncDoomEntriesSince(initial_time);

  DCHECK(end_time >= initial_time);

  if (disabled_)
    return net::ERR_FAILED;

  EntryImpl* node;
  std::unique_ptr<Rankings::Iterator> iterator(new Rankings::Iterator());
  EntryImpl* next = OpenNextEntryImpl(iterator.get());
  if (!next)
    return net::OK;

  while (next) {
    node = next;
    next = OpenNextEntryImpl(iterator.get());

    if (node->GetLastUsed() >= initial_time &&
        node->GetLastUsed() < end_time) {
      node->DoomImpl();
    } else if (node->GetLastUsed() < initial_time) {
      if (next)
        next->Release();
      next = NULL;
      SyncEndEnumeration(std::move(iterator));
    }

    node->Release();
  }

  return net::OK;
}

int BackendImpl::SyncCalculateSizeOfAllEntries() {
  DCHECK_NE(net::APP_CACHE, cache_type_);
  if (disabled_)
    return net::ERR_FAILED;

  return data_->header.num_bytes;
}

// We use OpenNextEntryImpl to retrieve elements from the cache, until we get
// entries that are too old.
int BackendImpl::SyncDoomEntriesSince(const base::Time initial_time) {
  DCHECK_NE(net::APP_CACHE, cache_type_);
  if (disabled_)
    return net::ERR_FAILED;

  stats_.OnEvent(Stats::DOOM_RECENT);
  for (;;) {
    std::unique_ptr<Rankings::Iterator> iterator(new Rankings::Iterator());
    EntryImpl* entry = OpenNextEntryImpl(iterator.get());
    if (!entry)
      return net::OK;

    if (initial_time > entry->GetLastUsed()) {
      entry->Release();
      SyncEndEnumeration(std::move(iterator));
      return net::OK;
    }

    entry->DoomImpl();
    entry->Release();
    SyncEndEnumeration(
        std::move(iterator));  // The doom invalidated the iterator.
  }
}

int BackendImpl::SyncOpenNextEntry(Rankings::Iterator* iterator,
                                   Entry** next_entry) {
  *next_entry = OpenNextEntryImpl(iterator);
  return (*next_entry) ? net::OK : net::ERR_FAILED;
}

void BackendImpl::SyncEndEnumeration(
    std::unique_ptr<Rankings::Iterator> iterator) {
  iterator->Reset();
}

void BackendImpl::SyncOnExternalCacheHit(const std::string& key) {
  if (disabled_)
    return;

  uint32_t hash = base::Hash(key);
  bool error;
  EntryImpl* cache_entry = MatchEntry(key, hash, false, Addr(), &error);
  if (cache_entry) {
    if (ENTRY_NORMAL == cache_entry->entry()->Data()->state) {
      UpdateRank(cache_entry, cache_type() == net::SHADER_CACHE);
    }
    cache_entry->Release();
  }
}

EntryImpl* BackendImpl::OpenEntryImpl(const std::string& key) {
  if (disabled_)
    return NULL;

  TimeTicks start = TimeTicks::Now();
  uint32_t hash = base::Hash(key);
  Trace("Open hash 0x%x", hash);

  bool error;
  EntryImpl* cache_entry = MatchEntry(key, hash, false, Addr(), &error);
  if (cache_entry && ENTRY_NORMAL != cache_entry->entry()->Data()->state) {
    // The entry was already evicted.
    cache_entry->Release();
    cache_entry = NULL;
    web_fonts_histogram::RecordEvictedEntry(key);
  } else if (!cache_entry) {
    web_fonts_histogram::RecordCacheMiss(key);
  }

  int current_size = data_->header.num_bytes / (1024 * 1024);
  int64_t total_hours = stats_.GetCounter(Stats::TIMER) / 120;
  int64_t no_use_hours = stats_.GetCounter(Stats::LAST_REPORT_TIMER) / 120;
  int64_t use_hours = total_hours - no_use_hours;

  if (!cache_entry) {
    stats_.OnEvent(Stats::OPEN_MISS);
    return NULL;
  }

  eviction_.OnOpenEntry(cache_entry);
  entry_count_++;

  Trace("Open hash 0x%x end: 0x%x", hash,
        cache_entry->entry()->address().value());
  CACHE_UMA(AGE_MS, "OpenTime", 0, start);
  CACHE_UMA(COUNTS_10000, "AllOpenBySize.Hit", 0, current_size);
  CACHE_UMA(HOURS, "AllOpenByTotalHours.Hit", 0,
            static_cast<base::HistogramBase::Sample>(total_hours));
  CACHE_UMA(HOURS, "AllOpenByUseHours.Hit", 0,
            static_cast<base::HistogramBase::Sample>(use_hours));
  stats_.OnEvent(Stats::OPEN_HIT);
  web_fonts_histogram::RecordCacheHit(cache_entry);
  return cache_entry;
}

EntryImpl* BackendImpl::CreateEntryImpl(const std::string& key) {
  if (disabled_ || key.empty())
    return NULL;

  TimeTicks start = TimeTicks::Now();
  uint32_t hash = base::Hash(key);
  Trace("Create hash 0x%x", hash);

  scoped_refptr<EntryImpl> parent;
  Addr entry_address(data_->table[hash & mask_]);
  if (entry_address.is_initialized()) {
    // We have an entry already. It could be the one we are looking for, or just
    // a hash conflict.
    bool error;
    EntryImpl* old_entry = MatchEntry(key, hash, false, Addr(), &error);
    if (old_entry)
      return ResurrectEntry(old_entry);

    EntryImpl* parent_entry = MatchEntry(key, hash, true, Addr(), &error);
    DCHECK(!error);
    if (parent_entry) {
      parent.swap(&parent_entry);
    } else if (data_->table[hash & mask_]) {
      // We should have corrected the problem.
      NOTREACHED();
      return NULL;
    }
  }

  // The general flow is to allocate disk space and initialize the entry data,
  // followed by saving that to disk, then linking the entry though the index
  // and finally through the lists. If there is a crash in this process, we may
  // end up with:
  // a. Used, unreferenced empty blocks on disk (basically just garbage).
  // b. Used, unreferenced but meaningful data on disk (more garbage).
  // c. A fully formed entry, reachable only through the index.
  // d. A fully formed entry, also reachable through the lists, but still dirty.
  //
  // Anything after (b) can be automatically cleaned up. We may consider saving
  // the current operation (as we do while manipulating the lists) so that we
  // can detect and cleanup (a) and (b).

  int num_blocks = EntryImpl::NumBlocksForEntry(key.size());
  if (!block_files_.CreateBlock(BLOCK_256, num_blocks, &entry_address)) {
    LOG(ERROR) << "Create entry failed " << key.c_str();
    stats_.OnEvent(Stats::CREATE_ERROR);
    return NULL;
  }

  Addr node_address(0);
  if (!block_files_.CreateBlock(RANKINGS, 1, &node_address)) {
    block_files_.DeleteBlock(entry_address, false);
    LOG(ERROR) << "Create entry failed " << key.c_str();
    stats_.OnEvent(Stats::CREATE_ERROR);
    return NULL;
  }

  scoped_refptr<EntryImpl> cache_entry(
      new EntryImpl(this, entry_address, false));
  IncreaseNumRefs();

  if (!cache_entry->CreateEntry(node_address, key, hash)) {
    block_files_.DeleteBlock(entry_address, false);
    block_files_.DeleteBlock(node_address, false);
    LOG(ERROR) << "Create entry failed " << key.c_str();
    stats_.OnEvent(Stats::CREATE_ERROR);
    return NULL;
  }

  cache_entry->BeginLogging(net_log_, true);

  // We are not failing the operation; let's add this to the map.
  open_entries_[entry_address.value()] = cache_entry.get();

  // Save the entry.
  cache_entry->entry()->Store();
  cache_entry->rankings()->Store();
  IncreaseNumEntries();
  entry_count_++;

  // Link this entry through the index.
  if (parent.get()) {
    parent->SetNextAddress(entry_address);
  } else {
    data_->table[hash & mask_] = entry_address.value();
  }

  // Link this entry through the lists.
  eviction_.OnCreateEntry(cache_entry.get());

  CACHE_UMA(AGE_MS, "CreateTime", 0, start);
  stats_.OnEvent(Stats::CREATE_HIT);
  Trace("create entry hit ");
  FlushIndex();
  cache_entry->AddRef();
  return cache_entry.get();
}

EntryImpl* BackendImpl::OpenNextEntryImpl(Rankings::Iterator* iterator) {
  if (disabled_)
    return NULL;

  const int kListsToSearch = 3;
  scoped_refptr<EntryImpl> entries[kListsToSearch];
  if (!iterator->my_rankings) {
    iterator->my_rankings = &rankings_;
    bool ret = false;

    // Get an entry from each list.
    for (int i = 0; i < kListsToSearch; i++) {
      EntryImpl* temp = NULL;
      ret |= OpenFollowingEntryFromList(static_cast<Rankings::List>(i),
                                        &iterator->nodes[i], &temp);
      entries[i].swap(&temp);  // The entry was already addref'd.
    }
    if (!ret) {
      iterator->Reset();
      return NULL;
    }
  } else {
    // Get the next entry from the last list, and the actual entries for the
    // elements on the other lists.
    for (int i = 0; i < kListsToSearch; i++) {
      EntryImpl* temp = NULL;
      if (iterator->list == i) {
          OpenFollowingEntryFromList(
              iterator->list, &iterator->nodes[i], &temp);
      } else {
        temp = GetEnumeratedEntry(iterator->nodes[i],
                                  static_cast<Rankings::List>(i));
      }

      entries[i].swap(&temp);  // The entry was already addref'd.
    }
  }

  int newest = -1;
  int oldest = -1;
  Time access_times[kListsToSearch];
  for (int i = 0; i < kListsToSearch; i++) {
    if (entries[i].get()) {
      access_times[i] = entries[i]->GetLastUsed();
      if (newest < 0) {
        DCHECK_LT(oldest, 0);
        newest = oldest = i;
        continue;
      }
      if (access_times[i] > access_times[newest])
        newest = i;
      if (access_times[i] < access_times[oldest])
        oldest = i;
    }
  }

  if (newest < 0 || oldest < 0) {
    iterator->Reset();
    return NULL;
  }

  EntryImpl* next_entry;
  next_entry = entries[newest].get();
  iterator->list = static_cast<Rankings::List>(newest);
  next_entry->AddRef();
  return next_entry;
}

bool BackendImpl::SetMaxSize(int max_bytes) {
  static_assert(sizeof(max_bytes) == sizeof(max_size_),
                "unsupported int model");
  if (max_bytes < 0)
    return false;

  // Zero size means use the default.
  if (!max_bytes)
    return true;

  // Avoid a DCHECK later on.
  if (max_bytes >= std::numeric_limits<int32_t>::max() -
                       std::numeric_limits<int32_t>::max() / 10) {
    max_bytes = std::numeric_limits<int32_t>::max() -
                std::numeric_limits<int32_t>::max() / 10 - 1;
  }

  user_flags_ |= kMaxSize;
  max_size_ = max_bytes;
  return true;
}

void BackendImpl::SetType(net::CacheType type) {
  DCHECK_NE(net::MEMORY_CACHE, type);
  cache_type_ = type;
}

base::FilePath BackendImpl::GetFileName(Addr address) const {
  if (!address.is_separate_file() || !address.is_initialized()) {
    NOTREACHED();
    return base::FilePath();
  }

  std::string tmp = base::StringPrintf("f_%06x", address.FileNumber());
  return path_.AppendASCII(tmp);
}

MappedFile* BackendImpl::File(Addr address) {
  if (disabled_)
    return NULL;
  return block_files_.GetFile(address);
}

base::WeakPtr<InFlightBackendIO> BackendImpl::GetBackgroundQueue() {
  return background_queue_.GetWeakPtr();
}

bool BackendImpl::CreateExternalFile(Addr* address) {
  int file_number = data_->header.last_file + 1;
  Addr file_address(0);
  bool success = false;
  for (int i = 0; i < 0x0fffffff; i++, file_number++) {
    if (!file_address.SetFileNumber(file_number)) {
      file_number = 1;
      continue;
    }
    base::FilePath name = GetFileName(file_address);
    int flags = base::File::FLAG_READ | base::File::FLAG_WRITE |
                base::File::FLAG_CREATE | base::File::FLAG_EXCLUSIVE_WRITE;
    base::File file(name, flags);
    if (!file.IsValid()) {
      base::File::Error error = file.error_details();
      if (error != base::File::FILE_ERROR_EXISTS) {
        LOG(ERROR) << "Unable to create file: " << error;
        return false;
      }
      continue;
    }

    success = true;
    break;
  }

  DCHECK(success);
  if (!success)
    return false;

  data_->header.last_file = file_number;
  address->set_value(file_address.value());
  return true;
}

bool BackendImpl::CreateBlock(FileType block_type, int block_count,
                             Addr* block_address) {
  return block_files_.CreateBlock(block_type, block_count, block_address);
}

void BackendImpl::DeleteBlock(Addr block_address, bool deep) {
  block_files_.DeleteBlock(block_address, deep);
}

LruData* BackendImpl::GetLruData() {
  return &data_->header.lru;
}

void BackendImpl::UpdateRank(EntryImpl* entry, bool modified) {
  if (read_only_ || (!modified && cache_type() == net::SHADER_CACHE))
    return;
  eviction_.UpdateRank(entry, modified);
}

void BackendImpl::RecoveredEntry(CacheRankingsBlock* rankings) {
  Addr address(rankings->Data()->contents);
  EntryImpl* cache_entry = NULL;
  if (NewEntry(address, &cache_entry)) {
    STRESS_NOTREACHED();
    return;
  }

  uint32_t hash = cache_entry->GetHash();
  cache_entry->Release();

  // Anything on the table means that this entry is there.
  if (data_->table[hash & mask_])
    return;

  data_->table[hash & mask_] = address.value();
  FlushIndex();
}

void BackendImpl::InternalDoomEntry(EntryImpl* entry) {
  uint32_t hash = entry->GetHash();
  std::string key = entry->GetKey();
  Addr entry_addr = entry->entry()->address();
  bool error;
  EntryImpl* parent_entry = MatchEntry(key, hash, true, entry_addr, &error);
  CacheAddr child(entry->GetNextAddress());

  Trace("Doom entry 0x%p", entry);

  if (!entry->doomed()) {
    // We may have doomed this entry from within MatchEntry.
    eviction_.OnDoomEntry(entry);
    entry->InternalDoom();
    if (!new_eviction_) {
      DecreaseNumEntries();
    }
    stats_.OnEvent(Stats::DOOM_ENTRY);
  }

  if (parent_entry) {
    parent_entry->SetNextAddress(Addr(child));
    parent_entry->Release();
  } else if (!error) {
    data_->table[hash & mask_] = child;
  }

  FlushIndex();
}

#if defined(NET_BUILD_STRESS_CACHE)

CacheAddr BackendImpl::GetNextAddr(Addr address) {
  EntriesMap::iterator it = open_entries_.find(address.value());
  if (it != open_entries_.end()) {
    EntryImpl* this_entry = it->second;
    return this_entry->GetNextAddress();
  }
  DCHECK(block_files_.IsValid(address));
  DCHECK(!address.is_separate_file() && address.file_type() == BLOCK_256);

  CacheEntryBlock entry(File(address), address);
  CHECK(entry.Load());
  return entry.Data()->next;
}

void BackendImpl::NotLinked(EntryImpl* entry) {
  Addr entry_addr = entry->entry()->address();
  uint32_t i = entry->GetHash() & mask_;
  Addr address(data_->table[i]);
  if (!address.is_initialized())
    return;

  for (;;) {
    DCHECK(entry_addr.value() != address.value());
    address.set_value(GetNextAddr(address));
    if (!address.is_initialized())
      break;
  }
}
#endif  // NET_BUILD_STRESS_CACHE

// An entry may be linked on the DELETED list for a while after being doomed.
// This function is called when we want to remove it.
void BackendImpl::RemoveEntry(EntryImpl* entry) {
#if defined(NET_BUILD_STRESS_CACHE)
  NotLinked(entry);
#endif
  if (!new_eviction_)
    return;

  DCHECK_NE(ENTRY_NORMAL, entry->entry()->Data()->state);

  Trace("Remove entry 0x%p", entry);
  eviction_.OnDestroyEntry(entry);
  DecreaseNumEntries();
}

void BackendImpl::OnEntryDestroyBegin(Addr address) {
  EntriesMap::iterator it = open_entries_.find(address.value());
  if (it != open_entries_.end())
    open_entries_.erase(it);
}

void BackendImpl::OnEntryDestroyEnd() {
  DecreaseNumRefs();
  if (data_->header.num_bytes > max_size_ && !read_only_ &&
      (up_ticks_ > kTrimDelay || user_flags_ & kNoRandom))
    eviction_.TrimCache(false);
}

EntryImpl* BackendImpl::GetOpenEntry(CacheRankingsBlock* rankings) const {
  DCHECK(rankings->HasData());
  EntriesMap::const_iterator it =
      open_entries_.find(rankings->Data()->contents);
  if (it != open_entries_.end()) {
    // We have this entry in memory.
    return it->second;
  }

  return NULL;
}

int32_t BackendImpl::GetCurrentEntryId() const {
  return data_->header.this_id;
}

int BackendImpl::MaxFileSize() const {
  return cache_type() == net::PNACL_CACHE ? max_size_ : max_size_ / 8;
}

void BackendImpl::ModifyStorageSize(int32_t old_size, int32_t new_size) {
  if (disabled_ || old_size == new_size)
    return;
  if (old_size > new_size)
    SubstractStorageSize(old_size - new_size);
  else
    AddStorageSize(new_size - old_size);

  FlushIndex();

  // Update the usage statistics.
  stats_.ModifyStorageStats(old_size, new_size);
}

void BackendImpl::TooMuchStorageRequested(int32_t size) {
  stats_.ModifyStorageStats(0, size);
}

bool BackendImpl::IsAllocAllowed(int current_size, int new_size) {
  DCHECK_GT(new_size, current_size);
  if (user_flags_ & kNoBuffering)
    return false;

  int to_add = new_size - current_size;
  if (buffer_bytes_ + to_add > MaxBuffersSize())
    return false;

  buffer_bytes_ += to_add;
  CACHE_UMA(COUNTS_50000, "BufferBytes", 0, buffer_bytes_ / 1024);
  return true;
}

void BackendImpl::BufferDeleted(int size) {
  buffer_bytes_ -= size;
  DCHECK_GE(size, 0);
}

bool BackendImpl::IsLoaded() const {
  CACHE_UMA(COUNTS, "PendingIO", 0, num_pending_io_);
  if (user_flags_ & kNoLoadProtection)
    return false;

  return (num_pending_io_ > 5 || user_load_);
}

std::string BackendImpl::HistogramName(const char* name, int experiment) const {
  if (!experiment)
    return base::StringPrintf("DiskCache.%d.%s", cache_type_, name);
  return base::StringPrintf("DiskCache.%d.%s_%d", cache_type_,
                            name, experiment);
}

base::WeakPtr<BackendImpl> BackendImpl::GetWeakPtr() {
  return ptr_factory_.GetWeakPtr();
}

// We want to remove biases from some histograms so we only send data once per
// week.
bool BackendImpl::ShouldReportAgain() {
  if (uma_report_)
    return uma_report_ == 2;

  uma_report_++;
  int64_t last_report = stats_.GetCounter(Stats::LAST_REPORT);
  Time last_time = Time::FromInternalValue(last_report);
  if (!last_report || (Time::Now() - last_time).InDays() >= 7) {
    stats_.SetCounter(Stats::LAST_REPORT, Time::Now().ToInternalValue());
    uma_report_++;
    return true;
  }
  return false;
}

void BackendImpl::FirstEviction() {
  DCHECK(data_->header.create_time);
  if (!GetEntryCount())
    return;  // This is just for unit tests.

  Time create_time = Time::FromInternalValue(data_->header.create_time);
  CACHE_UMA(AGE, "FillupAge", 0, create_time);

  int64_t use_time = stats_.GetCounter(Stats::TIMER);
  CACHE_UMA(HOURS, "FillupTime", 0, static_cast<int>(use_time / 120));
  CACHE_UMA(PERCENTAGE, "FirstHitRatio", 0, stats_.GetHitRatio());

  if (!use_time)
    use_time = 1;
  CACHE_UMA(COUNTS_10000, "FirstEntryAccessRate", 0,
            static_cast<int>(data_->header.num_entries / use_time));
  CACHE_UMA(COUNTS, "FirstByteIORate", 0,
            static_cast<int>((data_->header.num_bytes / 1024) / use_time));

  int avg_size = data_->header.num_bytes / GetEntryCount();
  CACHE_UMA(COUNTS, "FirstEntrySize", 0, avg_size);

  int large_entries_bytes = stats_.GetLargeEntriesSize();
  int large_ratio = large_entries_bytes * 100 / data_->header.num_bytes;
  CACHE_UMA(PERCENTAGE, "FirstLargeEntriesRatio", 0, large_ratio);

  if (new_eviction_) {
    CACHE_UMA(PERCENTAGE, "FirstResurrectRatio", 0, stats_.GetResurrectRatio());
    CACHE_UMA(PERCENTAGE, "FirstNoUseRatio", 0,
              data_->header.lru.sizes[0] * 100 / data_->header.num_entries);
    CACHE_UMA(PERCENTAGE, "FirstLowUseRatio", 0,
              data_->header.lru.sizes[1] * 100 / data_->header.num_entries);
    CACHE_UMA(PERCENTAGE, "FirstHighUseRatio", 0,
              data_->header.lru.sizes[2] * 100 / data_->header.num_entries);
  }

  stats_.ResetRatios();
}

void BackendImpl::CriticalError(int error) {
  STRESS_NOTREACHED();
  LOG(ERROR) << "Critical error found " << error;
  if (disabled_)
    return;

  stats_.OnEvent(Stats::FATAL_ERROR);
  LogStats();
  ReportError(error);

  // Setting the index table length to an invalid value will force re-creation
  // of the cache files.
  data_->header.table_len = 1;
  disabled_ = true;

  if (!num_refs_)
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BackendImpl::RestartCache, GetWeakPtr(), true));
}

void BackendImpl::ReportError(int error) {
  STRESS_DCHECK(!error || error == ERR_PREVIOUS_CRASH ||
                error == ERR_CACHE_CREATED);

  // We transmit positive numbers, instead of direct error codes.
  DCHECK_LE(error, 0);
  CACHE_UMA(CACHE_ERROR, "Error", 0, error * -1);
}

void BackendImpl::OnEvent(Stats::Counters an_event) {
  stats_.OnEvent(an_event);
}

void BackendImpl::OnRead(int32_t bytes) {
  DCHECK_GE(bytes, 0);
  byte_count_ += bytes;
  if (byte_count_ < 0)
    byte_count_ = std::numeric_limits<int32_t>::max();
}

void BackendImpl::OnWrite(int32_t bytes) {
  // We use the same implementation as OnRead... just log the number of bytes.
  OnRead(bytes);
}

void BackendImpl::OnStatsTimer() {
  if (disabled_)
    return;

  stats_.OnEvent(Stats::TIMER);
  int64_t time = stats_.GetCounter(Stats::TIMER);
  int64_t current = stats_.GetCounter(Stats::OPEN_ENTRIES);

  // OPEN_ENTRIES is a sampled average of the number of open entries, avoiding
  // the bias towards 0.
  if (num_refs_ && (current != num_refs_)) {
    int64_t diff = (num_refs_ - current) / 50;
    if (!diff)
      diff = num_refs_ > current ? 1 : -1;
    current = current + diff;
    stats_.SetCounter(Stats::OPEN_ENTRIES, current);
    stats_.SetCounter(Stats::MAX_ENTRIES, max_refs_);
  }

  CACHE_UMA(COUNTS, "NumberOfReferences", 0, num_refs_);

  CACHE_UMA(COUNTS_10000, "EntryAccessRate", 0, entry_count_);
  CACHE_UMA(COUNTS, "ByteIORate", 0, byte_count_ / 1024);

  // These values cover about 99.5% of the population (Oct 2011).
  user_load_ = (entry_count_ > 300 || byte_count_ > 7 * 1024 * 1024);
  entry_count_ = 0;
  byte_count_ = 0;
  up_ticks_++;

  if (!data_)
    first_timer_ = false;
  if (first_timer_) {
    first_timer_ = false;
    if (ShouldReportAgain())
      ReportStats();
  }

  // Save stats to disk at 5 min intervals.
  if (time % 10 == 0)
    StoreStats();
}

void BackendImpl::IncrementIoCount() {
  num_pending_io_++;
}

void BackendImpl::DecrementIoCount() {
  num_pending_io_--;
}

void BackendImpl::SetUnitTestMode() {
  user_flags_ |= kUnitTestMode;
  unit_test_ = true;
}

void BackendImpl::SetUpgradeMode() {
  user_flags_ |= kUpgradeMode;
  read_only_ = true;
}

void BackendImpl::SetNewEviction() {
  user_flags_ |= kNewEviction;
  new_eviction_ = true;
}

void BackendImpl::SetFlags(uint32_t flags) {
  user_flags_ |= flags;
}

void BackendImpl::ClearRefCountForTest() {
  num_refs_ = 0;
}

int BackendImpl::FlushQueueForTest(const CompletionCallback& callback) {
  background_queue_.FlushQueue(callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::RunTaskForTest(const base::Closure& task,
                                const CompletionCallback& callback) {
  background_queue_.RunTask(task, callback);
  return net::ERR_IO_PENDING;
}

void BackendImpl::TrimForTest(bool empty) {
  eviction_.SetTestMode();
  eviction_.TrimCache(empty);
}

void BackendImpl::TrimDeletedListForTest(bool empty) {
  eviction_.SetTestMode();
  eviction_.TrimDeletedList(empty);
}

base::RepeatingTimer* BackendImpl::GetTimerForTest() {
  return timer_.get();
}

int BackendImpl::SelfCheck() {
  if (!init_) {
    LOG(ERROR) << "Init failed";
    return ERR_INIT_FAILED;
  }

  int num_entries = rankings_.SelfCheck();
  if (num_entries < 0) {
    LOG(ERROR) << "Invalid rankings list, error " << num_entries;
#if !defined(NET_BUILD_STRESS_CACHE)
    return num_entries;
#endif
  }

  if (num_entries != data_->header.num_entries) {
    LOG(ERROR) << "Number of entries mismatch";
#if !defined(NET_BUILD_STRESS_CACHE)
    return ERR_NUM_ENTRIES_MISMATCH;
#endif
  }

  return CheckAllEntries();
}

void BackendImpl::FlushIndex() {
  if (index_.get() && !disabled_)
    index_->Flush();
}

// ------------------------------------------------------------------------

net::CacheType BackendImpl::GetCacheType() const {
  return cache_type_;
}

int32_t BackendImpl::GetEntryCount() const {
  if (!index_.get() || disabled_)
    return 0;
  // num_entries includes entries already evicted.
  int32_t not_deleted =
      data_->header.num_entries - data_->header.lru.sizes[Rankings::DELETED];

  if (not_deleted < 0) {
    NOTREACHED();
    not_deleted = 0;
  }

  return not_deleted;
}

int BackendImpl::OpenEntry(const std::string& key, Entry** entry,
                           const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.OpenEntry(key, entry, callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::CreateEntry(const std::string& key, Entry** entry,
                             const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.CreateEntry(key, entry, callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::DoomEntry(const std::string& key,
                           const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomEntry(key, callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::DoomAllEntries(const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomAllEntries(callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::DoomEntriesBetween(const base::Time initial_time,
                                    const base::Time end_time,
                                    const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomEntriesBetween(initial_time, end_time, callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::DoomEntriesSince(const base::Time initial_time,
                                  const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomEntriesSince(initial_time, callback);
  return net::ERR_IO_PENDING;
}

int BackendImpl::CalculateSizeOfAllEntries(const CompletionCallback& callback) {
  DCHECK(!callback.is_null());
  background_queue_.CalculateSizeOfAllEntries(callback);
  return net::ERR_IO_PENDING;
}

class BackendImpl::IteratorImpl : public Backend::Iterator {
 public:
  explicit IteratorImpl(base::WeakPtr<InFlightBackendIO> background_queue)
      : background_queue_(background_queue),
        iterator_(new Rankings::Iterator()) {
  }

  ~IteratorImpl() override {
    if (background_queue_)
      background_queue_->EndEnumeration(std::move(iterator_));
  }

  int OpenNextEntry(Entry** next_entry,
                    const net::CompletionCallback& callback) override {
    if (!background_queue_)
      return net::ERR_FAILED;
    background_queue_->OpenNextEntry(iterator_.get(), next_entry, callback);
    return net::ERR_IO_PENDING;
  }

 private:
  const base::WeakPtr<InFlightBackendIO> background_queue_;
  std::unique_ptr<Rankings::Iterator> iterator_;
};

std::unique_ptr<Backend::Iterator> BackendImpl::CreateIterator() {
  return std::unique_ptr<Backend::Iterator>(
      new IteratorImpl(GetBackgroundQueue()));
}

void BackendImpl::GetStats(StatsItems* stats) {
  if (disabled_)
    return;

  std::pair<std::string, std::string> item;

  item.first = "Entries";
  item.second = base::IntToString(data_->header.num_entries);
  stats->push_back(item);

  item.first = "Pending IO";
  item.second = base::IntToString(num_pending_io_);
  stats->push_back(item);

  item.first = "Max size";
  item.second = base::IntToString(max_size_);
  stats->push_back(item);

  item.first = "Current size";
  item.second = base::IntToString(data_->header.num_bytes);
  stats->push_back(item);

  item.first = "Cache type";
  item.second = "Blockfile Cache";
  stats->push_back(item);

  stats_.GetItems(stats);
}

void BackendImpl::OnExternalCacheHit(const std::string& key) {
  background_queue_.OnExternalCacheHit(key);
}

size_t BackendImpl::EstimateMemoryUsage() const {
  // TODO(xunjieli): Implement this. crbug.com/669108.
  return 0;
}

// ------------------------------------------------------------------------

// We just created a new file so we're going to write the header and set the
// file length to include the hash table (zero filled).
bool BackendImpl::CreateBackingStore(disk_cache::File* file) {
  AdjustMaxCacheSize(0);

  IndexHeader header;
  header.table_len = DesiredIndexTableLen(max_size_);

  // We need file version 2.1 for the new eviction algorithm.
  if (new_eviction_)
    header.version = 0x20001;

  header.create_time = Time::Now().ToInternalValue();

  if (!file->Write(&header, sizeof(header), 0))
    return false;

  return file->SetLength(GetIndexSize(header.table_len));
}

bool BackendImpl::InitBackingStore(bool* file_created) {
  if (!base::CreateDirectory(path_))
    return false;

  base::FilePath index_name = path_.AppendASCII(kIndexName);

  int flags = base::File::FLAG_READ | base::File::FLAG_WRITE |
              base::File::FLAG_OPEN_ALWAYS | base::File::FLAG_EXCLUSIVE_WRITE;
  base::File base_file(index_name, flags);
  if (!base_file.IsValid())
    return false;

  bool ret = true;
  *file_created = base_file.created();

  scoped_refptr<disk_cache::File> file(
      new disk_cache::File(std::move(base_file)));
  if (*file_created)
    ret = CreateBackingStore(file.get());

  file = NULL;
  if (!ret)
    return false;

  index_ = new MappedFile();
  data_ = static_cast<Index*>(index_->Init(index_name, 0));
  if (!data_) {
    LOG(ERROR) << "Unable to map Index file";
    return false;
  }

  if (index_->GetLength() < sizeof(Index)) {
    // We verify this again on CheckIndex() but it's easier to make sure now
    // that the header is there.
    LOG(ERROR) << "Corrupt Index file";
    return false;
  }

  return true;
}

// The maximum cache size will be either set explicitly by the caller, or
// calculated by this code.
void BackendImpl::AdjustMaxCacheSize(int table_len) {
  if (max_size_)
    return;

  // If table_len is provided, the index file exists.
  DCHECK(!table_len || data_->header.magic);

  // The user is not setting the size, let's figure it out.
  int64_t available = base::SysInfo::AmountOfFreeDiskSpace(path_);
  if (available < 0) {
    max_size_ = kDefaultCacheSize;
    return;
  }

  if (table_len)
    available += data_->header.num_bytes;

  max_size_ = PreferredCacheSize(available);

  if (!table_len)
    return;

  // If we already have a table, adjust the size to it.
  max_size_ = std::min(max_size_, MaxStorageSizeForTable(table_len));
}

bool BackendImpl::InitStats() {
  Addr address(data_->header.stats);
  int size = stats_.StorageSize();

  if (!address.is_initialized()) {
    FileType file_type = Addr::RequiredFileType(size);
    DCHECK_NE(file_type, EXTERNAL);
    int num_blocks = Addr::RequiredBlocks(size, file_type);

    if (!CreateBlock(file_type, num_blocks, &address))
      return false;

    data_->header.stats = address.value();
    return stats_.Init(NULL, 0, address);
  }

  if (!address.is_block_file()) {
    NOTREACHED();
    return false;
  }

  // Load the required data.
  size = address.num_blocks() * address.BlockSize();
  MappedFile* file = File(address);
  if (!file)
    return false;

  std::unique_ptr<char[]> data(new char[size]);
  size_t offset = address.start_block() * address.BlockSize() +
                  kBlockHeaderSize;
  if (!file->Read(data.get(), size, offset))
    return false;

  if (!stats_.Init(data.get(), size, address))
    return false;
  if (cache_type_ == net::DISK_CACHE && ShouldReportAgain())
    stats_.InitSizeHistogram();
  return true;
}

void BackendImpl::StoreStats() {
  int size = stats_.StorageSize();
  std::unique_ptr<char[]> data(new char[size]);
  Addr address;
  size = stats_.SerializeStats(data.get(), size, &address);
  DCHECK(size);
  if (!address.is_initialized())
    return;

  MappedFile* file = File(address);
  if (!file)
    return;

  size_t offset = address.start_block() * address.BlockSize() +
                  kBlockHeaderSize;
  file->Write(data.get(), size, offset);  // ignore result.
}

void BackendImpl::RestartCache(bool failure) {
  int64_t errors = stats_.GetCounter(Stats::FATAL_ERROR);
  int64_t full_dooms = stats_.GetCounter(Stats::DOOM_CACHE);
  int64_t partial_dooms = stats_.GetCounter(Stats::DOOM_RECENT);
  int64_t last_report = stats_.GetCounter(Stats::LAST_REPORT);

  PrepareForRestart();
  if (failure) {
    DCHECK(!num_refs_);
    DCHECK(open_entries_.empty());
    DelayedCacheCleanup(path_);
  } else {
    DeleteCache(path_, false);
  }

  // Don't call Init() if directed by the unit test: we are simulating a failure
  // trying to re-enable the cache.
  if (unit_test_) {
    init_ = true;  // Let the destructor do proper cleanup.
  } else if (SyncInit() == net::OK) {
    stats_.SetCounter(Stats::FATAL_ERROR, errors);
    stats_.SetCounter(Stats::DOOM_CACHE, full_dooms);
    stats_.SetCounter(Stats::DOOM_RECENT, partial_dooms);
    stats_.SetCounter(Stats::LAST_REPORT, last_report);
  }
}

void BackendImpl::PrepareForRestart() {
  // Reset the mask_ if it was not given by the user.
  if (!(user_flags_ & kMask))
    mask_ = 0;

  if (!(user_flags_ & kNewEviction))
    new_eviction_ = false;

  disabled_ = true;
  data_->header.crash = 0;
  index_->Flush();
  index_ = NULL;
  data_ = NULL;
  block_files_.CloseFiles();
  rankings_.Reset();
  init_ = false;
  restarted_ = true;
}

int BackendImpl::NewEntry(Addr address, EntryImpl** entry) {
  EntriesMap::iterator it = open_entries_.find(address.value());
  if (it != open_entries_.end()) {
    // Easy job. This entry is already in memory.
    EntryImpl* this_entry = it->second;
    this_entry->AddRef();
    *entry = this_entry;
    return 0;
  }

  STRESS_DCHECK(block_files_.IsValid(address));

  if (!address.SanityCheckForEntry()) {
    LOG(WARNING) << "Wrong entry address.";
    STRESS_NOTREACHED();
    return ERR_INVALID_ADDRESS;
  }

  scoped_refptr<EntryImpl> cache_entry(
      new EntryImpl(this, address, read_only_));
  IncreaseNumRefs();
  *entry = NULL;

  TimeTicks start = TimeTicks::Now();
  if (!cache_entry->entry()->Load())
    return ERR_READ_FAILURE;

  if (IsLoaded()) {
    CACHE_UMA(AGE_MS, "LoadTime", 0, start);
  }

  if (!cache_entry->SanityCheck()) {
    LOG(WARNING) << "Messed up entry found.";
    STRESS_NOTREACHED();
    return ERR_INVALID_ENTRY;
  }

  STRESS_DCHECK(block_files_.IsValid(
                    Addr(cache_entry->entry()->Data()->rankings_node)));

  if (!cache_entry->LoadNodeAddress())
    return ERR_READ_FAILURE;

  if (!rankings_.SanityCheck(cache_entry->rankings(), false)) {
    STRESS_NOTREACHED();
    cache_entry->SetDirtyFlag(0);
    // Don't remove this from the list (it is not linked properly). Instead,
    // break the link back to the entry because it is going away, and leave the
    // rankings node to be deleted if we find it through a list.
    rankings_.SetContents(cache_entry->rankings(), 0);
  } else if (!rankings_.DataSanityCheck(cache_entry->rankings(), false)) {
    STRESS_NOTREACHED();
    cache_entry->SetDirtyFlag(0);
    rankings_.SetContents(cache_entry->rankings(), address.value());
  }

  if (!cache_entry->DataSanityCheck()) {
    LOG(WARNING) << "Messed up entry found.";
    cache_entry->SetDirtyFlag(0);
    cache_entry->FixForDelete();
  }

  // Prevent overwriting the dirty flag on the destructor.
  cache_entry->SetDirtyFlag(GetCurrentEntryId());

  if (cache_entry->dirty()) {
    Trace("Dirty entry 0x%p 0x%x", reinterpret_cast<void*>(cache_entry.get()),
          address.value());
  }

  open_entries_[address.value()] = cache_entry.get();

  cache_entry->BeginLogging(net_log_, false);
  cache_entry.swap(entry);
  return 0;
}

EntryImpl* BackendImpl::MatchEntry(const std::string& key,
                                   uint32_t hash,
                                   bool find_parent,
                                   Addr entry_addr,
                                   bool* match_error) {
  Addr address(data_->table[hash & mask_]);
  scoped_refptr<EntryImpl> cache_entry, parent_entry;
  EntryImpl* tmp = NULL;
  bool found = false;
  std::set<CacheAddr> visited;
  *match_error = false;

  for (;;) {
    if (disabled_)
      break;

    if (visited.find(address.value()) != visited.end()) {
      // It's possible for a buggy version of the code to write a loop. Just
      // break it.
      Trace("Hash collision loop 0x%x", address.value());
      address.set_value(0);
      parent_entry->SetNextAddress(address);
    }
    visited.insert(address.value());

    if (!address.is_initialized()) {
      if (find_parent)
        found = true;
      break;
    }

    int error = NewEntry(address, &tmp);
    cache_entry.swap(&tmp);

    if (error || cache_entry->dirty()) {
      // This entry is dirty on disk (it was not properly closed): we cannot
      // trust it.
      Addr child(0);
      if (!error)
        child.set_value(cache_entry->GetNextAddress());

      if (parent_entry.get()) {
        parent_entry->SetNextAddress(child);
        parent_entry = NULL;
      } else {
        data_->table[hash & mask_] = child.value();
      }

      Trace("MatchEntry dirty %d 0x%x 0x%x", find_parent, entry_addr.value(),
            address.value());

      if (!error) {
        // It is important to call DestroyInvalidEntry after removing this
        // entry from the table.
        DestroyInvalidEntry(cache_entry.get());
        cache_entry = NULL;
      } else {
        Trace("NewEntry failed on MatchEntry 0x%x", address.value());
      }

      // Restart the search.
      address.set_value(data_->table[hash & mask_]);
      visited.clear();
      continue;
    }

    DCHECK_EQ(hash & mask_, cache_entry->entry()->Data()->hash & mask_);
    if (cache_entry->IsSameEntry(key, hash)) {
      if (!cache_entry->Update())
        cache_entry = NULL;
      found = true;
      if (find_parent && entry_addr.value() != address.value()) {
        Trace("Entry not on the index 0x%x", address.value());
        *match_error = true;
        parent_entry = NULL;
      }
      break;
    }
    if (!cache_entry->Update())
      cache_entry = NULL;
    parent_entry = cache_entry;
    cache_entry = NULL;
    if (!parent_entry.get())
      break;

    address.set_value(parent_entry->GetNextAddress());
  }

  if (parent_entry.get() && (!find_parent || !found))
    parent_entry = NULL;

  if (find_parent && entry_addr.is_initialized() && !cache_entry.get()) {
    *match_error = true;
    parent_entry = NULL;
  }

  if (cache_entry.get() && (find_parent || !found))
    cache_entry = NULL;

  if (find_parent)
    parent_entry.swap(&tmp);
  else
    cache_entry.swap(&tmp);

  FlushIndex();
  return tmp;
}

bool BackendImpl::OpenFollowingEntryFromList(Rankings::List list,
                                             CacheRankingsBlock** from_entry,
                                             EntryImpl** next_entry) {
  if (disabled_)
    return false;

  if (!new_eviction_ && Rankings::NO_USE != list)
    return false;

  Rankings::ScopedRankingsBlock rankings(&rankings_, *from_entry);
  CacheRankingsBlock* next_block = rankings_.GetNext(rankings.get(), list);
  Rankings::ScopedRankingsBlock next(&rankings_, next_block);
  *from_entry = NULL;

  *next_entry = GetEnumeratedEntry(next.get(), list);
  if (!*next_entry)
    return false;

  *from_entry = next.release();
  return true;
}

EntryImpl* BackendImpl::GetEnumeratedEntry(CacheRankingsBlock* next,
                                           Rankings::List list) {
  if (!next || disabled_)
    return NULL;

  EntryImpl* entry;
  int rv = NewEntry(Addr(next->Data()->contents), &entry);
  if (rv) {
    STRESS_NOTREACHED();
    rankings_.Remove(next, list, false);
    if (rv == ERR_INVALID_ADDRESS) {
      // There is nothing linked from the index. Delete the rankings node.
      DeleteBlock(next->address(), true);
    }
    return NULL;
  }

  if (entry->dirty()) {
    // We cannot trust this entry.
    InternalDoomEntry(entry);
    entry->Release();
    return NULL;
  }

  if (!entry->Update()) {
    STRESS_NOTREACHED();
    entry->Release();
    return NULL;
  }

  // Note that it is unfortunate (but possible) for this entry to be clean, but
  // not actually the real entry. In other words, we could have lost this entry
  // from the index, and it could have been replaced with a newer one. It's not
  // worth checking that this entry is "the real one", so we just return it and
  // let the enumeration continue; this entry will be evicted at some point, and
  // the regular path will work with the real entry. With time, this problem
  // will disasappear because this scenario is just a bug.

  // Make sure that we save the key for later.
  entry->GetKey();

  return entry;
}

EntryImpl* BackendImpl::ResurrectEntry(EntryImpl* deleted_entry) {
  if (ENTRY_NORMAL == deleted_entry->entry()->Data()->state) {
    deleted_entry->Release();
    stats_.OnEvent(Stats::CREATE_MISS);
    Trace("create entry miss ");
    return NULL;
  }

  // We are attempting to create an entry and found out that the entry was
  // previously deleted.

  eviction_.OnCreateEntry(deleted_entry);
  entry_count_++;

  stats_.OnEvent(Stats::RESURRECT_HIT);
  Trace("Resurrect entry hit ");
  return deleted_entry;
}

void BackendImpl::DestroyInvalidEntry(EntryImpl* entry) {
  LOG(WARNING) << "Destroying invalid entry.";
  Trace("Destroying invalid entry 0x%p", entry);

  entry->SetPointerForInvalidEntry(GetCurrentEntryId());

  eviction_.OnDoomEntry(entry);
  entry->InternalDoom();

  if (!new_eviction_)
    DecreaseNumEntries();
  stats_.OnEvent(Stats::INVALID_ENTRY);
}

void BackendImpl::AddStorageSize(int32_t bytes) {
  data_->header.num_bytes += bytes;
  DCHECK_GE(data_->header.num_bytes, 0);
}

void BackendImpl::SubstractStorageSize(int32_t bytes) {
  data_->header.num_bytes -= bytes;
  DCHECK_GE(data_->header.num_bytes, 0);
}

void BackendImpl::IncreaseNumRefs() {
  num_refs_++;
  if (max_refs_ < num_refs_)
    max_refs_ = num_refs_;
}

void BackendImpl::DecreaseNumRefs() {
  DCHECK(num_refs_);
  num_refs_--;

  if (!num_refs_ && disabled_)
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::Bind(&BackendImpl::RestartCache, GetWeakPtr(), true));
}

void BackendImpl::IncreaseNumEntries() {
  data_->header.num_entries++;
  DCHECK_GT(data_->header.num_entries, 0);
}

void BackendImpl::DecreaseNumEntries() {
  data_->header.num_entries--;
  if (data_->header.num_entries < 0) {
    NOTREACHED();
    data_->header.num_entries = 0;
  }
}

void BackendImpl::LogStats() {
  StatsItems stats;
  GetStats(&stats);

  for (size_t index = 0; index < stats.size(); index++)
    VLOG(1) << stats[index].first << ": " << stats[index].second;
}

void BackendImpl::ReportStats() {
  CACHE_UMA(COUNTS, "Entries", 0, data_->header.num_entries);

  int current_size = data_->header.num_bytes / (1024 * 1024);
  int max_size = max_size_ / (1024 * 1024);
  int hit_ratio_as_percentage = stats_.GetHitRatio();

  CACHE_UMA(COUNTS_10000, "Size2", 0, current_size);
  // For any bin in HitRatioBySize2, the hit ratio of caches of that size is the
  // ratio of that bin's total count to the count in the same bin in the Size2
  // histogram.
  if (base::RandInt(0, 99) < hit_ratio_as_percentage)
    CACHE_UMA(COUNTS_10000, "HitRatioBySize2", 0, current_size);
  CACHE_UMA(COUNTS_10000, "MaxSize2", 0, max_size);
  if (!max_size)
    max_size++;
  CACHE_UMA(PERCENTAGE, "UsedSpace", 0, current_size * 100 / max_size);

  CACHE_UMA(COUNTS_10000, "AverageOpenEntries2", 0,
            static_cast<int>(stats_.GetCounter(Stats::OPEN_ENTRIES)));
  CACHE_UMA(COUNTS_10000, "MaxOpenEntries2", 0,
            static_cast<int>(stats_.GetCounter(Stats::MAX_ENTRIES)));
  stats_.SetCounter(Stats::MAX_ENTRIES, 0);

  CACHE_UMA(COUNTS_10000, "TotalFatalErrors", 0,
            static_cast<int>(stats_.GetCounter(Stats::FATAL_ERROR)));
  CACHE_UMA(COUNTS_10000, "TotalDoomCache", 0,
            static_cast<int>(stats_.GetCounter(Stats::DOOM_CACHE)));
  CACHE_UMA(COUNTS_10000, "TotalDoomRecentEntries", 0,
            static_cast<int>(stats_.GetCounter(Stats::DOOM_RECENT)));
  stats_.SetCounter(Stats::FATAL_ERROR, 0);
  stats_.SetCounter(Stats::DOOM_CACHE, 0);
  stats_.SetCounter(Stats::DOOM_RECENT, 0);

  int age = (Time::Now() -
             Time::FromInternalValue(data_->header.create_time)).InHours();
  if (age)
    CACHE_UMA(HOURS, "FilesAge", 0, age);

  int64_t total_hours = stats_.GetCounter(Stats::TIMER) / 120;
  if (!data_->header.create_time || !data_->header.lru.filled) {
    int cause = data_->header.create_time ? 0 : 1;
    if (!data_->header.lru.filled)
      cause |= 2;
    CACHE_UMA(CACHE_ERROR, "ShortReport", 0, cause);
    CACHE_UMA(HOURS, "TotalTimeNotFull", 0, static_cast<int>(total_hours));
    return;
  }

  // This is an up to date client that will report FirstEviction() data. After
  // that event, start reporting this:

  CACHE_UMA(HOURS, "TotalTime", 0, static_cast<int>(total_hours));
  // For any bin in HitRatioByTotalTime, the hit ratio of caches of that total
  // time is the ratio of that bin's total count to the count in the same bin in
  // the TotalTime histogram.
  if (base::RandInt(0, 99) < hit_ratio_as_percentage)
    CACHE_UMA(HOURS, "HitRatioByTotalTime", 0, static_cast<int>(total_hours));

  int64_t use_hours = stats_.GetCounter(Stats::LAST_REPORT_TIMER) / 120;
  stats_.SetCounter(Stats::LAST_REPORT_TIMER, stats_.GetCounter(Stats::TIMER));

  // We may see users with no use_hours at this point if this is the first time
  // we are running this code.
  if (use_hours)
    use_hours = total_hours - use_hours;

  if (!use_hours || !GetEntryCount() || !data_->header.num_bytes)
    return;

  CACHE_UMA(HOURS, "UseTime", 0, static_cast<int>(use_hours));
  // For any bin in HitRatioByUseTime, the hit ratio of caches of that use time
  // is the ratio of that bin's total count to the count in the same bin in the
  // UseTime histogram.
  if (base::RandInt(0, 99) < hit_ratio_as_percentage)
    CACHE_UMA(HOURS, "HitRatioByUseTime", 0, static_cast<int>(use_hours));
  CACHE_UMA(PERCENTAGE, "HitRatio", 0, hit_ratio_as_percentage);

  int64_t trim_rate = stats_.GetCounter(Stats::TRIM_ENTRY) / use_hours;
  CACHE_UMA(COUNTS, "TrimRate", 0, static_cast<int>(trim_rate));

  int avg_size = data_->header.num_bytes / GetEntryCount();
  CACHE_UMA(COUNTS, "EntrySize", 0, avg_size);
  CACHE_UMA(COUNTS, "EntriesFull", 0, data_->header.num_entries);

  CACHE_UMA(PERCENTAGE, "IndexLoad", 0,
            data_->header.num_entries * 100 / (mask_ + 1));

  int large_entries_bytes = stats_.GetLargeEntriesSize();
  int large_ratio = large_entries_bytes * 100 / data_->header.num_bytes;
  CACHE_UMA(PERCENTAGE, "LargeEntriesRatio", 0, large_ratio);

  if (new_eviction_) {
    CACHE_UMA(PERCENTAGE, "ResurrectRatio", 0, stats_.GetResurrectRatio());
    CACHE_UMA(PERCENTAGE, "NoUseRatio", 0,
              data_->header.lru.sizes[0] * 100 / data_->header.num_entries);
    CACHE_UMA(PERCENTAGE, "LowUseRatio", 0,
              data_->header.lru.sizes[1] * 100 / data_->header.num_entries);
    CACHE_UMA(PERCENTAGE, "HighUseRatio", 0,
              data_->header.lru.sizes[2] * 100 / data_->header.num_entries);
    CACHE_UMA(PERCENTAGE, "DeletedRatio", 0,
              data_->header.lru.sizes[4] * 100 / data_->header.num_entries);
  }

  stats_.ResetRatios();
  stats_.SetCounter(Stats::TRIM_ENTRY, 0);

  if (cache_type_ == net::DISK_CACHE)
    block_files_.ReportStats();
}

void BackendImpl::UpgradeTo2_1() {
  // 2.1 is basically the same as 2.0, except that new fields are actually
  // updated by the new eviction algorithm.
  DCHECK(0x20000 == data_->header.version);
  data_->header.version = 0x20001;
  data_->header.lru.sizes[Rankings::NO_USE] = data_->header.num_entries;
}

bool BackendImpl::CheckIndex() {
  DCHECK(data_);

  size_t current_size = index_->GetLength();
  if (current_size < sizeof(Index)) {
    LOG(ERROR) << "Corrupt Index file";
    return false;
  }

  if (new_eviction_) {
    // We support versions 2.0 and 2.1, upgrading 2.0 to 2.1.
    if (kIndexMagic != data_->header.magic ||
        kCurrentVersion >> 16 != data_->header.version >> 16) {
      LOG(ERROR) << "Invalid file version or magic";
      return false;
    }
    if (kCurrentVersion == data_->header.version) {
      // We need file version 2.1 for the new eviction algorithm.
      UpgradeTo2_1();
    }
  } else {
    if (kIndexMagic != data_->header.magic ||
        kCurrentVersion != data_->header.version) {
      LOG(ERROR) << "Invalid file version or magic";
      return false;
    }
  }

  if (!data_->header.table_len) {
    LOG(ERROR) << "Invalid table size";
    return false;
  }

  if (current_size < GetIndexSize(data_->header.table_len) ||
      data_->header.table_len & (kBaseTableLen - 1)) {
    LOG(ERROR) << "Corrupt Index file";
    return false;
  }

  AdjustMaxCacheSize(data_->header.table_len);

#if !defined(NET_BUILD_STRESS_CACHE)
  if (data_->header.num_bytes < 0 ||
      (max_size_ < std::numeric_limits<int32_t>::max() - kDefaultCacheSize &&
       data_->header.num_bytes > max_size_ + kDefaultCacheSize)) {
    LOG(ERROR) << "Invalid cache (current) size";
    return false;
  }
#endif

  if (data_->header.num_entries < 0) {
    LOG(ERROR) << "Invalid number of entries";
    return false;
  }

  if (!mask_)
    mask_ = data_->header.table_len - 1;

  // Load the table into memory.
  return index_->Preload();
}

int BackendImpl::CheckAllEntries() {
  int num_dirty = 0;
  int num_entries = 0;
  DCHECK(mask_ < std::numeric_limits<uint32_t>::max());
  for (unsigned int i = 0; i <= mask_; i++) {
    Addr address(data_->table[i]);
    if (!address.is_initialized())
      continue;
    for (;;) {
      EntryImpl* tmp;
      int ret = NewEntry(address, &tmp);
      if (ret) {
        STRESS_NOTREACHED();
        return ret;
      }
      scoped_refptr<EntryImpl> cache_entry;
      cache_entry.swap(&tmp);

      if (cache_entry->dirty())
        num_dirty++;
      else if (CheckEntry(cache_entry.get()))
        num_entries++;
      else
        return ERR_INVALID_ENTRY;

      DCHECK_EQ(i, cache_entry->entry()->Data()->hash & mask_);
      address.set_value(cache_entry->GetNextAddress());
      if (!address.is_initialized())
        break;
    }
  }

  Trace("CheckAllEntries End");
  if (num_entries + num_dirty != data_->header.num_entries) {
    LOG(ERROR) << "Number of entries " << num_entries << " " << num_dirty <<
                  " " << data_->header.num_entries;
    DCHECK_LT(num_entries, data_->header.num_entries);
    return ERR_NUM_ENTRIES_MISMATCH;
  }

  return num_dirty;
}

bool BackendImpl::CheckEntry(EntryImpl* cache_entry) {
  bool ok = block_files_.IsValid(cache_entry->entry()->address());
  ok = ok && block_files_.IsValid(cache_entry->rankings()->address());
  EntryStore* data = cache_entry->entry()->Data();
  for (size_t i = 0; i < arraysize(data->data_addr); i++) {
    if (data->data_addr[i]) {
      Addr address(data->data_addr[i]);
      if (address.is_block_file())
        ok = ok && block_files_.IsValid(address);
    }
  }

  return ok && cache_entry->rankings()->VerifyHash();
}

int BackendImpl::MaxBuffersSize() {
  static int64_t total_memory = base::SysInfo::AmountOfPhysicalMemory();
  static bool done = false;

  if (!done) {
    const int kMaxBuffersSize = 30 * 1024 * 1024;

    // We want to use up to 2% of the computer's memory.
    total_memory = total_memory * 2 / 100;
    if (total_memory > kMaxBuffersSize || total_memory <= 0)
      total_memory = kMaxBuffersSize;

    done = true;
  }

  return static_cast<int>(total_memory);
}

}  // namespace disk_cache
