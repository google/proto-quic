// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_SIMPLE_SIMPLE_BACKEND_IMPL_H_
#define NET_DISK_CACHE_SIMPLE_SIMPLE_BACKEND_IMPL_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "base/callback_forward.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/string_split.h"
#include "base/task_runner.h"
#include "base/time/time.h"
#include "net/base/cache_type.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/simple/simple_entry_impl.h"
#include "net/disk_cache/simple/simple_index_delegate.h"

namespace base {
class SingleThreadTaskRunner;
class TaskRunner;
}

namespace disk_cache {

// SimpleBackendImpl is a new cache backend that stores entries in individual
// files.
// See http://www.chromium.org/developers/design-documents/network-stack/disk-cache/very-simple-backend
//
// The SimpleBackendImpl provides safe iteration; mutating entries during
// iteration cannot cause a crash. It is undefined whether entries created or
// destroyed during the iteration will be included in any pre-existing
// iterations.
//
// The non-static functions below must be called on the IO thread unless
// otherwise stated.

class SimpleEntryImpl;
class SimpleIndex;

class NET_EXPORT_PRIVATE SimpleBackendImpl : public Backend,
    public SimpleIndexDelegate,
    public base::SupportsWeakPtr<SimpleBackendImpl> {
 public:
  SimpleBackendImpl(
      const base::FilePath& path,
      int max_bytes,
      net::CacheType cache_type,
      const scoped_refptr<base::SingleThreadTaskRunner>& cache_thread,
      net::NetLog* net_log);

  ~SimpleBackendImpl() override;

  net::CacheType cache_type() const { return cache_type_; }
  SimpleIndex* index() { return index_.get(); }

  base::TaskRunner* worker_pool() { return worker_pool_.get(); }

  int Init(const CompletionCallback& completion_callback);

  // Sets the maximum size for the total amount of data stored by this instance.
  bool SetMaxSize(int max_bytes);

  // Returns the maximum file size permitted in this backend.
  int GetMaxFileSize() const;

  // Flush our SequencedWorkerPool.
  static void FlushWorkerPoolForTesting();

  // The entry for |entry_hash| is being doomed; the backend will not attempt
  // run new operations for this |entry_hash| until the Doom is completed.
  void OnDoomStart(uint64_t entry_hash);

  // The entry for |entry_hash| has been successfully doomed, we can now allow
  // operations on this entry, and we can run any operations enqueued while the
  // doom completed.
  void OnDoomComplete(uint64_t entry_hash);

  // SimpleIndexDelegate:
  void DoomEntries(std::vector<uint64_t>* entry_hashes,
                   const CompletionCallback& callback) override;

  // Backend:
  net::CacheType GetCacheType() const override;
  int32_t GetEntryCount() const override;
  int OpenEntry(const std::string& key,
                Entry** entry,
                const CompletionCallback& callback) override;
  int CreateEntry(const std::string& key,
                  Entry** entry,
                  const CompletionCallback& callback) override;
  int DoomEntry(const std::string& key,
                const CompletionCallback& callback) override;
  int DoomAllEntries(const CompletionCallback& callback) override;
  int DoomEntriesBetween(base::Time initial_time,
                         base::Time end_time,
                         const CompletionCallback& callback) override;
  int DoomEntriesSince(base::Time initial_time,
                       const CompletionCallback& callback) override;
  int CalculateSizeOfAllEntries(const CompletionCallback& callback) override;
  std::unique_ptr<Iterator> CreateIterator() override;
  void GetStats(base::StringPairs* stats) override;
  void OnExternalCacheHit(const std::string& key) override;

 private:
  class SimpleIterator;
  friend class SimpleIterator;

  using EntryMap = std::unordered_map<uint64_t, SimpleEntryImpl*>;

  using InitializeIndexCallback =
      base::Callback<void(base::Time mtime, uint64_t max_size, int result)>;

  class ActiveEntryProxy;
  friend class ActiveEntryProxy;

  // Return value of InitCacheStructureOnDisk().
  struct DiskStatResult {
    base::Time cache_dir_mtime;
    uint64_t max_size;
    bool detected_magic_number_mismatch;
    int net_error;
  };

  void InitializeIndex(const CompletionCallback& callback,
                       const DiskStatResult& result);

  // Dooms all entries previously accessed between |initial_time| and
  // |end_time|. Invoked when the index is ready.
  void IndexReadyForDoom(base::Time initial_time,
                         base::Time end_time,
                         const CompletionCallback& callback,
                         int result);

  // Calculates the size of the entire cache. Invoked when the index is ready.
  void IndexReadyForSizeCalculation(const CompletionCallback& callback,
                                    int result);

  // Try to create the directory if it doesn't exist. This must run on the IO
  // thread.
  static DiskStatResult InitCacheStructureOnDisk(const base::FilePath& path,
                                                 uint64_t suggested_max_size);

  // Searches |active_entries_| for the entry corresponding to |key|. If found,
  // returns the found entry. Otherwise, creates a new entry and returns that.
  scoped_refptr<SimpleEntryImpl> CreateOrFindActiveEntry(
      uint64_t entry_hash,
      const std::string& key);

  // Given a hash, will try to open the corresponding Entry. If we have an Entry
  // corresponding to |hash| in the map of active entries, opens it. Otherwise,
  // a new empty Entry will be created, opened and filled with information from
  // the disk.
  int OpenEntryFromHash(uint64_t entry_hash,
                        Entry** entry,
                        const CompletionCallback& callback);

  // Doom the entry corresponding to |entry_hash|, if it's active or currently
  // pending doom. This function does not block if there is an active entry,
  // which is very important to prevent races in DoomEntries() above.
  int DoomEntryFromHash(uint64_t entry_hash,
                        const CompletionCallback& callback);

  // Called when we tried to open an entry with hash alone. When a blank entry
  // has been created and filled in with information from the disk - based on a
  // hash alone - this checks that a duplicate active entry was not created
  // using a key in the meantime.
  void OnEntryOpenedFromHash(uint64_t hash,
                             Entry** entry,
                             const scoped_refptr<SimpleEntryImpl>& simple_entry,
                             const CompletionCallback& callback,
                             int error_code);

  // Called when we tried to open an entry from key. When the entry has been
  // opened, a check for key mismatch is performed.
  void OnEntryOpenedFromKey(const std::string key,
                            Entry** entry,
                            const scoped_refptr<SimpleEntryImpl>& simple_entry,
                            const CompletionCallback& callback,
                            int error_code);

  // A callback thunk used by DoomEntries to clear the |entries_pending_doom_|
  // after a mass doom.
  void DoomEntriesComplete(std::unique_ptr<std::vector<uint64_t>> entry_hashes,
                           const CompletionCallback& callback,
                           int result);

  const base::FilePath path_;
  const net::CacheType cache_type_;
  std::unique_ptr<SimpleIndex> index_;
  const scoped_refptr<base::SingleThreadTaskRunner> cache_thread_;
  scoped_refptr<base::TaskRunner> worker_pool_;

  int orig_max_size_;
  const SimpleEntryImpl::OperationsMode entry_operations_mode_;

  EntryMap active_entries_;

  // The set of all entries which are currently being doomed. To avoid races,
  // these entries cannot have Doom/Create/Open operations run until the doom
  // is complete. The base::Closure map target is used to store deferred
  // operations to be run at the completion of the Doom.
  std::unordered_map<uint64_t, std::vector<base::Closure>>
      entries_pending_doom_;

  net::NetLog* const net_log_;
};

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_SIMPLE_SIMPLE_BACKEND_IMPL_H_
