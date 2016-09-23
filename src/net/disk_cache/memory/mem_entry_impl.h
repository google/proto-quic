// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DISK_CACHE_MEMORY_MEM_ENTRY_IMPL_H_
#define NET_DISK_CACHE_MEMORY_MEM_ENTRY_IMPL_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/containers/linked_list.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/time/time.h"
#include "net/disk_cache/disk_cache.h"
#include "net/log/net_log.h"

namespace disk_cache {

class MemBackendImpl;

// This class implements the Entry interface for the memory-only cache. An
// object of this class represents a single entry on the cache. We use two types
// of entries, parent and child to support sparse caching.
//
// A parent entry is non-sparse until a sparse method is invoked (i.e.
// ReadSparseData, WriteSparseData, GetAvailableRange) when sparse information
// is initialized. It then manages a list of child entries and delegates the
// sparse API calls to the child entries. It creates and deletes child entries
// and updates the list when needed.
//
// A child entry is used to carry partial cache content, non-sparse methods like
// ReadData and WriteData cannot be applied to them. The lifetime of a child
// entry is managed by the parent entry that created it except that the entry
// can be evicted independently. A child entry does not have a key and it is not
// registered in the backend's entry map.
//
// A sparse child entry has a fixed maximum size and can be partially
// filled. There can only be one continous filled region in a sparse entry, as
// illustrated by the following example:
// | xxx ooooo |
// x = unfilled region
// o = filled region
// It is guaranteed that there is at most one unfilled region and one filled
// region, and the unfilled region (if there is one) is always before the filled
// region. The book keeping for filled region in a sparse entry is done by using
// the variable |child_first_pos_|.

class NET_EXPORT_PRIVATE MemEntryImpl final
    : public Entry,
      public base::LinkNode<MemEntryImpl> {
 public:
  enum EntryType {
    PARENT_ENTRY,
    CHILD_ENTRY,
  };

  // Provided to better document calls to |UpdateStateOnUse()|.
  enum EntryModified {
    ENTRY_WAS_NOT_MODIFIED,
    ENTRY_WAS_MODIFIED,
  };

  // Constructor for parent entries.
  MemEntryImpl(MemBackendImpl* backend,
               const std::string& key,
               net::NetLog* net_log);

  // Constructor for child entries.
  MemEntryImpl(MemBackendImpl* backend,
               int child_id,
               MemEntryImpl* parent,
               net::NetLog* net_log);

  void Open();
  bool InUse() const;

  EntryType type() const { return parent_ ? CHILD_ENTRY : PARENT_ENTRY; }
  const std::string& key() const { return key_; }
  const MemEntryImpl* parent() const { return parent_; }
  int child_id() const { return child_id_; }
  base::Time last_used() const { return last_used_; }

  // The in-memory size of this entry to use for the purposes of eviction.
  int GetStorageSize() const;

  // Update an entry's position in the backend LRU list and set |last_used_|. If
  // the entry was modified, also update |last_modified_|.
  void UpdateStateOnUse(EntryModified modified_enum);

  // From disk_cache::Entry:
  void Doom() override;
  void Close() override;
  std::string GetKey() const override;
  base::Time GetLastUsed() const override;
  base::Time GetLastModified() const override;
  int32_t GetDataSize(int index) const override;
  int ReadData(int index,
               int offset,
               IOBuffer* buf,
               int buf_len,
               const CompletionCallback& callback) override;
  int WriteData(int index,
                int offset,
                IOBuffer* buf,
                int buf_len,
                const CompletionCallback& callback,
                bool truncate) override;
  int ReadSparseData(int64_t offset,
                     IOBuffer* buf,
                     int buf_len,
                     const CompletionCallback& callback) override;
  int WriteSparseData(int64_t offset,
                      IOBuffer* buf,
                      int buf_len,
                      const CompletionCallback& callback) override;
  int GetAvailableRange(int64_t offset,
                        int len,
                        int64_t* start,
                        const CompletionCallback& callback) override;
  bool CouldBeSparse() const override;
  void CancelSparseIO() override {}
  int ReadyForSparseIO(const CompletionCallback& callback) override;

 private:
  MemEntryImpl(MemBackendImpl* backend,
               const std::string& key,
               int child_id,
               MemEntryImpl* parent,
               net::NetLog* net_log);

  using EntryMap = std::unordered_map<int, MemEntryImpl*>;

  static const int kNumStreams = 3;

  ~MemEntryImpl() override;

  // Do all the work for corresponding public functions.  Implemented as
  // separate functions to make logging of results simpler.
  int InternalReadData(int index, int offset, IOBuffer* buf, int buf_len);
  int InternalWriteData(int index, int offset, IOBuffer* buf, int buf_len,
                        bool truncate);
  int InternalReadSparseData(int64_t offset, IOBuffer* buf, int buf_len);
  int InternalWriteSparseData(int64_t offset, IOBuffer* buf, int buf_len);
  int InternalGetAvailableRange(int64_t offset, int len, int64_t* start);

  // Initializes the children map and sparse info. This method is only called
  // on a parent entry.
  bool InitSparseInfo();

  // Returns an entry responsible for |offset|. The returned entry can be a
  // child entry or this entry itself if |offset| points to the first range.
  // If such entry does not exist and |create| is true, a new child entry is
  // created.
  MemEntryImpl* GetChild(int64_t offset, bool create);

  // Finds the first child located within the range [|offset|, |offset + len|).
  // Returns the number of bytes ahead of |offset| to reach the first available
  // bytes in the entry. The first child found is output to |child|.
  int FindNextChild(int64_t offset, int len, MemEntryImpl** child);

  std::string key_;
  std::vector<char> data_[kNumStreams];  // User data.
  int ref_count_;

  int child_id_;              // The ID of a child entry.
  int child_first_pos_;       // The position of the first byte in a child
                              // entry.
  // Pointer to the parent entry, or nullptr if this entry is a parent entry.
  MemEntryImpl* parent_;
  std::unique_ptr<EntryMap> children_;

  base::Time last_modified_;
  base::Time last_used_;
  MemBackendImpl* backend_;   // Back pointer to the cache.
  bool doomed_;               // True if this entry was removed from the cache.

  net::NetLogWithSource net_log_;

  DISALLOW_COPY_AND_ASSIGN(MemEntryImpl);
};

}  // namespace disk_cache

#endif  // NET_DISK_CACHE_MEMORY_MEM_ENTRY_IMPL_H_
