// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_HEAP_PROFILER_ALLOCATION_REGISTER_H_
#define BASE_TRACE_EVENT_HEAP_PROFILER_ALLOCATION_REGISTER_H_

#include <stddef.h>
#include <stdint.h>

#include <utility>

#include "base/bits.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/process/process_metrics.h"
#include "base/template_util.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "build/build_config.h"

namespace base {
namespace trace_event {

class AllocationRegisterTest;

namespace internal {

// Allocates a region of virtual address space of |size| rounded up to the
// system page size. The memory is zeroed by the system. A guard page is
// added after the end.
void* AllocateGuardedVirtualMemory(size_t size);

// Frees a region of virtual address space allocated by a call to
// |AllocateVirtualMemory|.
void FreeGuardedVirtualMemory(void* address, size_t allocated_size);

// Hash map that mmaps memory only once in the constructor. Its API is
// similar to std::unordered_map, only index (KVIndex) is used to address
template <size_t NumBuckets, class Key, class Value, class KeyHasher>
class FixedHashMap {
  // To keep things simple we don't call destructors.
  static_assert(is_trivially_destructible<Key>::value &&
                    is_trivially_destructible<Value>::value,
                "Key and Value shouldn't have destructors");
 public:
  using KVPair = std::pair<const Key, Value>;

  // For implementation simplicity API uses integer index instead
  // of iterators. Most operations (except Find) on KVIndex are O(1).
  using KVIndex = size_t;
  static const KVIndex kInvalidKVIndex = static_cast<KVIndex>(-1);

  // Capacity controls how many items this hash map can hold, and largely
  // affects memory footprint.
  FixedHashMap(size_t capacity)
    : num_cells_(capacity),
      cells_(static_cast<Cell*>(
          AllocateGuardedVirtualMemory(num_cells_ * sizeof(Cell)))),
      buckets_(static_cast<Bucket*>(
          AllocateGuardedVirtualMemory(NumBuckets * sizeof(Bucket)))),
      free_list_(nullptr),
      next_unused_cell_(0) {}

  ~FixedHashMap() {
    FreeGuardedVirtualMemory(cells_, num_cells_ * sizeof(Cell));
    FreeGuardedVirtualMemory(buckets_, NumBuckets * sizeof(Bucket));
  }

  std::pair<KVIndex, bool> Insert(const Key& key, const Value& value) {
    Cell** p_cell = Lookup(key);
    Cell* cell = *p_cell;
    if (cell) {
      return {static_cast<KVIndex>(cell - cells_), false};  // not inserted
    }

    // Get a free cell and link it.
    *p_cell = cell = GetFreeCell();
    cell->p_prev = p_cell;
    cell->next = nullptr;

    // Initialize key/value pair. Since key is 'const Key' this is the
    // only way to initialize it.
    new (&cell->kv) KVPair(key, value);

    return {static_cast<KVIndex>(cell - cells_), true};  // inserted
  }

  void Remove(KVIndex index) {
    DCHECK_LT(index, next_unused_cell_);

    Cell* cell = &cells_[index];

    // Unlink the cell.
    *cell->p_prev = cell->next;
    if (cell->next) {
      cell->next->p_prev = cell->p_prev;
    }
    cell->p_prev = nullptr;  // mark as free

    // Add it to the free list.
    cell->next = free_list_;
    free_list_ = cell;
  }

  KVIndex Find(const Key& key) const {
    Cell* cell = *Lookup(key);
    return cell ? static_cast<KVIndex>(cell - cells_) : kInvalidKVIndex;
  }

  KVPair& Get(KVIndex index) {
    return cells_[index].kv;
  }

  const KVPair& Get(KVIndex index) const {
    return cells_[index].kv;
  }

  // Finds next index that has a KVPair associated with it. Search starts
  // with the specified index. Returns kInvalidKVIndex if nothing was found.
  // To find the first valid index, call this function with 0. Continue
  // calling with the last_index + 1 until kInvalidKVIndex is returned.
  KVIndex Next(KVIndex index) const {
    for (;index < next_unused_cell_; ++index) {
      if (cells_[index].p_prev) {
        return index;
      }
    }
    return kInvalidKVIndex;
  }

  // Estimates number of bytes used in allocated memory regions.
  size_t EstimateUsedMemory() const {
    size_t page_size = base::GetPageSize();
    // |next_unused_cell_| is the first cell that wasn't touched, i.e.
    // it's the number of touched cells.
    return bits::Align(sizeof(Cell) * next_unused_cell_, page_size) +
           bits::Align(sizeof(Bucket) * NumBuckets, page_size);
  }

 private:
  friend base::trace_event::AllocationRegisterTest;

  struct Cell {
    KVPair kv;
    Cell* next;

    // Conceptually this is |prev| in a doubly linked list. However, buckets
    // also participate in the bucket's cell list - they point to the list's
    // head and also need to be linked / unlinked properly. To treat these two
    // cases uniformly, instead of |prev| we're storing "pointer to a Cell*
    // that points to this Cell" kind of thing. So |p_prev| points to a bucket
    // for the first cell in a list, and points to |next| of the previous cell
    // for any other cell. With that Lookup() is the only function that handles
    // buckets / cells differently.
    // If |p_prev| is nullptr, the cell is in the free list.
    Cell** p_prev;
  };

  using Bucket = Cell*;

  // Returns a pointer to the cell that contains or should contain the entry
  // for |key|. The pointer may point at an element of |buckets_| or at the
  // |next| member of an element of |cells_|.
  Cell** Lookup(const Key& key) const {
    // The list head is in |buckets_| at the hash offset.
    Cell** p_cell = &buckets_[Hash(key)];

    // Chase down the list until the cell that holds |key| is found,
    // or until the list ends.
    while (*p_cell && (*p_cell)->kv.first != key) {
      p_cell = &(*p_cell)->next;
    }

    return p_cell;
  }

  // Returns a cell that is not being used to store an entry (either by
  // recycling from the free list or by taking a fresh cell).
  Cell* GetFreeCell() {
    // First try to re-use a cell from the free list.
    if (free_list_) {
      Cell* cell = free_list_;
      free_list_ = cell->next;
      return cell;
    }

    // Otherwise pick the next cell that has not been touched before.
    size_t idx = next_unused_cell_;
    next_unused_cell_++;

    // If the hash table has too little capacity (when too little address space
    // was reserved for |cells_|), |next_unused_cell_| can be an index outside
    // of the allocated storage. A guard page is allocated there to crash the
    // program in that case. There are alternative solutions:
    // - Deal with it, increase capacity by reallocating |cells_|.
    // - Refuse to insert and let the caller deal with it.
    // Because free cells are re-used before accessing fresh cells with a higher
    // index, and because reserving address space without touching it is cheap,
    // the simplest solution is to just allocate a humongous chunk of address
    // space.

    CHECK_LT(next_unused_cell_, num_cells_ + 1)
        << "Allocation Register hash table has too little capacity. Increase "
           "the capacity to run heap profiler in large sessions.";

    return &cells_[idx];
  }

  // Returns a value in the range [0, NumBuckets - 1] (inclusive).
  size_t Hash(const Key& key) const {
    if (NumBuckets == (NumBuckets & ~(NumBuckets - 1))) {
      // NumBuckets is a power of 2.
      return KeyHasher()(key) & (NumBuckets - 1);
    } else {
      return KeyHasher()(key) % NumBuckets;
    }
  }

  // Number of cells.
  size_t const num_cells_;

  // The array of cells. This array is backed by mmapped memory. Lower indices
  // are accessed first, higher indices are accessed only when the |free_list_|
  // is empty. This is to minimize the amount of resident memory used.
  Cell* const cells_;

  // The array of buckets (pointers into |cells_|). |buckets_[Hash(key)]| will
  // contain the pointer to the linked list of cells for |Hash(key)|.
  // This array is backed by mmapped memory.
  mutable Bucket* buckets_;

  // The head of the free list.
  Cell* free_list_;

  // The index of the first element of |cells_| that has not been used before.
  // If the free list is empty and a new cell is needed, the cell at this index
  // is used. This is the high water mark for the number of entries stored.
  size_t next_unused_cell_;

  DISALLOW_COPY_AND_ASSIGN(FixedHashMap);
};

}  // namespace internal

class TraceEventMemoryOverhead;

// The allocation register keeps track of all allocations that have not been
// freed. Internally it has two hashtables: one for Backtraces and one for
// actual allocations. Sizes of both hashtables are fixed, and this class
// allocates (mmaps) only in its constructor.
class BASE_EXPORT AllocationRegister {
 public:
  // Details about an allocation.
  struct Allocation {
    const void* address;
    size_t size;
    AllocationContext context;
  };

  // An iterator that iterates entries in no particular order.
  class BASE_EXPORT ConstIterator {
   public:
    void operator++();
    bool operator!=(const ConstIterator& other) const;
    Allocation operator*() const;

   private:
    friend class AllocationRegister;
    using AllocationIndex = size_t;

    ConstIterator(const AllocationRegister& alloc_register,
                  AllocationIndex index);

    const AllocationRegister& register_;
    AllocationIndex index_;
  };

  AllocationRegister();
  AllocationRegister(size_t allocation_capacity, size_t backtrace_capacity);

  ~AllocationRegister();

  // Inserts allocation details into the table. If the address was present
  // already, its details are updated. |address| must not be null.
  void Insert(const void* address,
              size_t size,
              const AllocationContext& context);

  // Removes the address from the table if it is present. It is ok to call this
  // with a null pointer.
  void Remove(const void* address);

  // Finds allocation for the address and fills |out_allocation|.
  bool Get(const void* address, Allocation* out_allocation) const;

  ConstIterator begin() const;
  ConstIterator end() const;

  // Estimates memory overhead including |sizeof(AllocationRegister)|.
  void EstimateTraceMemoryOverhead(TraceEventMemoryOverhead* overhead) const;

 private:
  friend AllocationRegisterTest;

// Expect lower number of allocations from mobile platforms. Load factor
// (capacity / bucket count) is kept less than 10 for optimal hashing. The
// number of buckets should be changed together with AddressHasher.
#if defined(OS_ANDROID) || defined(OS_IOS)
  static const size_t kAllocationBuckets = 1 << 18;
  static const size_t kAllocationCapacity = 1500000;
#else
  static const size_t kAllocationBuckets = 1 << 19;
  static const size_t kAllocationCapacity = 5000000;
#endif

  // 2^16 works well with BacktraceHasher. When increasing this number make
  // sure BacktraceHasher still produces low number of collisions.
  static const size_t kBacktraceBuckets = 1 << 16;
#if defined(OS_ANDROID)
  static const size_t kBacktraceCapacity = 32000;  // 22K was observed
#else
  static const size_t kBacktraceCapacity = 55000;  // 45K was observed on Linux
#endif

  struct BacktraceHasher {
    size_t operator () (const Backtrace& backtrace) const;
  };

  using BacktraceMap = internal::FixedHashMap<
      kBacktraceBuckets,
      Backtrace,
      size_t, // Number of references to the backtrace (the key). Incremented
              // when an allocation that references the backtrace is inserted,
              // and decremented when the allocation is removed. When the
              // number drops to zero, the backtrace is removed from the map.
      BacktraceHasher>;

  struct AllocationInfo {
    size_t size;
    const char* type_name;
    BacktraceMap::KVIndex backtrace_index;
  };

  struct AddressHasher {
    size_t operator () (const void* address) const;
  };

  using AllocationMap = internal::FixedHashMap<
      kAllocationBuckets,
      const void*,
      AllocationInfo,
      AddressHasher>;

  BacktraceMap::KVIndex InsertBacktrace(const Backtrace& backtrace);
  void RemoveBacktrace(BacktraceMap::KVIndex index);

  Allocation GetAllocation(AllocationMap::KVIndex) const;

  AllocationMap allocations_;
  BacktraceMap backtraces_;

  DISALLOW_COPY_AND_ASSIGN(AllocationRegister);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_HEAP_PROFILER_ALLOCATION_REGISTER_H_
