// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/partition_allocator/partition_alloc.h"

#include <string.h>

#include "base/allocator/oom.h"
#include "base/compiler_specific.h"
#include "base/synchronization/spin_lock.h"

// Two partition pages are used as guard / metadata page so make sure the super
// page size is bigger.
static_assert(base::kPartitionPageSize * 4 <= base::kSuperPageSize,
              "ok super page size");
static_assert(!(base::kSuperPageSize % base::kPartitionPageSize),
              "ok super page multiple");
// Four system pages gives us room to hack out a still-guard-paged piece
// of metadata in the middle of a guard partition page.
static_assert(base::kSystemPageSize * 4 <= base::kPartitionPageSize,
              "ok partition page size");
static_assert(!(base::kPartitionPageSize % base::kSystemPageSize),
              "ok partition page multiple");
static_assert(sizeof(base::PartitionPage) <= base::kPageMetadataSize,
              "PartitionPage should not be too big");
static_assert(sizeof(base::PartitionBucket) <= base::kPageMetadataSize,
              "PartitionBucket should not be too big");
static_assert(sizeof(base::PartitionSuperPageExtentEntry) <=
                  base::kPageMetadataSize,
              "PartitionSuperPageExtentEntry should not be too big");
static_assert(base::kPageMetadataSize * base::kNumPartitionPagesPerSuperPage <=
                  base::kSystemPageSize,
              "page metadata fits in hole");
// Check that some of our zanier calculations worked out as expected.
static_assert(base::kGenericSmallestBucket == 8, "generic smallest bucket");
static_assert(base::kGenericMaxBucketed == 983040, "generic max bucketed");
static_assert(base::kMaxSystemPagesPerSlotSpan < (1 << 8),
              "System pages per slot span must be less than 128.");

namespace base {

subtle::SpinLock PartitionRootBase::gInitializedLock;
bool PartitionRootBase::gInitialized = false;
PartitionPage PartitionRootBase::gSeedPage;
PartitionBucket PartitionRootBase::gPagedBucket;
void (*PartitionRootBase::gOomHandlingFunction)() = nullptr;
PartitionAllocHooks::AllocationHook* PartitionAllocHooks::allocation_hook_ =
    nullptr;
PartitionAllocHooks::FreeHook* PartitionAllocHooks::free_hook_ = nullptr;

static uint8_t PartitionBucketNumSystemPages(size_t size) {
  // This works out reasonably for the current bucket sizes of the generic
  // allocator, and the current values of partition page size and constants.
  // Specifically, we have enough room to always pack the slots perfectly into
  // some number of system pages. The only waste is the waste associated with
  // unfaulted pages (i.e. wasted address space).
  // TODO: we end up using a lot of system pages for very small sizes. For
  // example, we'll use 12 system pages for slot size 24. The slot size is
  // so small that the waste would be tiny with just 4, or 1, system pages.
  // Later, we can investigate whether there are anti-fragmentation benefits
  // to using fewer system pages.
  double best_waste_ratio = 1.0f;
  uint16_t best_pages = 0;
  if (size > kMaxSystemPagesPerSlotSpan * kSystemPageSize) {
    DCHECK(!(size % kSystemPageSize));
    best_pages = static_cast<uint16_t>(size / kSystemPageSize);
    CHECK(best_pages < (1 << 8));
    return static_cast<uint8_t>(best_pages);
  }
  DCHECK(size <= kMaxSystemPagesPerSlotSpan * kSystemPageSize);
  for (uint16_t i = kNumSystemPagesPerPartitionPage - 1;
       i <= kMaxSystemPagesPerSlotSpan; ++i) {
    size_t page_size = kSystemPageSize * i;
    size_t num_slots = page_size / size;
    size_t waste = page_size - (num_slots * size);
    // Leaving a page unfaulted is not free; the page will occupy an empty page
    // table entry.  Make a simple attempt to account for that.
    size_t num_remainder_pages = i & (kNumSystemPagesPerPartitionPage - 1);
    size_t num_unfaulted_pages =
        num_remainder_pages
            ? (kNumSystemPagesPerPartitionPage - num_remainder_pages)
            : 0;
    waste += sizeof(void*) * num_unfaulted_pages;
    double waste_ratio = (double)waste / (double)page_size;
    if (waste_ratio < best_waste_ratio) {
      best_waste_ratio = waste_ratio;
      best_pages = i;
    }
  }
  DCHECK(best_pages > 0);
  CHECK(best_pages <= kMaxSystemPagesPerSlotSpan);
  return static_cast<uint8_t>(best_pages);
}

static void PartitionAllocBaseInit(PartitionRootBase* root) {
  DCHECK(!root->initialized);
  {
    subtle::SpinLock::Guard guard(PartitionRootBase::gInitializedLock);
    if (!PartitionRootBase::gInitialized) {
      PartitionRootBase::gInitialized = true;
      // We mark the seed page as free to make sure it is skipped by our
      // logic to find a new active page.
      PartitionRootBase::gPagedBucket.active_pages_head =
          &PartitionRootGeneric::gSeedPage;
    }
  }

  root->initialized = true;
  root->total_size_of_committed_pages = 0;
  root->total_size_of_super_pages = 0;
  root->total_size_of_direct_mapped_pages = 0;
  root->next_super_page = 0;
  root->next_partition_page = 0;
  root->next_partition_page_end = 0;
  root->first_extent = 0;
  root->current_extent = 0;
  root->direct_map_list = 0;

  memset(&root->global_empty_page_ring, '\0',
         sizeof(root->global_empty_page_ring));
  root->global_empty_page_ring_index = 0;

  // This is a "magic" value so we can test if a root pointer is valid.
  root->inverted_self = ~reinterpret_cast<uintptr_t>(root);
}

static void PartitionBucketInitBase(PartitionBucket* bucket,
                                    PartitionRootBase* root) {
  bucket->active_pages_head = &PartitionRootGeneric::gSeedPage;
  bucket->empty_pages_head = 0;
  bucket->decommitted_pages_head = 0;
  bucket->num_full_pages = 0;
  bucket->num_system_pages_per_slot_span =
      PartitionBucketNumSystemPages(bucket->slot_size);
}

void PartitionAllocGlobalInit(void (*oom_handling_function)()) {
  DCHECK(oom_handling_function);
  PartitionRootBase::gOomHandlingFunction = oom_handling_function;
}

void PartitionAllocInit(PartitionRoot* root,
                        size_t num_buckets,
                        size_t max_allocation) {
  PartitionAllocBaseInit(root);

  root->num_buckets = num_buckets;
  root->max_allocation = max_allocation;
  size_t i;
  for (i = 0; i < root->num_buckets; ++i) {
    PartitionBucket* bucket = &root->buckets()[i];
    if (!i)
      bucket->slot_size = kAllocationGranularity;
    else
      bucket->slot_size = i << kBucketShift;
    PartitionBucketInitBase(bucket, root);
  }
}

void PartitionAllocGenericInit(PartitionRootGeneric* root) {
  subtle::SpinLock::Guard guard(root->lock);

  PartitionAllocBaseInit(root);

  // Precalculate some shift and mask constants used in the hot path.
  // Example: malloc(41) == 101001 binary.
  // Order is 6 (1 << 6-1) == 32 is highest bit set.
  // order_index is the next three MSB == 010 == 2.
  // sub_order_index_mask is a mask for the remaining bits == 11 (masking to 01
  // for
  // the sub_order_index).
  size_t order;
  for (order = 0; order <= kBitsPerSizeT; ++order) {
    size_t order_index_shift;
    if (order < kGenericNumBucketsPerOrderBits + 1)
      order_index_shift = 0;
    else
      order_index_shift = order - (kGenericNumBucketsPerOrderBits + 1);
    root->order_index_shifts[order] = order_index_shift;
    size_t sub_order_index_mask;
    if (order == kBitsPerSizeT) {
      // This avoids invoking undefined behavior for an excessive shift.
      sub_order_index_mask =
          static_cast<size_t>(-1) >> (kGenericNumBucketsPerOrderBits + 1);
    } else {
      sub_order_index_mask = ((static_cast<size_t>(1) << order) - 1) >>
                             (kGenericNumBucketsPerOrderBits + 1);
    }
    root->order_sub_index_masks[order] = sub_order_index_mask;
  }

  // Set up the actual usable buckets first.
  // Note that typical values (i.e. min allocation size of 8) will result in
  // pseudo buckets (size==9 etc. or more generally, size is not a multiple
  // of the smallest allocation granularity).
  // We avoid them in the bucket lookup map, but we tolerate them to keep the
  // code simpler and the structures more generic.
  size_t i, j;
  size_t current_size = kGenericSmallestBucket;
  size_t currentIncrement =
      kGenericSmallestBucket >> kGenericNumBucketsPerOrderBits;
  PartitionBucket* bucket = &root->buckets[0];
  for (i = 0; i < kGenericNumBucketedOrders; ++i) {
    for (j = 0; j < kGenericNumBucketsPerOrder; ++j) {
      bucket->slot_size = current_size;
      PartitionBucketInitBase(bucket, root);
      // Disable psuedo buckets so that touching them faults.
      if (current_size % kGenericSmallestBucket)
        bucket->active_pages_head = 0;
      current_size += currentIncrement;
      ++bucket;
    }
    currentIncrement <<= 1;
  }
  DCHECK(current_size == 1 << kGenericMaxBucketedOrder);
  DCHECK(bucket == &root->buckets[0] + kGenericNumBuckets);

  // Then set up the fast size -> bucket lookup table.
  bucket = &root->buckets[0];
  PartitionBucket** bucketPtr = &root->bucket_lookups[0];
  for (order = 0; order <= kBitsPerSizeT; ++order) {
    for (j = 0; j < kGenericNumBucketsPerOrder; ++j) {
      if (order < kGenericMinBucketedOrder) {
        // Use the bucket of the finest granularity for malloc(0) etc.
        *bucketPtr++ = &root->buckets[0];
      } else if (order > kGenericMaxBucketedOrder) {
        *bucketPtr++ = &PartitionRootGeneric::gPagedBucket;
      } else {
        PartitionBucket* validBucket = bucket;
        // Skip over invalid buckets.
        while (validBucket->slot_size % kGenericSmallestBucket)
          validBucket++;
        *bucketPtr++ = validBucket;
        bucket++;
      }
    }
  }
  DCHECK(bucket == &root->buckets[0] + kGenericNumBuckets);
  DCHECK(bucketPtr ==
         &root->bucket_lookups[0] +
             ((kBitsPerSizeT + 1) * kGenericNumBucketsPerOrder));
  // And there's one last bucket lookup that will be hit for e.g. malloc(-1),
  // which tries to overflow to a non-existant order.
  *bucketPtr = &PartitionRootGeneric::gPagedBucket;
}

#if !defined(ARCH_CPU_64_BITS)
static NOINLINE void partitionOutOfMemoryWithLotsOfUncommitedPages() {
  OOM_CRASH();
}
#endif

static NOINLINE void partitionOutOfMemory(const PartitionRootBase* root) {
#if !defined(ARCH_CPU_64_BITS)
  // Check whether this OOM is due to a lot of super pages that are allocated
  // but not committed, probably due to http://crbug.com/421387.
  if (root->total_size_of_super_pages +
          root->total_size_of_direct_mapped_pages -
          root->total_size_of_committed_pages >
      kReasonableSizeOfUnusedPages) {
    partitionOutOfMemoryWithLotsOfUncommitedPages();
  }
#endif
  if (PartitionRootBase::gOomHandlingFunction)
    (*PartitionRootBase::gOomHandlingFunction)();
  OOM_CRASH();
}

static NOINLINE void partitionExcessiveAllocationSize() {
  OOM_CRASH();
}

static NOINLINE void partitionBucketFull() {
  OOM_CRASH();
}

// partitionPageStateIs*
// Note that it's only valid to call these functions on pages found on one of
// the page lists. Specifically, you can't call these functions on full pages
// that were detached from the active list.
static bool ALWAYS_INLINE
PartitionPageStateIsActive(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->page_offset);
  return (page->num_allocated_slots > 0 &&
          (page->freelist_head || page->num_unprovisioned_slots));
}

static bool ALWAYS_INLINE PartitionPageStateIsFull(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->page_offset);
  bool ret = (page->num_allocated_slots == PartitionBucketSlots(page->bucket));
  if (ret) {
    DCHECK(!page->freelist_head);
    DCHECK(!page->num_unprovisioned_slots);
  }
  return ret;
}

static bool ALWAYS_INLINE PartitionPageStateIsEmpty(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->page_offset);
  return (!page->num_allocated_slots && page->freelist_head);
}

static bool ALWAYS_INLINE
PartitionPageStateIsDecommitted(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->page_offset);
  bool ret = (!page->num_allocated_slots && !page->freelist_head);
  if (ret) {
    DCHECK(!page->num_unprovisioned_slots);
    DCHECK(page->empty_cache_index == -1);
  }
  return ret;
}

static void partitionIncreaseCommittedPages(PartitionRootBase* root,
                                            size_t len) {
  root->total_size_of_committed_pages += len;
  DCHECK(root->total_size_of_committed_pages <=
         root->total_size_of_super_pages +
             root->total_size_of_direct_mapped_pages);
}

static void partitionDecreaseCommittedPages(PartitionRootBase* root,
                                            size_t len) {
  root->total_size_of_committed_pages -= len;
  DCHECK(root->total_size_of_committed_pages <=
         root->total_size_of_super_pages +
             root->total_size_of_direct_mapped_pages);
}

static ALWAYS_INLINE void partitionDecommitSystemPages(PartitionRootBase* root,
                                                       void* address,
                                                       size_t length) {
  DecommitSystemPages(address, length);
  partitionDecreaseCommittedPages(root, length);
}

static ALWAYS_INLINE void partitionRecommitSystemPages(PartitionRootBase* root,
                                                       void* address,
                                                       size_t length) {
  RecommitSystemPages(address, length);
  partitionIncreaseCommittedPages(root, length);
}

static ALWAYS_INLINE void* PartitionAllocPartitionPages(
    PartitionRootBase* root,
    int flags,
    uint16_t num_partition_pages) {
  DCHECK(!(reinterpret_cast<uintptr_t>(root->next_partition_page) %
           kPartitionPageSize));
  DCHECK(!(reinterpret_cast<uintptr_t>(root->next_partition_page_end) %
           kPartitionPageSize));
  DCHECK(num_partition_pages <= kNumPartitionPagesPerSuperPage);
  size_t total_size = kPartitionPageSize * num_partition_pages;
  size_t num_partition_pages_left =
      (root->next_partition_page_end - root->next_partition_page) >>
      kPartitionPageShift;
  if (LIKELY(num_partition_pages_left >= num_partition_pages)) {
    // In this case, we can still hand out pages from the current super page
    // allocation.
    char* ret = root->next_partition_page;
    root->next_partition_page += total_size;
    partitionIncreaseCommittedPages(root, total_size);
    return ret;
  }

  // Need a new super page. We want to allocate super pages in a continguous
  // address region as much as possible. This is important for not causing
  // page table bloat and not fragmenting address spaces in 32 bit
  // architectures.
  char* requestedAddress = root->next_super_page;
  char* super_page = reinterpret_cast<char*>(AllocPages(
      requestedAddress, kSuperPageSize, kSuperPageSize, PageAccessible));
  if (UNLIKELY(!super_page))
    return 0;

  root->total_size_of_super_pages += kSuperPageSize;
  partitionIncreaseCommittedPages(root, total_size);

  root->next_super_page = super_page + kSuperPageSize;
  char* ret = super_page + kPartitionPageSize;
  root->next_partition_page = ret + total_size;
  root->next_partition_page_end = root->next_super_page - kPartitionPageSize;
  // Make the first partition page in the super page a guard page, but leave a
  // hole in the middle.
  // This is where we put page metadata and also a tiny amount of extent
  // metadata.
  SetSystemPagesInaccessible(super_page, kSystemPageSize);
  SetSystemPagesInaccessible(super_page + (kSystemPageSize * 2),
                             kPartitionPageSize - (kSystemPageSize * 2));
  // Also make the last partition page a guard page.
  SetSystemPagesInaccessible(super_page + (kSuperPageSize - kPartitionPageSize),
                             kPartitionPageSize);

  // If we were after a specific address, but didn't get it, assume that
  // the system chose a lousy address. Here most OS'es have a default
  // algorithm that isn't randomized. For example, most Linux
  // distributions will allocate the mapping directly before the last
  // successful mapping, which is far from random. So we just get fresh
  // randomness for the next mapping attempt.
  if (requestedAddress && requestedAddress != super_page)
    root->next_super_page = 0;

  // We allocated a new super page so update super page metadata.
  // First check if this is a new extent or not.
  PartitionSuperPageExtentEntry* latest_extent =
      reinterpret_cast<PartitionSuperPageExtentEntry*>(
          PartitionSuperPageToMetadataArea(super_page));
  // By storing the root in every extent metadata object, we have a fast way
  // to go from a pointer within the partition to the root object.
  latest_extent->root = root;
  // Most new extents will be part of a larger extent, and these three fields
  // are unused, but we initialize them to 0 so that we get a clear signal
  // in case they are accidentally used.
  latest_extent->super_page_base = 0;
  latest_extent->super_pages_end = 0;
  latest_extent->next = 0;

  PartitionSuperPageExtentEntry* current_extent = root->current_extent;
  bool isNewExtent = (super_page != requestedAddress);
  if (UNLIKELY(isNewExtent)) {
    if (UNLIKELY(!current_extent)) {
      DCHECK(!root->first_extent);
      root->first_extent = latest_extent;
    } else {
      DCHECK(current_extent->super_page_base);
      current_extent->next = latest_extent;
    }
    root->current_extent = latest_extent;
    latest_extent->super_page_base = super_page;
    latest_extent->super_pages_end = super_page + kSuperPageSize;
  } else {
    // We allocated next to an existing extent so just nudge the size up a
    // little.
    DCHECK(current_extent->super_pages_end);
    current_extent->super_pages_end += kSuperPageSize;
    DCHECK(ret >= current_extent->super_page_base &&
           ret < current_extent->super_pages_end);
  }
  return ret;
}

static ALWAYS_INLINE uint16_t
partitionBucketPartitionPages(const PartitionBucket* bucket) {
  return (bucket->num_system_pages_per_slot_span +
          (kNumSystemPagesPerPartitionPage - 1)) /
         kNumSystemPagesPerPartitionPage;
}

static ALWAYS_INLINE void partitionPageReset(PartitionPage* page) {
  DCHECK(PartitionPageStateIsDecommitted(page));

  page->num_unprovisioned_slots = PartitionBucketSlots(page->bucket);
  DCHECK(page->num_unprovisioned_slots);

  page->next_page = nullptr;
}

static ALWAYS_INLINE void partitionPageSetup(PartitionPage* page,
                                             PartitionBucket* bucket) {
  // The bucket never changes. We set it up once.
  page->bucket = bucket;
  page->empty_cache_index = -1;

  partitionPageReset(page);

  // If this page has just a single slot, do not set up page offsets for any
  // page metadata other than the first one. This ensures that attempts to
  // touch invalid page metadata fail.
  if (page->num_unprovisioned_slots == 1)
    return;

  uint16_t num_partition_pages = partitionBucketPartitionPages(bucket);
  char* pageCharPtr = reinterpret_cast<char*>(page);
  for (uint16_t i = 1; i < num_partition_pages; ++i) {
    pageCharPtr += kPageMetadataSize;
    PartitionPage* secondaryPage =
        reinterpret_cast<PartitionPage*>(pageCharPtr);
    secondaryPage->page_offset = i;
  }
}

static ALWAYS_INLINE char* partitionPageAllocAndFillFreelist(
    PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  uint16_t num_slots = page->num_unprovisioned_slots;
  DCHECK(num_slots);
  PartitionBucket* bucket = page->bucket;
  // We should only get here when _every_ slot is either used or unprovisioned.
  // (The third state is "on the freelist". If we have a non-empty freelist, we
  // should not get here.)
  DCHECK(num_slots + page->num_allocated_slots == PartitionBucketSlots(bucket));
  // Similarly, make explicitly sure that the freelist is empty.
  DCHECK(!page->freelist_head);
  DCHECK(page->num_allocated_slots >= 0);

  size_t size = bucket->slot_size;
  char* base = reinterpret_cast<char*>(PartitionPageToPointer(page));
  char* return_object = base + (size * page->num_allocated_slots);
  char* firstFreelistPointer = return_object + size;
  char* firstFreelistPointerExtent =
      firstFreelistPointer + sizeof(PartitionFreelistEntry*);
  // Our goal is to fault as few system pages as possible. We calculate the
  // page containing the "end" of the returned slot, and then allow freelist
  // pointers to be written up to the end of that page.
  char* sub_page_limit = reinterpret_cast<char*>(
      RoundUpToSystemPage(reinterpret_cast<size_t>(firstFreelistPointer)));
  char* slots_limit = return_object + (size * num_slots);
  char* freelist_limit = sub_page_limit;
  if (UNLIKELY(slots_limit < freelist_limit))
    freelist_limit = slots_limit;

  uint16_t num_new_freelist_entries = 0;
  if (LIKELY(firstFreelistPointerExtent <= freelist_limit)) {
    // Only consider used space in the slot span. If we consider wasted
    // space, we may get an off-by-one when a freelist pointer fits in the
    // wasted space, but a slot does not.
    // We know we can fit at least one freelist pointer.
    num_new_freelist_entries = 1;
    // Any further entries require space for the whole slot span.
    num_new_freelist_entries += static_cast<uint16_t>(
        (freelist_limit - firstFreelistPointerExtent) / size);
  }

  // We always return an object slot -- that's the +1 below.
  // We do not neccessarily create any new freelist entries, because we cross
  // sub page boundaries frequently for large bucket sizes.
  DCHECK(num_new_freelist_entries + 1 <= num_slots);
  num_slots -= (num_new_freelist_entries + 1);
  page->num_unprovisioned_slots = num_slots;
  page->num_allocated_slots++;

  if (LIKELY(num_new_freelist_entries)) {
    char* freelist_pointer = firstFreelistPointer;
    PartitionFreelistEntry* entry =
        reinterpret_cast<PartitionFreelistEntry*>(freelist_pointer);
    page->freelist_head = entry;
    while (--num_new_freelist_entries) {
      freelist_pointer += size;
      PartitionFreelistEntry* nextEntry =
          reinterpret_cast<PartitionFreelistEntry*>(freelist_pointer);
      entry->next = PartitionFreelistMask(nextEntry);
      entry = nextEntry;
    }
    entry->next = PartitionFreelistMask(0);
  } else {
    page->freelist_head = 0;
  }
  return return_object;
}

// This helper function scans a bucket's active page list for a suitable new
// active page.
// When it finds a suitable new active page (one that has free slots and is not
// empty), it is set as the new active page. If there is no suitable new
// active page, the current active page is set to the seed page.
// As potential pages are scanned, they are tidied up according to their state.
// Empty pages are swept on to the empty page list, decommitted pages on to the
// decommitted page list and full pages are unlinked from any list.
static bool partitionSetNewActivePage(PartitionBucket* bucket) {
  PartitionPage* page = bucket->active_pages_head;
  if (page == &PartitionRootBase::gSeedPage)
    return false;

  PartitionPage* next_page;

  for (; page; page = next_page) {
    next_page = page->next_page;
    DCHECK(page->bucket == bucket);
    DCHECK(page != bucket->empty_pages_head);
    DCHECK(page != bucket->decommitted_pages_head);

    // Deal with empty and decommitted pages.
    if (LIKELY(PartitionPageStateIsActive(page))) {
      // This page is usable because it has freelist entries, or has
      // unprovisioned slots we can create freelist entries from.
      bucket->active_pages_head = page;
      return true;
    }
    if (LIKELY(PartitionPageStateIsEmpty(page))) {
      page->next_page = bucket->empty_pages_head;
      bucket->empty_pages_head = page;
    } else if (LIKELY(PartitionPageStateIsDecommitted(page))) {
      page->next_page = bucket->decommitted_pages_head;
      bucket->decommitted_pages_head = page;
    } else {
      DCHECK(PartitionPageStateIsFull(page));
      // If we get here, we found a full page. Skip over it too, and also
      // tag it as full (via a negative value). We need it tagged so that
      // free'ing can tell, and move it back into the active page list.
      page->num_allocated_slots = -page->num_allocated_slots;
      ++bucket->num_full_pages;
      // num_full_pages is a uint16_t for efficient packing so guard against
      // overflow to be safe.
      if (UNLIKELY(!bucket->num_full_pages))
        partitionBucketFull();
      // Not necessary but might help stop accidents.
      page->next_page = 0;
    }
  }

  bucket->active_pages_head = &PartitionRootGeneric::gSeedPage;
  return false;
}

static ALWAYS_INLINE PartitionDirectMapExtent* partitionPageToDirectMapExtent(
    PartitionPage* page) {
  DCHECK(PartitionBucketIsDirectMapped(page->bucket));
  return reinterpret_cast<PartitionDirectMapExtent*>(
      reinterpret_cast<char*>(page) + 3 * kPageMetadataSize);
}

static ALWAYS_INLINE void partitionPageSetRawSize(PartitionPage* page,
                                                  size_t size) {
  size_t* raw_sizePtr = PartitionPageGetRawSizePtr(page);
  if (UNLIKELY(raw_sizePtr != nullptr))
    *raw_sizePtr = size;
}

static ALWAYS_INLINE PartitionPage* partitionDirectMap(PartitionRootBase* root,
                                                       int flags,
                                                       size_t raw_size) {
  size_t size = PartitionDirectMapSize(raw_size);

  // Because we need to fake looking like a super page, we need to allocate
  // a bunch of system pages more than "size":
  // - The first few system pages are the partition page in which the super
  // page metadata is stored. We fault just one system page out of a partition
  // page sized clump.
  // - We add a trailing guard page on 32-bit (on 64-bit we rely on the
  // massive address space plus randomization instead).
  size_t map_size = size + kPartitionPageSize;
#if !defined(ARCH_CPU_64_BITS)
  map_size += kSystemPageSize;
#endif
  // Round up to the allocation granularity.
  map_size += kPageAllocationGranularityOffsetMask;
  map_size &= kPageAllocationGranularityBaseMask;

  // TODO: these pages will be zero-filled. Consider internalizing an
  // allocZeroed() API so we can avoid a memset() entirely in this case.
  char* ptr = reinterpret_cast<char*>(
      AllocPages(0, map_size, kSuperPageSize, PageAccessible));
  if (UNLIKELY(!ptr))
    return nullptr;

  size_t committedPageSize = size + kSystemPageSize;
  root->total_size_of_direct_mapped_pages += committedPageSize;
  partitionIncreaseCommittedPages(root, committedPageSize);

  char* slot = ptr + kPartitionPageSize;
  SetSystemPagesInaccessible(ptr + (kSystemPageSize * 2),
                             kPartitionPageSize - (kSystemPageSize * 2));
#if !defined(ARCH_CPU_64_BITS)
  SetSystemPagesInaccessible(ptr, kSystemPageSize);
  SetSystemPagesInaccessible(slot + size, kSystemPageSize);
#endif

  PartitionSuperPageExtentEntry* extent =
      reinterpret_cast<PartitionSuperPageExtentEntry*>(
          PartitionSuperPageToMetadataArea(ptr));
  extent->root = root;
  // The new structures are all located inside a fresh system page so they
  // will all be zeroed out. These DCHECKs are for documentation.
  DCHECK(!extent->super_page_base);
  DCHECK(!extent->super_pages_end);
  DCHECK(!extent->next);
  PartitionPage* page = PartitionPointerToPageNoAlignmentCheck(slot);
  PartitionBucket* bucket = reinterpret_cast<PartitionBucket*>(
      reinterpret_cast<char*>(page) + (kPageMetadataSize * 2));
  DCHECK(!page->next_page);
  DCHECK(!page->num_allocated_slots);
  DCHECK(!page->num_unprovisioned_slots);
  DCHECK(!page->page_offset);
  DCHECK(!page->empty_cache_index);
  page->bucket = bucket;
  page->freelist_head = reinterpret_cast<PartitionFreelistEntry*>(slot);
  PartitionFreelistEntry* nextEntry =
      reinterpret_cast<PartitionFreelistEntry*>(slot);
  nextEntry->next = PartitionFreelistMask(0);

  DCHECK(!bucket->active_pages_head);
  DCHECK(!bucket->empty_pages_head);
  DCHECK(!bucket->decommitted_pages_head);
  DCHECK(!bucket->num_system_pages_per_slot_span);
  DCHECK(!bucket->num_full_pages);
  bucket->slot_size = size;

  PartitionDirectMapExtent* mapExtent = partitionPageToDirectMapExtent(page);
  mapExtent->map_size = map_size - kPartitionPageSize - kSystemPageSize;
  mapExtent->bucket = bucket;

  // Maintain the doubly-linked list of all direct mappings.
  mapExtent->next_extent = root->direct_map_list;
  if (mapExtent->next_extent)
    mapExtent->next_extent->prev_extent = mapExtent;
  mapExtent->prev_extent = nullptr;
  root->direct_map_list = mapExtent;

  return page;
}

static ALWAYS_INLINE void partitionDirectUnmap(PartitionPage* page) {
  PartitionRootBase* root = PartitionPageToRoot(page);
  const PartitionDirectMapExtent* extent = partitionPageToDirectMapExtent(page);
  size_t unmap_size = extent->map_size;

  // Maintain the doubly-linked list of all direct mappings.
  if (extent->prev_extent) {
    DCHECK(extent->prev_extent->next_extent == extent);
    extent->prev_extent->next_extent = extent->next_extent;
  } else {
    root->direct_map_list = extent->next_extent;
  }
  if (extent->next_extent) {
    DCHECK(extent->next_extent->prev_extent == extent);
    extent->next_extent->prev_extent = extent->prev_extent;
  }

  // Add on the size of the trailing guard page and preceeding partition
  // page.
  unmap_size += kPartitionPageSize + kSystemPageSize;

  size_t uncommittedPageSize = page->bucket->slot_size + kSystemPageSize;
  partitionDecreaseCommittedPages(root, uncommittedPageSize);
  DCHECK(root->total_size_of_direct_mapped_pages >= uncommittedPageSize);
  root->total_size_of_direct_mapped_pages -= uncommittedPageSize;

  DCHECK(!(unmap_size & kPageAllocationGranularityOffsetMask));

  char* ptr = reinterpret_cast<char*>(PartitionPageToPointer(page));
  // Account for the mapping starting a partition page before the actual
  // allocation address.
  ptr -= kPartitionPageSize;

  FreePages(ptr, unmap_size);
}

void* PartitionAllocSlowPath(PartitionRootBase* root,
                             int flags,
                             size_t size,
                             PartitionBucket* bucket) {
  // The slow path is called when the freelist is empty.
  DCHECK(!bucket->active_pages_head->freelist_head);

  PartitionPage* newPage = nullptr;

  // For the PartitionAllocGeneric API, we have a bunch of buckets marked
  // as special cases. We bounce them through to the slow path so that we
  // can still have a blazing fast hot path due to lack of corner-case
  // branches.
  bool returnNull = flags & PartitionAllocReturnNull;
  if (UNLIKELY(PartitionBucketIsDirectMapped(bucket))) {
    DCHECK(size > kGenericMaxBucketed);
    DCHECK(bucket == &PartitionRootBase::gPagedBucket);
    DCHECK(bucket->active_pages_head == &PartitionRootGeneric::gSeedPage);
    if (size > kGenericMaxDirectMapped) {
      if (returnNull)
        return nullptr;
      partitionExcessiveAllocationSize();
    }
    newPage = partitionDirectMap(root, flags, size);
  } else if (LIKELY(partitionSetNewActivePage(bucket))) {
    // First, did we find an active page in the active pages list?
    newPage = bucket->active_pages_head;
    DCHECK(PartitionPageStateIsActive(newPage));
  } else if (LIKELY(bucket->empty_pages_head != nullptr) ||
             LIKELY(bucket->decommitted_pages_head != nullptr)) {
    // Second, look in our lists of empty and decommitted pages.
    // Check empty pages first, which are preferred, but beware that an
    // empty page might have been decommitted.
    while (LIKELY((newPage = bucket->empty_pages_head) != nullptr)) {
      DCHECK(newPage->bucket == bucket);
      DCHECK(PartitionPageStateIsEmpty(newPage) ||
             PartitionPageStateIsDecommitted(newPage));
      bucket->empty_pages_head = newPage->next_page;
      // Accept the empty page unless it got decommitted.
      if (newPage->freelist_head) {
        newPage->next_page = nullptr;
        break;
      }
      DCHECK(PartitionPageStateIsDecommitted(newPage));
      newPage->next_page = bucket->decommitted_pages_head;
      bucket->decommitted_pages_head = newPage;
    }
    if (UNLIKELY(!newPage) &&
        LIKELY(bucket->decommitted_pages_head != nullptr)) {
      newPage = bucket->decommitted_pages_head;
      DCHECK(newPage->bucket == bucket);
      DCHECK(PartitionPageStateIsDecommitted(newPage));
      bucket->decommitted_pages_head = newPage->next_page;
      void* addr = PartitionPageToPointer(newPage);
      partitionRecommitSystemPages(root, addr,
                                   PartitionBucketBytes(newPage->bucket));
      partitionPageReset(newPage);
    }
    DCHECK(newPage);
  } else {
    // Third. If we get here, we need a brand new page.
    uint16_t num_partition_pages = partitionBucketPartitionPages(bucket);
    void* rawPages =
        PartitionAllocPartitionPages(root, flags, num_partition_pages);
    if (LIKELY(rawPages != nullptr)) {
      newPage = PartitionPointerToPageNoAlignmentCheck(rawPages);
      partitionPageSetup(newPage, bucket);
    }
  }

  // Bail if we had a memory allocation failure.
  if (UNLIKELY(!newPage)) {
    DCHECK(bucket->active_pages_head == &PartitionRootGeneric::gSeedPage);
    if (returnNull)
      return nullptr;
    partitionOutOfMemory(root);
  }

  bucket = newPage->bucket;
  DCHECK(bucket != &PartitionRootBase::gPagedBucket);
  bucket->active_pages_head = newPage;
  partitionPageSetRawSize(newPage, size);

  // If we found an active page with free slots, or an empty page, we have a
  // usable freelist head.
  if (LIKELY(newPage->freelist_head != nullptr)) {
    PartitionFreelistEntry* entry = newPage->freelist_head;
    PartitionFreelistEntry* newHead = PartitionFreelistMask(entry->next);
    newPage->freelist_head = newHead;
    newPage->num_allocated_slots++;
    return entry;
  }
  // Otherwise, we need to build the freelist.
  DCHECK(newPage->num_unprovisioned_slots);
  return partitionPageAllocAndFillFreelist(newPage);
}

static ALWAYS_INLINE void partitionDecommitPage(PartitionRootBase* root,
                                                PartitionPage* page) {
  DCHECK(PartitionPageStateIsEmpty(page));
  DCHECK(!PartitionBucketIsDirectMapped(page->bucket));
  void* addr = PartitionPageToPointer(page);
  partitionDecommitSystemPages(root, addr, PartitionBucketBytes(page->bucket));

  // We actually leave the decommitted page in the active list. We'll sweep
  // it on to the decommitted page list when we next walk the active page
  // list.
  // Pulling this trick enables us to use a singly-linked page list for all
  // cases, which is critical in keeping the page metadata structure down to
  // 32 bytes in size.
  page->freelist_head = 0;
  page->num_unprovisioned_slots = 0;
  DCHECK(PartitionPageStateIsDecommitted(page));
}

static void partitionDecommitPageIfPossible(PartitionRootBase* root,
                                            PartitionPage* page) {
  DCHECK(page->empty_cache_index >= 0);
  DCHECK(static_cast<unsigned>(page->empty_cache_index) < kMaxFreeableSpans);
  DCHECK(page == root->global_empty_page_ring[page->empty_cache_index]);
  page->empty_cache_index = -1;
  if (PartitionPageStateIsEmpty(page))
    partitionDecommitPage(root, page);
}

static ALWAYS_INLINE void partitionRegisterEmptyPage(PartitionPage* page) {
  DCHECK(PartitionPageStateIsEmpty(page));
  PartitionRootBase* root = PartitionPageToRoot(page);

  // If the page is already registered as empty, give it another life.
  if (page->empty_cache_index != -1) {
    DCHECK(page->empty_cache_index >= 0);
    DCHECK(static_cast<unsigned>(page->empty_cache_index) < kMaxFreeableSpans);
    DCHECK(root->global_empty_page_ring[page->empty_cache_index] == page);
    root->global_empty_page_ring[page->empty_cache_index] = 0;
  }

  int16_t currentIndex = root->global_empty_page_ring_index;
  PartitionPage* pageToDecommit = root->global_empty_page_ring[currentIndex];
  // The page might well have been re-activated, filled up, etc. before we get
  // around to looking at it here.
  if (pageToDecommit)
    partitionDecommitPageIfPossible(root, pageToDecommit);

  // We put the empty slot span on our global list of "pages that were once
  // empty". thus providing it a bit of breathing room to get re-used before
  // we really free it. This improves performance, particularly on Mac OS X
  // which has subpar memory management performance.
  root->global_empty_page_ring[currentIndex] = page;
  page->empty_cache_index = currentIndex;
  ++currentIndex;
  if (currentIndex == kMaxFreeableSpans)
    currentIndex = 0;
  root->global_empty_page_ring_index = currentIndex;
}

static void partitionDecommitEmptyPages(PartitionRootBase* root) {
  for (size_t i = 0; i < kMaxFreeableSpans; ++i) {
    PartitionPage* page = root->global_empty_page_ring[i];
    if (page)
      partitionDecommitPageIfPossible(root, page);
    root->global_empty_page_ring[i] = nullptr;
  }
}

void PartitionFreeSlowPath(PartitionPage* page) {
  PartitionBucket* bucket = page->bucket;
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  if (LIKELY(page->num_allocated_slots == 0)) {
    // Page became fully unused.
    if (UNLIKELY(PartitionBucketIsDirectMapped(bucket))) {
      partitionDirectUnmap(page);
      return;
    }
    // If it's the current active page, change it. We bounce the page to
    // the empty list as a force towards defragmentation.
    if (LIKELY(page == bucket->active_pages_head))
      (void)partitionSetNewActivePage(bucket);
    DCHECK(bucket->active_pages_head != page);

    partitionPageSetRawSize(page, 0);
    DCHECK(!PartitionPageGetRawSize(page));

    partitionRegisterEmptyPage(page);
  } else {
    DCHECK(!PartitionBucketIsDirectMapped(bucket));
    // Ensure that the page is full. That's the only valid case if we
    // arrive here.
    DCHECK(page->num_allocated_slots < 0);
    // A transition of num_allocated_slots from 0 to -1 is not legal, and
    // likely indicates a double-free.
    CHECK(page->num_allocated_slots != -1);
    page->num_allocated_slots = -page->num_allocated_slots - 2;
    DCHECK(page->num_allocated_slots == PartitionBucketSlots(bucket) - 1);
    // Fully used page became partially used. It must be put back on the
    // non-full page list. Also make it the current page to increase the
    // chances of it being filled up again. The old current page will be
    // the next page.
    DCHECK(!page->next_page);
    if (LIKELY(bucket->active_pages_head != &PartitionRootGeneric::gSeedPage))
      page->next_page = bucket->active_pages_head;
    bucket->active_pages_head = page;
    --bucket->num_full_pages;
    // Special case: for a partition page with just a single slot, it may
    // now be empty and we want to run it through the empty logic.
    if (UNLIKELY(page->num_allocated_slots == 0))
      PartitionFreeSlowPath(page);
  }
}

bool partitionReallocDirectMappedInPlace(PartitionRootGeneric* root,
                                         PartitionPage* page,
                                         size_t raw_size) {
  DCHECK(PartitionBucketIsDirectMapped(page->bucket));

  raw_size = PartitionCookieSizeAdjustAdd(raw_size);

  // Note that the new size might be a bucketed size; this function is called
  // whenever we're reallocating a direct mapped allocation.
  size_t new_size = PartitionDirectMapSize(raw_size);
  if (new_size < kGenericMinDirectMappedDownsize)
    return false;

  // bucket->slot_size is the current size of the allocation.
  size_t current_size = page->bucket->slot_size;
  if (new_size == current_size)
    return true;

  char* char_ptr = static_cast<char*>(PartitionPageToPointer(page));

  if (new_size < current_size) {
    size_t map_size = partitionPageToDirectMapExtent(page)->map_size;

    // Don't reallocate in-place if new size is less than 80 % of the full
    // map size, to avoid holding on to too much unused address space.
    if ((new_size / kSystemPageSize) * 5 < (map_size / kSystemPageSize) * 4)
      return false;

    // Shrink by decommitting unneeded pages and making them inaccessible.
    size_t decommitSize = current_size - new_size;
    partitionDecommitSystemPages(root, char_ptr + new_size, decommitSize);
    SetSystemPagesInaccessible(char_ptr + new_size, decommitSize);
  } else if (new_size <= partitionPageToDirectMapExtent(page)->map_size) {
    // Grow within the actually allocated memory. Just need to make the
    // pages accessible again.
    size_t recommit_size = new_size - current_size;
    bool ret = SetSystemPagesAccessible(char_ptr + current_size, recommit_size);
    CHECK(ret);
    partitionRecommitSystemPages(root, char_ptr + current_size, recommit_size);

#if DCHECK_IS_ON()
    memset(char_ptr + current_size, kUninitializedByte, recommit_size);
#endif
  } else {
    // We can't perform the realloc in-place.
    // TODO: support this too when possible.
    return false;
  }

#if DCHECK_IS_ON()
  // Write a new trailing cookie.
  PartitionCookieWriteValue(char_ptr + raw_size - kCookieSize);
#endif

  partitionPageSetRawSize(page, raw_size);
  DCHECK(PartitionPageGetRawSize(page) == raw_size);

  page->bucket->slot_size = new_size;
  return true;
}

void* PartitionReallocGeneric(PartitionRootGeneric* root,
                              void* ptr,
                              size_t new_size,
                              const char* type_name) {
#if defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
  return realloc(ptr, new_size);
#else
  if (UNLIKELY(!ptr))
    return PartitionAllocGeneric(root, new_size, type_name);
  if (UNLIKELY(!new_size)) {
    PartitionFreeGeneric(root, ptr);
    return 0;
  }

  if (new_size > kGenericMaxDirectMapped)
    partitionExcessiveAllocationSize();

  DCHECK(PartitionPointerIsValid(PartitionCookieFreePointerAdjust(ptr)));

  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));

  if (UNLIKELY(PartitionBucketIsDirectMapped(page->bucket))) {
    // We may be able to perform the realloc in place by changing the
    // accessibility of memory pages and, if reducing the size, decommitting
    // them.
    if (partitionReallocDirectMappedInPlace(root, page, new_size)) {
      PartitionAllocHooks::ReallocHookIfEnabled(ptr, ptr, new_size, type_name);
      return ptr;
    }
  }

  size_t actualNewSize = PartitionAllocActualSize(root, new_size);
  size_t actualOldSize = PartitionAllocGetSize(ptr);

  // TODO: note that tcmalloc will "ignore" a downsizing realloc() unless the
  // new size is a significant percentage smaller. We could do the same if we
  // determine it is a win.
  if (actualNewSize == actualOldSize) {
    // Trying to allocate a block of size new_size would give us a block of
    // the same size as the one we've already got, so no point in doing
    // anything here.
    return ptr;
  }

  // This realloc cannot be resized in-place. Sadness.
  void* ret = PartitionAllocGeneric(root, new_size, type_name);
  size_t copy_size = actualOldSize;
  if (new_size < copy_size)
    copy_size = new_size;

  memcpy(ret, ptr, copy_size);
  PartitionFreeGeneric(root, ptr);
  return ret;
#endif
}

static size_t PartitionPurgePage(PartitionPage* page, bool discard) {
  const PartitionBucket* bucket = page->bucket;
  size_t slot_size = bucket->slot_size;
  if (slot_size < kSystemPageSize || !page->num_allocated_slots)
    return 0;

  size_t bucket_num_slots = PartitionBucketSlots(bucket);
  size_t discardable_bytes = 0;

  size_t raw_size = PartitionPageGetRawSize(const_cast<PartitionPage*>(page));
  if (raw_size) {
    uint32_t usedBytes = static_cast<uint32_t>(RoundUpToSystemPage(raw_size));
    discardable_bytes = bucket->slot_size - usedBytes;
    if (discardable_bytes && discard) {
      char* ptr = reinterpret_cast<char*>(PartitionPageToPointer(page));
      ptr += usedBytes;
      DiscardSystemPages(ptr, discardable_bytes);
    }
    return discardable_bytes;
  }

  const size_t maxSlotCount =
      (kPartitionPageSize * kMaxPartitionPagesPerSlotSpan) / kSystemPageSize;
  DCHECK(bucket_num_slots <= maxSlotCount);
  DCHECK(page->num_unprovisioned_slots < bucket_num_slots);
  size_t num_slots = bucket_num_slots - page->num_unprovisioned_slots;
  char slotUsage[maxSlotCount];
  size_t lastSlot = static_cast<size_t>(-1);
  memset(slotUsage, 1, num_slots);
  char* ptr = reinterpret_cast<char*>(PartitionPageToPointer(page));
  PartitionFreelistEntry* entry = page->freelist_head;
  // First, walk the freelist for this page and make a bitmap of which slots
  // are not in use.
  while (entry) {
    size_t slotIndex = (reinterpret_cast<char*>(entry) - ptr) / slot_size;
    DCHECK(slotIndex < num_slots);
    slotUsage[slotIndex] = 0;
    entry = PartitionFreelistMask(entry->next);
    // If we have a slot where the masked freelist entry is 0, we can
    // actually discard that freelist entry because touching a discarded
    // page is guaranteed to return original content or 0.
    // (Note that this optimization won't fire on big endian machines
    // because the masking function is negation.)
    if (!PartitionFreelistMask(entry))
      lastSlot = slotIndex;
  }

  // If the slot(s) at the end of the slot span are not in used, we can
  // truncate them entirely and rewrite the freelist.
  size_t truncatedSlots = 0;
  while (!slotUsage[num_slots - 1]) {
    truncatedSlots++;
    num_slots--;
    DCHECK(num_slots);
  }
  // First, do the work of calculating the discardable bytes. Don't actually
  // discard anything unless the discard flag was passed in.
  char* beginPtr = nullptr;
  char* endPtr = nullptr;
  size_t unprovisionedBytes = 0;
  if (truncatedSlots) {
    beginPtr = ptr + (num_slots * slot_size);
    endPtr = beginPtr + (slot_size * truncatedSlots);
    beginPtr = reinterpret_cast<char*>(
        RoundUpToSystemPage(reinterpret_cast<size_t>(beginPtr)));
    // We round the end pointer here up and not down because we're at the
    // end of a slot span, so we "own" all the way up the page boundary.
    endPtr = reinterpret_cast<char*>(
        RoundUpToSystemPage(reinterpret_cast<size_t>(endPtr)));
    DCHECK(endPtr <= ptr + PartitionBucketBytes(bucket));
    if (beginPtr < endPtr) {
      unprovisionedBytes = endPtr - beginPtr;
      discardable_bytes += unprovisionedBytes;
    }
  }
  if (unprovisionedBytes && discard) {
    DCHECK(truncatedSlots > 0);
    size_t numNewEntries = 0;
    page->num_unprovisioned_slots += static_cast<uint16_t>(truncatedSlots);
    // Rewrite the freelist.
    PartitionFreelistEntry** entryPtr = &page->freelist_head;
    for (size_t slotIndex = 0; slotIndex < num_slots; ++slotIndex) {
      if (slotUsage[slotIndex])
        continue;
      PartitionFreelistEntry* entry = reinterpret_cast<PartitionFreelistEntry*>(
          ptr + (slot_size * slotIndex));
      *entryPtr = PartitionFreelistMask(entry);
      entryPtr = reinterpret_cast<PartitionFreelistEntry**>(entry);
      numNewEntries++;
    }
    // Terminate the freelist chain.
    *entryPtr = nullptr;
    // The freelist head is stored unmasked.
    page->freelist_head = PartitionFreelistMask(page->freelist_head);
    DCHECK(numNewEntries == num_slots - page->num_allocated_slots);
    // Discard the memory.
    DiscardSystemPages(beginPtr, unprovisionedBytes);
  }

  // Next, walk the slots and for any not in use, consider where the system
  // page boundaries occur. We can release any system pages back to the
  // system as long as we don't interfere with a freelist pointer or an
  // adjacent slot.
  for (size_t i = 0; i < num_slots; ++i) {
    if (slotUsage[i])
      continue;
    // The first address we can safely discard is just after the freelist
    // pointer. There's one quirk: if the freelist pointer is actually a
    // null, we can discard that pointer value too.
    char* beginPtr = ptr + (i * slot_size);
    char* endPtr = beginPtr + slot_size;
    if (i != lastSlot)
      beginPtr += sizeof(PartitionFreelistEntry);
    beginPtr = reinterpret_cast<char*>(
        RoundUpToSystemPage(reinterpret_cast<size_t>(beginPtr)));
    endPtr = reinterpret_cast<char*>(
        RoundDownToSystemPage(reinterpret_cast<size_t>(endPtr)));
    if (beginPtr < endPtr) {
      size_t partialSlotBytes = endPtr - beginPtr;
      discardable_bytes += partialSlotBytes;
      if (discard)
        DiscardSystemPages(beginPtr, partialSlotBytes);
    }
  }
  return discardable_bytes;
}

static void partitionPurgeBucket(PartitionBucket* bucket) {
  if (bucket->active_pages_head != &PartitionRootGeneric::gSeedPage) {
    for (PartitionPage* page = bucket->active_pages_head; page;
         page = page->next_page) {
      DCHECK(page != &PartitionRootGeneric::gSeedPage);
      (void)PartitionPurgePage(page, true);
    }
  }
}

void PartitionPurgeMemory(PartitionRoot* root, int flags) {
  if (flags & PartitionPurgeDecommitEmptyPages)
    partitionDecommitEmptyPages(root);
  // We don't currently do anything for PartitionPurgeDiscardUnusedSystemPages
  // here because that flag is only useful for allocations >= system page
  // size. We only have allocations that large inside generic partitions
  // at the moment.
}

void PartitionPurgeMemoryGeneric(PartitionRootGeneric* root, int flags) {
  subtle::SpinLock::Guard guard(root->lock);
  if (flags & PartitionPurgeDecommitEmptyPages)
    partitionDecommitEmptyPages(root);
  if (flags & PartitionPurgeDiscardUnusedSystemPages) {
    for (size_t i = 0; i < kGenericNumBuckets; ++i) {
      PartitionBucket* bucket = &root->buckets[i];
      if (bucket->slot_size >= kSystemPageSize)
        partitionPurgeBucket(bucket);
    }
  }
}

static void PartitionDumpPageStats(PartitionBucketMemoryStats* stats_out,
                                   const PartitionPage* page) {
  uint16_t bucket_num_slots = PartitionBucketSlots(page->bucket);

  if (PartitionPageStateIsDecommitted(page)) {
    ++stats_out->num_decommitted_pages;
    return;
  }

  stats_out->discardable_bytes +=
      PartitionPurgePage(const_cast<PartitionPage*>(page), false);

  size_t raw_size = PartitionPageGetRawSize(const_cast<PartitionPage*>(page));
  if (raw_size)
    stats_out->active_bytes += static_cast<uint32_t>(raw_size);
  else
    stats_out->active_bytes +=
        (page->num_allocated_slots * stats_out->bucket_slot_size);

  size_t page_bytes_resident =
      RoundUpToSystemPage((bucket_num_slots - page->num_unprovisioned_slots) *
                          stats_out->bucket_slot_size);
  stats_out->resident_bytes += page_bytes_resident;
  if (PartitionPageStateIsEmpty(page)) {
    stats_out->decommittable_bytes += page_bytes_resident;
    ++stats_out->num_empty_pages;
  } else if (PartitionPageStateIsFull(page)) {
    ++stats_out->num_full_pages;
  } else {
    DCHECK(PartitionPageStateIsActive(page));
    ++stats_out->num_active_pages;
  }
}

static void PartitionDumpBucketStats(PartitionBucketMemoryStats* stats_out,
                                     const PartitionBucket* bucket) {
  DCHECK(!PartitionBucketIsDirectMapped(bucket));
  stats_out->is_valid = false;
  // If the active page list is empty (== &PartitionRootGeneric::gSeedPage),
  // the bucket might still need to be reported if it has a list of empty,
  // decommitted or full pages.
  if (bucket->active_pages_head == &PartitionRootGeneric::gSeedPage &&
      !bucket->empty_pages_head && !bucket->decommitted_pages_head &&
      !bucket->num_full_pages)
    return;

  memset(stats_out, '\0', sizeof(*stats_out));
  stats_out->is_valid = true;
  stats_out->is_direct_map = false;
  stats_out->num_full_pages = static_cast<size_t>(bucket->num_full_pages);
  stats_out->bucket_slot_size = bucket->slot_size;
  uint16_t bucket_num_slots = PartitionBucketSlots(bucket);
  size_t bucketUsefulStorage = stats_out->bucket_slot_size * bucket_num_slots;
  stats_out->allocated_page_size = PartitionBucketBytes(bucket);
  stats_out->active_bytes = bucket->num_full_pages * bucketUsefulStorage;
  stats_out->resident_bytes =
      bucket->num_full_pages * stats_out->allocated_page_size;

  for (const PartitionPage* page = bucket->empty_pages_head; page;
       page = page->next_page) {
    DCHECK(PartitionPageStateIsEmpty(page) ||
           PartitionPageStateIsDecommitted(page));
    PartitionDumpPageStats(stats_out, page);
  }
  for (const PartitionPage* page = bucket->decommitted_pages_head; page;
       page = page->next_page) {
    DCHECK(PartitionPageStateIsDecommitted(page));
    PartitionDumpPageStats(stats_out, page);
  }

  if (bucket->active_pages_head != &PartitionRootGeneric::gSeedPage) {
    for (const PartitionPage* page = bucket->active_pages_head; page;
         page = page->next_page) {
      DCHECK(page != &PartitionRootGeneric::gSeedPage);
      PartitionDumpPageStats(stats_out, page);
    }
  }
}

void PartitionDumpStatsGeneric(PartitionRootGeneric* partition,
                               const char* partition_name,
                               bool is_light_dump,
                               PartitionStatsDumper* dumper) {
  PartitionBucketMemoryStats bucket_stats[kGenericNumBuckets];
  static const size_t kMaxReportableDirectMaps = 4096;
  uint32_t direct_map_lengths[kMaxReportableDirectMaps];
  size_t num_direct_mapped_allocations = 0;

  {
    subtle::SpinLock::Guard guard(partition->lock);

    for (size_t i = 0; i < kGenericNumBuckets; ++i) {
      const PartitionBucket* bucket = &partition->buckets[i];
      // Don't report the pseudo buckets that the generic allocator sets up in
      // order to preserve a fast size->bucket map (see
      // PartitionAllocGenericInit for details).
      if (!bucket->active_pages_head)
        bucket_stats[i].is_valid = false;
      else
        PartitionDumpBucketStats(&bucket_stats[i], bucket);
    }

    for (PartitionDirectMapExtent* extent = partition->direct_map_list; extent;
         extent = extent->next_extent) {
      DCHECK(!extent->next_extent ||
             extent->next_extent->prev_extent == extent);
      direct_map_lengths[num_direct_mapped_allocations] =
          extent->bucket->slot_size;
      ++num_direct_mapped_allocations;
      if (num_direct_mapped_allocations == kMaxReportableDirectMaps)
        break;
    }
  }

  // Call |PartitionsDumpBucketStats| after collecting stats because it can try
  // to allocate using |PartitionAllocGeneric| and it can't obtain the lock.
  PartitionMemoryStats stats = {0};
  stats.total_mmapped_bytes = partition->total_size_of_super_pages +
                              partition->total_size_of_direct_mapped_pages;
  stats.total_committed_bytes = partition->total_size_of_committed_pages;
  for (size_t i = 0; i < kGenericNumBuckets; ++i) {
    if (bucket_stats[i].is_valid) {
      stats.total_resident_bytes += bucket_stats[i].resident_bytes;
      stats.total_active_bytes += bucket_stats[i].active_bytes;
      stats.total_decommittable_bytes += bucket_stats[i].decommittable_bytes;
      stats.total_discardable_bytes += bucket_stats[i].discardable_bytes;
      if (!is_light_dump)
        dumper->PartitionsDumpBucketStats(partition_name, &bucket_stats[i]);
    }
  }

  size_t direct_mapped_allocations_total_size = 0;
  for (size_t i = 0; i < num_direct_mapped_allocations; ++i) {
    uint32_t size = direct_map_lengths[i];
    direct_mapped_allocations_total_size += size;
    if (is_light_dump)
      continue;

    PartitionBucketMemoryStats stats;
    memset(&stats, '\0', sizeof(stats));
    stats.is_valid = true;
    stats.is_direct_map = true;
    stats.num_full_pages = 1;
    stats.allocated_page_size = size;
    stats.bucket_slot_size = size;
    stats.active_bytes = size;
    stats.resident_bytes = size;
    dumper->PartitionsDumpBucketStats(partition_name, &stats);
  }
  stats.total_resident_bytes += direct_mapped_allocations_total_size;
  stats.total_active_bytes += direct_mapped_allocations_total_size;
  dumper->PartitionDumpTotals(partition_name, &stats);
}

void PartitionDumpStats(PartitionRoot* partition,
                        const char* partition_name,
                        bool is_light_dump,
                        PartitionStatsDumper* dumper) {
  static const size_t kMaxReportableBuckets = 4096 / sizeof(void*);
  PartitionBucketMemoryStats memory_stats[kMaxReportableBuckets];
  const size_t partitionNumBuckets = partition->num_buckets;
  DCHECK(partitionNumBuckets <= kMaxReportableBuckets);

  for (size_t i = 0; i < partitionNumBuckets; ++i)
    PartitionDumpBucketStats(&memory_stats[i], &partition->buckets()[i]);

  // PartitionsDumpBucketStats is called after collecting stats because it
  // can use PartitionAlloc to allocate and this can affect the statistics.
  PartitionMemoryStats stats = {0};
  stats.total_mmapped_bytes = partition->total_size_of_super_pages;
  stats.total_committed_bytes = partition->total_size_of_committed_pages;
  DCHECK(!partition->total_size_of_direct_mapped_pages);
  for (size_t i = 0; i < partitionNumBuckets; ++i) {
    if (memory_stats[i].is_valid) {
      stats.total_resident_bytes += memory_stats[i].resident_bytes;
      stats.total_active_bytes += memory_stats[i].active_bytes;
      stats.total_decommittable_bytes += memory_stats[i].decommittable_bytes;
      stats.total_discardable_bytes += memory_stats[i].discardable_bytes;
      if (!is_light_dump)
        dumper->PartitionsDumpBucketStats(partition_name, &memory_stats[i]);
    }
  }
  dumper->PartitionDumpTotals(partition_name, &stats);
}

}  // namespace base
