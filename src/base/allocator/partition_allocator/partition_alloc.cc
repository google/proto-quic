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
PartitionAllocHooks::AllocationHook* PartitionAllocHooks::m_allocationHook =
    nullptr;
PartitionAllocHooks::FreeHook* PartitionAllocHooks::m_freeHook = nullptr;

static uint8_t partitionBucketNumSystemPages(size_t size) {
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
  double bestWasteRatio = 1.0f;
  uint16_t bestPages = 0;
  if (size > kMaxSystemPagesPerSlotSpan * kSystemPageSize) {
    DCHECK(!(size % kSystemPageSize));
    bestPages = static_cast<uint16_t>(size / kSystemPageSize);
    CHECK(bestPages < (1 << 8));
    return static_cast<uint8_t>(bestPages);
  }
  DCHECK(size <= kMaxSystemPagesPerSlotSpan * kSystemPageSize);
  for (uint16_t i = kNumSystemPagesPerPartitionPage - 1;
       i <= kMaxSystemPagesPerSlotSpan; ++i) {
    size_t pageSize = kSystemPageSize * i;
    size_t numSlots = pageSize / size;
    size_t waste = pageSize - (numSlots * size);
    // Leaving a page unfaulted is not free; the page will occupy an empty page
    // table entry.  Make a simple attempt to account for that.
    size_t numRemainderPages = i & (kNumSystemPagesPerPartitionPage - 1);
    size_t numUnfaultedPages =
        numRemainderPages
            ? (kNumSystemPagesPerPartitionPage - numRemainderPages)
            : 0;
    waste += sizeof(void*) * numUnfaultedPages;
    double wasteRatio = (double)waste / (double)pageSize;
    if (wasteRatio < bestWasteRatio) {
      bestWasteRatio = wasteRatio;
      bestPages = i;
    }
  }
  DCHECK(bestPages > 0);
  CHECK(bestPages <= kMaxSystemPagesPerSlotSpan);
  return static_cast<uint8_t>(bestPages);
}

static void partitionAllocBaseInit(PartitionRootBase* root) {
  DCHECK(!root->initialized);
  {
    subtle::SpinLock::Guard guard(PartitionRootBase::gInitializedLock);
    if (!PartitionRootBase::gInitialized) {
      PartitionRootBase::gInitialized = true;
      // We mark the seed page as free to make sure it is skipped by our
      // logic to find a new active page.
      PartitionRootBase::gPagedBucket.activePagesHead =
          &PartitionRootGeneric::gSeedPage;
    }
  }

  root->initialized = true;
  root->totalSizeOfCommittedPages = 0;
  root->totalSizeOfSuperPages = 0;
  root->totalSizeOfDirectMappedPages = 0;
  root->nextSuperPage = 0;
  root->nextPartitionPage = 0;
  root->nextPartitionPageEnd = 0;
  root->firstExtent = 0;
  root->currentExtent = 0;
  root->directMapList = 0;

  memset(&root->globalEmptyPageRing, '\0', sizeof(root->globalEmptyPageRing));
  root->globalEmptyPageRingIndex = 0;

  // This is a "magic" value so we can test if a root pointer is valid.
  root->invertedSelf = ~reinterpret_cast<uintptr_t>(root);
}

static void partitionBucketInitBase(PartitionBucket* bucket,
                                    PartitionRootBase* root) {
  bucket->activePagesHead = &PartitionRootGeneric::gSeedPage;
  bucket->emptyPagesHead = 0;
  bucket->decommittedPagesHead = 0;
  bucket->numFullPages = 0;
  bucket->numSystemPagesPerSlotSpan =
      partitionBucketNumSystemPages(bucket->slotSize);
}

void partitionAllocGlobalInit(void (*oomHandlingFunction)()) {
  DCHECK(oomHandlingFunction);
  PartitionRootBase::gOomHandlingFunction = oomHandlingFunction;
}

void partitionAllocInit(PartitionRoot* root,
                        size_t numBuckets,
                        size_t maxAllocation) {
  partitionAllocBaseInit(root);

  root->numBuckets = numBuckets;
  root->maxAllocation = maxAllocation;
  size_t i;
  for (i = 0; i < root->numBuckets; ++i) {
    PartitionBucket* bucket = &root->buckets()[i];
    if (!i)
      bucket->slotSize = kAllocationGranularity;
    else
      bucket->slotSize = i << kBucketShift;
    partitionBucketInitBase(bucket, root);
  }
}

void partitionAllocGenericInit(PartitionRootGeneric* root) {
  subtle::SpinLock::Guard guard(root->lock);

  partitionAllocBaseInit(root);

  // Precalculate some shift and mask constants used in the hot path.
  // Example: malloc(41) == 101001 binary.
  // Order is 6 (1 << 6-1)==32 is highest bit set.
  // orderIndex is the next three MSB == 010 == 2.
  // subOrderIndexMask is a mask for the remaining bits == 11 (masking to 01 for
  // the subOrderIndex).
  size_t order;
  for (order = 0; order <= kBitsPerSizet; ++order) {
    size_t orderIndexShift;
    if (order < kGenericNumBucketsPerOrderBits + 1)
      orderIndexShift = 0;
    else
      orderIndexShift = order - (kGenericNumBucketsPerOrderBits + 1);
    root->orderIndexShifts[order] = orderIndexShift;
    size_t subOrderIndexMask;
    if (order == kBitsPerSizet) {
      // This avoids invoking undefined behavior for an excessive shift.
      subOrderIndexMask =
          static_cast<size_t>(-1) >> (kGenericNumBucketsPerOrderBits + 1);
    } else {
      subOrderIndexMask = ((static_cast<size_t>(1) << order) - 1) >>
                          (kGenericNumBucketsPerOrderBits + 1);
    }
    root->orderSubIndexMasks[order] = subOrderIndexMask;
  }

  // Set up the actual usable buckets first.
  // Note that typical values (i.e. min allocation size of 8) will result in
  // pseudo buckets (size==9 etc. or more generally, size is not a multiple
  // of the smallest allocation granularity).
  // We avoid them in the bucket lookup map, but we tolerate them to keep the
  // code simpler and the structures more generic.
  size_t i, j;
  size_t currentSize = kGenericSmallestBucket;
  size_t currentIncrement =
      kGenericSmallestBucket >> kGenericNumBucketsPerOrderBits;
  PartitionBucket* bucket = &root->buckets[0];
  for (i = 0; i < kGenericNumBucketedOrders; ++i) {
    for (j = 0; j < kGenericNumBucketsPerOrder; ++j) {
      bucket->slotSize = currentSize;
      partitionBucketInitBase(bucket, root);
      // Disable psuedo buckets so that touching them faults.
      if (currentSize % kGenericSmallestBucket)
        bucket->activePagesHead = 0;
      currentSize += currentIncrement;
      ++bucket;
    }
    currentIncrement <<= 1;
  }
  DCHECK(currentSize == 1 << kGenericMaxBucketedOrder);
  DCHECK(bucket == &root->buckets[0] + kGenericNumBuckets);

  // Then set up the fast size -> bucket lookup table.
  bucket = &root->buckets[0];
  PartitionBucket** bucketPtr = &root->bucketLookups[0];
  for (order = 0; order <= kBitsPerSizet; ++order) {
    for (j = 0; j < kGenericNumBucketsPerOrder; ++j) {
      if (order < kGenericMinBucketedOrder) {
        // Use the bucket of the finest granularity for malloc(0) etc.
        *bucketPtr++ = &root->buckets[0];
      } else if (order > kGenericMaxBucketedOrder) {
        *bucketPtr++ = &PartitionRootGeneric::gPagedBucket;
      } else {
        PartitionBucket* validBucket = bucket;
        // Skip over invalid buckets.
        while (validBucket->slotSize % kGenericSmallestBucket)
          validBucket++;
        *bucketPtr++ = validBucket;
        bucket++;
      }
    }
  }
  DCHECK(bucket == &root->buckets[0] + kGenericNumBuckets);
  DCHECK(bucketPtr ==
         &root->bucketLookups[0] +
             ((kBitsPerSizet + 1) * kGenericNumBucketsPerOrder));
  // And there's one last bucket lookup that will be hit for e.g. malloc(-1),
  // which tries to overflow to a non-existant order.
  *bucketPtr = &PartitionRootGeneric::gPagedBucket;
}

static bool partitionAllocShutdownBucket(PartitionBucket* bucket) {
  // Failure here indicates a memory leak.
  bool foundLeak = bucket->numFullPages != 0;
  for (PartitionPage* page = bucket->activePagesHead; page;
       page = page->nextPage)
    foundLeak |= (page->numAllocatedSlots > 0);
  return foundLeak;
}

static bool partitionAllocBaseShutdown(PartitionRootBase* root) {
  DCHECK(root->initialized);
  root->initialized = false;

  // Now that we've examined all partition pages in all buckets, it's safe
  // to free all our super pages. Since the super page extent entries are
  // stored in the super pages, we need to be careful not to access them
  // after we've released the corresponding super page.
  PartitionSuperPageExtentEntry* entry = root->firstExtent;
  while (entry) {
    PartitionSuperPageExtentEntry* nextEntry = entry->next;
    char* superPage = entry->superPageBase;
    char* superPagesEnd = entry->superPagesEnd;
    while (superPage < superPagesEnd) {
      freePages(superPage, kSuperPageSize);
      superPage += kSuperPageSize;
    }
    entry = nextEntry;
  }
  return root->directMapList != nullptr;
}

bool partitionAllocShutdown(PartitionRoot* root) {
  bool foundLeak = false;
  size_t i;
  for (i = 0; i < root->numBuckets; ++i) {
    PartitionBucket* bucket = &root->buckets()[i];
    foundLeak |= partitionAllocShutdownBucket(bucket);
  }
  foundLeak |= partitionAllocBaseShutdown(root);
  return !foundLeak;
}

bool partitionAllocGenericShutdown(PartitionRootGeneric* root) {
  subtle::SpinLock::Guard guard(root->lock);
  bool foundLeak = false;
  size_t i;
  for (i = 0; i < kGenericNumBuckets; ++i) {
    PartitionBucket* bucket = &root->buckets[i];
    foundLeak |= partitionAllocShutdownBucket(bucket);
  }
  foundLeak |= partitionAllocBaseShutdown(root);
  return !foundLeak;
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
  if (root->totalSizeOfSuperPages + root->totalSizeOfDirectMappedPages -
          root->totalSizeOfCommittedPages >
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
partitionPageStateIsActive(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->pageOffset);
  return (page->numAllocatedSlots > 0 &&
          (page->freelistHead || page->numUnprovisionedSlots));
}

static bool ALWAYS_INLINE partitionPageStateIsFull(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->pageOffset);
  bool ret = (page->numAllocatedSlots == partitionBucketSlots(page->bucket));
  if (ret) {
    DCHECK(!page->freelistHead);
    DCHECK(!page->numUnprovisionedSlots);
  }
  return ret;
}

static bool ALWAYS_INLINE partitionPageStateIsEmpty(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->pageOffset);
  return (!page->numAllocatedSlots && page->freelistHead);
}

static bool ALWAYS_INLINE
partitionPageStateIsDecommitted(const PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  DCHECK(!page->pageOffset);
  bool ret = (!page->numAllocatedSlots && !page->freelistHead);
  if (ret) {
    DCHECK(!page->numUnprovisionedSlots);
    DCHECK(page->emptyCacheIndex == -1);
  }
  return ret;
}

static void partitionIncreaseCommittedPages(PartitionRootBase* root,
                                            size_t len) {
  root->totalSizeOfCommittedPages += len;
  DCHECK(root->totalSizeOfCommittedPages <=
         root->totalSizeOfSuperPages + root->totalSizeOfDirectMappedPages);
}

static void partitionDecreaseCommittedPages(PartitionRootBase* root,
                                            size_t len) {
  root->totalSizeOfCommittedPages -= len;
  DCHECK(root->totalSizeOfCommittedPages <=
         root->totalSizeOfSuperPages + root->totalSizeOfDirectMappedPages);
}

static ALWAYS_INLINE void partitionDecommitSystemPages(PartitionRootBase* root,
                                                       void* addr,
                                                       size_t len) {
  decommitSystemPages(addr, len);
  partitionDecreaseCommittedPages(root, len);
}

static ALWAYS_INLINE void partitionRecommitSystemPages(PartitionRootBase* root,
                                                       void* addr,
                                                       size_t len) {
  recommitSystemPages(addr, len);
  partitionIncreaseCommittedPages(root, len);
}

static ALWAYS_INLINE void* partitionAllocPartitionPages(
    PartitionRootBase* root,
    int flags,
    uint16_t numPartitionPages) {
  DCHECK(!(reinterpret_cast<uintptr_t>(root->nextPartitionPage) %
           kPartitionPageSize));
  DCHECK(!(reinterpret_cast<uintptr_t>(root->nextPartitionPageEnd) %
           kPartitionPageSize));
  DCHECK(numPartitionPages <= kNumPartitionPagesPerSuperPage);
  size_t totalSize = kPartitionPageSize * numPartitionPages;
  size_t numPartitionPagesLeft =
      (root->nextPartitionPageEnd - root->nextPartitionPage) >>
      kPartitionPageShift;
  if (LIKELY(numPartitionPagesLeft >= numPartitionPages)) {
    // In this case, we can still hand out pages from the current super page
    // allocation.
    char* ret = root->nextPartitionPage;
    root->nextPartitionPage += totalSize;
    partitionIncreaseCommittedPages(root, totalSize);
    return ret;
  }

  // Need a new super page. We want to allocate super pages in a continguous
  // address region as much as possible. This is important for not causing
  // page table bloat and not fragmenting address spaces in 32 bit
  // architectures.
  char* requestedAddress = root->nextSuperPage;
  char* superPage = reinterpret_cast<char*>(allocPages(
      requestedAddress, kSuperPageSize, kSuperPageSize, PageAccessible));
  if (UNLIKELY(!superPage))
    return 0;

  root->totalSizeOfSuperPages += kSuperPageSize;
  partitionIncreaseCommittedPages(root, totalSize);

  root->nextSuperPage = superPage + kSuperPageSize;
  char* ret = superPage + kPartitionPageSize;
  root->nextPartitionPage = ret + totalSize;
  root->nextPartitionPageEnd = root->nextSuperPage - kPartitionPageSize;
  // Make the first partition page in the super page a guard page, but leave a
  // hole in the middle.
  // This is where we put page metadata and also a tiny amount of extent
  // metadata.
  setSystemPagesInaccessible(superPage, kSystemPageSize);
  setSystemPagesInaccessible(superPage + (kSystemPageSize * 2),
                             kPartitionPageSize - (kSystemPageSize * 2));
  // Also make the last partition page a guard page.
  setSystemPagesInaccessible(superPage + (kSuperPageSize - kPartitionPageSize),
                             kPartitionPageSize);

  // If we were after a specific address, but didn't get it, assume that
  // the system chose a lousy address. Here most OS'es have a default
  // algorithm that isn't randomized. For example, most Linux
  // distributions will allocate the mapping directly before the last
  // successful mapping, which is far from random. So we just get fresh
  // randomness for the next mapping attempt.
  if (requestedAddress && requestedAddress != superPage)
    root->nextSuperPage = 0;

  // We allocated a new super page so update super page metadata.
  // First check if this is a new extent or not.
  PartitionSuperPageExtentEntry* latestExtent =
      reinterpret_cast<PartitionSuperPageExtentEntry*>(
          partitionSuperPageToMetadataArea(superPage));
  // By storing the root in every extent metadata object, we have a fast way
  // to go from a pointer within the partition to the root object.
  latestExtent->root = root;
  // Most new extents will be part of a larger extent, and these three fields
  // are unused, but we initialize them to 0 so that we get a clear signal
  // in case they are accidentally used.
  latestExtent->superPageBase = 0;
  latestExtent->superPagesEnd = 0;
  latestExtent->next = 0;

  PartitionSuperPageExtentEntry* currentExtent = root->currentExtent;
  bool isNewExtent = (superPage != requestedAddress);
  if (UNLIKELY(isNewExtent)) {
    if (UNLIKELY(!currentExtent)) {
      DCHECK(!root->firstExtent);
      root->firstExtent = latestExtent;
    } else {
      DCHECK(currentExtent->superPageBase);
      currentExtent->next = latestExtent;
    }
    root->currentExtent = latestExtent;
    latestExtent->superPageBase = superPage;
    latestExtent->superPagesEnd = superPage + kSuperPageSize;
  } else {
    // We allocated next to an existing extent so just nudge the size up a
    // little.
    DCHECK(currentExtent->superPagesEnd);
    currentExtent->superPagesEnd += kSuperPageSize;
    DCHECK(ret >= currentExtent->superPageBase &&
           ret < currentExtent->superPagesEnd);
  }
  return ret;
}

static ALWAYS_INLINE uint16_t
partitionBucketPartitionPages(const PartitionBucket* bucket) {
  return (bucket->numSystemPagesPerSlotSpan +
          (kNumSystemPagesPerPartitionPage - 1)) /
         kNumSystemPagesPerPartitionPage;
}

static ALWAYS_INLINE void partitionPageReset(PartitionPage* page) {
  DCHECK(partitionPageStateIsDecommitted(page));

  page->numUnprovisionedSlots = partitionBucketSlots(page->bucket);
  DCHECK(page->numUnprovisionedSlots);

  page->nextPage = nullptr;
}

static ALWAYS_INLINE void partitionPageSetup(PartitionPage* page,
                                             PartitionBucket* bucket) {
  // The bucket never changes. We set it up once.
  page->bucket = bucket;
  page->emptyCacheIndex = -1;

  partitionPageReset(page);

  // If this page has just a single slot, do not set up page offsets for any
  // page metadata other than the first one. This ensures that attempts to
  // touch invalid page metadata fail.
  if (page->numUnprovisionedSlots == 1)
    return;

  uint16_t numPartitionPages = partitionBucketPartitionPages(bucket);
  char* pageCharPtr = reinterpret_cast<char*>(page);
  for (uint16_t i = 1; i < numPartitionPages; ++i) {
    pageCharPtr += kPageMetadataSize;
    PartitionPage* secondaryPage =
        reinterpret_cast<PartitionPage*>(pageCharPtr);
    secondaryPage->pageOffset = i;
  }
}

static ALWAYS_INLINE char* partitionPageAllocAndFillFreelist(
    PartitionPage* page) {
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  uint16_t numSlots = page->numUnprovisionedSlots;
  DCHECK(numSlots);
  PartitionBucket* bucket = page->bucket;
  // We should only get here when _every_ slot is either used or unprovisioned.
  // (The third state is "on the freelist". If we have a non-empty freelist, we
  // should not get here.)
  DCHECK(numSlots + page->numAllocatedSlots == partitionBucketSlots(bucket));
  // Similarly, make explicitly sure that the freelist is empty.
  DCHECK(!page->freelistHead);
  DCHECK(page->numAllocatedSlots >= 0);

  size_t size = bucket->slotSize;
  char* base = reinterpret_cast<char*>(partitionPageToPointer(page));
  char* returnObject = base + (size * page->numAllocatedSlots);
  char* firstFreelistPointer = returnObject + size;
  char* firstFreelistPointerExtent =
      firstFreelistPointer + sizeof(PartitionFreelistEntry*);
  // Our goal is to fault as few system pages as possible. We calculate the
  // page containing the "end" of the returned slot, and then allow freelist
  // pointers to be written up to the end of that page.
  char* subPageLimit = reinterpret_cast<char*>(
      roundUpToSystemPage(reinterpret_cast<size_t>(firstFreelistPointer)));
  char* slotsLimit = returnObject + (size * numSlots);
  char* freelistLimit = subPageLimit;
  if (UNLIKELY(slotsLimit < freelistLimit))
    freelistLimit = slotsLimit;

  uint16_t numNewFreelistEntries = 0;
  if (LIKELY(firstFreelistPointerExtent <= freelistLimit)) {
    // Only consider used space in the slot span. If we consider wasted
    // space, we may get an off-by-one when a freelist pointer fits in the
    // wasted space, but a slot does not.
    // We know we can fit at least one freelist pointer.
    numNewFreelistEntries = 1;
    // Any further entries require space for the whole slot span.
    numNewFreelistEntries += static_cast<uint16_t>(
        (freelistLimit - firstFreelistPointerExtent) / size);
  }

  // We always return an object slot -- that's the +1 below.
  // We do not neccessarily create any new freelist entries, because we cross
  // sub page boundaries frequently for large bucket sizes.
  DCHECK(numNewFreelistEntries + 1 <= numSlots);
  numSlots -= (numNewFreelistEntries + 1);
  page->numUnprovisionedSlots = numSlots;
  page->numAllocatedSlots++;

  if (LIKELY(numNewFreelistEntries)) {
    char* freelistPointer = firstFreelistPointer;
    PartitionFreelistEntry* entry =
        reinterpret_cast<PartitionFreelistEntry*>(freelistPointer);
    page->freelistHead = entry;
    while (--numNewFreelistEntries) {
      freelistPointer += size;
      PartitionFreelistEntry* nextEntry =
          reinterpret_cast<PartitionFreelistEntry*>(freelistPointer);
      entry->next = partitionFreelistMask(nextEntry);
      entry = nextEntry;
    }
    entry->next = partitionFreelistMask(0);
  } else {
    page->freelistHead = 0;
  }
  return returnObject;
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
  PartitionPage* page = bucket->activePagesHead;
  if (page == &PartitionRootBase::gSeedPage)
    return false;

  PartitionPage* nextPage;

  for (; page; page = nextPage) {
    nextPage = page->nextPage;
    DCHECK(page->bucket == bucket);
    DCHECK(page != bucket->emptyPagesHead);
    DCHECK(page != bucket->decommittedPagesHead);

    // Deal with empty and decommitted pages.
    if (LIKELY(partitionPageStateIsActive(page))) {
      // This page is usable because it has freelist entries, or has
      // unprovisioned slots we can create freelist entries from.
      bucket->activePagesHead = page;
      return true;
    }
    if (LIKELY(partitionPageStateIsEmpty(page))) {
      page->nextPage = bucket->emptyPagesHead;
      bucket->emptyPagesHead = page;
    } else if (LIKELY(partitionPageStateIsDecommitted(page))) {
      page->nextPage = bucket->decommittedPagesHead;
      bucket->decommittedPagesHead = page;
    } else {
      DCHECK(partitionPageStateIsFull(page));
      // If we get here, we found a full page. Skip over it too, and also
      // tag it as full (via a negative value). We need it tagged so that
      // free'ing can tell, and move it back into the active page list.
      page->numAllocatedSlots = -page->numAllocatedSlots;
      ++bucket->numFullPages;
      // numFullPages is a uint16_t for efficient packing so guard against
      // overflow to be safe.
      if (UNLIKELY(!bucket->numFullPages))
        partitionBucketFull();
      // Not necessary but might help stop accidents.
      page->nextPage = 0;
    }
  }

  bucket->activePagesHead = &PartitionRootGeneric::gSeedPage;
  return false;
}

static ALWAYS_INLINE PartitionDirectMapExtent* partitionPageToDirectMapExtent(
    PartitionPage* page) {
  DCHECK(partitionBucketIsDirectMapped(page->bucket));
  return reinterpret_cast<PartitionDirectMapExtent*>(
      reinterpret_cast<char*>(page) + 3 * kPageMetadataSize);
}

static ALWAYS_INLINE void partitionPageSetRawSize(PartitionPage* page,
                                                  size_t size) {
  size_t* rawSizePtr = partitionPageGetRawSizePtr(page);
  if (UNLIKELY(rawSizePtr != nullptr))
    *rawSizePtr = size;
}

static ALWAYS_INLINE PartitionPage* partitionDirectMap(PartitionRootBase* root,
                                                       int flags,
                                                       size_t rawSize) {
  size_t size = partitionDirectMapSize(rawSize);

  // Because we need to fake looking like a super page, we need to allocate
  // a bunch of system pages more than "size":
  // - The first few system pages are the partition page in which the super
  // page metadata is stored. We fault just one system page out of a partition
  // page sized clump.
  // - We add a trailing guard page on 32-bit (on 64-bit we rely on the
  // massive address space plus randomization instead).
  size_t mapSize = size + kPartitionPageSize;
#if !defined(ARCH_CPU_64_BITS)
  mapSize += kSystemPageSize;
#endif
  // Round up to the allocation granularity.
  mapSize += kPageAllocationGranularityOffsetMask;
  mapSize &= kPageAllocationGranularityBaseMask;

  // TODO: these pages will be zero-filled. Consider internalizing an
  // allocZeroed() API so we can avoid a memset() entirely in this case.
  char* ptr = reinterpret_cast<char*>(
      allocPages(0, mapSize, kSuperPageSize, PageAccessible));
  if (UNLIKELY(!ptr))
    return nullptr;

  size_t committedPageSize = size + kSystemPageSize;
  root->totalSizeOfDirectMappedPages += committedPageSize;
  partitionIncreaseCommittedPages(root, committedPageSize);

  char* slot = ptr + kPartitionPageSize;
  setSystemPagesInaccessible(ptr + (kSystemPageSize * 2),
                             kPartitionPageSize - (kSystemPageSize * 2));
#if !defined(ARCH_CPU_64_BITS)
  setSystemPagesInaccessible(ptr, kSystemPageSize);
  setSystemPagesInaccessible(slot + size, kSystemPageSize);
#endif

  PartitionSuperPageExtentEntry* extent =
      reinterpret_cast<PartitionSuperPageExtentEntry*>(
          partitionSuperPageToMetadataArea(ptr));
  extent->root = root;
  // The new structures are all located inside a fresh system page so they
  // will all be zeroed out. These DCHECKs are for documentation.
  DCHECK(!extent->superPageBase);
  DCHECK(!extent->superPagesEnd);
  DCHECK(!extent->next);
  PartitionPage* page = partitionPointerToPageNoAlignmentCheck(slot);
  PartitionBucket* bucket = reinterpret_cast<PartitionBucket*>(
      reinterpret_cast<char*>(page) + (kPageMetadataSize * 2));
  DCHECK(!page->nextPage);
  DCHECK(!page->numAllocatedSlots);
  DCHECK(!page->numUnprovisionedSlots);
  DCHECK(!page->pageOffset);
  DCHECK(!page->emptyCacheIndex);
  page->bucket = bucket;
  page->freelistHead = reinterpret_cast<PartitionFreelistEntry*>(slot);
  PartitionFreelistEntry* nextEntry =
      reinterpret_cast<PartitionFreelistEntry*>(slot);
  nextEntry->next = partitionFreelistMask(0);

  DCHECK(!bucket->activePagesHead);
  DCHECK(!bucket->emptyPagesHead);
  DCHECK(!bucket->decommittedPagesHead);
  DCHECK(!bucket->numSystemPagesPerSlotSpan);
  DCHECK(!bucket->numFullPages);
  bucket->slotSize = size;

  PartitionDirectMapExtent* mapExtent = partitionPageToDirectMapExtent(page);
  mapExtent->mapSize = mapSize - kPartitionPageSize - kSystemPageSize;
  mapExtent->bucket = bucket;

  // Maintain the doubly-linked list of all direct mappings.
  mapExtent->nextExtent = root->directMapList;
  if (mapExtent->nextExtent)
    mapExtent->nextExtent->prevExtent = mapExtent;
  mapExtent->prevExtent = nullptr;
  root->directMapList = mapExtent;

  return page;
}

static ALWAYS_INLINE void partitionDirectUnmap(PartitionPage* page) {
  PartitionRootBase* root = partitionPageToRoot(page);
  const PartitionDirectMapExtent* extent = partitionPageToDirectMapExtent(page);
  size_t unmapSize = extent->mapSize;

  // Maintain the doubly-linked list of all direct mappings.
  if (extent->prevExtent) {
    DCHECK(extent->prevExtent->nextExtent == extent);
    extent->prevExtent->nextExtent = extent->nextExtent;
  } else {
    root->directMapList = extent->nextExtent;
  }
  if (extent->nextExtent) {
    DCHECK(extent->nextExtent->prevExtent == extent);
    extent->nextExtent->prevExtent = extent->prevExtent;
  }

  // Add on the size of the trailing guard page and preceeding partition
  // page.
  unmapSize += kPartitionPageSize + kSystemPageSize;

  size_t uncommittedPageSize = page->bucket->slotSize + kSystemPageSize;
  partitionDecreaseCommittedPages(root, uncommittedPageSize);
  DCHECK(root->totalSizeOfDirectMappedPages >= uncommittedPageSize);
  root->totalSizeOfDirectMappedPages -= uncommittedPageSize;

  DCHECK(!(unmapSize & kPageAllocationGranularityOffsetMask));

  char* ptr = reinterpret_cast<char*>(partitionPageToPointer(page));
  // Account for the mapping starting a partition page before the actual
  // allocation address.
  ptr -= kPartitionPageSize;

  freePages(ptr, unmapSize);
}

void* partitionAllocSlowPath(PartitionRootBase* root,
                             int flags,
                             size_t size,
                             PartitionBucket* bucket) {
  // The slow path is called when the freelist is empty.
  DCHECK(!bucket->activePagesHead->freelistHead);

  PartitionPage* newPage = nullptr;

  // For the partitionAllocGeneric API, we have a bunch of buckets marked
  // as special cases. We bounce them through to the slow path so that we
  // can still have a blazing fast hot path due to lack of corner-case
  // branches.
  bool returnNull = flags & PartitionAllocReturnNull;
  if (UNLIKELY(partitionBucketIsDirectMapped(bucket))) {
    DCHECK(size > kGenericMaxBucketed);
    DCHECK(bucket == &PartitionRootBase::gPagedBucket);
    DCHECK(bucket->activePagesHead == &PartitionRootGeneric::gSeedPage);
    if (size > kGenericMaxDirectMapped) {
      if (returnNull)
        return nullptr;
      partitionExcessiveAllocationSize();
    }
    newPage = partitionDirectMap(root, flags, size);
  } else if (LIKELY(partitionSetNewActivePage(bucket))) {
    // First, did we find an active page in the active pages list?
    newPage = bucket->activePagesHead;
    DCHECK(partitionPageStateIsActive(newPage));
  } else if (LIKELY(bucket->emptyPagesHead != nullptr) ||
             LIKELY(bucket->decommittedPagesHead != nullptr)) {
    // Second, look in our lists of empty and decommitted pages.
    // Check empty pages first, which are preferred, but beware that an
    // empty page might have been decommitted.
    while (LIKELY((newPage = bucket->emptyPagesHead) != nullptr)) {
      DCHECK(newPage->bucket == bucket);
      DCHECK(partitionPageStateIsEmpty(newPage) ||
             partitionPageStateIsDecommitted(newPage));
      bucket->emptyPagesHead = newPage->nextPage;
      // Accept the empty page unless it got decommitted.
      if (newPage->freelistHead) {
        newPage->nextPage = nullptr;
        break;
      }
      DCHECK(partitionPageStateIsDecommitted(newPage));
      newPage->nextPage = bucket->decommittedPagesHead;
      bucket->decommittedPagesHead = newPage;
    }
    if (UNLIKELY(!newPage) && LIKELY(bucket->decommittedPagesHead != nullptr)) {
      newPage = bucket->decommittedPagesHead;
      DCHECK(newPage->bucket == bucket);
      DCHECK(partitionPageStateIsDecommitted(newPage));
      bucket->decommittedPagesHead = newPage->nextPage;
      void* addr = partitionPageToPointer(newPage);
      partitionRecommitSystemPages(root, addr,
                                   partitionBucketBytes(newPage->bucket));
      partitionPageReset(newPage);
    }
    DCHECK(newPage);
  } else {
    // Third. If we get here, we need a brand new page.
    uint16_t numPartitionPages = partitionBucketPartitionPages(bucket);
    void* rawPages =
        partitionAllocPartitionPages(root, flags, numPartitionPages);
    if (LIKELY(rawPages != nullptr)) {
      newPage = partitionPointerToPageNoAlignmentCheck(rawPages);
      partitionPageSetup(newPage, bucket);
    }
  }

  // Bail if we had a memory allocation failure.
  if (UNLIKELY(!newPage)) {
    DCHECK(bucket->activePagesHead == &PartitionRootGeneric::gSeedPage);
    if (returnNull)
      return nullptr;
    partitionOutOfMemory(root);
  }

  bucket = newPage->bucket;
  DCHECK(bucket != &PartitionRootBase::gPagedBucket);
  bucket->activePagesHead = newPage;
  partitionPageSetRawSize(newPage, size);

  // If we found an active page with free slots, or an empty page, we have a
  // usable freelist head.
  if (LIKELY(newPage->freelistHead != nullptr)) {
    PartitionFreelistEntry* entry = newPage->freelistHead;
    PartitionFreelistEntry* newHead = partitionFreelistMask(entry->next);
    newPage->freelistHead = newHead;
    newPage->numAllocatedSlots++;
    return entry;
  }
  // Otherwise, we need to build the freelist.
  DCHECK(newPage->numUnprovisionedSlots);
  return partitionPageAllocAndFillFreelist(newPage);
}

static ALWAYS_INLINE void partitionDecommitPage(PartitionRootBase* root,
                                                PartitionPage* page) {
  DCHECK(partitionPageStateIsEmpty(page));
  DCHECK(!partitionBucketIsDirectMapped(page->bucket));
  void* addr = partitionPageToPointer(page);
  partitionDecommitSystemPages(root, addr, partitionBucketBytes(page->bucket));

  // We actually leave the decommitted page in the active list. We'll sweep
  // it on to the decommitted page list when we next walk the active page
  // list.
  // Pulling this trick enables us to use a singly-linked page list for all
  // cases, which is critical in keeping the page metadata structure down to
  // 32 bytes in size.
  page->freelistHead = 0;
  page->numUnprovisionedSlots = 0;
  DCHECK(partitionPageStateIsDecommitted(page));
}

static void partitionDecommitPageIfPossible(PartitionRootBase* root,
                                            PartitionPage* page) {
  DCHECK(page->emptyCacheIndex >= 0);
  DCHECK(static_cast<unsigned>(page->emptyCacheIndex) < kMaxFreeableSpans);
  DCHECK(page == root->globalEmptyPageRing[page->emptyCacheIndex]);
  page->emptyCacheIndex = -1;
  if (partitionPageStateIsEmpty(page))
    partitionDecommitPage(root, page);
}

static ALWAYS_INLINE void partitionRegisterEmptyPage(PartitionPage* page) {
  DCHECK(partitionPageStateIsEmpty(page));
  PartitionRootBase* root = partitionPageToRoot(page);

  // If the page is already registered as empty, give it another life.
  if (page->emptyCacheIndex != -1) {
    DCHECK(page->emptyCacheIndex >= 0);
    DCHECK(static_cast<unsigned>(page->emptyCacheIndex) < kMaxFreeableSpans);
    DCHECK(root->globalEmptyPageRing[page->emptyCacheIndex] == page);
    root->globalEmptyPageRing[page->emptyCacheIndex] = 0;
  }

  int16_t currentIndex = root->globalEmptyPageRingIndex;
  PartitionPage* pageToDecommit = root->globalEmptyPageRing[currentIndex];
  // The page might well have been re-activated, filled up, etc. before we get
  // around to looking at it here.
  if (pageToDecommit)
    partitionDecommitPageIfPossible(root, pageToDecommit);

  // We put the empty slot span on our global list of "pages that were once
  // empty". thus providing it a bit of breathing room to get re-used before
  // we really free it. This improves performance, particularly on Mac OS X
  // which has subpar memory management performance.
  root->globalEmptyPageRing[currentIndex] = page;
  page->emptyCacheIndex = currentIndex;
  ++currentIndex;
  if (currentIndex == kMaxFreeableSpans)
    currentIndex = 0;
  root->globalEmptyPageRingIndex = currentIndex;
}

static void partitionDecommitEmptyPages(PartitionRootBase* root) {
  for (size_t i = 0; i < kMaxFreeableSpans; ++i) {
    PartitionPage* page = root->globalEmptyPageRing[i];
    if (page)
      partitionDecommitPageIfPossible(root, page);
    root->globalEmptyPageRing[i] = nullptr;
  }
}

void partitionFreeSlowPath(PartitionPage* page) {
  PartitionBucket* bucket = page->bucket;
  DCHECK(page != &PartitionRootGeneric::gSeedPage);
  if (LIKELY(page->numAllocatedSlots == 0)) {
    // Page became fully unused.
    if (UNLIKELY(partitionBucketIsDirectMapped(bucket))) {
      partitionDirectUnmap(page);
      return;
    }
    // If it's the current active page, change it. We bounce the page to
    // the empty list as a force towards defragmentation.
    if (LIKELY(page == bucket->activePagesHead))
      (void)partitionSetNewActivePage(bucket);
    DCHECK(bucket->activePagesHead != page);

    partitionPageSetRawSize(page, 0);
    DCHECK(!partitionPageGetRawSize(page));

    partitionRegisterEmptyPage(page);
  } else {
    DCHECK(!partitionBucketIsDirectMapped(bucket));
    // Ensure that the page is full. That's the only valid case if we
    // arrive here.
    DCHECK(page->numAllocatedSlots < 0);
    // A transition of numAllocatedSlots from 0 to -1 is not legal, and
    // likely indicates a double-free.
    CHECK(page->numAllocatedSlots != -1);
    page->numAllocatedSlots = -page->numAllocatedSlots - 2;
    DCHECK(page->numAllocatedSlots == partitionBucketSlots(bucket) - 1);
    // Fully used page became partially used. It must be put back on the
    // non-full page list. Also make it the current page to increase the
    // chances of it being filled up again. The old current page will be
    // the next page.
    DCHECK(!page->nextPage);
    if (LIKELY(bucket->activePagesHead != &PartitionRootGeneric::gSeedPage))
      page->nextPage = bucket->activePagesHead;
    bucket->activePagesHead = page;
    --bucket->numFullPages;
    // Special case: for a partition page with just a single slot, it may
    // now be empty and we want to run it through the empty logic.
    if (UNLIKELY(page->numAllocatedSlots == 0))
      partitionFreeSlowPath(page);
  }
}

bool partitionReallocDirectMappedInPlace(PartitionRootGeneric* root,
                                         PartitionPage* page,
                                         size_t rawSize) {
  DCHECK(partitionBucketIsDirectMapped(page->bucket));

  rawSize = partitionCookieSizeAdjustAdd(rawSize);

  // Note that the new size might be a bucketed size; this function is called
  // whenever we're reallocating a direct mapped allocation.
  size_t newSize = partitionDirectMapSize(rawSize);
  if (newSize < kGenericMinDirectMappedDownsize)
    return false;

  // bucket->slotSize is the current size of the allocation.
  size_t currentSize = page->bucket->slotSize;
  if (newSize == currentSize)
    return true;

  char* charPtr = static_cast<char*>(partitionPageToPointer(page));

  if (newSize < currentSize) {
    size_t mapSize = partitionPageToDirectMapExtent(page)->mapSize;

    // Don't reallocate in-place if new size is less than 80 % of the full
    // map size, to avoid holding on to too much unused address space.
    if ((newSize / kSystemPageSize) * 5 < (mapSize / kSystemPageSize) * 4)
      return false;

    // Shrink by decommitting unneeded pages and making them inaccessible.
    size_t decommitSize = currentSize - newSize;
    partitionDecommitSystemPages(root, charPtr + newSize, decommitSize);
    setSystemPagesInaccessible(charPtr + newSize, decommitSize);
  } else if (newSize <= partitionPageToDirectMapExtent(page)->mapSize) {
    // Grow within the actually allocated memory. Just need to make the
    // pages accessible again.
    size_t recommitSize = newSize - currentSize;
    bool ret = setSystemPagesAccessible(charPtr + currentSize, recommitSize);
    CHECK(ret);
    partitionRecommitSystemPages(root, charPtr + currentSize, recommitSize);

#if DCHECK_IS_ON()
    memset(charPtr + currentSize, kUninitializedByte, recommitSize);
#endif
  } else {
    // We can't perform the realloc in-place.
    // TODO: support this too when possible.
    return false;
  }

#if DCHECK_IS_ON()
  // Write a new trailing cookie.
  partitionCookieWriteValue(charPtr + rawSize - kCookieSize);
#endif

  partitionPageSetRawSize(page, rawSize);
  DCHECK(partitionPageGetRawSize(page) == rawSize);

  page->bucket->slotSize = newSize;
  return true;
}

void* partitionReallocGeneric(PartitionRootGeneric* root,
                              void* ptr,
                              size_t newSize,
                              const char* typeName) {
#if defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
  return realloc(ptr, newSize);
#else
  if (UNLIKELY(!ptr))
    return partitionAllocGeneric(root, newSize, typeName);
  if (UNLIKELY(!newSize)) {
    partitionFreeGeneric(root, ptr);
    return 0;
  }

  if (newSize > kGenericMaxDirectMapped)
    partitionExcessiveAllocationSize();

  DCHECK(partitionPointerIsValid(partitionCookieFreePointerAdjust(ptr)));

  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));

  if (UNLIKELY(partitionBucketIsDirectMapped(page->bucket))) {
    // We may be able to perform the realloc in place by changing the
    // accessibility of memory pages and, if reducing the size, decommitting
    // them.
    if (partitionReallocDirectMappedInPlace(root, page, newSize)) {
      PartitionAllocHooks::reallocHookIfEnabled(ptr, ptr, newSize, typeName);
      return ptr;
    }
  }

  size_t actualNewSize = partitionAllocActualSize(root, newSize);
  size_t actualOldSize = partitionAllocGetSize(ptr);

  // TODO: note that tcmalloc will "ignore" a downsizing realloc() unless the
  // new size is a significant percentage smaller. We could do the same if we
  // determine it is a win.
  if (actualNewSize == actualOldSize) {
    // Trying to allocate a block of size newSize would give us a block of
    // the same size as the one we've already got, so no point in doing
    // anything here.
    return ptr;
  }

  // This realloc cannot be resized in-place. Sadness.
  void* ret = partitionAllocGeneric(root, newSize, typeName);
  size_t copySize = actualOldSize;
  if (newSize < copySize)
    copySize = newSize;

  memcpy(ret, ptr, copySize);
  partitionFreeGeneric(root, ptr);
  return ret;
#endif
}

static size_t partitionPurgePage(PartitionPage* page, bool discard) {
  const PartitionBucket* bucket = page->bucket;
  size_t slotSize = bucket->slotSize;
  if (slotSize < kSystemPageSize || !page->numAllocatedSlots)
    return 0;

  size_t bucketNumSlots = partitionBucketSlots(bucket);
  size_t discardableBytes = 0;

  size_t rawSize = partitionPageGetRawSize(const_cast<PartitionPage*>(page));
  if (rawSize) {
    uint32_t usedBytes = static_cast<uint32_t>(roundUpToSystemPage(rawSize));
    discardableBytes = bucket->slotSize - usedBytes;
    if (discardableBytes && discard) {
      char* ptr = reinterpret_cast<char*>(partitionPageToPointer(page));
      ptr += usedBytes;
      discardSystemPages(ptr, discardableBytes);
    }
    return discardableBytes;
  }

  const size_t maxSlotCount =
      (kPartitionPageSize * kMaxPartitionPagesPerSlotSpan) / kSystemPageSize;
  DCHECK(bucketNumSlots <= maxSlotCount);
  DCHECK(page->numUnprovisionedSlots < bucketNumSlots);
  size_t numSlots = bucketNumSlots - page->numUnprovisionedSlots;
  char slotUsage[maxSlotCount];
  size_t lastSlot = static_cast<size_t>(-1);
  memset(slotUsage, 1, numSlots);
  char* ptr = reinterpret_cast<char*>(partitionPageToPointer(page));
  PartitionFreelistEntry* entry = page->freelistHead;
  // First, walk the freelist for this page and make a bitmap of which slots
  // are not in use.
  while (entry) {
    size_t slotIndex = (reinterpret_cast<char*>(entry) - ptr) / slotSize;
    DCHECK(slotIndex < numSlots);
    slotUsage[slotIndex] = 0;
    entry = partitionFreelistMask(entry->next);
    // If we have a slot where the masked freelist entry is 0, we can
    // actually discard that freelist entry because touching a discarded
    // page is guaranteed to return original content or 0.
    // (Note that this optimization won't fire on big endian machines
    // because the masking function is negation.)
    if (!partitionFreelistMask(entry))
      lastSlot = slotIndex;
  }

  // If the slot(s) at the end of the slot span are not in used, we can
  // truncate them entirely and rewrite the freelist.
  size_t truncatedSlots = 0;
  while (!slotUsage[numSlots - 1]) {
    truncatedSlots++;
    numSlots--;
    DCHECK(numSlots);
  }
  // First, do the work of calculating the discardable bytes. Don't actually
  // discard anything unless the discard flag was passed in.
  char* beginPtr = nullptr;
  char* endPtr = nullptr;
  size_t unprovisionedBytes = 0;
  if (truncatedSlots) {
    beginPtr = ptr + (numSlots * slotSize);
    endPtr = beginPtr + (slotSize * truncatedSlots);
    beginPtr = reinterpret_cast<char*>(
        roundUpToSystemPage(reinterpret_cast<size_t>(beginPtr)));
    // We round the end pointer here up and not down because we're at the
    // end of a slot span, so we "own" all the way up the page boundary.
    endPtr = reinterpret_cast<char*>(
        roundUpToSystemPage(reinterpret_cast<size_t>(endPtr)));
    DCHECK(endPtr <= ptr + partitionBucketBytes(bucket));
    if (beginPtr < endPtr) {
      unprovisionedBytes = endPtr - beginPtr;
      discardableBytes += unprovisionedBytes;
    }
  }
  if (unprovisionedBytes && discard) {
    DCHECK(truncatedSlots > 0);
    size_t numNewEntries = 0;
    page->numUnprovisionedSlots += static_cast<uint16_t>(truncatedSlots);
    // Rewrite the freelist.
    PartitionFreelistEntry** entryPtr = &page->freelistHead;
    for (size_t slotIndex = 0; slotIndex < numSlots; ++slotIndex) {
      if (slotUsage[slotIndex])
        continue;
      PartitionFreelistEntry* entry = reinterpret_cast<PartitionFreelistEntry*>(
          ptr + (slotSize * slotIndex));
      *entryPtr = partitionFreelistMask(entry);
      entryPtr = reinterpret_cast<PartitionFreelistEntry**>(entry);
      numNewEntries++;
    }
    // Terminate the freelist chain.
    *entryPtr = nullptr;
    // The freelist head is stored unmasked.
    page->freelistHead = partitionFreelistMask(page->freelistHead);
    DCHECK(numNewEntries == numSlots - page->numAllocatedSlots);
    // Discard the memory.
    discardSystemPages(beginPtr, unprovisionedBytes);
  }

  // Next, walk the slots and for any not in use, consider where the system
  // page boundaries occur. We can release any system pages back to the
  // system as long as we don't interfere with a freelist pointer or an
  // adjacent slot.
  for (size_t i = 0; i < numSlots; ++i) {
    if (slotUsage[i])
      continue;
    // The first address we can safely discard is just after the freelist
    // pointer. There's one quirk: if the freelist pointer is actually a
    // null, we can discard that pointer value too.
    char* beginPtr = ptr + (i * slotSize);
    char* endPtr = beginPtr + slotSize;
    if (i != lastSlot)
      beginPtr += sizeof(PartitionFreelistEntry);
    beginPtr = reinterpret_cast<char*>(
        roundUpToSystemPage(reinterpret_cast<size_t>(beginPtr)));
    endPtr = reinterpret_cast<char*>(
        roundDownToSystemPage(reinterpret_cast<size_t>(endPtr)));
    if (beginPtr < endPtr) {
      size_t partialSlotBytes = endPtr - beginPtr;
      discardableBytes += partialSlotBytes;
      if (discard)
        discardSystemPages(beginPtr, partialSlotBytes);
    }
  }
  return discardableBytes;
}

static void partitionPurgeBucket(PartitionBucket* bucket) {
  if (bucket->activePagesHead != &PartitionRootGeneric::gSeedPage) {
    for (PartitionPage* page = bucket->activePagesHead; page;
         page = page->nextPage) {
      DCHECK(page != &PartitionRootGeneric::gSeedPage);
      (void)partitionPurgePage(page, true);
    }
  }
}

void partitionPurgeMemory(PartitionRoot* root, int flags) {
  if (flags & PartitionPurgeDecommitEmptyPages)
    partitionDecommitEmptyPages(root);
  // We don't currently do anything for PartitionPurgeDiscardUnusedSystemPages
  // here because that flag is only useful for allocations >= system page
  // size. We only have allocations that large inside generic partitions
  // at the moment.
}

void partitionPurgeMemoryGeneric(PartitionRootGeneric* root, int flags) {
  subtle::SpinLock::Guard guard(root->lock);
  if (flags & PartitionPurgeDecommitEmptyPages)
    partitionDecommitEmptyPages(root);
  if (flags & PartitionPurgeDiscardUnusedSystemPages) {
    for (size_t i = 0; i < kGenericNumBuckets; ++i) {
      PartitionBucket* bucket = &root->buckets[i];
      if (bucket->slotSize >= kSystemPageSize)
        partitionPurgeBucket(bucket);
    }
  }
}

static void partitionDumpPageStats(PartitionBucketMemoryStats* statsOut,
                                   const PartitionPage* page) {
  uint16_t bucketNumSlots = partitionBucketSlots(page->bucket);

  if (partitionPageStateIsDecommitted(page)) {
    ++statsOut->numDecommittedPages;
    return;
  }

  statsOut->discardableBytes +=
      partitionPurgePage(const_cast<PartitionPage*>(page), false);

  size_t rawSize = partitionPageGetRawSize(const_cast<PartitionPage*>(page));
  if (rawSize)
    statsOut->activeBytes += static_cast<uint32_t>(rawSize);
  else
    statsOut->activeBytes +=
        (page->numAllocatedSlots * statsOut->bucketSlotSize);

  size_t pageBytesResident =
      roundUpToSystemPage((bucketNumSlots - page->numUnprovisionedSlots) *
                          statsOut->bucketSlotSize);
  statsOut->residentBytes += pageBytesResident;
  if (partitionPageStateIsEmpty(page)) {
    statsOut->decommittableBytes += pageBytesResident;
    ++statsOut->numEmptyPages;
  } else if (partitionPageStateIsFull(page)) {
    ++statsOut->numFullPages;
  } else {
    DCHECK(partitionPageStateIsActive(page));
    ++statsOut->numActivePages;
  }
}

static void partitionDumpBucketStats(PartitionBucketMemoryStats* statsOut,
                                     const PartitionBucket* bucket) {
  DCHECK(!partitionBucketIsDirectMapped(bucket));
  statsOut->isValid = false;
  // If the active page list is empty (== &PartitionRootGeneric::gSeedPage),
  // the bucket might still need to be reported if it has a list of empty,
  // decommitted or full pages.
  if (bucket->activePagesHead == &PartitionRootGeneric::gSeedPage &&
      !bucket->emptyPagesHead && !bucket->decommittedPagesHead &&
      !bucket->numFullPages)
    return;

  memset(statsOut, '\0', sizeof(*statsOut));
  statsOut->isValid = true;
  statsOut->isDirectMap = false;
  statsOut->numFullPages = static_cast<size_t>(bucket->numFullPages);
  statsOut->bucketSlotSize = bucket->slotSize;
  uint16_t bucketNumSlots = partitionBucketSlots(bucket);
  size_t bucketUsefulStorage = statsOut->bucketSlotSize * bucketNumSlots;
  statsOut->allocatedPageSize = partitionBucketBytes(bucket);
  statsOut->activeBytes = bucket->numFullPages * bucketUsefulStorage;
  statsOut->residentBytes = bucket->numFullPages * statsOut->allocatedPageSize;

  for (const PartitionPage* page = bucket->emptyPagesHead; page;
       page = page->nextPage) {
    DCHECK(partitionPageStateIsEmpty(page) ||
           partitionPageStateIsDecommitted(page));
    partitionDumpPageStats(statsOut, page);
  }
  for (const PartitionPage* page = bucket->decommittedPagesHead; page;
       page = page->nextPage) {
    DCHECK(partitionPageStateIsDecommitted(page));
    partitionDumpPageStats(statsOut, page);
  }

  if (bucket->activePagesHead != &PartitionRootGeneric::gSeedPage) {
    for (const PartitionPage* page = bucket->activePagesHead; page;
         page = page->nextPage) {
      DCHECK(page != &PartitionRootGeneric::gSeedPage);
      partitionDumpPageStats(statsOut, page);
    }
  }
}

void partitionDumpStatsGeneric(PartitionRootGeneric* partition,
                               const char* partitionName,
                               bool isLightDump,
                               PartitionStatsDumper* partitionStatsDumper) {
  PartitionBucketMemoryStats bucketStats[kGenericNumBuckets];
  static const size_t kMaxReportableDirectMaps = 4096;
  uint32_t directMapLengths[kMaxReportableDirectMaps];
  size_t numDirectMappedAllocations = 0;

  {
    subtle::SpinLock::Guard guard(partition->lock);

    for (size_t i = 0; i < kGenericNumBuckets; ++i) {
      const PartitionBucket* bucket = &partition->buckets[i];
      // Don't report the pseudo buckets that the generic allocator sets up in
      // order to preserve a fast size->bucket map (see
      // partitionAllocGenericInit for details).
      if (!bucket->activePagesHead)
        bucketStats[i].isValid = false;
      else
        partitionDumpBucketStats(&bucketStats[i], bucket);
    }

    for (PartitionDirectMapExtent* extent = partition->directMapList; extent;
         extent = extent->nextExtent) {
      DCHECK(!extent->nextExtent || extent->nextExtent->prevExtent == extent);
      directMapLengths[numDirectMappedAllocations] = extent->bucket->slotSize;
      ++numDirectMappedAllocations;
      if (numDirectMappedAllocations == kMaxReportableDirectMaps)
        break;
    }
  }

  // partitionsDumpBucketStats is called after collecting stats because it
  // can try to allocate using PartitionAllocGeneric and it can't obtain the
  // lock.
  PartitionMemoryStats partitionStats = {0};
  partitionStats.totalMmappedBytes = partition->totalSizeOfSuperPages +
                                     partition->totalSizeOfDirectMappedPages;
  partitionStats.totalCommittedBytes = partition->totalSizeOfCommittedPages;
  for (size_t i = 0; i < kGenericNumBuckets; ++i) {
    if (bucketStats[i].isValid) {
      partitionStats.totalResidentBytes += bucketStats[i].residentBytes;
      partitionStats.totalActiveBytes += bucketStats[i].activeBytes;
      partitionStats.totalDecommittableBytes +=
          bucketStats[i].decommittableBytes;
      partitionStats.totalDiscardableBytes += bucketStats[i].discardableBytes;
      if (!isLightDump)
        partitionStatsDumper->partitionsDumpBucketStats(partitionName,
                                                        &bucketStats[i]);
    }
  }

  size_t directMappedAllocationsTotalSize = 0;
  for (size_t i = 0; i < numDirectMappedAllocations; ++i) {
    uint32_t size = directMapLengths[i];
    directMappedAllocationsTotalSize += size;
    if (isLightDump)
      continue;

    PartitionBucketMemoryStats stats;
    memset(&stats, '\0', sizeof(stats));
    stats.isValid = true;
    stats.isDirectMap = true;
    stats.numFullPages = 1;
    stats.allocatedPageSize = size;
    stats.bucketSlotSize = size;
    stats.activeBytes = size;
    stats.residentBytes = size;
    partitionStatsDumper->partitionsDumpBucketStats(partitionName, &stats);
  }
  partitionStats.totalResidentBytes += directMappedAllocationsTotalSize;
  partitionStats.totalActiveBytes += directMappedAllocationsTotalSize;
  partitionStatsDumper->partitionDumpTotals(partitionName, &partitionStats);
}

void partitionDumpStats(PartitionRoot* partition,
                        const char* partitionName,
                        bool isLightDump,
                        PartitionStatsDumper* partitionStatsDumper) {
  static const size_t kMaxReportableBuckets = 4096 / sizeof(void*);
  PartitionBucketMemoryStats memoryStats[kMaxReportableBuckets];
  const size_t partitionNumBuckets = partition->numBuckets;
  DCHECK(partitionNumBuckets <= kMaxReportableBuckets);

  for (size_t i = 0; i < partitionNumBuckets; ++i)
    partitionDumpBucketStats(&memoryStats[i], &partition->buckets()[i]);

  // partitionsDumpBucketStats is called after collecting stats because it
  // can use PartitionAlloc to allocate and this can affect the statistics.
  PartitionMemoryStats partitionStats = {0};
  partitionStats.totalMmappedBytes = partition->totalSizeOfSuperPages;
  partitionStats.totalCommittedBytes = partition->totalSizeOfCommittedPages;
  DCHECK(!partition->totalSizeOfDirectMappedPages);
  for (size_t i = 0; i < partitionNumBuckets; ++i) {
    if (memoryStats[i].isValid) {
      partitionStats.totalResidentBytes += memoryStats[i].residentBytes;
      partitionStats.totalActiveBytes += memoryStats[i].activeBytes;
      partitionStats.totalDecommittableBytes +=
          memoryStats[i].decommittableBytes;
      partitionStats.totalDiscardableBytes += memoryStats[i].discardableBytes;
      if (!isLightDump)
        partitionStatsDumper->partitionsDumpBucketStats(partitionName,
                                                        &memoryStats[i]);
    }
  }
  partitionStatsDumper->partitionDumpTotals(partitionName, &partitionStats);
}

}  // namespace base
