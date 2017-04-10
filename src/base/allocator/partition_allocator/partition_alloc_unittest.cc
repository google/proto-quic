// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/partition_allocator/partition_alloc.h"

#include <stdlib.h>
#include <string.h>

#include <memory>
#include <vector>

#include "base/bits.h"
#include "base/sys_info.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_POSIX)
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif  // defined(OS_POSIX)

namespace {
template <typename T>
std::unique_ptr<T[]> WrapArrayUnique(T* ptr) {
  return std::unique_ptr<T[]>(ptr);
}
}  // namespace

#if !defined(MEMORY_TOOL_REPLACES_ALLOCATOR)

namespace base {

namespace {

const size_t kTestMaxAllocation = 4096;
SizeSpecificPartitionAllocator<kTestMaxAllocation> allocator;
PartitionAllocatorGeneric generic_allocator;

const size_t kTestAllocSize = 16;
#if !DCHECK_IS_ON()
const size_t kPointerOffset = 0;
const size_t kExtraAllocSize = 0;
#else
const size_t kPointerOffset = kCookieSize;
const size_t kExtraAllocSize = kCookieSize * 2;
#endif
const size_t kRealAllocSize = kTestAllocSize + kExtraAllocSize;
const size_t kTestBucketIndex = kRealAllocSize >> kBucketShift;

const char* type_name = nullptr;

void TestSetup() {
  // Zero the allocator structs to clear out traces
  // from previous test.
  memset(&allocator, 0, sizeof(allocator));
  memset(&generic_allocator, 0, sizeof(generic_allocator));

  allocator.init();
  generic_allocator.init();
}

#if !defined(ARCH_CPU_64_BITS) || defined(OS_POSIX)
bool SetAddressSpaceLimit() {
#if !defined(ARCH_CPU_64_BITS)
  // 32 bits => address space is limited already.
  return true;
#elif defined(OS_POSIX) && !defined(OS_MACOSX)
  // Mac will accept RLIMIT_AS changes but it is not enforced.
  // See https://crbug.com/435269 and rdar://17576114.
  // Note: this number must be not less than 6 GB, because with
  // sanitizer_coverage_flags=edge, it reserves > 5 GB of address
  // space, see https://crbug.com/674665.
  const size_t kAddressSpaceLimit = static_cast<size_t>(6144) * 1024 * 1024;
  struct rlimit limit;
  if (getrlimit(RLIMIT_AS, &limit) != 0)
    return false;
  if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > kAddressSpaceLimit) {
    limit.rlim_cur = kAddressSpaceLimit;
    if (setrlimit(RLIMIT_AS, &limit) != 0)
      return false;
  }
  return true;
#else
  return false;
#endif
}

bool ClearAddressSpaceLimit() {
#if !defined(ARCH_CPU_64_BITS)
  return true;
#elif defined(OS_POSIX)
  struct rlimit limit;
  if (getrlimit(RLIMIT_AS, &limit) != 0)
    return false;
  limit.rlim_cur = limit.rlim_max;
  if (setrlimit(RLIMIT_AS, &limit) != 0)
    return false;
  return true;
#else
  return false;
#endif
}
#endif

PartitionPage* GetFullPage(size_t size) {
  size_t real_size = size + kExtraAllocSize;
  size_t bucket_index = real_size >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucket_index];
  size_t num_slots =
      (bucket->num_system_pages_per_slot_span * kSystemPageSize) / real_size;
  void* first = 0;
  void* last = 0;
  size_t i;
  for (i = 0; i < num_slots; ++i) {
    void* ptr = PartitionAlloc(allocator.root(), size, type_name);
    EXPECT_TRUE(ptr);
    if (!i)
      first = PartitionCookieFreePointerAdjust(ptr);
    else if (i == num_slots - 1)
      last = PartitionCookieFreePointerAdjust(ptr);
  }
  EXPECT_EQ(PartitionPointerToPage(first), PartitionPointerToPage(last));
  if (bucket->num_system_pages_per_slot_span == kNumSystemPagesPerPartitionPage)
    EXPECT_EQ(reinterpret_cast<size_t>(first) & kPartitionPageBaseMask,
              reinterpret_cast<size_t>(last) & kPartitionPageBaseMask);
  EXPECT_EQ(num_slots, static_cast<size_t>(
                           bucket->active_pages_head->num_allocated_slots));
  EXPECT_EQ(0, bucket->active_pages_head->freelist_head);
  EXPECT_TRUE(bucket->active_pages_head);
  EXPECT_TRUE(bucket->active_pages_head != &PartitionRootGeneric::gSeedPage);
  return bucket->active_pages_head;
}

void FreeFullPage(PartitionPage* page) {
  size_t size = page->bucket->slot_size;
  size_t num_slots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) / size;
  EXPECT_EQ(num_slots, static_cast<size_t>(abs(page->num_allocated_slots)));
  char* ptr = reinterpret_cast<char*>(PartitionPageToPointer(page));
  size_t i;
  for (i = 0; i < num_slots; ++i) {
    PartitionFree(ptr + kPointerOffset);
    ptr += size;
  }
}

void CycleFreeCache(size_t size) {
  size_t real_size = size + kExtraAllocSize;
  size_t bucket_index = real_size >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucket_index];
  DCHECK(!bucket->active_pages_head->num_allocated_slots);

  for (size_t i = 0; i < kMaxFreeableSpans; ++i) {
    void* ptr = PartitionAlloc(allocator.root(), size, type_name);
    EXPECT_EQ(1, bucket->active_pages_head->num_allocated_slots);
    PartitionFree(ptr);
    EXPECT_EQ(0, bucket->active_pages_head->num_allocated_slots);
    EXPECT_NE(-1, bucket->active_pages_head->empty_cache_index);
  }
}

void CycleGenericFreeCache(size_t size) {
  for (size_t i = 0; i < kMaxFreeableSpans; ++i) {
    void* ptr =
        PartitionAllocGeneric(generic_allocator.root(), size, type_name);
    PartitionPage* page =
        PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
    PartitionBucket* bucket = page->bucket;
    EXPECT_EQ(1, bucket->active_pages_head->num_allocated_slots);
    PartitionFreeGeneric(generic_allocator.root(), ptr);
    EXPECT_EQ(0, bucket->active_pages_head->num_allocated_slots);
    EXPECT_NE(-1, bucket->active_pages_head->empty_cache_index);
  }
}

void CheckPageInCore(void* ptr, bool inCore) {
#if defined(OS_LINUX)
  unsigned char ret;
  EXPECT_EQ(0, mincore(ptr, kSystemPageSize, &ret));
  EXPECT_EQ(inCore, ret);
#endif
}

bool IsLargeMemoryDevice() {
  return base::SysInfo::AmountOfPhysicalMemory() >= 2LL * 1024 * 1024 * 1024;
}

class MockPartitionStatsDumper : public PartitionStatsDumper {
 public:
  MockPartitionStatsDumper()
      : total_resident_bytes(0),
        total_active_bytes(0),
        total_decommittable_bytes(0),
        total_discardable_bytes(0) {}

  void PartitionDumpTotals(const char* partition_name,
                           const PartitionMemoryStats* stats) override {
    EXPECT_GE(stats->total_mmapped_bytes, stats->total_resident_bytes);
    EXPECT_EQ(total_resident_bytes, stats->total_resident_bytes);
    EXPECT_EQ(total_active_bytes, stats->total_active_bytes);
    EXPECT_EQ(total_decommittable_bytes, stats->total_decommittable_bytes);
    EXPECT_EQ(total_discardable_bytes, stats->total_discardable_bytes);
  }

  void PartitionsDumpBucketStats(
      const char* partition_name,
      const PartitionBucketMemoryStats* stats) override {
    (void)partition_name;
    EXPECT_TRUE(stats->is_valid);
    EXPECT_EQ(0u, stats->bucket_slot_size & kAllocationGranularityMask);
    bucket_stats.push_back(*stats);
    total_resident_bytes += stats->resident_bytes;
    total_active_bytes += stats->active_bytes;
    total_decommittable_bytes += stats->decommittable_bytes;
    total_discardable_bytes += stats->discardable_bytes;
  }

  bool IsMemoryAllocationRecorded() {
    return total_resident_bytes != 0 && total_active_bytes != 0;
  }

  const PartitionBucketMemoryStats* GetBucketStats(size_t bucket_size) {
    for (size_t i = 0; i < bucket_stats.size(); ++i) {
      if (bucket_stats[i].bucket_slot_size == bucket_size)
        return &bucket_stats[i];
    }
    return 0;
  }

 private:
  size_t total_resident_bytes;
  size_t total_active_bytes;
  size_t total_decommittable_bytes;
  size_t total_discardable_bytes;

  std::vector<PartitionBucketMemoryStats> bucket_stats;
};

}  // anonymous namespace

// Check that the most basic of allocate / free pairs work.
TEST(PartitionAllocTest, Basic) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];
  PartitionPage* seedPage = &PartitionRootGeneric::gSeedPage;

  EXPECT_FALSE(bucket->empty_pages_head);
  EXPECT_FALSE(bucket->decommitted_pages_head);
  EXPECT_EQ(seedPage, bucket->active_pages_head);
  EXPECT_EQ(0, bucket->active_pages_head->next_page);

  void* ptr = PartitionAlloc(allocator.root(), kTestAllocSize, type_name);
  EXPECT_TRUE(ptr);
  EXPECT_EQ(kPointerOffset,
            reinterpret_cast<size_t>(ptr) & kPartitionPageOffsetMask);
  // Check that the offset appears to include a guard page.
  EXPECT_EQ(kPartitionPageSize + kPointerOffset,
            reinterpret_cast<size_t>(ptr) & kSuperPageOffsetMask);

  PartitionFree(ptr);
  // Expect that the last active page gets noticed as empty but doesn't get
  // decommitted.
  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_FALSE(bucket->decommitted_pages_head);
}

// Test multiple allocations, and freelist handling.
TEST(PartitionAllocTest, MultiAlloc) {
  TestSetup();

  char* ptr1 = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  char* ptr2 = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  EXPECT_TRUE(ptr1);
  EXPECT_TRUE(ptr2);
  ptrdiff_t diff = ptr2 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize), diff);

  // Check that we re-use the just-freed slot.
  PartitionFree(ptr2);
  ptr2 = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  EXPECT_TRUE(ptr2);
  diff = ptr2 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize), diff);
  PartitionFree(ptr1);
  ptr1 = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  EXPECT_TRUE(ptr1);
  diff = ptr2 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize), diff);

  char* ptr3 = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  EXPECT_TRUE(ptr3);
  diff = ptr3 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize * 2), diff);

  PartitionFree(ptr1);
  PartitionFree(ptr2);
  PartitionFree(ptr3);
}

// Test a bucket with multiple pages.
TEST(PartitionAllocTest, MultiPages) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  PartitionPage* page = GetFullPage(kTestAllocSize);
  FreeFullPage(page);
  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->active_pages_head);
  EXPECT_EQ(0, page->next_page);
  EXPECT_EQ(0, page->num_allocated_slots);

  page = GetFullPage(kTestAllocSize);
  PartitionPage* page2 = GetFullPage(kTestAllocSize);

  EXPECT_EQ(page2, bucket->active_pages_head);
  EXPECT_EQ(0, page2->next_page);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(PartitionPageToPointer(page)) &
                kSuperPageBaseMask,
            reinterpret_cast<uintptr_t>(PartitionPageToPointer(page2)) &
                kSuperPageBaseMask);

  // Fully free the non-current page. This will leave us with no current
  // active page because one is empty and the other is full.
  FreeFullPage(page);
  EXPECT_EQ(0, page->num_allocated_slots);
  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->active_pages_head);

  // Allocate a new page, it should pull from the freelist.
  page = GetFullPage(kTestAllocSize);
  EXPECT_FALSE(bucket->empty_pages_head);
  EXPECT_EQ(page, bucket->active_pages_head);

  FreeFullPage(page);
  FreeFullPage(page2);
  EXPECT_EQ(0, page->num_allocated_slots);
  EXPECT_EQ(0, page2->num_allocated_slots);
  EXPECT_EQ(0, page2->num_unprovisioned_slots);
  EXPECT_NE(-1, page2->empty_cache_index);
}

// Test some finer aspects of internal page transitions.
TEST(PartitionAllocTest, PageTransitions) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  PartitionPage* page1 = GetFullPage(kTestAllocSize);
  EXPECT_EQ(page1, bucket->active_pages_head);
  EXPECT_EQ(0, page1->next_page);
  PartitionPage* page2 = GetFullPage(kTestAllocSize);
  EXPECT_EQ(page2, bucket->active_pages_head);
  EXPECT_EQ(0, page2->next_page);

  // Bounce page1 back into the non-full list then fill it up again.
  char* ptr =
      reinterpret_cast<char*>(PartitionPageToPointer(page1)) + kPointerOffset;
  PartitionFree(ptr);
  EXPECT_EQ(page1, bucket->active_pages_head);
  (void)PartitionAlloc(allocator.root(), kTestAllocSize, type_name);
  EXPECT_EQ(page1, bucket->active_pages_head);
  EXPECT_EQ(page2, bucket->active_pages_head->next_page);

  // Allocating another page at this point should cause us to scan over page1
  // (which is both full and NOT our current page), and evict it from the
  // freelist. Older code had a O(n^2) condition due to failure to do this.
  PartitionPage* page3 = GetFullPage(kTestAllocSize);
  EXPECT_EQ(page3, bucket->active_pages_head);
  EXPECT_EQ(0, page3->next_page);

  // Work out a pointer into page2 and free it.
  ptr = reinterpret_cast<char*>(PartitionPageToPointer(page2)) + kPointerOffset;
  PartitionFree(ptr);
  // Trying to allocate at this time should cause us to cycle around to page2
  // and find the recently freed slot.
  char* newPtr = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  EXPECT_EQ(ptr, newPtr);
  EXPECT_EQ(page2, bucket->active_pages_head);
  EXPECT_EQ(page3, page2->next_page);

  // Work out a pointer into page1 and free it. This should pull the page
  // back into the list of available pages.
  ptr = reinterpret_cast<char*>(PartitionPageToPointer(page1)) + kPointerOffset;
  PartitionFree(ptr);
  // This allocation should be satisfied by page1.
  newPtr = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  EXPECT_EQ(ptr, newPtr);
  EXPECT_EQ(page1, bucket->active_pages_head);
  EXPECT_EQ(page2, page1->next_page);

  FreeFullPage(page3);
  FreeFullPage(page2);
  FreeFullPage(page1);

  // Allocating whilst in this state exposed a bug, so keep the test.
  ptr = reinterpret_cast<char*>(
      PartitionAlloc(allocator.root(), kTestAllocSize, type_name));
  PartitionFree(ptr);
}

// Test some corner cases relating to page transitions in the internal
// free page list metadata bucket.
TEST(PartitionAllocTest, FreePageListPageTransitions) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  size_t numToFillFreeListPage =
      kPartitionPageSize / (sizeof(PartitionPage) + kExtraAllocSize);
  // The +1 is because we need to account for the fact that the current page
  // never gets thrown on the freelist.
  ++numToFillFreeListPage;
  std::unique_ptr<PartitionPage* []> pages =
      WrapArrayUnique(new PartitionPage*[numToFillFreeListPage]);

  size_t i;
  for (i = 0; i < numToFillFreeListPage; ++i) {
    pages[i] = GetFullPage(kTestAllocSize);
  }
  EXPECT_EQ(pages[numToFillFreeListPage - 1], bucket->active_pages_head);
  for (i = 0; i < numToFillFreeListPage; ++i)
    FreeFullPage(pages[i]);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->active_pages_head);
  EXPECT_TRUE(bucket->empty_pages_head);

  // Allocate / free in a different bucket size so we get control of a
  // different free page list. We need two pages because one will be the last
  // active page and not get freed.
  PartitionPage* page1 = GetFullPage(kTestAllocSize * 2);
  PartitionPage* page2 = GetFullPage(kTestAllocSize * 2);
  FreeFullPage(page1);
  FreeFullPage(page2);

  for (i = 0; i < numToFillFreeListPage; ++i) {
    pages[i] = GetFullPage(kTestAllocSize);
  }
  EXPECT_EQ(pages[numToFillFreeListPage - 1], bucket->active_pages_head);

  for (i = 0; i < numToFillFreeListPage; ++i)
    FreeFullPage(pages[i]);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->active_pages_head);
  EXPECT_TRUE(bucket->empty_pages_head);
}

// Test a large series of allocations that cross more than one underlying
// 64KB super page allocation.
TEST(PartitionAllocTest, MultiPageAllocs) {
  TestSetup();
  // This is guaranteed to cross a super page boundary because the first
  // partition page "slot" will be taken up by a guard page.
  size_t numPagesNeeded = kNumPartitionPagesPerSuperPage;
  // The super page should begin and end in a guard so we one less page in
  // order to allocate a single page in the new super page.
  --numPagesNeeded;

  EXPECT_GT(numPagesNeeded, 1u);
  std::unique_ptr<PartitionPage* []> pages;
  pages = WrapArrayUnique(new PartitionPage*[numPagesNeeded]);
  uintptr_t firstSuperPageBase = 0;
  size_t i;
  for (i = 0; i < numPagesNeeded; ++i) {
    pages[i] = GetFullPage(kTestAllocSize);
    void* storagePtr = PartitionPageToPointer(pages[i]);
    if (!i)
      firstSuperPageBase =
          reinterpret_cast<uintptr_t>(storagePtr) & kSuperPageBaseMask;
    if (i == numPagesNeeded - 1) {
      uintptr_t secondSuperPageBase =
          reinterpret_cast<uintptr_t>(storagePtr) & kSuperPageBaseMask;
      uintptr_t secondSuperPageOffset =
          reinterpret_cast<uintptr_t>(storagePtr) & kSuperPageOffsetMask;
      EXPECT_FALSE(secondSuperPageBase == firstSuperPageBase);
      // Check that we allocated a guard page for the second page.
      EXPECT_EQ(kPartitionPageSize, secondSuperPageOffset);
    }
  }
  for (i = 0; i < numPagesNeeded; ++i)
    FreeFullPage(pages[i]);
}

// Test the generic allocation functions that can handle arbitrary sizes and
// reallocing etc.
TEST(PartitionAllocTest, GenericAlloc) {
  TestSetup();

  void* ptr = PartitionAllocGeneric(generic_allocator.root(), 1, type_name);
  EXPECT_TRUE(ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr);
  ptr = PartitionAllocGeneric(generic_allocator.root(), kGenericMaxBucketed + 1,
                              type_name);
  EXPECT_TRUE(ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  ptr = PartitionAllocGeneric(generic_allocator.root(), 1, type_name);
  EXPECT_TRUE(ptr);
  void* origPtr = ptr;
  char* charPtr = static_cast<char*>(ptr);
  *charPtr = 'A';

  // Change the size of the realloc, remaining inside the same bucket.
  void* newPtr =
      PartitionReallocGeneric(generic_allocator.root(), ptr, 2, type_name);
  EXPECT_EQ(ptr, newPtr);
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr, 1, type_name);
  EXPECT_EQ(ptr, newPtr);
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr,
                                   kGenericSmallestBucket, type_name);
  EXPECT_EQ(ptr, newPtr);

  // Change the size of the realloc, switching buckets.
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr,
                                   kGenericSmallestBucket + 1, type_name);
  EXPECT_NE(newPtr, ptr);
  // Check that the realloc copied correctly.
  char* newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'A');
#if DCHECK_IS_ON()
  // Subtle: this checks for an old bug where we copied too much from the
  // source of the realloc. The condition can be detected by a trashing of
  // the uninitialized value in the space of the upsized allocation.
  EXPECT_EQ(kUninitializedByte,
            static_cast<unsigned char>(*(newCharPtr + kGenericSmallestBucket)));
#endif
  *newCharPtr = 'B';
  // The realloc moved. To check that the old allocation was freed, we can
  // do an alloc of the old allocation size and check that the old allocation
  // address is at the head of the freelist and reused.
  void* reusedPtr =
      PartitionAllocGeneric(generic_allocator.root(), 1, type_name);
  EXPECT_EQ(reusedPtr, origPtr);
  PartitionFreeGeneric(generic_allocator.root(), reusedPtr);

  // Downsize the realloc.
  ptr = newPtr;
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr, 1, type_name);
  EXPECT_EQ(newPtr, origPtr);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'B');
  *newCharPtr = 'C';

  // Upsize the realloc to outside the partition.
  ptr = newPtr;
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr,
                                   kGenericMaxBucketed + 1, type_name);
  EXPECT_NE(newPtr, ptr);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'C');
  *newCharPtr = 'D';

  // Upsize and downsize the realloc, remaining outside the partition.
  ptr = newPtr;
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr,
                                   kGenericMaxBucketed * 10, type_name);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'D');
  *newCharPtr = 'E';
  ptr = newPtr;
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr,
                                   kGenericMaxBucketed * 2, type_name);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'E');
  *newCharPtr = 'F';

  // Downsize the realloc to inside the partition.
  ptr = newPtr;
  newPtr = PartitionReallocGeneric(generic_allocator.root(), ptr, 1, type_name);
  EXPECT_NE(newPtr, ptr);
  EXPECT_EQ(newPtr, origPtr);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'F');

  PartitionFreeGeneric(generic_allocator.root(), newPtr);
}

// Test the generic allocation functions can handle some specific sizes of
// interest.
TEST(PartitionAllocTest, GenericAllocSizes) {
  TestSetup();

  void* ptr = PartitionAllocGeneric(generic_allocator.root(), 0, type_name);
  EXPECT_TRUE(ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // kPartitionPageSize is interesting because it results in just one
  // allocation per page, which tripped up some corner cases.
  size_t size = kPartitionPageSize - kExtraAllocSize;
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr);
  void* ptr2 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr2);
  PartitionFreeGeneric(generic_allocator.root(), ptr);
  // Should be freeable at this point.
  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_NE(-1, page->empty_cache_index);
  PartitionFreeGeneric(generic_allocator.root(), ptr2);

  size = (((kPartitionPageSize * kMaxPartitionPagesPerSlotSpan) -
           kSystemPageSize) /
          2) -
         kExtraAllocSize;
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr);
  memset(ptr, 'A', size);
  ptr2 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr2);
  void* ptr3 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr3);
  void* ptr4 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr4);

  page = PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  PartitionPage* page2 =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr3));
  EXPECT_NE(page, page2);

  PartitionFreeGeneric(generic_allocator.root(), ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr3);
  PartitionFreeGeneric(generic_allocator.root(), ptr2);
  // Should be freeable at this point.
  EXPECT_NE(-1, page->empty_cache_index);
  EXPECT_EQ(0, page->num_allocated_slots);
  EXPECT_EQ(0, page->num_unprovisioned_slots);
  void* newPtr =
      PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_EQ(ptr3, newPtr);
  newPtr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_EQ(ptr2, newPtr);
#if defined(OS_LINUX) && !DCHECK_IS_ON()
  // On Linux, we have a guarantee that freelisting a page should cause its
  // contents to be nulled out. We check for null here to detect an bug we
  // had where a large slot size was causing us to not properly free all
  // resources back to the system.
  // We only run the check when asserts are disabled because when they are
  // enabled, the allocated area is overwritten with an "uninitialized"
  // byte pattern.
  EXPECT_EQ(0, *(reinterpret_cast<char*>(newPtr) + (size - 1)));
#endif
  PartitionFreeGeneric(generic_allocator.root(), newPtr);
  PartitionFreeGeneric(generic_allocator.root(), ptr3);
  PartitionFreeGeneric(generic_allocator.root(), ptr4);

  // Can we allocate a massive (512MB) size?
  // Allocate 512MB, but +1, to test for cookie writing alignment issues.
  // Test this only if the device has enough memory or it might fail due
  // to OOM.
  if (IsLargeMemoryDevice()) {
    ptr = PartitionAllocGeneric(generic_allocator.root(), 512 * 1024 * 1024 + 1,
                                type_name);
    PartitionFreeGeneric(generic_allocator.root(), ptr);
  }

  // Check a more reasonable, but still direct mapped, size.
  // Chop a system page and a byte off to test for rounding errors.
  size = 20 * 1024 * 1024;
  size -= kSystemPageSize;
  size -= 1;
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  char* charPtr = reinterpret_cast<char*>(ptr);
  *(charPtr + (size - 1)) = 'A';
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // Can we free null?
  PartitionFreeGeneric(generic_allocator.root(), 0);

  // Do we correctly get a null for a failed allocation?
  EXPECT_EQ(0, PartitionAllocGenericFlags(generic_allocator.root(),
                                          PartitionAllocReturnNull,
                                          3u * 1024 * 1024 * 1024, type_name));
}

// Test that we can fetch the real allocated size after an allocation.
TEST(PartitionAllocTest, GenericAllocGetSize) {
  TestSetup();

  void* ptr;
  size_t requestedSize, actualSize, predictedSize;

  EXPECT_TRUE(PartitionAllocSupportsGetSize());

  // Allocate something small.
  requestedSize = 511 - kExtraAllocSize;
  predictedSize =
      PartitionAllocActualSize(generic_allocator.root(), requestedSize);
  ptr =
      PartitionAllocGeneric(generic_allocator.root(), requestedSize, type_name);
  EXPECT_TRUE(ptr);
  actualSize = PartitionAllocGetSize(ptr);
  EXPECT_EQ(predictedSize, actualSize);
  EXPECT_LT(requestedSize, actualSize);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // Allocate a size that should be a perfect match for a bucket, because it
  // is an exact power of 2.
  requestedSize = (256 * 1024) - kExtraAllocSize;
  predictedSize =
      PartitionAllocActualSize(generic_allocator.root(), requestedSize);
  ptr =
      PartitionAllocGeneric(generic_allocator.root(), requestedSize, type_name);
  EXPECT_TRUE(ptr);
  actualSize = PartitionAllocGetSize(ptr);
  EXPECT_EQ(predictedSize, actualSize);
  EXPECT_EQ(requestedSize, actualSize);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // Allocate a size that is a system page smaller than a bucket. GetSize()
  // should return a larger size than we asked for now.
  requestedSize = (256 * 1024) - kSystemPageSize - kExtraAllocSize;
  predictedSize =
      PartitionAllocActualSize(generic_allocator.root(), requestedSize);
  ptr =
      PartitionAllocGeneric(generic_allocator.root(), requestedSize, type_name);
  EXPECT_TRUE(ptr);
  actualSize = PartitionAllocGetSize(ptr);
  EXPECT_EQ(predictedSize, actualSize);
  EXPECT_EQ(requestedSize + kSystemPageSize, actualSize);
  // Check that we can write at the end of the reported size too.
  char* charPtr = reinterpret_cast<char*>(ptr);
  *(charPtr + (actualSize - 1)) = 'A';
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // Allocate something very large, and uneven.
  if (IsLargeMemoryDevice()) {
    requestedSize = 512 * 1024 * 1024 - 1;
    predictedSize =
        PartitionAllocActualSize(generic_allocator.root(), requestedSize);
    ptr = PartitionAllocGeneric(generic_allocator.root(), requestedSize,
                                type_name);
    EXPECT_TRUE(ptr);
    actualSize = PartitionAllocGetSize(ptr);
    EXPECT_EQ(predictedSize, actualSize);
    EXPECT_LT(requestedSize, actualSize);
    PartitionFreeGeneric(generic_allocator.root(), ptr);
  }

  // Too large allocation.
  requestedSize = INT_MAX;
  predictedSize =
      PartitionAllocActualSize(generic_allocator.root(), requestedSize);
  EXPECT_EQ(requestedSize, predictedSize);
}

// Test the realloc() contract.
TEST(PartitionAllocTest, Realloc) {
  TestSetup();

  // realloc(0, size) should be equivalent to malloc().
  void* ptr = PartitionReallocGeneric(generic_allocator.root(), 0,
                                      kTestAllocSize, type_name);
  memset(ptr, 'A', kTestAllocSize);
  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  // realloc(ptr, 0) should be equivalent to free().
  void* ptr2 =
      PartitionReallocGeneric(generic_allocator.root(), ptr, 0, type_name);
  EXPECT_EQ(0, ptr2);
  EXPECT_EQ(PartitionCookieFreePointerAdjust(ptr), page->freelist_head);

  // Test that growing an allocation with realloc() copies everything from the
  // old allocation.
  size_t size = kSystemPageSize - kExtraAllocSize;
  EXPECT_EQ(size, PartitionAllocActualSize(generic_allocator.root(), size));
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  memset(ptr, 'A', size);
  ptr2 = PartitionReallocGeneric(generic_allocator.root(), ptr, size + 1,
                                 type_name);
  EXPECT_NE(ptr, ptr2);
  char* charPtr2 = static_cast<char*>(ptr2);
  EXPECT_EQ('A', charPtr2[0]);
  EXPECT_EQ('A', charPtr2[size - 1]);
#if DCHECK_IS_ON()
  EXPECT_EQ(kUninitializedByte, static_cast<unsigned char>(charPtr2[size]));
#endif

  // Test that shrinking an allocation with realloc() also copies everything
  // from the old allocation.
  ptr = PartitionReallocGeneric(generic_allocator.root(), ptr2, size - 1,
                                type_name);
  EXPECT_NE(ptr2, ptr);
  char* charPtr = static_cast<char*>(ptr);
  EXPECT_EQ('A', charPtr[0]);
  EXPECT_EQ('A', charPtr[size - 2]);
#if DCHECK_IS_ON()
  EXPECT_EQ(kUninitializedByte, static_cast<unsigned char>(charPtr[size - 1]));
#endif

  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // Test that shrinking a direct mapped allocation happens in-place.
  size = kGenericMaxBucketed + 16 * kSystemPageSize;
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  size_t actualSize = PartitionAllocGetSize(ptr);
  ptr2 = PartitionReallocGeneric(generic_allocator.root(), ptr,
                                 kGenericMaxBucketed + 8 * kSystemPageSize,
                                 type_name);
  EXPECT_EQ(ptr, ptr2);
  EXPECT_EQ(actualSize - 8 * kSystemPageSize, PartitionAllocGetSize(ptr2));

  // Test that a previously in-place shrunk direct mapped allocation can be
  // expanded up again within its original size.
  ptr = PartitionReallocGeneric(generic_allocator.root(), ptr2,
                                size - kSystemPageSize, type_name);
  EXPECT_EQ(ptr2, ptr);
  EXPECT_EQ(actualSize - kSystemPageSize, PartitionAllocGetSize(ptr));

  // Test that a direct mapped allocation is performed not in-place when the
  // new size is small enough.
  ptr2 = PartitionReallocGeneric(generic_allocator.root(), ptr, kSystemPageSize,
                                 type_name);
  EXPECT_NE(ptr, ptr2);

  PartitionFreeGeneric(generic_allocator.root(), ptr2);
}

// Tests the handing out of freelists for partial pages.
TEST(PartitionAllocTest, PartialPageFreelists) {
  TestSetup();

  size_t big_size = allocator.root()->max_allocation - kExtraAllocSize;
  EXPECT_EQ(kSystemPageSize - kAllocationGranularity,
            big_size + kExtraAllocSize);
  size_t bucket_index = (big_size + kExtraAllocSize) >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucket_index];
  EXPECT_EQ(0, bucket->empty_pages_head);

  void* ptr = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_TRUE(ptr);

  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  size_t totalSlots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) /
      (big_size + kExtraAllocSize);
  EXPECT_EQ(4u, totalSlots);
  // The freelist should have one entry, because we were able to exactly fit
  // one object slot and one freelist pointer (the null that the head points
  // to) into a system page.
  EXPECT_TRUE(page->freelist_head);
  EXPECT_EQ(1, page->num_allocated_slots);
  EXPECT_EQ(2, page->num_unprovisioned_slots);

  void* ptr2 = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_TRUE(ptr2);
  EXPECT_FALSE(page->freelist_head);
  EXPECT_EQ(2, page->num_allocated_slots);
  EXPECT_EQ(2, page->num_unprovisioned_slots);

  void* ptr3 = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_TRUE(ptr3);
  EXPECT_TRUE(page->freelist_head);
  EXPECT_EQ(3, page->num_allocated_slots);
  EXPECT_EQ(0, page->num_unprovisioned_slots);

  void* ptr4 = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_TRUE(ptr4);
  EXPECT_FALSE(page->freelist_head);
  EXPECT_EQ(4, page->num_allocated_slots);
  EXPECT_EQ(0, page->num_unprovisioned_slots);

  void* ptr5 = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_TRUE(ptr5);

  PartitionPage* page2 =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr5));
  EXPECT_EQ(1, page2->num_allocated_slots);

  // Churn things a little whilst there's a partial page freelist.
  PartitionFree(ptr);
  ptr = PartitionAlloc(allocator.root(), big_size, type_name);
  void* ptr6 = PartitionAlloc(allocator.root(), big_size, type_name);

  PartitionFree(ptr);
  PartitionFree(ptr2);
  PartitionFree(ptr3);
  PartitionFree(ptr4);
  PartitionFree(ptr5);
  PartitionFree(ptr6);
  EXPECT_NE(-1, page->empty_cache_index);
  EXPECT_NE(-1, page2->empty_cache_index);
  EXPECT_TRUE(page2->freelist_head);
  EXPECT_EQ(0, page2->num_allocated_slots);

  // And test a couple of sizes that do not cross kSystemPageSize with a single
  // allocation.
  size_t mediumSize = (kSystemPageSize / 2) - kExtraAllocSize;
  bucket_index = (mediumSize + kExtraAllocSize) >> kBucketShift;
  bucket = &allocator.root()->buckets()[bucket_index];
  EXPECT_EQ(0, bucket->empty_pages_head);

  ptr = PartitionAlloc(allocator.root(), mediumSize, type_name);
  EXPECT_TRUE(ptr);
  page = PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->num_allocated_slots);
  totalSlots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) /
      (mediumSize + kExtraAllocSize);
  size_t firstPageSlots = kSystemPageSize / (mediumSize + kExtraAllocSize);
  EXPECT_EQ(2u, firstPageSlots);
  EXPECT_EQ(totalSlots - firstPageSlots, page->num_unprovisioned_slots);

  PartitionFree(ptr);

  size_t smallSize = (kSystemPageSize / 4) - kExtraAllocSize;
  bucket_index = (smallSize + kExtraAllocSize) >> kBucketShift;
  bucket = &allocator.root()->buckets()[bucket_index];
  EXPECT_EQ(0, bucket->empty_pages_head);

  ptr = PartitionAlloc(allocator.root(), smallSize, type_name);
  EXPECT_TRUE(ptr);
  page = PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->num_allocated_slots);
  totalSlots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) /
      (smallSize + kExtraAllocSize);
  firstPageSlots = kSystemPageSize / (smallSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - firstPageSlots, page->num_unprovisioned_slots);

  PartitionFree(ptr);
  EXPECT_TRUE(page->freelist_head);
  EXPECT_EQ(0, page->num_allocated_slots);

  size_t verySmallSize = 32 - kExtraAllocSize;
  bucket_index = (verySmallSize + kExtraAllocSize) >> kBucketShift;
  bucket = &allocator.root()->buckets()[bucket_index];
  EXPECT_EQ(0, bucket->empty_pages_head);

  ptr = PartitionAlloc(allocator.root(), verySmallSize, type_name);
  EXPECT_TRUE(ptr);
  page = PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->num_allocated_slots);
  totalSlots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) /
      (verySmallSize + kExtraAllocSize);
  firstPageSlots = kSystemPageSize / (verySmallSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - firstPageSlots, page->num_unprovisioned_slots);

  PartitionFree(ptr);
  EXPECT_TRUE(page->freelist_head);
  EXPECT_EQ(0, page->num_allocated_slots);

  // And try an allocation size (against the generic allocator) that is
  // larger than a system page.
  size_t pageAndAHalfSize =
      (kSystemPageSize + (kSystemPageSize / 2)) - kExtraAllocSize;
  ptr = PartitionAllocGeneric(generic_allocator.root(), pageAndAHalfSize,
                              type_name);
  EXPECT_TRUE(ptr);
  page = PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->num_allocated_slots);
  EXPECT_TRUE(page->freelist_head);
  totalSlots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) /
      (pageAndAHalfSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - 2, page->num_unprovisioned_slots);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  // And then make sure than exactly the page size only faults one page.
  size_t pageSize = kSystemPageSize - kExtraAllocSize;
  ptr = PartitionAllocGeneric(generic_allocator.root(), pageSize, type_name);
  EXPECT_TRUE(ptr);
  page = PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->num_allocated_slots);
  EXPECT_FALSE(page->freelist_head);
  totalSlots =
      (page->bucket->num_system_pages_per_slot_span * kSystemPageSize) /
      (pageSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - 1, page->num_unprovisioned_slots);
  PartitionFreeGeneric(generic_allocator.root(), ptr);
}

// Test some of the fragmentation-resistant properties of the allocator.
TEST(PartitionAllocTest, PageRefilling) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  // Grab two full pages and a non-full page.
  PartitionPage* page1 = GetFullPage(kTestAllocSize);
  PartitionPage* page2 = GetFullPage(kTestAllocSize);
  void* ptr = PartitionAlloc(allocator.root(), kTestAllocSize, type_name);
  EXPECT_TRUE(ptr);
  EXPECT_NE(page1, bucket->active_pages_head);
  EXPECT_NE(page2, bucket->active_pages_head);
  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->num_allocated_slots);

  // Work out a pointer into page2 and free it; and then page1 and free it.
  char* ptr2 =
      reinterpret_cast<char*>(PartitionPageToPointer(page1)) + kPointerOffset;
  PartitionFree(ptr2);
  ptr2 =
      reinterpret_cast<char*>(PartitionPageToPointer(page2)) + kPointerOffset;
  PartitionFree(ptr2);

  // If we perform two allocations from the same bucket now, we expect to
  // refill both the nearly full pages.
  (void)PartitionAlloc(allocator.root(), kTestAllocSize, type_name);
  (void)PartitionAlloc(allocator.root(), kTestAllocSize, type_name);
  EXPECT_EQ(1, page->num_allocated_slots);

  FreeFullPage(page2);
  FreeFullPage(page1);
  PartitionFree(ptr);
}

// Basic tests to ensure that allocations work for partial page buckets.
TEST(PartitionAllocTest, PartialPages) {
  TestSetup();

  // Find a size that is backed by a partial partition page.
  size_t size = sizeof(void*);
  PartitionBucket* bucket = 0;
  while (size < kTestMaxAllocation) {
    bucket = &allocator.root()->buckets()[size >> kBucketShift];
    if (bucket->num_system_pages_per_slot_span %
        kNumSystemPagesPerPartitionPage)
      break;
    size += sizeof(void*);
  }
  EXPECT_LT(size, kTestMaxAllocation);

  PartitionPage* page1 = GetFullPage(size);
  PartitionPage* page2 = GetFullPage(size);
  FreeFullPage(page2);
  FreeFullPage(page1);
}

// Test correct handling if our mapping collides with another.
TEST(PartitionAllocTest, MappingCollision) {
  TestSetup();
  // The -2 is because the first and last partition pages in a super page are
  // guard pages.
  size_t numPartitionPagesNeeded = kNumPartitionPagesPerSuperPage - 2;
  std::unique_ptr<PartitionPage* []> firstSuperPagePages =
      WrapArrayUnique(new PartitionPage*[numPartitionPagesNeeded]);
  std::unique_ptr<PartitionPage* []> secondSuperPagePages =
      WrapArrayUnique(new PartitionPage*[numPartitionPagesNeeded]);

  size_t i;
  for (i = 0; i < numPartitionPagesNeeded; ++i)
    firstSuperPagePages[i] = GetFullPage(kTestAllocSize);

  char* pageBase =
      reinterpret_cast<char*>(PartitionPageToPointer(firstSuperPagePages[0]));
  EXPECT_EQ(kPartitionPageSize,
            reinterpret_cast<uintptr_t>(pageBase) & kSuperPageOffsetMask);
  pageBase -= kPartitionPageSize;
  // Map a single system page either side of the mapping for our allocations,
  // with the goal of tripping up alignment of the next mapping.
  void* map1 = AllocPages(pageBase - kPageAllocationGranularity,
                          kPageAllocationGranularity,
                          kPageAllocationGranularity, PageInaccessible);
  EXPECT_TRUE(map1);
  void* map2 = AllocPages(pageBase + kSuperPageSize, kPageAllocationGranularity,
                          kPageAllocationGranularity, PageInaccessible);
  EXPECT_TRUE(map2);

  for (i = 0; i < numPartitionPagesNeeded; ++i)
    secondSuperPagePages[i] = GetFullPage(kTestAllocSize);

  FreePages(map1, kPageAllocationGranularity);
  FreePages(map2, kPageAllocationGranularity);

  pageBase =
      reinterpret_cast<char*>(PartitionPageToPointer(secondSuperPagePages[0]));
  EXPECT_EQ(kPartitionPageSize,
            reinterpret_cast<uintptr_t>(pageBase) & kSuperPageOffsetMask);
  pageBase -= kPartitionPageSize;
  // Map a single system page either side of the mapping for our allocations,
  // with the goal of tripping up alignment of the next mapping.
  map1 = AllocPages(pageBase - kPageAllocationGranularity,
                    kPageAllocationGranularity, kPageAllocationGranularity,
                    PageAccessible);
  EXPECT_TRUE(map1);
  map2 = AllocPages(pageBase + kSuperPageSize, kPageAllocationGranularity,
                    kPageAllocationGranularity, PageAccessible);
  EXPECT_TRUE(map2);
  SetSystemPagesInaccessible(map1, kPageAllocationGranularity);
  SetSystemPagesInaccessible(map2, kPageAllocationGranularity);

  PartitionPage* pageInThirdSuperPage = GetFullPage(kTestAllocSize);
  FreePages(map1, kPageAllocationGranularity);
  FreePages(map2, kPageAllocationGranularity);

  EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(
                    PartitionPageToPointer(pageInThirdSuperPage)) &
                    kPartitionPageOffsetMask);

  // And make sure we really did get a page in a new superpage.
  EXPECT_NE(reinterpret_cast<uintptr_t>(
                PartitionPageToPointer(firstSuperPagePages[0])) &
                kSuperPageBaseMask,
            reinterpret_cast<uintptr_t>(
                PartitionPageToPointer(pageInThirdSuperPage)) &
                kSuperPageBaseMask);
  EXPECT_NE(reinterpret_cast<uintptr_t>(
                PartitionPageToPointer(secondSuperPagePages[0])) &
                kSuperPageBaseMask,
            reinterpret_cast<uintptr_t>(
                PartitionPageToPointer(pageInThirdSuperPage)) &
                kSuperPageBaseMask);

  FreeFullPage(pageInThirdSuperPage);
  for (i = 0; i < numPartitionPagesNeeded; ++i) {
    FreeFullPage(firstSuperPagePages[i]);
    FreeFullPage(secondSuperPagePages[i]);
  }
}

// Tests that pages in the free page cache do get freed as appropriate.
TEST(PartitionAllocTest, FreeCache) {
  TestSetup();

  EXPECT_EQ(0U, allocator.root()->total_size_of_committed_pages);

  size_t big_size = allocator.root()->max_allocation - kExtraAllocSize;
  size_t bucket_index = (big_size + kExtraAllocSize) >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucket_index];

  void* ptr = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_TRUE(ptr);
  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(0, bucket->empty_pages_head);
  EXPECT_EQ(1, page->num_allocated_slots);
  EXPECT_EQ(kPartitionPageSize,
            allocator.root()->total_size_of_committed_pages);
  PartitionFree(ptr);
  EXPECT_EQ(0, page->num_allocated_slots);
  EXPECT_NE(-1, page->empty_cache_index);
  EXPECT_TRUE(page->freelist_head);

  CycleFreeCache(kTestAllocSize);

  // Flushing the cache should have really freed the unused page.
  EXPECT_FALSE(page->freelist_head);
  EXPECT_EQ(-1, page->empty_cache_index);
  EXPECT_EQ(0, page->num_allocated_slots);
  PartitionBucket* cycle_free_cache_bucket =
      &allocator.root()->buckets()[kTestBucketIndex];
  EXPECT_EQ(
      cycle_free_cache_bucket->num_system_pages_per_slot_span * kSystemPageSize,
      allocator.root()->total_size_of_committed_pages);

  // Check that an allocation works ok whilst in this state (a free'd page
  // as the active pages head).
  ptr = PartitionAlloc(allocator.root(), big_size, type_name);
  EXPECT_FALSE(bucket->empty_pages_head);
  PartitionFree(ptr);

  // Also check that a page that is bouncing immediately between empty and
  // used does not get freed.
  for (size_t i = 0; i < kMaxFreeableSpans * 2; ++i) {
    ptr = PartitionAlloc(allocator.root(), big_size, type_name);
    EXPECT_TRUE(page->freelist_head);
    PartitionFree(ptr);
    EXPECT_TRUE(page->freelist_head);
  }
  EXPECT_EQ(kPartitionPageSize,
            allocator.root()->total_size_of_committed_pages);
}

// Tests for a bug we had with losing references to free pages.
TEST(PartitionAllocTest, LostFreePagesBug) {
  TestSetup();

  size_t size = kPartitionPageSize - kExtraAllocSize;

  void* ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr);
  void* ptr2 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr2);

  PartitionPage* page =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr));
  PartitionPage* page2 =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr2));
  PartitionBucket* bucket = page->bucket;

  EXPECT_EQ(0, bucket->empty_pages_head);
  EXPECT_EQ(-1, page->num_allocated_slots);
  EXPECT_EQ(1, page2->num_allocated_slots);

  PartitionFreeGeneric(generic_allocator.root(), ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr2);

  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_TRUE(bucket->empty_pages_head->next_page);
  EXPECT_EQ(0, page->num_allocated_slots);
  EXPECT_EQ(0, page2->num_allocated_slots);
  EXPECT_TRUE(page->freelist_head);
  EXPECT_TRUE(page2->freelist_head);

  CycleGenericFreeCache(kTestAllocSize);

  EXPECT_FALSE(page->freelist_head);
  EXPECT_FALSE(page2->freelist_head);

  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_TRUE(bucket->empty_pages_head->next_page);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->active_pages_head);

  // At this moment, we have two decommitted pages, on the empty list.
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->active_pages_head);
  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_TRUE(bucket->decommitted_pages_head);

  CycleGenericFreeCache(kTestAllocSize);

  // We're now set up to trigger a historical bug by scanning over the active
  // pages list. The current code gets into a different state, but we'll keep
  // the test as being an interesting corner case.
  ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_TRUE(ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  EXPECT_TRUE(bucket->active_pages_head);
  EXPECT_TRUE(bucket->empty_pages_head);
  EXPECT_TRUE(bucket->decommitted_pages_head);
}

#if !defined(ARCH_CPU_64_BITS) || defined(OS_POSIX)

static void DoReturnNullTest(size_t allocSize) {
  // TODO(crbug.com/678782): Where necessary and possible, disable the
  // platform's OOM-killing behavior. OOM-killing makes this test flaky on
  // low-memory devices.
  if (!IsLargeMemoryDevice()) {
    LOG(WARNING) << "Skipping test on this device because of crbug.com/678782";
    return;
  }

  TestSetup();

  EXPECT_TRUE(SetAddressSpaceLimit());

  // Work out the number of allocations for 6 GB of memory.
  const int numAllocations = (6 * 1024 * 1024) / (allocSize / 1024);

  void** ptrs = reinterpret_cast<void**>(PartitionAllocGeneric(
      generic_allocator.root(), numAllocations * sizeof(void*), type_name));
  int i;

  for (i = 0; i < numAllocations; ++i) {
    ptrs[i] = PartitionAllocGenericFlags(generic_allocator.root(),
                                         PartitionAllocReturnNull, allocSize,
                                         type_name);
    if (!i)
      EXPECT_TRUE(ptrs[0]);
    if (!ptrs[i]) {
      ptrs[i] = PartitionAllocGenericFlags(generic_allocator.root(),
                                           PartitionAllocReturnNull, allocSize,
                                           type_name);
      EXPECT_FALSE(ptrs[i]);
      break;
    }
  }

  // We shouldn't succeed in allocating all 6 GB of memory. If we do, then
  // we're not actually testing anything here.
  EXPECT_LT(i, numAllocations);

  // Free, reallocate and free again each block we allocated. We do this to
  // check that freeing memory also works correctly after a failed allocation.
  for (--i; i >= 0; --i) {
    PartitionFreeGeneric(generic_allocator.root(), ptrs[i]);
    ptrs[i] = PartitionAllocGenericFlags(generic_allocator.root(),
                                         PartitionAllocReturnNull, allocSize,
                                         type_name);
    EXPECT_TRUE(ptrs[i]);
    PartitionFreeGeneric(generic_allocator.root(), ptrs[i]);
  }

  PartitionFreeGeneric(generic_allocator.root(), ptrs);

  EXPECT_TRUE(ClearAddressSpaceLimit());
}

// Unit tests that check if an allocation fails in "return null" mode,
// repeating it doesn't crash, and still returns null. The tests need to
// stress memory subsystem limits to do so, hence they try to allocate
// 6 GB of memory, each with a different per-allocation block sizes.
//
// On 64-bit POSIX systems, the address space is limited to 6 GB using
// setrlimit() first.

// Test "return null" for larger, direct-mapped allocations first. As a
// direct-mapped allocation's pages are unmapped and freed on release, this
// test is performd first for these "return null" tests in order to leave
// sufficient unreserved virtual memory around for the later one(s).

// Disable this test on Android because, due to its allocation-heavy behavior,
// it tends to get OOM-killed rather than pass.
#if defined(OS_MACOSX) || defined(OS_ANDROID)
#define MAYBE_RepeatedReturnNullDirect DISABLED_RepeatedReturnNullDirect
#else
#define MAYBE_RepeatedReturnNullDirect RepeatedReturnNullDirect
#endif
TEST(PartitionAllocTest, MAYBE_RepeatedReturnNullDirect) {
  // A direct-mapped allocation size.
  DoReturnNullTest(32 * 1024 * 1024);
}

// Test "return null" with a 512 kB block size.

// Disable this test on Android because, due to its allocation-heavy behavior,
// it tends to get OOM-killed rather than pass.
#if defined(OS_MACOSX) || defined(OS_ANDROID)
#define MAYBE_RepeatedReturnNull DISABLED_RepeatedReturnNull
#else
#define MAYBE_RepeatedReturnNull RepeatedReturnNull
#endif
TEST(PartitionAllocTest, MAYBE_RepeatedReturnNull) {
  // A single-slot but non-direct-mapped allocation size.
  DoReturnNullTest(512 * 1024);
}

#endif  // !defined(ARCH_CPU_64_BITS) || defined(OS_POSIX)

// Death tests misbehave on Android, http://crbug.com/643760.
#if defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

// Make sure that malloc(-1) dies.
// In the past, we had an integer overflow that would alias malloc(-1) to
// malloc(0), which is not good.
TEST(PartitionAllocDeathTest, LargeAllocs) {
  TestSetup();
  // Largest alloc.
  EXPECT_DEATH(PartitionAllocGeneric(generic_allocator.root(),
                                     static_cast<size_t>(-1), type_name),
               "");
  // And the smallest allocation we expect to die.
  EXPECT_DEATH(
      PartitionAllocGeneric(generic_allocator.root(),
                            static_cast<size_t>(INT_MAX) + 1, type_name),
      "");
}

// Check that our immediate double-free detection works.
TEST(PartitionAllocDeathTest, ImmediateDoubleFree) {
  TestSetup();

  void* ptr = PartitionAllocGeneric(generic_allocator.root(), kTestAllocSize,
                                    type_name);
  EXPECT_TRUE(ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr);

  EXPECT_DEATH(PartitionFreeGeneric(generic_allocator.root(), ptr), "");
}

// Check that our refcount-based double-free detection works.
TEST(PartitionAllocDeathTest, RefcountDoubleFree) {
  TestSetup();

  void* ptr = PartitionAllocGeneric(generic_allocator.root(), kTestAllocSize,
                                    type_name);
  EXPECT_TRUE(ptr);
  void* ptr2 = PartitionAllocGeneric(generic_allocator.root(), kTestAllocSize,
                                     type_name);
  EXPECT_TRUE(ptr2);
  PartitionFreeGeneric(generic_allocator.root(), ptr);
  PartitionFreeGeneric(generic_allocator.root(), ptr2);
  // This is not an immediate double-free so our immediate detection won't
  // fire. However, it does take the "refcount" of the partition page to -1,
  // which is illegal and should be trapped.
  EXPECT_DEATH(PartitionFreeGeneric(generic_allocator.root(), ptr), "");
}

// Check that guard pages are present where expected.
TEST(PartitionAllocDeathTest, GuardPages) {
  TestSetup();

// PartitionAlloc adds kPartitionPageSize to the requested size
// (for metadata), and then rounds that size to kPageAllocationGranularity.
// To be able to reliably write one past a direct allocation, choose a size
// that's
// a) larger than kGenericMaxBucketed (to make the allocation direct)
// b) aligned at kPageAllocationGranularity boundaries after
//    kPartitionPageSize has been added to it.
// (On 32-bit, PartitionAlloc adds another kSystemPageSize to the
// allocation size before rounding, but there it marks the memory right
// after size as inaccessible, so it's fine to write 1 past the size we
// hand to PartitionAlloc and we don't need to worry about allocation
// granularities.)
#define ALIGN(N, A) (((N) + (A)-1) / (A) * (A))
  const int kSize = ALIGN(kGenericMaxBucketed + 1 + kPartitionPageSize,
                          kPageAllocationGranularity) -
                    kPartitionPageSize;
#undef ALIGN
  static_assert(kSize > kGenericMaxBucketed,
                "allocation not large enough for direct allocation");
  size_t size = kSize - kExtraAllocSize;
  void* ptr = PartitionAllocGeneric(generic_allocator.root(), size, type_name);

  EXPECT_TRUE(ptr);
  char* charPtr = reinterpret_cast<char*>(ptr) - kPointerOffset;

  EXPECT_DEATH(*(charPtr - 1) = 'A', "");
  EXPECT_DEATH(*(charPtr + size + kExtraAllocSize) = 'A', "");

  PartitionFreeGeneric(generic_allocator.root(), ptr);
}

// Check that a bad free() is caught where the free() refers to an unused
// partition page of a large allocation.
TEST(PartitionAllocDeathTest, FreeWrongPartitionPage) {
  TestSetup();

  // This large size will result in a direct mapped allocation with guard
  // pages at either end.
  void* ptr = PartitionAllocGeneric(generic_allocator.root(),
                                    kPartitionPageSize * 2, type_name);
  EXPECT_TRUE(ptr);
  char* badPtr = reinterpret_cast<char*>(ptr) + kPartitionPageSize;

  EXPECT_DEATH(PartitionFreeGeneric(generic_allocator.root(), badPtr), "");

  PartitionFreeGeneric(generic_allocator.root(), ptr);
}

#endif  // !defined(OS_ANDROID) && !defined(OS_IOS)

// Tests that PartitionDumpStatsGeneric and PartitionDumpStats runs without
// crashing and returns non zero values when memory is allocated.
TEST(PartitionAllocTest, DumpMemoryStats) {
  TestSetup();
  {
    void* ptr = PartitionAlloc(allocator.root(), kTestAllocSize, type_name);
    MockPartitionStatsDumper mockStatsDumper;
    PartitionDumpStats(allocator.root(), "mock_allocator",
                       false /* detailed dump */, &mockStatsDumper);
    EXPECT_TRUE(mockStatsDumper.IsMemoryAllocationRecorded());

    PartitionFree(ptr);
  }

  // This series of tests checks the active -> empty -> decommitted states.
  {
    void* genericPtr = PartitionAllocGeneric(generic_allocator.root(),
                                             2048 - kExtraAllocSize, type_name);
    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats = dumper.GetBucketStats(2048);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(2048u, stats->bucket_slot_size);
      EXPECT_EQ(2048u, stats->active_bytes);
      EXPECT_EQ(kSystemPageSize, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(0u, stats->num_full_pages);
      EXPECT_EQ(1u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);
    }

    PartitionFreeGeneric(generic_allocator.root(), genericPtr);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_FALSE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats = dumper.GetBucketStats(2048);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(2048u, stats->bucket_slot_size);
      EXPECT_EQ(0u, stats->active_bytes);
      EXPECT_EQ(kSystemPageSize, stats->resident_bytes);
      EXPECT_EQ(kSystemPageSize, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(0u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(1u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);
    }

    CycleGenericFreeCache(kTestAllocSize);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_FALSE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats = dumper.GetBucketStats(2048);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(2048u, stats->bucket_slot_size);
      EXPECT_EQ(0u, stats->active_bytes);
      EXPECT_EQ(0u, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(0u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(1u, stats->num_decommitted_pages);
    }
  }

  // This test checks for correct empty page list accounting.
  {
    size_t size = kPartitionPageSize - kExtraAllocSize;
    void* ptr1 =
        PartitionAllocGeneric(generic_allocator.root(), size, type_name);
    void* ptr2 =
        PartitionAllocGeneric(generic_allocator.root(), size, type_name);
    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    PartitionFreeGeneric(generic_allocator.root(), ptr2);

    CycleGenericFreeCache(kTestAllocSize);

    ptr1 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(kPartitionPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(kPartitionPageSize, stats->bucket_slot_size);
      EXPECT_EQ(kPartitionPageSize, stats->active_bytes);
      EXPECT_EQ(kPartitionPageSize, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(1u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(1u, stats->num_decommitted_pages);
    }
    PartitionFreeGeneric(generic_allocator.root(), ptr1);
  }

  // This test checks for correct direct mapped accounting.
  {
    size_t size_smaller = kGenericMaxBucketed + 1;
    size_t size_bigger = (kGenericMaxBucketed * 2) + 1;
    size_t real_size_smaller =
        (size_smaller + kSystemPageOffsetMask) & kSystemPageBaseMask;
    size_t real_size_bigger =
        (size_bigger + kSystemPageOffsetMask) & kSystemPageBaseMask;
    void* ptr = PartitionAllocGeneric(generic_allocator.root(), size_smaller,
                                      type_name);
    void* ptr2 =
        PartitionAllocGeneric(generic_allocator.root(), size_bigger, type_name);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(real_size_smaller);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_TRUE(stats->is_direct_map);
      EXPECT_EQ(real_size_smaller, stats->bucket_slot_size);
      EXPECT_EQ(real_size_smaller, stats->active_bytes);
      EXPECT_EQ(real_size_smaller, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(1u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);

      stats = dumper.GetBucketStats(real_size_bigger);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_TRUE(stats->is_direct_map);
      EXPECT_EQ(real_size_bigger, stats->bucket_slot_size);
      EXPECT_EQ(real_size_bigger, stats->active_bytes);
      EXPECT_EQ(real_size_bigger, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(1u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);
    }

    PartitionFreeGeneric(generic_allocator.root(), ptr2);
    PartitionFreeGeneric(generic_allocator.root(), ptr);

    // Whilst we're here, allocate again and free with different ordering
    // to give a workout to our linked list code.
    ptr = PartitionAllocGeneric(generic_allocator.root(), size_smaller,
                                type_name);
    ptr2 =
        PartitionAllocGeneric(generic_allocator.root(), size_bigger, type_name);
    PartitionFreeGeneric(generic_allocator.root(), ptr);
    PartitionFreeGeneric(generic_allocator.root(), ptr2);
  }

  // This test checks large-but-not-quite-direct allocations.
  {
    void* ptr =
        PartitionAllocGeneric(generic_allocator.root(), 65536 + 1, type_name);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      size_t slot_size = 65536 + (65536 / kGenericNumBucketsPerOrder);
      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(slot_size);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_FALSE(stats->is_direct_map);
      EXPECT_EQ(slot_size, stats->bucket_slot_size);
      EXPECT_EQ(65536u + 1 + kExtraAllocSize, stats->active_bytes);
      EXPECT_EQ(slot_size, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(1u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);
    }

    PartitionFreeGeneric(generic_allocator.root(), ptr);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_FALSE(dumper.IsMemoryAllocationRecorded());

      size_t slot_size = 65536 + (65536 / kGenericNumBucketsPerOrder);
      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(slot_size);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_FALSE(stats->is_direct_map);
      EXPECT_EQ(slot_size, stats->bucket_slot_size);
      EXPECT_EQ(0u, stats->active_bytes);
      EXPECT_EQ(slot_size, stats->resident_bytes);
      EXPECT_EQ(slot_size, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(1u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);
    }

    void* ptr2 = PartitionAllocGeneric(generic_allocator.root(),
                                       65536 + kSystemPageSize + 1, type_name);
    EXPECT_EQ(ptr, ptr2);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      size_t slot_size = 65536 + (65536 / kGenericNumBucketsPerOrder);
      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(slot_size);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_FALSE(stats->is_direct_map);
      EXPECT_EQ(slot_size, stats->bucket_slot_size);
      EXPECT_EQ(65536u + kSystemPageSize + 1 + kExtraAllocSize,
                stats->active_bytes);
      EXPECT_EQ(slot_size, stats->resident_bytes);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(0u, stats->discardable_bytes);
      EXPECT_EQ(1u, stats->num_full_pages);
      EXPECT_EQ(0u, stats->num_active_pages);
      EXPECT_EQ(0u, stats->num_empty_pages);
      EXPECT_EQ(0u, stats->num_decommitted_pages);
    }

    PartitionFreeGeneric(generic_allocator.root(), ptr2);
  }
}

// Tests the API to purge freeable memory.
TEST(PartitionAllocTest, Purge) {
  TestSetup();

  char* ptr = reinterpret_cast<char*>(PartitionAllocGeneric(
      generic_allocator.root(), 2048 - kExtraAllocSize, type_name));
  PartitionFreeGeneric(generic_allocator.root(), ptr);
  {
    MockPartitionStatsDumper dumper;
    PartitionDumpStatsGeneric(generic_allocator.root(),
                              "mock_generic_allocator",
                              false /* detailed dump */, &dumper);
    EXPECT_FALSE(dumper.IsMemoryAllocationRecorded());

    const PartitionBucketMemoryStats* stats = dumper.GetBucketStats(2048);
    EXPECT_TRUE(stats);
    EXPECT_TRUE(stats->is_valid);
    EXPECT_EQ(kSystemPageSize, stats->decommittable_bytes);
    EXPECT_EQ(kSystemPageSize, stats->resident_bytes);
  }
  PartitionPurgeMemoryGeneric(generic_allocator.root(),
                              PartitionPurgeDecommitEmptyPages);
  {
    MockPartitionStatsDumper dumper;
    PartitionDumpStatsGeneric(generic_allocator.root(),
                              "mock_generic_allocator",
                              false /* detailed dump */, &dumper);
    EXPECT_FALSE(dumper.IsMemoryAllocationRecorded());

    const PartitionBucketMemoryStats* stats = dumper.GetBucketStats(2048);
    EXPECT_TRUE(stats);
    EXPECT_TRUE(stats->is_valid);
    EXPECT_EQ(0u, stats->decommittable_bytes);
    EXPECT_EQ(0u, stats->resident_bytes);
  }
  // Calling purge again here is a good way of testing we didn't mess up the
  // state of the free cache ring.
  PartitionPurgeMemoryGeneric(generic_allocator.root(),
                              PartitionPurgeDecommitEmptyPages);

  char* bigPtr = reinterpret_cast<char*>(
      PartitionAllocGeneric(generic_allocator.root(), 256 * 1024, type_name));
  PartitionFreeGeneric(generic_allocator.root(), bigPtr);
  PartitionPurgeMemoryGeneric(generic_allocator.root(),
                              PartitionPurgeDecommitEmptyPages);

  CheckPageInCore(ptr - kPointerOffset, false);
  CheckPageInCore(bigPtr - kPointerOffset, false);
}

// Tests that we prefer to allocate into a non-empty partition page over an
// empty one. This is an important aspect of minimizing memory usage for some
// allocation sizes, particularly larger ones.
TEST(PartitionAllocTest, PreferActiveOverEmpty) {
  TestSetup();

  size_t size = (kSystemPageSize * 2) - kExtraAllocSize;
  // Allocate 3 full slot spans worth of 8192-byte allocations.
  // Each slot span for this size is 16384 bytes, or 1 partition page and 2
  // slots.
  void* ptr1 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  void* ptr2 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  void* ptr3 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  void* ptr4 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  void* ptr5 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  void* ptr6 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);

  PartitionPage* page1 =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr1));
  PartitionPage* page2 =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr3));
  PartitionPage* page3 =
      PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr6));
  EXPECT_NE(page1, page2);
  EXPECT_NE(page2, page3);
  PartitionBucket* bucket = page1->bucket;
  EXPECT_EQ(page3, bucket->active_pages_head);

  // Free up the 2nd slot in each slot span.
  // This leaves the active list containing 3 pages, each with 1 used and 1
  // free slot. The active page will be the one containing ptr1.
  PartitionFreeGeneric(generic_allocator.root(), ptr6);
  PartitionFreeGeneric(generic_allocator.root(), ptr4);
  PartitionFreeGeneric(generic_allocator.root(), ptr2);
  EXPECT_EQ(page1, bucket->active_pages_head);

  // Empty the middle page in the active list.
  PartitionFreeGeneric(generic_allocator.root(), ptr3);
  EXPECT_EQ(page1, bucket->active_pages_head);

  // Empty the the first page in the active list -- also the current page.
  PartitionFreeGeneric(generic_allocator.root(), ptr1);

  // A good choice here is to re-fill the third page since the first two are
  // empty. We used to fail that.
  void* ptr7 = PartitionAllocGeneric(generic_allocator.root(), size, type_name);
  EXPECT_EQ(ptr6, ptr7);
  EXPECT_EQ(page3, bucket->active_pages_head);

  PartitionFreeGeneric(generic_allocator.root(), ptr5);
  PartitionFreeGeneric(generic_allocator.root(), ptr7);
}

// Tests the API to purge discardable memory.
TEST(PartitionAllocTest, PurgeDiscardable) {
  TestSetup();

  // Free the second of two 4096 byte allocations and then purge.
  {
    void* ptr1 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    char* ptr2 = reinterpret_cast<char*>(
        PartitionAllocGeneric(generic_allocator.root(),
                              kSystemPageSize - kExtraAllocSize, type_name));
    PartitionFreeGeneric(generic_allocator.root(), ptr2);
    PartitionPage* page =
        PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr1));
    EXPECT_EQ(2u, page->num_unprovisioned_slots);
    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(kSystemPageSize, stats->active_bytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->resident_bytes);
    }
    CheckPageInCore(ptr2 - kPointerOffset, true);
    PartitionPurgeMemoryGeneric(generic_allocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr2 - kPointerOffset, false);
    EXPECT_EQ(3u, page->num_unprovisioned_slots);

    PartitionFreeGeneric(generic_allocator.root(), ptr1);
  }
  // Free the first of two 4096 byte allocations and then purge.
  {
    char* ptr1 = reinterpret_cast<char*>(
        PartitionAllocGeneric(generic_allocator.root(),
                              kSystemPageSize - kExtraAllocSize, type_name));
    void* ptr2 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(kSystemPageSize, stats->active_bytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->resident_bytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    PartitionPurgeMemoryGeneric(generic_allocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr1 - kPointerOffset, false);

    PartitionFreeGeneric(generic_allocator.root(), ptr2);
  }
  {
    char* ptr1 = reinterpret_cast<char*>(PartitionAllocGeneric(
        generic_allocator.root(), 9216 - kExtraAllocSize, type_name));
    void* ptr2 = PartitionAllocGeneric(generic_allocator.root(),
                                       9216 - kExtraAllocSize, type_name);
    void* ptr3 = PartitionAllocGeneric(generic_allocator.root(),
                                       9216 - kExtraAllocSize, type_name);
    void* ptr4 = PartitionAllocGeneric(generic_allocator.root(),
                                       9216 - kExtraAllocSize, type_name);
    memset(ptr1, 'A', 9216 - kExtraAllocSize);
    memset(ptr2, 'A', 9216 - kExtraAllocSize);
    PartitionFreeGeneric(generic_allocator.root(), ptr2);
    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats = dumper.GetBucketStats(9216);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(9216u * 2, stats->active_bytes);
      EXPECT_EQ(9 * kSystemPageSize, stats->resident_bytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 4), true);
    PartitionPurgeMemoryGeneric(generic_allocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 4), true);

    PartitionFreeGeneric(generic_allocator.root(), ptr3);
    PartitionFreeGeneric(generic_allocator.root(), ptr4);
  }
  {
    char* ptr1 = reinterpret_cast<char*>(PartitionAllocGeneric(
        generic_allocator.root(), (64 * kSystemPageSize) - kExtraAllocSize,
        type_name));
    memset(ptr1, 'A', (64 * kSystemPageSize) - kExtraAllocSize);
    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    ptr1 = reinterpret_cast<char*>(PartitionAllocGeneric(
        generic_allocator.root(), (61 * kSystemPageSize) - kExtraAllocSize,
        type_name));
    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(64 * kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(3 * kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(61 * kSystemPageSize, stats->active_bytes);
      EXPECT_EQ(64 * kSystemPageSize, stats->resident_bytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 60), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 61), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 62), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 63), true);
    PartitionPurgeMemoryGeneric(generic_allocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 60), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 61), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 62), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 63), false);

    PartitionFreeGeneric(generic_allocator.root(), ptr1);
  }
  // This sub-test tests truncation of the provisioned slots in a trickier
  // case where the freelist is rewritten.
  PartitionPurgeMemoryGeneric(generic_allocator.root(),
                              PartitionPurgeDecommitEmptyPages);
  {
    char* ptr1 = reinterpret_cast<char*>(
        PartitionAllocGeneric(generic_allocator.root(),
                              kSystemPageSize - kExtraAllocSize, type_name));
    void* ptr2 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    void* ptr3 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    void* ptr4 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    ptr1[0] = 'A';
    ptr1[kSystemPageSize] = 'A';
    ptr1[kSystemPageSize * 2] = 'A';
    ptr1[kSystemPageSize * 3] = 'A';
    PartitionPage* page =
        PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr1));
    PartitionFreeGeneric(generic_allocator.root(), ptr2);
    PartitionFreeGeneric(generic_allocator.root(), ptr4);
    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    EXPECT_EQ(0u, page->num_unprovisioned_slots);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(kSystemPageSize, stats->active_bytes);
      EXPECT_EQ(4 * kSystemPageSize, stats->resident_bytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), true);
    PartitionPurgeMemoryGeneric(generic_allocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    EXPECT_EQ(1u, page->num_unprovisioned_slots);
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), false);

    // Let's check we didn't brick the freelist.
    void* ptr1b = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    EXPECT_EQ(ptr1, ptr1b);
    void* ptr2b = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    EXPECT_EQ(ptr2, ptr2b);
    EXPECT_FALSE(page->freelist_head);

    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    PartitionFreeGeneric(generic_allocator.root(), ptr2);
    PartitionFreeGeneric(generic_allocator.root(), ptr3);
  }
  // This sub-test is similar, but tests a double-truncation.
  PartitionPurgeMemoryGeneric(generic_allocator.root(),
                              PartitionPurgeDecommitEmptyPages);
  {
    char* ptr1 = reinterpret_cast<char*>(
        PartitionAllocGeneric(generic_allocator.root(),
                              kSystemPageSize - kExtraAllocSize, type_name));
    void* ptr2 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    void* ptr3 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    void* ptr4 = PartitionAllocGeneric(
        generic_allocator.root(), kSystemPageSize - kExtraAllocSize, type_name);
    ptr1[0] = 'A';
    ptr1[kSystemPageSize] = 'A';
    ptr1[kSystemPageSize * 2] = 'A';
    ptr1[kSystemPageSize * 3] = 'A';
    PartitionPage* page =
        PartitionPointerToPage(PartitionCookieFreePointerAdjust(ptr1));
    PartitionFreeGeneric(generic_allocator.root(), ptr4);
    PartitionFreeGeneric(generic_allocator.root(), ptr3);
    EXPECT_EQ(0u, page->num_unprovisioned_slots);

    {
      MockPartitionStatsDumper dumper;
      PartitionDumpStatsGeneric(generic_allocator.root(),
                                "mock_generic_allocator",
                                false /* detailed dump */, &dumper);
      EXPECT_TRUE(dumper.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          dumper.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->is_valid);
      EXPECT_EQ(0u, stats->decommittable_bytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->discardable_bytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->active_bytes);
      EXPECT_EQ(4 * kSystemPageSize, stats->resident_bytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), true);
    PartitionPurgeMemoryGeneric(generic_allocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    EXPECT_EQ(2u, page->num_unprovisioned_slots);
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), false);

    EXPECT_FALSE(page->freelist_head);

    PartitionFreeGeneric(generic_allocator.root(), ptr1);
    PartitionFreeGeneric(generic_allocator.root(), ptr2);
  }
}

TEST(PartitionAllocTest, ReallocMovesCookies) {
  TestSetup();

  // Resize so as to be sure to hit a "resize in place" case, and ensure that
  // use of the entire result is compatible with the debug mode's cookies, even
  // when the bucket size is large enough to span more than one partition page
  // and we can track the "raw" size. See https://crbug.com/709271
  const size_t kSize = base::kMaxSystemPagesPerSlotSpan * base::kSystemPageSize;
  void* ptr =
      PartitionAllocGeneric(generic_allocator.root(), kSize + 1, type_name);
  EXPECT_TRUE(ptr);

  memset(ptr, 0xbd, kSize + 1);
  ptr = PartitionReallocGeneric(generic_allocator.root(), ptr, kSize + 2,
                                type_name);
  EXPECT_TRUE(ptr);

  memset(ptr, 0xbd, kSize + 2);
  PartitionFreeGeneric(generic_allocator.root(), ptr);
}

}  // namespace base

#endif  // !defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
