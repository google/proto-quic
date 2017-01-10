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
PartitionAllocatorGeneric genericAllocator;

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

const char* typeName = nullptr;

void TestSetup() {
  allocator.init();
  genericAllocator.init();
}

void TestShutdown() {
  // We expect no leaks in the general case. We have a test for leak
  // detection.
  EXPECT_TRUE(allocator.shutdown());
  EXPECT_TRUE(genericAllocator.shutdown());
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
  size_t realSize = size + kExtraAllocSize;
  size_t bucketIdx = realSize >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucketIdx];
  size_t numSlots =
      (bucket->numSystemPagesPerSlotSpan * kSystemPageSize) / realSize;
  void* first = 0;
  void* last = 0;
  size_t i;
  for (i = 0; i < numSlots; ++i) {
    void* ptr = partitionAlloc(allocator.root(), size, typeName);
    EXPECT_TRUE(ptr);
    if (!i)
      first = partitionCookieFreePointerAdjust(ptr);
    else if (i == numSlots - 1)
      last = partitionCookieFreePointerAdjust(ptr);
  }
  EXPECT_EQ(partitionPointerToPage(first), partitionPointerToPage(last));
  if (bucket->numSystemPagesPerSlotSpan == kNumSystemPagesPerPartitionPage)
    EXPECT_EQ(reinterpret_cast<size_t>(first) & kPartitionPageBaseMask,
              reinterpret_cast<size_t>(last) & kPartitionPageBaseMask);
  EXPECT_EQ(numSlots,
            static_cast<size_t>(bucket->activePagesHead->numAllocatedSlots));
  EXPECT_EQ(0, bucket->activePagesHead->freelistHead);
  EXPECT_TRUE(bucket->activePagesHead);
  EXPECT_TRUE(bucket->activePagesHead != &PartitionRootGeneric::gSeedPage);
  return bucket->activePagesHead;
}

void FreeFullPage(PartitionPage* page) {
  size_t size = page->bucket->slotSize;
  size_t numSlots =
      (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) / size;
  EXPECT_EQ(numSlots, static_cast<size_t>(abs(page->numAllocatedSlots)));
  char* ptr = reinterpret_cast<char*>(partitionPageToPointer(page));
  size_t i;
  for (i = 0; i < numSlots; ++i) {
    partitionFree(ptr + kPointerOffset);
    ptr += size;
  }
}

void CycleFreeCache(size_t size) {
  size_t realSize = size + kExtraAllocSize;
  size_t bucketIdx = realSize >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucketIdx];
  DCHECK(!bucket->activePagesHead->numAllocatedSlots);

  for (size_t i = 0; i < kMaxFreeableSpans; ++i) {
    void* ptr = partitionAlloc(allocator.root(), size, typeName);
    EXPECT_EQ(1, bucket->activePagesHead->numAllocatedSlots);
    partitionFree(ptr);
    EXPECT_EQ(0, bucket->activePagesHead->numAllocatedSlots);
    EXPECT_NE(-1, bucket->activePagesHead->emptyCacheIndex);
  }
}

void CycleGenericFreeCache(size_t size) {
  for (size_t i = 0; i < kMaxFreeableSpans; ++i) {
    void* ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
    PartitionPage* page =
        partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
    PartitionBucket* bucket = page->bucket;
    EXPECT_EQ(1, bucket->activePagesHead->numAllocatedSlots);
    partitionFreeGeneric(genericAllocator.root(), ptr);
    EXPECT_EQ(0, bucket->activePagesHead->numAllocatedSlots);
    EXPECT_NE(-1, bucket->activePagesHead->emptyCacheIndex);
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
      : m_totalResidentBytes(0),
        m_totalActiveBytes(0),
        m_totalDecommittableBytes(0),
        m_totalDiscardableBytes(0) {}

  void partitionDumpTotals(const char* partitionName,
                           const PartitionMemoryStats* memoryStats) override {
    EXPECT_GE(memoryStats->totalMmappedBytes, memoryStats->totalResidentBytes);
    EXPECT_EQ(m_totalResidentBytes, memoryStats->totalResidentBytes);
    EXPECT_EQ(m_totalActiveBytes, memoryStats->totalActiveBytes);
    EXPECT_EQ(m_totalDecommittableBytes, memoryStats->totalDecommittableBytes);
    EXPECT_EQ(m_totalDiscardableBytes, memoryStats->totalDiscardableBytes);
  }

  void partitionsDumpBucketStats(
      const char* partitionName,
      const PartitionBucketMemoryStats* memoryStats) override {
    (void)partitionName;
    EXPECT_TRUE(memoryStats->isValid);
    EXPECT_EQ(0u, memoryStats->bucketSlotSize & kAllocationGranularityMask);
    m_bucketStats.push_back(*memoryStats);
    m_totalResidentBytes += memoryStats->residentBytes;
    m_totalActiveBytes += memoryStats->activeBytes;
    m_totalDecommittableBytes += memoryStats->decommittableBytes;
    m_totalDiscardableBytes += memoryStats->discardableBytes;
  }

  bool IsMemoryAllocationRecorded() {
    return m_totalResidentBytes != 0 && m_totalActiveBytes != 0;
  }

  const PartitionBucketMemoryStats* GetBucketStats(size_t bucketSize) {
    for (size_t i = 0; i < m_bucketStats.size(); ++i) {
      if (m_bucketStats[i].bucketSlotSize == bucketSize)
        return &m_bucketStats[i];
    }
    return 0;
  }

 private:
  size_t m_totalResidentBytes;
  size_t m_totalActiveBytes;
  size_t m_totalDecommittableBytes;
  size_t m_totalDiscardableBytes;

  std::vector<PartitionBucketMemoryStats> m_bucketStats;
};

}  // anonymous namespace

// Check that the most basic of allocate / free pairs work.
TEST(PartitionAllocTest, Basic) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];
  PartitionPage* seedPage = &PartitionRootGeneric::gSeedPage;

  EXPECT_FALSE(bucket->emptyPagesHead);
  EXPECT_FALSE(bucket->decommittedPagesHead);
  EXPECT_EQ(seedPage, bucket->activePagesHead);
  EXPECT_EQ(0, bucket->activePagesHead->nextPage);

  void* ptr = partitionAlloc(allocator.root(), kTestAllocSize, typeName);
  EXPECT_TRUE(ptr);
  EXPECT_EQ(kPointerOffset,
            reinterpret_cast<size_t>(ptr) & kPartitionPageOffsetMask);
  // Check that the offset appears to include a guard page.
  EXPECT_EQ(kPartitionPageSize + kPointerOffset,
            reinterpret_cast<size_t>(ptr) & kSuperPageOffsetMask);

  partitionFree(ptr);
  // Expect that the last active page gets noticed as empty but doesn't get
  // decommitted.
  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_FALSE(bucket->decommittedPagesHead);

  TestShutdown();
}

// Check that we can detect a memory leak.
TEST(PartitionAllocTest, SimpleLeak) {
  TestSetup();
  void* leakedPtr = partitionAlloc(allocator.root(), kTestAllocSize, typeName);
  (void)leakedPtr;
  void* leakedPtr2 =
      partitionAllocGeneric(genericAllocator.root(), kTestAllocSize, typeName);
  (void)leakedPtr2;
  EXPECT_FALSE(allocator.shutdown());
  EXPECT_FALSE(genericAllocator.shutdown());
}

// Test multiple allocations, and freelist handling.
TEST(PartitionAllocTest, MultiAlloc) {
  TestSetup();

  char* ptr1 = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  char* ptr2 = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  EXPECT_TRUE(ptr1);
  EXPECT_TRUE(ptr2);
  ptrdiff_t diff = ptr2 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize), diff);

  // Check that we re-use the just-freed slot.
  partitionFree(ptr2);
  ptr2 = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  EXPECT_TRUE(ptr2);
  diff = ptr2 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize), diff);
  partitionFree(ptr1);
  ptr1 = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  EXPECT_TRUE(ptr1);
  diff = ptr2 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize), diff);

  char* ptr3 = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  EXPECT_TRUE(ptr3);
  diff = ptr3 - ptr1;
  EXPECT_EQ(static_cast<ptrdiff_t>(kRealAllocSize * 2), diff);

  partitionFree(ptr1);
  partitionFree(ptr2);
  partitionFree(ptr3);

  TestShutdown();
}

// Test a bucket with multiple pages.
TEST(PartitionAllocTest, MultiPages) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  PartitionPage* page = GetFullPage(kTestAllocSize);
  FreeFullPage(page);
  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->activePagesHead);
  EXPECT_EQ(0, page->nextPage);
  EXPECT_EQ(0, page->numAllocatedSlots);

  page = GetFullPage(kTestAllocSize);
  PartitionPage* page2 = GetFullPage(kTestAllocSize);

  EXPECT_EQ(page2, bucket->activePagesHead);
  EXPECT_EQ(0, page2->nextPage);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(partitionPageToPointer(page)) &
                kSuperPageBaseMask,
            reinterpret_cast<uintptr_t>(partitionPageToPointer(page2)) &
                kSuperPageBaseMask);

  // Fully free the non-current page. This will leave us with no current
  // active page because one is empty and the other is full.
  FreeFullPage(page);
  EXPECT_EQ(0, page->numAllocatedSlots);
  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->activePagesHead);

  // Allocate a new page, it should pull from the freelist.
  page = GetFullPage(kTestAllocSize);
  EXPECT_FALSE(bucket->emptyPagesHead);
  EXPECT_EQ(page, bucket->activePagesHead);

  FreeFullPage(page);
  FreeFullPage(page2);
  EXPECT_EQ(0, page->numAllocatedSlots);
  EXPECT_EQ(0, page2->numAllocatedSlots);
  EXPECT_EQ(0, page2->numUnprovisionedSlots);
  EXPECT_NE(-1, page2->emptyCacheIndex);

  TestShutdown();
}

// Test some finer aspects of internal page transitions.
TEST(PartitionAllocTest, PageTransitions) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  PartitionPage* page1 = GetFullPage(kTestAllocSize);
  EXPECT_EQ(page1, bucket->activePagesHead);
  EXPECT_EQ(0, page1->nextPage);
  PartitionPage* page2 = GetFullPage(kTestAllocSize);
  EXPECT_EQ(page2, bucket->activePagesHead);
  EXPECT_EQ(0, page2->nextPage);

  // Bounce page1 back into the non-full list then fill it up again.
  char* ptr =
      reinterpret_cast<char*>(partitionPageToPointer(page1)) + kPointerOffset;
  partitionFree(ptr);
  EXPECT_EQ(page1, bucket->activePagesHead);
  (void)partitionAlloc(allocator.root(), kTestAllocSize, typeName);
  EXPECT_EQ(page1, bucket->activePagesHead);
  EXPECT_EQ(page2, bucket->activePagesHead->nextPage);

  // Allocating another page at this point should cause us to scan over page1
  // (which is both full and NOT our current page), and evict it from the
  // freelist. Older code had a O(n^2) condition due to failure to do this.
  PartitionPage* page3 = GetFullPage(kTestAllocSize);
  EXPECT_EQ(page3, bucket->activePagesHead);
  EXPECT_EQ(0, page3->nextPage);

  // Work out a pointer into page2 and free it.
  ptr = reinterpret_cast<char*>(partitionPageToPointer(page2)) + kPointerOffset;
  partitionFree(ptr);
  // Trying to allocate at this time should cause us to cycle around to page2
  // and find the recently freed slot.
  char* newPtr = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  EXPECT_EQ(ptr, newPtr);
  EXPECT_EQ(page2, bucket->activePagesHead);
  EXPECT_EQ(page3, page2->nextPage);

  // Work out a pointer into page1 and free it. This should pull the page
  // back into the list of available pages.
  ptr = reinterpret_cast<char*>(partitionPageToPointer(page1)) + kPointerOffset;
  partitionFree(ptr);
  // This allocation should be satisfied by page1.
  newPtr = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  EXPECT_EQ(ptr, newPtr);
  EXPECT_EQ(page1, bucket->activePagesHead);
  EXPECT_EQ(page2, page1->nextPage);

  FreeFullPage(page3);
  FreeFullPage(page2);
  FreeFullPage(page1);

  // Allocating whilst in this state exposed a bug, so keep the test.
  ptr = reinterpret_cast<char*>(
      partitionAlloc(allocator.root(), kTestAllocSize, typeName));
  partitionFree(ptr);

  TestShutdown();
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
  EXPECT_EQ(pages[numToFillFreeListPage - 1], bucket->activePagesHead);
  for (i = 0; i < numToFillFreeListPage; ++i)
    FreeFullPage(pages[i]);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->activePagesHead);
  EXPECT_TRUE(bucket->emptyPagesHead);

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
  EXPECT_EQ(pages[numToFillFreeListPage - 1], bucket->activePagesHead);

  for (i = 0; i < numToFillFreeListPage; ++i)
    FreeFullPage(pages[i]);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->activePagesHead);
  EXPECT_TRUE(bucket->emptyPagesHead);

  TestShutdown();
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
    void* storagePtr = partitionPageToPointer(pages[i]);
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

  TestShutdown();
}

// Test the generic allocation functions that can handle arbitrary sizes and
// reallocing etc.
TEST(PartitionAllocTest, GenericAlloc) {
  TestSetup();

  void* ptr = partitionAllocGeneric(genericAllocator.root(), 1, typeName);
  EXPECT_TRUE(ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr);
  ptr = partitionAllocGeneric(genericAllocator.root(), kGenericMaxBucketed + 1,
                              typeName);
  EXPECT_TRUE(ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  ptr = partitionAllocGeneric(genericAllocator.root(), 1, typeName);
  EXPECT_TRUE(ptr);
  void* origPtr = ptr;
  char* charPtr = static_cast<char*>(ptr);
  *charPtr = 'A';

  // Change the size of the realloc, remaining inside the same bucket.
  void* newPtr =
      partitionReallocGeneric(genericAllocator.root(), ptr, 2, typeName);
  EXPECT_EQ(ptr, newPtr);
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr, 1, typeName);
  EXPECT_EQ(ptr, newPtr);
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr,
                                   kGenericSmallestBucket, typeName);
  EXPECT_EQ(ptr, newPtr);

  // Change the size of the realloc, switching buckets.
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr,
                                   kGenericSmallestBucket + 1, typeName);
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
  void* reusedPtr = partitionAllocGeneric(genericAllocator.root(), 1, typeName);
  EXPECT_EQ(reusedPtr, origPtr);
  partitionFreeGeneric(genericAllocator.root(), reusedPtr);

  // Downsize the realloc.
  ptr = newPtr;
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr, 1, typeName);
  EXPECT_EQ(newPtr, origPtr);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'B');
  *newCharPtr = 'C';

  // Upsize the realloc to outside the partition.
  ptr = newPtr;
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr,
                                   kGenericMaxBucketed + 1, typeName);
  EXPECT_NE(newPtr, ptr);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'C');
  *newCharPtr = 'D';

  // Upsize and downsize the realloc, remaining outside the partition.
  ptr = newPtr;
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr,
                                   kGenericMaxBucketed * 10, typeName);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'D');
  *newCharPtr = 'E';
  ptr = newPtr;
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr,
                                   kGenericMaxBucketed * 2, typeName);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'E');
  *newCharPtr = 'F';

  // Downsize the realloc to inside the partition.
  ptr = newPtr;
  newPtr = partitionReallocGeneric(genericAllocator.root(), ptr, 1, typeName);
  EXPECT_NE(newPtr, ptr);
  EXPECT_EQ(newPtr, origPtr);
  newCharPtr = static_cast<char*>(newPtr);
  EXPECT_EQ(*newCharPtr, 'F');

  partitionFreeGeneric(genericAllocator.root(), newPtr);
  TestShutdown();
}

// Test the generic allocation functions can handle some specific sizes of
// interest.
TEST(PartitionAllocTest, GenericAllocSizes) {
  TestSetup();

  void* ptr = partitionAllocGeneric(genericAllocator.root(), 0, typeName);
  EXPECT_TRUE(ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  // kPartitionPageSize is interesting because it results in just one
  // allocation per page, which tripped up some corner cases.
  size_t size = kPartitionPageSize - kExtraAllocSize;
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr);
  void* ptr2 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr2);
  partitionFreeGeneric(genericAllocator.root(), ptr);
  // Should be freeable at this point.
  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_NE(-1, page->emptyCacheIndex);
  partitionFreeGeneric(genericAllocator.root(), ptr2);

  size = (((kPartitionPageSize * kMaxPartitionPagesPerSlotSpan) -
           kSystemPageSize) /
          2) -
         kExtraAllocSize;
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr);
  memset(ptr, 'A', size);
  ptr2 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr2);
  void* ptr3 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr3);
  void* ptr4 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr4);

  page = partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  PartitionPage* page2 =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr3));
  EXPECT_NE(page, page2);

  partitionFreeGeneric(genericAllocator.root(), ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr3);
  partitionFreeGeneric(genericAllocator.root(), ptr2);
  // Should be freeable at this point.
  EXPECT_NE(-1, page->emptyCacheIndex);
  EXPECT_EQ(0, page->numAllocatedSlots);
  EXPECT_EQ(0, page->numUnprovisionedSlots);
  void* newPtr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_EQ(ptr3, newPtr);
  newPtr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
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
  partitionFreeGeneric(genericAllocator.root(), newPtr);
  partitionFreeGeneric(genericAllocator.root(), ptr3);
  partitionFreeGeneric(genericAllocator.root(), ptr4);

  // Can we allocate a massive (512MB) size?
  // Allocate 512MB, but +1, to test for cookie writing alignment issues.
  // Test this only if the device has enough memory or it might fail due
  // to OOM.
  if (IsLargeMemoryDevice()) {
    ptr = partitionAllocGeneric(genericAllocator.root(), 512 * 1024 * 1024 + 1,
                                typeName);
    partitionFreeGeneric(genericAllocator.root(), ptr);
  }

  // Check a more reasonable, but still direct mapped, size.
  // Chop a system page and a byte off to test for rounding errors.
  size = 20 * 1024 * 1024;
  size -= kSystemPageSize;
  size -= 1;
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  char* charPtr = reinterpret_cast<char*>(ptr);
  *(charPtr + (size - 1)) = 'A';
  partitionFreeGeneric(genericAllocator.root(), ptr);

  // Can we free null?
  partitionFreeGeneric(genericAllocator.root(), 0);

  // Do we correctly get a null for a failed allocation?
  EXPECT_EQ(0, partitionAllocGenericFlags(genericAllocator.root(),
                                          PartitionAllocReturnNull,
                                          3u * 1024 * 1024 * 1024, typeName));

  TestShutdown();
}

// Test that we can fetch the real allocated size after an allocation.
TEST(PartitionAllocTest, GenericAllocGetSize) {
  TestSetup();

  void* ptr;
  size_t requestedSize, actualSize, predictedSize;

  EXPECT_TRUE(partitionAllocSupportsGetSize());

  // Allocate something small.
  requestedSize = 511 - kExtraAllocSize;
  predictedSize =
      partitionAllocActualSize(genericAllocator.root(), requestedSize);
  ptr = partitionAllocGeneric(genericAllocator.root(), requestedSize, typeName);
  EXPECT_TRUE(ptr);
  actualSize = partitionAllocGetSize(ptr);
  EXPECT_EQ(predictedSize, actualSize);
  EXPECT_LT(requestedSize, actualSize);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  // Allocate a size that should be a perfect match for a bucket, because it
  // is an exact power of 2.
  requestedSize = (256 * 1024) - kExtraAllocSize;
  predictedSize =
      partitionAllocActualSize(genericAllocator.root(), requestedSize);
  ptr = partitionAllocGeneric(genericAllocator.root(), requestedSize, typeName);
  EXPECT_TRUE(ptr);
  actualSize = partitionAllocGetSize(ptr);
  EXPECT_EQ(predictedSize, actualSize);
  EXPECT_EQ(requestedSize, actualSize);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  // Allocate a size that is a system page smaller than a bucket. GetSize()
  // should return a larger size than we asked for now.
  requestedSize = (256 * 1024) - kSystemPageSize - kExtraAllocSize;
  predictedSize =
      partitionAllocActualSize(genericAllocator.root(), requestedSize);
  ptr = partitionAllocGeneric(genericAllocator.root(), requestedSize, typeName);
  EXPECT_TRUE(ptr);
  actualSize = partitionAllocGetSize(ptr);
  EXPECT_EQ(predictedSize, actualSize);
  EXPECT_EQ(requestedSize + kSystemPageSize, actualSize);
  // Check that we can write at the end of the reported size too.
  char* charPtr = reinterpret_cast<char*>(ptr);
  *(charPtr + (actualSize - 1)) = 'A';
  partitionFreeGeneric(genericAllocator.root(), ptr);

  // Allocate something very large, and uneven.
  if (IsLargeMemoryDevice()) {
    requestedSize = 512 * 1024 * 1024 - 1;
    predictedSize =
        partitionAllocActualSize(genericAllocator.root(), requestedSize);
    ptr =
        partitionAllocGeneric(genericAllocator.root(), requestedSize, typeName);
    EXPECT_TRUE(ptr);
    actualSize = partitionAllocGetSize(ptr);
    EXPECT_EQ(predictedSize, actualSize);
    EXPECT_LT(requestedSize, actualSize);
    partitionFreeGeneric(genericAllocator.root(), ptr);
  }

  // Too large allocation.
  requestedSize = INT_MAX;
  predictedSize =
      partitionAllocActualSize(genericAllocator.root(), requestedSize);
  EXPECT_EQ(requestedSize, predictedSize);

  TestShutdown();
}

// Test the realloc() contract.
TEST(PartitionAllocTest, Realloc) {
  TestSetup();

  // realloc(0, size) should be equivalent to malloc().
  void* ptr = partitionReallocGeneric(genericAllocator.root(), 0,
                                      kTestAllocSize, typeName);
  memset(ptr, 'A', kTestAllocSize);
  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  // realloc(ptr, 0) should be equivalent to free().
  void* ptr2 =
      partitionReallocGeneric(genericAllocator.root(), ptr, 0, typeName);
  EXPECT_EQ(0, ptr2);
  EXPECT_EQ(partitionCookieFreePointerAdjust(ptr), page->freelistHead);

  // Test that growing an allocation with realloc() copies everything from the
  // old allocation.
  size_t size = kSystemPageSize - kExtraAllocSize;
  EXPECT_EQ(size, partitionAllocActualSize(genericAllocator.root(), size));
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  memset(ptr, 'A', size);
  ptr2 =
      partitionReallocGeneric(genericAllocator.root(), ptr, size + 1, typeName);
  EXPECT_NE(ptr, ptr2);
  char* charPtr2 = static_cast<char*>(ptr2);
  EXPECT_EQ('A', charPtr2[0]);
  EXPECT_EQ('A', charPtr2[size - 1]);
#if DCHECK_IS_ON()
  EXPECT_EQ(kUninitializedByte, static_cast<unsigned char>(charPtr2[size]));
#endif

  // Test that shrinking an allocation with realloc() also copies everything
  // from the old allocation.
  ptr = partitionReallocGeneric(genericAllocator.root(), ptr2, size - 1,
                                typeName);
  EXPECT_NE(ptr2, ptr);
  char* charPtr = static_cast<char*>(ptr);
  EXPECT_EQ('A', charPtr[0]);
  EXPECT_EQ('A', charPtr[size - 2]);
#if DCHECK_IS_ON()
  EXPECT_EQ(kUninitializedByte, static_cast<unsigned char>(charPtr[size - 1]));
#endif

  partitionFreeGeneric(genericAllocator.root(), ptr);

  // Test that shrinking a direct mapped allocation happens in-place.
  size = kGenericMaxBucketed + 16 * kSystemPageSize;
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  size_t actualSize = partitionAllocGetSize(ptr);
  ptr2 = partitionReallocGeneric(genericAllocator.root(), ptr,
                                 kGenericMaxBucketed + 8 * kSystemPageSize,
                                 typeName);
  EXPECT_EQ(ptr, ptr2);
  EXPECT_EQ(actualSize - 8 * kSystemPageSize, partitionAllocGetSize(ptr2));

  // Test that a previously in-place shrunk direct mapped allocation can be
  // expanded up again within its original size.
  ptr = partitionReallocGeneric(genericAllocator.root(), ptr2,
                                size - kSystemPageSize, typeName);
  EXPECT_EQ(ptr2, ptr);
  EXPECT_EQ(actualSize - kSystemPageSize, partitionAllocGetSize(ptr));

  // Test that a direct mapped allocation is performed not in-place when the
  // new size is small enough.
  ptr2 = partitionReallocGeneric(genericAllocator.root(), ptr, kSystemPageSize,
                                 typeName);
  EXPECT_NE(ptr, ptr2);

  partitionFreeGeneric(genericAllocator.root(), ptr2);

  TestShutdown();
}

// Tests the handing out of freelists for partial pages.
TEST(PartitionAllocTest, PartialPageFreelists) {
  TestSetup();

  size_t bigSize = allocator.root()->maxAllocation - kExtraAllocSize;
  EXPECT_EQ(kSystemPageSize - kAllocationGranularity,
            bigSize + kExtraAllocSize);
  size_t bucketIdx = (bigSize + kExtraAllocSize) >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucketIdx];
  EXPECT_EQ(0, bucket->emptyPagesHead);

  void* ptr = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_TRUE(ptr);

  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  size_t totalSlots =
      (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) /
      (bigSize + kExtraAllocSize);
  EXPECT_EQ(4u, totalSlots);
  // The freelist should have one entry, because we were able to exactly fit
  // one object slot and one freelist pointer (the null that the head points
  // to) into a system page.
  EXPECT_TRUE(page->freelistHead);
  EXPECT_EQ(1, page->numAllocatedSlots);
  EXPECT_EQ(2, page->numUnprovisionedSlots);

  void* ptr2 = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_TRUE(ptr2);
  EXPECT_FALSE(page->freelistHead);
  EXPECT_EQ(2, page->numAllocatedSlots);
  EXPECT_EQ(2, page->numUnprovisionedSlots);

  void* ptr3 = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_TRUE(ptr3);
  EXPECT_TRUE(page->freelistHead);
  EXPECT_EQ(3, page->numAllocatedSlots);
  EXPECT_EQ(0, page->numUnprovisionedSlots);

  void* ptr4 = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_TRUE(ptr4);
  EXPECT_FALSE(page->freelistHead);
  EXPECT_EQ(4, page->numAllocatedSlots);
  EXPECT_EQ(0, page->numUnprovisionedSlots);

  void* ptr5 = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_TRUE(ptr5);

  PartitionPage* page2 =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr5));
  EXPECT_EQ(1, page2->numAllocatedSlots);

  // Churn things a little whilst there's a partial page freelist.
  partitionFree(ptr);
  ptr = partitionAlloc(allocator.root(), bigSize, typeName);
  void* ptr6 = partitionAlloc(allocator.root(), bigSize, typeName);

  partitionFree(ptr);
  partitionFree(ptr2);
  partitionFree(ptr3);
  partitionFree(ptr4);
  partitionFree(ptr5);
  partitionFree(ptr6);
  EXPECT_NE(-1, page->emptyCacheIndex);
  EXPECT_NE(-1, page2->emptyCacheIndex);
  EXPECT_TRUE(page2->freelistHead);
  EXPECT_EQ(0, page2->numAllocatedSlots);

  // And test a couple of sizes that do not cross kSystemPageSize with a single
  // allocation.
  size_t mediumSize = (kSystemPageSize / 2) - kExtraAllocSize;
  bucketIdx = (mediumSize + kExtraAllocSize) >> kBucketShift;
  bucket = &allocator.root()->buckets()[bucketIdx];
  EXPECT_EQ(0, bucket->emptyPagesHead);

  ptr = partitionAlloc(allocator.root(), mediumSize, typeName);
  EXPECT_TRUE(ptr);
  page = partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->numAllocatedSlots);
  totalSlots = (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) /
               (mediumSize + kExtraAllocSize);
  size_t firstPageSlots = kSystemPageSize / (mediumSize + kExtraAllocSize);
  EXPECT_EQ(2u, firstPageSlots);
  EXPECT_EQ(totalSlots - firstPageSlots, page->numUnprovisionedSlots);

  partitionFree(ptr);

  size_t smallSize = (kSystemPageSize / 4) - kExtraAllocSize;
  bucketIdx = (smallSize + kExtraAllocSize) >> kBucketShift;
  bucket = &allocator.root()->buckets()[bucketIdx];
  EXPECT_EQ(0, bucket->emptyPagesHead);

  ptr = partitionAlloc(allocator.root(), smallSize, typeName);
  EXPECT_TRUE(ptr);
  page = partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->numAllocatedSlots);
  totalSlots = (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) /
               (smallSize + kExtraAllocSize);
  firstPageSlots = kSystemPageSize / (smallSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - firstPageSlots, page->numUnprovisionedSlots);

  partitionFree(ptr);
  EXPECT_TRUE(page->freelistHead);
  EXPECT_EQ(0, page->numAllocatedSlots);

  size_t verySmallSize = 32 - kExtraAllocSize;
  bucketIdx = (verySmallSize + kExtraAllocSize) >> kBucketShift;
  bucket = &allocator.root()->buckets()[bucketIdx];
  EXPECT_EQ(0, bucket->emptyPagesHead);

  ptr = partitionAlloc(allocator.root(), verySmallSize, typeName);
  EXPECT_TRUE(ptr);
  page = partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->numAllocatedSlots);
  totalSlots = (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) /
               (verySmallSize + kExtraAllocSize);
  firstPageSlots = kSystemPageSize / (verySmallSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - firstPageSlots, page->numUnprovisionedSlots);

  partitionFree(ptr);
  EXPECT_TRUE(page->freelistHead);
  EXPECT_EQ(0, page->numAllocatedSlots);

  // And try an allocation size (against the generic allocator) that is
  // larger than a system page.
  size_t pageAndAHalfSize =
      (kSystemPageSize + (kSystemPageSize / 2)) - kExtraAllocSize;
  ptr = partitionAllocGeneric(genericAllocator.root(), pageAndAHalfSize,
                              typeName);
  EXPECT_TRUE(ptr);
  page = partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->numAllocatedSlots);
  EXPECT_TRUE(page->freelistHead);
  totalSlots = (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) /
               (pageAndAHalfSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - 2, page->numUnprovisionedSlots);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  // And then make sure than exactly the page size only faults one page.
  size_t pageSize = kSystemPageSize - kExtraAllocSize;
  ptr = partitionAllocGeneric(genericAllocator.root(), pageSize, typeName);
  EXPECT_TRUE(ptr);
  page = partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->numAllocatedSlots);
  EXPECT_FALSE(page->freelistHead);
  totalSlots = (page->bucket->numSystemPagesPerSlotSpan * kSystemPageSize) /
               (pageSize + kExtraAllocSize);
  EXPECT_EQ(totalSlots - 1, page->numUnprovisionedSlots);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  TestShutdown();
}

// Test some of the fragmentation-resistant properties of the allocator.
TEST(PartitionAllocTest, PageRefilling) {
  TestSetup();
  PartitionBucket* bucket = &allocator.root()->buckets()[kTestBucketIndex];

  // Grab two full pages and a non-full page.
  PartitionPage* page1 = GetFullPage(kTestAllocSize);
  PartitionPage* page2 = GetFullPage(kTestAllocSize);
  void* ptr = partitionAlloc(allocator.root(), kTestAllocSize, typeName);
  EXPECT_TRUE(ptr);
  EXPECT_NE(page1, bucket->activePagesHead);
  EXPECT_NE(page2, bucket->activePagesHead);
  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(1, page->numAllocatedSlots);

  // Work out a pointer into page2 and free it; and then page1 and free it.
  char* ptr2 =
      reinterpret_cast<char*>(partitionPageToPointer(page1)) + kPointerOffset;
  partitionFree(ptr2);
  ptr2 =
      reinterpret_cast<char*>(partitionPageToPointer(page2)) + kPointerOffset;
  partitionFree(ptr2);

  // If we perform two allocations from the same bucket now, we expect to
  // refill both the nearly full pages.
  (void)partitionAlloc(allocator.root(), kTestAllocSize, typeName);
  (void)partitionAlloc(allocator.root(), kTestAllocSize, typeName);
  EXPECT_EQ(1, page->numAllocatedSlots);

  FreeFullPage(page2);
  FreeFullPage(page1);
  partitionFree(ptr);

  TestShutdown();
}

// Basic tests to ensure that allocations work for partial page buckets.
TEST(PartitionAllocTest, PartialPages) {
  TestSetup();

  // Find a size that is backed by a partial partition page.
  size_t size = sizeof(void*);
  PartitionBucket* bucket = 0;
  while (size < kTestMaxAllocation) {
    bucket = &allocator.root()->buckets()[size >> kBucketShift];
    if (bucket->numSystemPagesPerSlotSpan % kNumSystemPagesPerPartitionPage)
      break;
    size += sizeof(void*);
  }
  EXPECT_LT(size, kTestMaxAllocation);

  PartitionPage* page1 = GetFullPage(size);
  PartitionPage* page2 = GetFullPage(size);
  FreeFullPage(page2);
  FreeFullPage(page1);

  TestShutdown();
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
      reinterpret_cast<char*>(partitionPageToPointer(firstSuperPagePages[0]));
  EXPECT_EQ(kPartitionPageSize,
            reinterpret_cast<uintptr_t>(pageBase) & kSuperPageOffsetMask);
  pageBase -= kPartitionPageSize;
  // Map a single system page either side of the mapping for our allocations,
  // with the goal of tripping up alignment of the next mapping.
  void* map1 = allocPages(pageBase - kPageAllocationGranularity,
                          kPageAllocationGranularity,
                          kPageAllocationGranularity, PageInaccessible);
  EXPECT_TRUE(map1);
  void* map2 = allocPages(pageBase + kSuperPageSize, kPageAllocationGranularity,
                          kPageAllocationGranularity, PageInaccessible);
  EXPECT_TRUE(map2);

  for (i = 0; i < numPartitionPagesNeeded; ++i)
    secondSuperPagePages[i] = GetFullPage(kTestAllocSize);

  freePages(map1, kPageAllocationGranularity);
  freePages(map2, kPageAllocationGranularity);

  pageBase =
      reinterpret_cast<char*>(partitionPageToPointer(secondSuperPagePages[0]));
  EXPECT_EQ(kPartitionPageSize,
            reinterpret_cast<uintptr_t>(pageBase) & kSuperPageOffsetMask);
  pageBase -= kPartitionPageSize;
  // Map a single system page either side of the mapping for our allocations,
  // with the goal of tripping up alignment of the next mapping.
  map1 = allocPages(pageBase - kPageAllocationGranularity,
                    kPageAllocationGranularity, kPageAllocationGranularity,
                    PageAccessible);
  EXPECT_TRUE(map1);
  map2 = allocPages(pageBase + kSuperPageSize, kPageAllocationGranularity,
                    kPageAllocationGranularity, PageAccessible);
  EXPECT_TRUE(map2);
  setSystemPagesInaccessible(map1, kPageAllocationGranularity);
  setSystemPagesInaccessible(map2, kPageAllocationGranularity);

  PartitionPage* pageInThirdSuperPage = GetFullPage(kTestAllocSize);
  freePages(map1, kPageAllocationGranularity);
  freePages(map2, kPageAllocationGranularity);

  EXPECT_EQ(0u, reinterpret_cast<uintptr_t>(
                    partitionPageToPointer(pageInThirdSuperPage)) &
                    kPartitionPageOffsetMask);

  // And make sure we really did get a page in a new superpage.
  EXPECT_NE(reinterpret_cast<uintptr_t>(
                partitionPageToPointer(firstSuperPagePages[0])) &
                kSuperPageBaseMask,
            reinterpret_cast<uintptr_t>(
                partitionPageToPointer(pageInThirdSuperPage)) &
                kSuperPageBaseMask);
  EXPECT_NE(reinterpret_cast<uintptr_t>(
                partitionPageToPointer(secondSuperPagePages[0])) &
                kSuperPageBaseMask,
            reinterpret_cast<uintptr_t>(
                partitionPageToPointer(pageInThirdSuperPage)) &
                kSuperPageBaseMask);

  FreeFullPage(pageInThirdSuperPage);
  for (i = 0; i < numPartitionPagesNeeded; ++i) {
    FreeFullPage(firstSuperPagePages[i]);
    FreeFullPage(secondSuperPagePages[i]);
  }

  TestShutdown();
}

// Tests that pages in the free page cache do get freed as appropriate.
TEST(PartitionAllocTest, FreeCache) {
  TestSetup();

  EXPECT_EQ(0U, allocator.root()->totalSizeOfCommittedPages);

  size_t bigSize = allocator.root()->maxAllocation - kExtraAllocSize;
  size_t bucketIdx = (bigSize + kExtraAllocSize) >> kBucketShift;
  PartitionBucket* bucket = &allocator.root()->buckets()[bucketIdx];

  void* ptr = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_TRUE(ptr);
  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  EXPECT_EQ(0, bucket->emptyPagesHead);
  EXPECT_EQ(1, page->numAllocatedSlots);
  EXPECT_EQ(kPartitionPageSize, allocator.root()->totalSizeOfCommittedPages);
  partitionFree(ptr);
  EXPECT_EQ(0, page->numAllocatedSlots);
  EXPECT_NE(-1, page->emptyCacheIndex);
  EXPECT_TRUE(page->freelistHead);

  CycleFreeCache(kTestAllocSize);

  // Flushing the cache should have really freed the unused page.
  EXPECT_FALSE(page->freelistHead);
  EXPECT_EQ(-1, page->emptyCacheIndex);
  EXPECT_EQ(0, page->numAllocatedSlots);
  PartitionBucket* cycleFreeCacheBucket =
      &allocator.root()->buckets()[kTestBucketIndex];
  EXPECT_EQ(cycleFreeCacheBucket->numSystemPagesPerSlotSpan * kSystemPageSize,
            allocator.root()->totalSizeOfCommittedPages);

  // Check that an allocation works ok whilst in this state (a free'd page
  // as the active pages head).
  ptr = partitionAlloc(allocator.root(), bigSize, typeName);
  EXPECT_FALSE(bucket->emptyPagesHead);
  partitionFree(ptr);

  // Also check that a page that is bouncing immediately between empty and
  // used does not get freed.
  for (size_t i = 0; i < kMaxFreeableSpans * 2; ++i) {
    ptr = partitionAlloc(allocator.root(), bigSize, typeName);
    EXPECT_TRUE(page->freelistHead);
    partitionFree(ptr);
    EXPECT_TRUE(page->freelistHead);
  }
  EXPECT_EQ(kPartitionPageSize, allocator.root()->totalSizeOfCommittedPages);
  TestShutdown();
}

// Tests for a bug we had with losing references to free pages.
TEST(PartitionAllocTest, LostFreePagesBug) {
  TestSetup();

  size_t size = kPartitionPageSize - kExtraAllocSize;

  void* ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr);
  void* ptr2 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr2);

  PartitionPage* page =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr));
  PartitionPage* page2 =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr2));
  PartitionBucket* bucket = page->bucket;

  EXPECT_EQ(0, bucket->emptyPagesHead);
  EXPECT_EQ(-1, page->numAllocatedSlots);
  EXPECT_EQ(1, page2->numAllocatedSlots);

  partitionFreeGeneric(genericAllocator.root(), ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr2);

  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_TRUE(bucket->emptyPagesHead->nextPage);
  EXPECT_EQ(0, page->numAllocatedSlots);
  EXPECT_EQ(0, page2->numAllocatedSlots);
  EXPECT_TRUE(page->freelistHead);
  EXPECT_TRUE(page2->freelistHead);

  CycleGenericFreeCache(kTestAllocSize);

  EXPECT_FALSE(page->freelistHead);
  EXPECT_FALSE(page2->freelistHead);

  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_TRUE(bucket->emptyPagesHead->nextPage);
  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->activePagesHead);

  // At this moment, we have two decommitted pages, on the empty list.
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  EXPECT_EQ(&PartitionRootGeneric::gSeedPage, bucket->activePagesHead);
  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_TRUE(bucket->decommittedPagesHead);

  CycleGenericFreeCache(kTestAllocSize);

  // We're now set up to trigger a historical bug by scanning over the active
  // pages list. The current code gets into a different state, but we'll keep
  // the test as being an interesting corner case.
  ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_TRUE(ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  EXPECT_TRUE(bucket->activePagesHead);
  EXPECT_TRUE(bucket->emptyPagesHead);
  EXPECT_TRUE(bucket->decommittedPagesHead);

  TestShutdown();
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

  void** ptrs = reinterpret_cast<void**>(partitionAllocGeneric(
      genericAllocator.root(), numAllocations * sizeof(void*), typeName));
  int i;

  for (i = 0; i < numAllocations; ++i) {
    ptrs[i] = partitionAllocGenericFlags(
        genericAllocator.root(), PartitionAllocReturnNull, allocSize, typeName);
    if (!i)
      EXPECT_TRUE(ptrs[0]);
    if (!ptrs[i]) {
      ptrs[i] = partitionAllocGenericFlags(genericAllocator.root(),
                                           PartitionAllocReturnNull, allocSize,
                                           typeName);
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
    partitionFreeGeneric(genericAllocator.root(), ptrs[i]);
    ptrs[i] = partitionAllocGenericFlags(
        genericAllocator.root(), PartitionAllocReturnNull, allocSize, typeName);
    EXPECT_TRUE(ptrs[i]);
    partitionFreeGeneric(genericAllocator.root(), ptrs[i]);
  }

  partitionFreeGeneric(genericAllocator.root(), ptrs);

  EXPECT_TRUE(ClearAddressSpaceLimit());

  TestShutdown();
}

// Tests that if an allocation fails in "return null" mode, repeating it doesn't
// crash, and still returns null. The test tries to allocate 6 GB of memory in
// 512 kB blocks. On 64-bit POSIX systems, the address space is limited to 6 GB
// using setrlimit() first.
//
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

// Another "return null" test but for larger, direct-mapped allocations.
//
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

#endif  // !defined(ARCH_CPU_64_BITS) || defined(OS_POSIX)

// Death tests misbehave on Android, http://crbug.com/643760.
#if defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

// Make sure that malloc(-1) dies.
// In the past, we had an integer overflow that would alias malloc(-1) to
// malloc(0), which is not good.
TEST(PartitionAllocDeathTest, LargeAllocs) {
  TestSetup();
  // Largest alloc.
  EXPECT_DEATH(partitionAllocGeneric(genericAllocator.root(),
                                     static_cast<size_t>(-1), typeName),
               "");
  // And the smallest allocation we expect to die.
  EXPECT_DEATH(
      partitionAllocGeneric(genericAllocator.root(),
                            static_cast<size_t>(INT_MAX) + 1, typeName),
      "");

  TestShutdown();
}

// Check that our immediate double-free detection works.
TEST(PartitionAllocDeathTest, ImmediateDoubleFree) {
  TestSetup();

  void* ptr =
      partitionAllocGeneric(genericAllocator.root(), kTestAllocSize, typeName);
  EXPECT_TRUE(ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr);

  EXPECT_DEATH(partitionFreeGeneric(genericAllocator.root(), ptr), "");

  TestShutdown();
}

// Check that our refcount-based double-free detection works.
TEST(PartitionAllocDeathTest, RefcountDoubleFree) {
  TestSetup();

  void* ptr =
      partitionAllocGeneric(genericAllocator.root(), kTestAllocSize, typeName);
  EXPECT_TRUE(ptr);
  void* ptr2 =
      partitionAllocGeneric(genericAllocator.root(), kTestAllocSize, typeName);
  EXPECT_TRUE(ptr2);
  partitionFreeGeneric(genericAllocator.root(), ptr);
  partitionFreeGeneric(genericAllocator.root(), ptr2);
  // This is not an immediate double-free so our immediate detection won't
  // fire. However, it does take the "refcount" of the partition page to -1,
  // which is illegal and should be trapped.
  EXPECT_DEATH(partitionFreeGeneric(genericAllocator.root(), ptr), "");

  TestShutdown();
}

// Check that guard pages are present where expected.
TEST(PartitionAllocDeathTest, GuardPages) {
  TestSetup();

// partitionAlloc adds kPartitionPageSize to the requested size
// (for metadata), and then rounds that size to kPageAllocationGranularity.
// To be able to reliably write one past a direct allocation, choose a size
// that's
// a) larger than kGenericMaxBucketed (to make the allocation direct)
// b) aligned at kPageAllocationGranularity boundaries after
//    kPartitionPageSize has been added to it.
// (On 32-bit, partitionAlloc adds another kSystemPageSize to the
// allocation size before rounding, but there it marks the memory right
// after size as inaccessible, so it's fine to write 1 past the size we
// hand to partitionAlloc and we don't need to worry about allocation
// granularities.)
#define ALIGN(N, A) (((N) + (A)-1) / (A) * (A))
  const int kSize = ALIGN(kGenericMaxBucketed + 1 + kPartitionPageSize,
                          kPageAllocationGranularity) -
                    kPartitionPageSize;
#undef ALIGN
  static_assert(kSize > kGenericMaxBucketed,
                "allocation not large enough for direct allocation");
  size_t size = kSize - kExtraAllocSize;
  void* ptr = partitionAllocGeneric(genericAllocator.root(), size, typeName);

  EXPECT_TRUE(ptr);
  char* charPtr = reinterpret_cast<char*>(ptr) - kPointerOffset;

  EXPECT_DEATH(*(charPtr - 1) = 'A', "");
  EXPECT_DEATH(*(charPtr + size + kExtraAllocSize) = 'A', "");

  partitionFreeGeneric(genericAllocator.root(), ptr);

  TestShutdown();
}

// Check that a bad free() is caught where the free() refers to an unused
// partition page of a large allocation.
TEST(PartitionAllocDeathTest, FreeWrongPartitionPage) {
  TestSetup();

  // This large size will result in a direct mapped allocation with guard
  // pages at either end.
  void* ptr = partitionAllocGeneric(genericAllocator.root(),
                                    kPartitionPageSize * 2, typeName);
  EXPECT_TRUE(ptr);
  char* badPtr = reinterpret_cast<char*>(ptr) + kPartitionPageSize;

  EXPECT_DEATH(partitionFreeGeneric(genericAllocator.root(), badPtr), "");

  partitionFreeGeneric(genericAllocator.root(), ptr);

  TestShutdown();
}

#endif  // !defined(OS_ANDROID) && !defined(OS_IOS)

// Tests that partitionDumpStatsGeneric and partitionDumpStats runs without
// crashing and returns non zero values when memory is allocated.
TEST(PartitionAllocTest, DumpMemoryStats) {
  TestSetup();
  {
    void* ptr = partitionAlloc(allocator.root(), kTestAllocSize, typeName);
    MockPartitionStatsDumper mockStatsDumper;
    partitionDumpStats(allocator.root(), "mock_allocator",
                       false /* detailed dump */, &mockStatsDumper);
    EXPECT_TRUE(mockStatsDumper.IsMemoryAllocationRecorded());

    partitionFree(ptr);
  }

  // This series of tests checks the active -> empty -> decommitted states.
  {
    void* genericPtr = partitionAllocGeneric(genericAllocator.root(),
                                             2048 - kExtraAllocSize, typeName);
    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(2048);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(2048u, stats->bucketSlotSize);
      EXPECT_EQ(2048u, stats->activeBytes);
      EXPECT_EQ(kSystemPageSize, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(0u, stats->numFullPages);
      EXPECT_EQ(1u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);
    }

    partitionFreeGeneric(genericAllocator.root(), genericPtr);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_FALSE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(2048);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(2048u, stats->bucketSlotSize);
      EXPECT_EQ(0u, stats->activeBytes);
      EXPECT_EQ(kSystemPageSize, stats->residentBytes);
      EXPECT_EQ(kSystemPageSize, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(0u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(1u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);
    }

    CycleGenericFreeCache(kTestAllocSize);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_FALSE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(2048);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(2048u, stats->bucketSlotSize);
      EXPECT_EQ(0u, stats->activeBytes);
      EXPECT_EQ(0u, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(0u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(1u, stats->numDecommittedPages);
    }
  }

  // This test checks for correct empty page list accounting.
  {
    size_t size = kPartitionPageSize - kExtraAllocSize;
    void* ptr1 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
    void* ptr2 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
    partitionFreeGeneric(genericAllocator.root(), ptr1);
    partitionFreeGeneric(genericAllocator.root(), ptr2);

    CycleGenericFreeCache(kTestAllocSize);

    ptr1 = partitionAllocGeneric(genericAllocator.root(), size, typeName);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(kPartitionPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(kPartitionPageSize, stats->bucketSlotSize);
      EXPECT_EQ(kPartitionPageSize, stats->activeBytes);
      EXPECT_EQ(kPartitionPageSize, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(1u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(1u, stats->numDecommittedPages);
    }
    partitionFreeGeneric(genericAllocator.root(), ptr1);
  }

  // This test checks for correct direct mapped accounting.
  {
    size_t sizeSmaller = kGenericMaxBucketed + 1;
    size_t sizeBigger = (kGenericMaxBucketed * 2) + 1;
    size_t realSizeSmaller =
        (sizeSmaller + kSystemPageOffsetMask) & kSystemPageBaseMask;
    size_t realSizeBigger =
        (sizeBigger + kSystemPageOffsetMask) & kSystemPageBaseMask;
    void* ptr =
        partitionAllocGeneric(genericAllocator.root(), sizeSmaller, typeName);
    void* ptr2 =
        partitionAllocGeneric(genericAllocator.root(), sizeBigger, typeName);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(realSizeSmaller);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_TRUE(stats->isDirectMap);
      EXPECT_EQ(realSizeSmaller, stats->bucketSlotSize);
      EXPECT_EQ(realSizeSmaller, stats->activeBytes);
      EXPECT_EQ(realSizeSmaller, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(1u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);

      stats = mockStatsDumperGeneric.GetBucketStats(realSizeBigger);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_TRUE(stats->isDirectMap);
      EXPECT_EQ(realSizeBigger, stats->bucketSlotSize);
      EXPECT_EQ(realSizeBigger, stats->activeBytes);
      EXPECT_EQ(realSizeBigger, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(1u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);
    }

    partitionFreeGeneric(genericAllocator.root(), ptr2);
    partitionFreeGeneric(genericAllocator.root(), ptr);

    // Whilst we're here, allocate again and free with different ordering
    // to give a workout to our linked list code.
    ptr = partitionAllocGeneric(genericAllocator.root(), sizeSmaller, typeName);
    ptr2 = partitionAllocGeneric(genericAllocator.root(), sizeBigger, typeName);
    partitionFreeGeneric(genericAllocator.root(), ptr);
    partitionFreeGeneric(genericAllocator.root(), ptr2);
  }

  // This test checks large-but-not-quite-direct allocations.
  {
    void* ptr =
        partitionAllocGeneric(genericAllocator.root(), 65536 + 1, typeName);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      size_t slotSize = 65536 + (65536 / kGenericNumBucketsPerOrder);
      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(slotSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_FALSE(stats->isDirectMap);
      EXPECT_EQ(slotSize, stats->bucketSlotSize);
      EXPECT_EQ(65536u + 1 + kExtraAllocSize, stats->activeBytes);
      EXPECT_EQ(slotSize, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(1u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);
    }

    partitionFreeGeneric(genericAllocator.root(), ptr);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_FALSE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      size_t slotSize = 65536 + (65536 / kGenericNumBucketsPerOrder);
      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(slotSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_FALSE(stats->isDirectMap);
      EXPECT_EQ(slotSize, stats->bucketSlotSize);
      EXPECT_EQ(0u, stats->activeBytes);
      EXPECT_EQ(slotSize, stats->residentBytes);
      EXPECT_EQ(slotSize, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(1u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);
    }

    void* ptr2 = partitionAllocGeneric(genericAllocator.root(),
                                       65536 + kSystemPageSize + 1, typeName);
    EXPECT_EQ(ptr, ptr2);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      size_t slotSize = 65536 + (65536 / kGenericNumBucketsPerOrder);
      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(slotSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_FALSE(stats->isDirectMap);
      EXPECT_EQ(slotSize, stats->bucketSlotSize);
      EXPECT_EQ(65536u + kSystemPageSize + 1 + kExtraAllocSize,
                stats->activeBytes);
      EXPECT_EQ(slotSize, stats->residentBytes);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(0u, stats->discardableBytes);
      EXPECT_EQ(1u, stats->numFullPages);
      EXPECT_EQ(0u, stats->numActivePages);
      EXPECT_EQ(0u, stats->numEmptyPages);
      EXPECT_EQ(0u, stats->numDecommittedPages);
    }

    partitionFreeGeneric(genericAllocator.root(), ptr2);
  }

  TestShutdown();
}

// Tests the API to purge freeable memory.
TEST(PartitionAllocTest, Purge) {
  TestSetup();

  char* ptr = reinterpret_cast<char*>(partitionAllocGeneric(
      genericAllocator.root(), 2048 - kExtraAllocSize, typeName));
  partitionFreeGeneric(genericAllocator.root(), ptr);
  {
    MockPartitionStatsDumper mockStatsDumperGeneric;
    partitionDumpStatsGeneric(genericAllocator.root(), "mock_generic_allocator",
                              false /* detailed dump */,
                              &mockStatsDumperGeneric);
    EXPECT_FALSE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

    const PartitionBucketMemoryStats* stats =
        mockStatsDumperGeneric.GetBucketStats(2048);
    EXPECT_TRUE(stats);
    EXPECT_TRUE(stats->isValid);
    EXPECT_EQ(kSystemPageSize, stats->decommittableBytes);
    EXPECT_EQ(kSystemPageSize, stats->residentBytes);
  }
  partitionPurgeMemoryGeneric(genericAllocator.root(),
                              PartitionPurgeDecommitEmptyPages);
  {
    MockPartitionStatsDumper mockStatsDumperGeneric;
    partitionDumpStatsGeneric(genericAllocator.root(), "mock_generic_allocator",
                              false /* detailed dump */,
                              &mockStatsDumperGeneric);
    EXPECT_FALSE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

    const PartitionBucketMemoryStats* stats =
        mockStatsDumperGeneric.GetBucketStats(2048);
    EXPECT_TRUE(stats);
    EXPECT_TRUE(stats->isValid);
    EXPECT_EQ(0u, stats->decommittableBytes);
    EXPECT_EQ(0u, stats->residentBytes);
  }
  // Calling purge again here is a good way of testing we didn't mess up the
  // state of the free cache ring.
  partitionPurgeMemoryGeneric(genericAllocator.root(),
                              PartitionPurgeDecommitEmptyPages);

  char* bigPtr = reinterpret_cast<char*>(
      partitionAllocGeneric(genericAllocator.root(), 256 * 1024, typeName));
  partitionFreeGeneric(genericAllocator.root(), bigPtr);
  partitionPurgeMemoryGeneric(genericAllocator.root(),
                              PartitionPurgeDecommitEmptyPages);

  CheckPageInCore(ptr - kPointerOffset, false);
  CheckPageInCore(bigPtr - kPointerOffset, false);

  TestShutdown();
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
  void* ptr1 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  void* ptr2 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  void* ptr3 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  void* ptr4 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  void* ptr5 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  void* ptr6 = partitionAllocGeneric(genericAllocator.root(), size, typeName);

  PartitionPage* page1 =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr1));
  PartitionPage* page2 =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr3));
  PartitionPage* page3 =
      partitionPointerToPage(partitionCookieFreePointerAdjust(ptr6));
  EXPECT_NE(page1, page2);
  EXPECT_NE(page2, page3);
  PartitionBucket* bucket = page1->bucket;
  EXPECT_EQ(page3, bucket->activePagesHead);

  // Free up the 2nd slot in each slot span.
  // This leaves the active list containing 3 pages, each with 1 used and 1
  // free slot. The active page will be the one containing ptr1.
  partitionFreeGeneric(genericAllocator.root(), ptr6);
  partitionFreeGeneric(genericAllocator.root(), ptr4);
  partitionFreeGeneric(genericAllocator.root(), ptr2);
  EXPECT_EQ(page1, bucket->activePagesHead);

  // Empty the middle page in the active list.
  partitionFreeGeneric(genericAllocator.root(), ptr3);
  EXPECT_EQ(page1, bucket->activePagesHead);

  // Empty the the first page in the active list -- also the current page.
  partitionFreeGeneric(genericAllocator.root(), ptr1);

  // A good choice here is to re-fill the third page since the first two are
  // empty. We used to fail that.
  void* ptr7 = partitionAllocGeneric(genericAllocator.root(), size, typeName);
  EXPECT_EQ(ptr6, ptr7);
  EXPECT_EQ(page3, bucket->activePagesHead);

  partitionFreeGeneric(genericAllocator.root(), ptr5);
  partitionFreeGeneric(genericAllocator.root(), ptr7);

  TestShutdown();
}

// Tests the API to purge discardable memory.
TEST(PartitionAllocTest, PurgeDiscardable) {
  TestSetup();

  // Free the second of two 4096 byte allocations and then purge.
  {
    void* ptr1 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    char* ptr2 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName));
    partitionFreeGeneric(genericAllocator.root(), ptr2);
    PartitionPage* page =
        partitionPointerToPage(partitionCookieFreePointerAdjust(ptr1));
    EXPECT_EQ(2u, page->numUnprovisionedSlots);
    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(kSystemPageSize, stats->activeBytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->residentBytes);
    }
    CheckPageInCore(ptr2 - kPointerOffset, true);
    partitionPurgeMemoryGeneric(genericAllocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr2 - kPointerOffset, false);
    EXPECT_EQ(3u, page->numUnprovisionedSlots);

    partitionFreeGeneric(genericAllocator.root(), ptr1);
  }
  // Free the first of two 4096 byte allocations and then purge.
  {
    char* ptr1 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName));
    void* ptr2 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    partitionFreeGeneric(genericAllocator.root(), ptr1);
    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(kSystemPageSize, stats->activeBytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->residentBytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    partitionPurgeMemoryGeneric(genericAllocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr1 - kPointerOffset, false);

    partitionFreeGeneric(genericAllocator.root(), ptr2);
  }
  {
    char* ptr1 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), 9216 - kExtraAllocSize, typeName));
    void* ptr2 = partitionAllocGeneric(genericAllocator.root(),
                                       9216 - kExtraAllocSize, typeName);
    void* ptr3 = partitionAllocGeneric(genericAllocator.root(),
                                       9216 - kExtraAllocSize, typeName);
    void* ptr4 = partitionAllocGeneric(genericAllocator.root(),
                                       9216 - kExtraAllocSize, typeName);
    memset(ptr1, 'A', 9216 - kExtraAllocSize);
    memset(ptr2, 'A', 9216 - kExtraAllocSize);
    partitionFreeGeneric(genericAllocator.root(), ptr2);
    partitionFreeGeneric(genericAllocator.root(), ptr1);
    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(9216);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(9216u * 2, stats->activeBytes);
      EXPECT_EQ(9 * kSystemPageSize, stats->residentBytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 4), true);
    partitionPurgeMemoryGeneric(genericAllocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 4), true);

    partitionFreeGeneric(genericAllocator.root(), ptr3);
    partitionFreeGeneric(genericAllocator.root(), ptr4);
  }
  {
    char* ptr1 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), (64 * kSystemPageSize) - kExtraAllocSize,
        typeName));
    memset(ptr1, 'A', (64 * kSystemPageSize) - kExtraAllocSize);
    partitionFreeGeneric(genericAllocator.root(), ptr1);
    ptr1 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), (61 * kSystemPageSize) - kExtraAllocSize,
        typeName));
    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(64 * kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(3 * kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(61 * kSystemPageSize, stats->activeBytes);
      EXPECT_EQ(64 * kSystemPageSize, stats->residentBytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 60), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 61), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 62), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 63), true);
    partitionPurgeMemoryGeneric(genericAllocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 60), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 61), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 62), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 63), false);

    partitionFreeGeneric(genericAllocator.root(), ptr1);
  }
  // This sub-test tests truncation of the provisioned slots in a trickier
  // case where the freelist is rewritten.
  partitionPurgeMemoryGeneric(genericAllocator.root(),
                              PartitionPurgeDecommitEmptyPages);
  {
    char* ptr1 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName));
    void* ptr2 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    void* ptr3 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    void* ptr4 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    ptr1[0] = 'A';
    ptr1[kSystemPageSize] = 'A';
    ptr1[kSystemPageSize * 2] = 'A';
    ptr1[kSystemPageSize * 3] = 'A';
    PartitionPage* page =
        partitionPointerToPage(partitionCookieFreePointerAdjust(ptr1));
    partitionFreeGeneric(genericAllocator.root(), ptr2);
    partitionFreeGeneric(genericAllocator.root(), ptr4);
    partitionFreeGeneric(genericAllocator.root(), ptr1);
    EXPECT_EQ(0u, page->numUnprovisionedSlots);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(kSystemPageSize, stats->activeBytes);
      EXPECT_EQ(4 * kSystemPageSize, stats->residentBytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), true);
    partitionPurgeMemoryGeneric(genericAllocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    EXPECT_EQ(1u, page->numUnprovisionedSlots);
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), false);

    // Let's check we didn't brick the freelist.
    void* ptr1b = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    EXPECT_EQ(ptr1, ptr1b);
    void* ptr2b = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    EXPECT_EQ(ptr2, ptr2b);
    EXPECT_FALSE(page->freelistHead);

    partitionFreeGeneric(genericAllocator.root(), ptr1);
    partitionFreeGeneric(genericAllocator.root(), ptr2);
    partitionFreeGeneric(genericAllocator.root(), ptr3);
  }
  // This sub-test is similar, but tests a double-truncation.
  partitionPurgeMemoryGeneric(genericAllocator.root(),
                              PartitionPurgeDecommitEmptyPages);
  {
    char* ptr1 = reinterpret_cast<char*>(partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName));
    void* ptr2 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    void* ptr3 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    void* ptr4 = partitionAllocGeneric(
        genericAllocator.root(), kSystemPageSize - kExtraAllocSize, typeName);
    ptr1[0] = 'A';
    ptr1[kSystemPageSize] = 'A';
    ptr1[kSystemPageSize * 2] = 'A';
    ptr1[kSystemPageSize * 3] = 'A';
    PartitionPage* page =
        partitionPointerToPage(partitionCookieFreePointerAdjust(ptr1));
    partitionFreeGeneric(genericAllocator.root(), ptr4);
    partitionFreeGeneric(genericAllocator.root(), ptr3);
    EXPECT_EQ(0u, page->numUnprovisionedSlots);

    {
      MockPartitionStatsDumper mockStatsDumperGeneric;
      partitionDumpStatsGeneric(
          genericAllocator.root(), "mock_generic_allocator",
          false /* detailed dump */, &mockStatsDumperGeneric);
      EXPECT_TRUE(mockStatsDumperGeneric.IsMemoryAllocationRecorded());

      const PartitionBucketMemoryStats* stats =
          mockStatsDumperGeneric.GetBucketStats(kSystemPageSize);
      EXPECT_TRUE(stats);
      EXPECT_TRUE(stats->isValid);
      EXPECT_EQ(0u, stats->decommittableBytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->discardableBytes);
      EXPECT_EQ(2 * kSystemPageSize, stats->activeBytes);
      EXPECT_EQ(4 * kSystemPageSize, stats->residentBytes);
    }
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), true);
    partitionPurgeMemoryGeneric(genericAllocator.root(),
                                PartitionPurgeDiscardUnusedSystemPages);
    EXPECT_EQ(2u, page->numUnprovisionedSlots);
    CheckPageInCore(ptr1 - kPointerOffset, true);
    CheckPageInCore(ptr1 - kPointerOffset + kSystemPageSize, true);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 2), false);
    CheckPageInCore(ptr1 - kPointerOffset + (kSystemPageSize * 3), false);

    EXPECT_FALSE(page->freelistHead);

    partitionFreeGeneric(genericAllocator.root(), ptr1);
    partitionFreeGeneric(genericAllocator.root(), ptr2);
  }

  TestShutdown();
}

}  // namespace base

#endif  // !defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
