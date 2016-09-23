// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/android/library_loader/library_prefetcher.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <string>
#include <vector>
#include "base/debug/proc_maps_linux.h"
#include "base/memory/shared_memory.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace android {

namespace {
const uint8_t kRead = base::debug::MappedMemoryRegion::READ;
const uint8_t kReadPrivate = base::debug::MappedMemoryRegion::READ |
                             base::debug::MappedMemoryRegion::PRIVATE;
const uint8_t kExecutePrivate = base::debug::MappedMemoryRegion::EXECUTE |
                                base::debug::MappedMemoryRegion::PRIVATE;
const size_t kPageSize = 4096;
}  // namespace

TEST(NativeLibraryPrefetcherTest, TestIsGoodToPrefetchNoRange) {
  const base::debug::MappedMemoryRegion regions[4] = {
      base::debug::MappedMemoryRegion{0x4000, 0x5000, 10, kReadPrivate, ""},
      base::debug::MappedMemoryRegion{0x4000, 0x5000, 10, kReadPrivate, "foo"},
      base::debug::MappedMemoryRegion{
          0x4000, 0x5000, 10, kReadPrivate, "foobar.apk"},
      base::debug::MappedMemoryRegion{
          0x4000, 0x5000, 10, kReadPrivate, "libchromium.so"}};
  for (int i = 0; i < 4; ++i) {
    ASSERT_FALSE(NativeLibraryPrefetcher::IsGoodToPrefetch(regions[i]));
  }
}

TEST(NativeLibraryPrefetcherTest, TestIsGoodToPrefetchUnreadableRange) {
  const base::debug::MappedMemoryRegion region = {
      0x4000, 0x5000, 10, kExecutePrivate, "base.apk"};
  ASSERT_FALSE(NativeLibraryPrefetcher::IsGoodToPrefetch(region));
}

TEST(NativeLibraryPrefetcherTest, TestIsGoodToPrefetchSkipSharedRange) {
  const base::debug::MappedMemoryRegion region = {
      0x4000, 0x5000, 10, kRead, "base.apk"};
  ASSERT_FALSE(NativeLibraryPrefetcher::IsGoodToPrefetch(region));
}

TEST(NativeLibraryPrefetcherTest, TestIsGoodToPrefetchLibchromeRange) {
  const base::debug::MappedMemoryRegion region = {
      0x4000, 0x5000, 10, kReadPrivate, "libchrome.so"};
  ASSERT_TRUE(NativeLibraryPrefetcher::IsGoodToPrefetch(region));
}

TEST(NativeLibraryPrefetcherTest, TestIsGoodToPrefetchBaseApkRange) {
  const base::debug::MappedMemoryRegion region = {
      0x4000, 0x5000, 10, kReadPrivate, "base.apk"};
  ASSERT_TRUE(NativeLibraryPrefetcher::IsGoodToPrefetch(region));
}

TEST(NativeLibraryPrefetcherTest,
     TestFilterLibchromeRangesOnlyIfPossibleNoLibchrome) {
  std::vector<base::debug::MappedMemoryRegion> regions;
  regions.push_back(
      base::debug::MappedMemoryRegion{0x1, 0x2, 0, kReadPrivate, "base.apk"});
  regions.push_back(
      base::debug::MappedMemoryRegion{0x3, 0x4, 0, kReadPrivate, "base.apk"});
  std::vector<NativeLibraryPrefetcher::AddressRange> ranges;
  NativeLibraryPrefetcher::FilterLibchromeRangesOnlyIfPossible(regions,
                                                               &ranges);
  EXPECT_EQ(ranges.size(), 2U);
  EXPECT_EQ(ranges[0].first, 0x1U);
  EXPECT_EQ(ranges[0].second, 0x2U);
  EXPECT_EQ(ranges[1].first, 0x3U);
  EXPECT_EQ(ranges[1].second, 0x4U);
}

TEST(NativeLibraryPrefetcherTest,
     TestFilterLibchromeRangesOnlyIfPossibleHasLibchrome) {
  std::vector<base::debug::MappedMemoryRegion> regions;
  regions.push_back(
      base::debug::MappedMemoryRegion{0x1, 0x2, 0, kReadPrivate, "base.apk"});
  regions.push_back(base::debug::MappedMemoryRegion{
      0x6, 0x7, 0, kReadPrivate, "libchrome.so"});
  regions.push_back(
      base::debug::MappedMemoryRegion{0x3, 0x4, 0, kReadPrivate, "base.apk"});
  std::vector<NativeLibraryPrefetcher::AddressRange> ranges;
  NativeLibraryPrefetcher::FilterLibchromeRangesOnlyIfPossible(regions,
                                                               &ranges);
  EXPECT_EQ(ranges.size(), 1U);
  EXPECT_EQ(ranges[0].first, 0x6U);
  EXPECT_EQ(ranges[0].second, 0x7U);
}

TEST(NativeLibraryPrefetcherTest, DISABLED_TestPercentageOfResidentCode) {
  size_t length = 4 * kPageSize;
  base::SharedMemory shared_mem;
  ASSERT_TRUE(shared_mem.CreateAndMapAnonymous(length));
  void* address = shared_mem.memory();

  std::vector<NativeLibraryPrefetcher::AddressRange> ranges = {
      {reinterpret_cast<uintptr_t>(address),
       reinterpret_cast<uintptr_t>(address) + length}};

  // Remove everything.
  ASSERT_EQ(0, madvise(address, length, MADV_DONTNEED));
  // TODO(lizeb): If flaky, mock mincore().
  EXPECT_EQ(0, NativeLibraryPrefetcher::PercentageOfResidentCode(ranges));

  // Get everything back.
  ASSERT_EQ(0, mlock(address, length));
  EXPECT_EQ(100, NativeLibraryPrefetcher::PercentageOfResidentCode(ranges));
  munlock(address, length);
}

TEST(NativeLibraryPrefetcherTest,
     DISABLED_TestPercentageOfResidentCodeTwoRegions) {
  size_t length = 4 * kPageSize;
  base::SharedMemory shared_mem;
  ASSERT_TRUE(shared_mem.CreateAndMapAnonymous(length));
  void* address = shared_mem.memory();

  size_t length2 = 8 * kPageSize;
  base::SharedMemory shared_mem2;
  ASSERT_TRUE(shared_mem2.CreateAndMapAnonymous(length2));
  void* address2 = shared_mem2.memory();

  std::vector<NativeLibraryPrefetcher::AddressRange> ranges = {
      {reinterpret_cast<uintptr_t>(address),
       reinterpret_cast<uintptr_t>(address) + length},
      {reinterpret_cast<uintptr_t>(address2),
       reinterpret_cast<uintptr_t>(address2) + length2}};

  // Remove everything.
  ASSERT_EQ(0, madvise(address, length, MADV_DONTNEED));
  ASSERT_EQ(0, madvise(address2, length, MADV_DONTNEED));
  // TODO(lizeb): If flaky, mock mincore().
  EXPECT_EQ(0, NativeLibraryPrefetcher::PercentageOfResidentCode(ranges));

  // Get back the first range.
  ASSERT_EQ(0, mlock(address, length));
  EXPECT_EQ(33, NativeLibraryPrefetcher::PercentageOfResidentCode(ranges));
  // The second one.
  ASSERT_EQ(0, mlock(address2, length2));
  EXPECT_EQ(100, NativeLibraryPrefetcher::PercentageOfResidentCode(ranges));
  munlock(address, length);
  munlock(address2, length);
}

}  // namespace android
}  // namespace base
