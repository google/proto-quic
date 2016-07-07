// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_allocation_register.h"

#include <stddef.h>
#include <stdint.h>

#include "base/process/process_metrics.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

class AllocationRegisterTest : public testing::Test {
 public:
  // Use a lower number of backtrace cells for unittests to avoid reserving
  // a virtual region which is too big.
  static const size_t kAllocationBuckets =
      AllocationRegister::kAllocationBuckets + 100;
  static const size_t kAllocationCapacity = kAllocationBuckets;
  static const size_t kBacktraceCapacity = 10;

  // Returns the number of cells that the |AllocationRegister| can store per
  // system page.
  size_t GetAllocationCapacityPerPage() {
    return GetPageSize() / sizeof(AllocationRegister::AllocationMap::Cell);
  }

  size_t GetHighWaterMark(const AllocationRegister& reg) {
    return reg.allocations_.next_unused_cell_;
  }
};

// Iterates over all entries in the allocation register and returns the bitwise
// or of all addresses stored in it.
uintptr_t OrAllAddresses(const AllocationRegister& reg) {
  uintptr_t acc = 0;

  for (auto i : reg)
    acc |= reinterpret_cast<uintptr_t>(i.address);

  return acc;
}

// Iterates over all entries in the allocation register and returns the sum of
// the sizes of the entries.
size_t SumAllSizes(const AllocationRegister& reg) {
  size_t sum = 0;

  for (auto i : reg)
    sum += i.size;

  return sum;
}

TEST_F(AllocationRegisterTest, InsertRemove) {
  AllocationRegister reg(kAllocationCapacity, kBacktraceCapacity);
  AllocationContext ctx;

  // Zero-sized allocations should be discarded.
  reg.Insert(reinterpret_cast<void*>(1), 0, ctx);

  EXPECT_EQ(0u, OrAllAddresses(reg));

  reg.Insert(reinterpret_cast<void*>(1), 1, ctx);

  EXPECT_EQ(1u, OrAllAddresses(reg));

  reg.Insert(reinterpret_cast<void*>(2), 1, ctx);

  EXPECT_EQ(3u, OrAllAddresses(reg));

  reg.Insert(reinterpret_cast<void*>(4), 1, ctx);

  EXPECT_EQ(7u, OrAllAddresses(reg));

  reg.Remove(reinterpret_cast<void*>(2));

  EXPECT_EQ(5u, OrAllAddresses(reg));

  reg.Remove(reinterpret_cast<void*>(4));

  EXPECT_EQ(1u, OrAllAddresses(reg));

  reg.Remove(reinterpret_cast<void*>(1));

  EXPECT_EQ(0u, OrAllAddresses(reg));
}

TEST_F(AllocationRegisterTest, DoubleFreeIsAllowed) {
  AllocationRegister reg(kAllocationCapacity, kBacktraceCapacity);
  AllocationContext ctx;

  reg.Insert(reinterpret_cast<void*>(1), 1, ctx);
  reg.Insert(reinterpret_cast<void*>(2), 1, ctx);
  reg.Remove(reinterpret_cast<void*>(1));
  reg.Remove(reinterpret_cast<void*>(1));  // Remove for the second time.
  reg.Remove(reinterpret_cast<void*>(4));  // Remove never inserted address.

  EXPECT_EQ(2u, OrAllAddresses(reg));
}

TEST_F(AllocationRegisterTest, DoubleInsertOverwrites) {
  AllocationRegister reg(kAllocationCapacity, kBacktraceCapacity);
  AllocationContext ctx;
  StackFrame frame1 = StackFrame::FromTraceEventName("Foo");
  StackFrame frame2 = StackFrame::FromTraceEventName("Bar");

  ctx.backtrace.frame_count = 1;

  ctx.backtrace.frames[0] = frame1;
  reg.Insert(reinterpret_cast<void*>(1), 11, ctx);

  {
    AllocationRegister::Allocation elem = *reg.begin();

    EXPECT_EQ(frame1, elem.context.backtrace.frames[0]);
    EXPECT_EQ(11u, elem.size);
    EXPECT_EQ(reinterpret_cast<void*>(1), elem.address);
  }

  ctx.backtrace.frames[0] = frame2;
  reg.Insert(reinterpret_cast<void*>(1), 13, ctx);

  {
    AllocationRegister::Allocation elem = *reg.begin();

    EXPECT_EQ(frame2, elem.context.backtrace.frames[0]);
    EXPECT_EQ(13u, elem.size);
    EXPECT_EQ(reinterpret_cast<void*>(1), elem.address);
  }
}

// Check that even if more entries than the number of buckets are inserted, the
// register still behaves correctly.
TEST_F(AllocationRegisterTest, InsertRemoveCollisions) {
  size_t expected_sum = 0;
  AllocationRegister reg(kAllocationCapacity, kBacktraceCapacity);
  AllocationContext ctx;

  // By inserting 100 more entries than the number of buckets, there will be at
  // least 100 collisions (100 = kAllocationCapacity - kAllocationBuckets).
  for (uintptr_t i = 1; i <= kAllocationCapacity; i++) {
    size_t size = i % 31;
    expected_sum += size;
    reg.Insert(reinterpret_cast<void*>(i), size, ctx);

    // Don't check the sum on every iteration to keep the test fast.
    if (i % (1 << 14) == 0)
      EXPECT_EQ(expected_sum, SumAllSizes(reg));
  }

  EXPECT_EQ(expected_sum, SumAllSizes(reg));

  for (uintptr_t i = 1; i <= kAllocationCapacity; i++) {
    size_t size = i % 31;
    expected_sum -= size;
    reg.Remove(reinterpret_cast<void*>(i));

    if (i % (1 << 14) == 0)
      EXPECT_EQ(expected_sum, SumAllSizes(reg));
  }

  EXPECT_EQ(expected_sum, SumAllSizes(reg));
}

// The previous tests are not particularly good for testing iterators, because
// elements are removed and inserted in the same order, meaning that the cells
// fill up from low to high index, and are then freed from low to high index.
// This test removes entries in a different order, to ensure that the iterator
// skips over the freed cells properly. Then insert again to ensure that the
// free list is utilised properly.
TEST_F(AllocationRegisterTest, InsertRemoveRandomOrder) {
  size_t expected_sum = 0;
  AllocationRegister reg(kAllocationCapacity, kBacktraceCapacity);
  AllocationContext ctx;

  uintptr_t generator = 3;
  uintptr_t prime = 1013;
  uint32_t initial_water_mark = GetHighWaterMark(reg);

  for (uintptr_t i = 2; i < prime; i++) {
    size_t size = i % 31 + 1;
    expected_sum += size;
    reg.Insert(reinterpret_cast<void*>(i), size, ctx);
  }

  // This should have used a fresh slot for each of the |prime - 2| inserts.
  ASSERT_EQ(prime - 2, GetHighWaterMark(reg) - initial_water_mark);

  // Iterate the numbers 2, 3, ..., prime - 1 in pseudorandom order.
  for (uintptr_t i = generator; i != 1; i = (i * generator) % prime) {
    size_t size = i % 31 + 1;
    expected_sum -= size;
    reg.Remove(reinterpret_cast<void*>(i));
    EXPECT_EQ(expected_sum, SumAllSizes(reg));
  }

  ASSERT_EQ(0u, expected_sum);

  // Insert |prime - 2| entries again. This should use cells from the free list,
  // so the |next_unused_cell_| index should not change.
  for (uintptr_t i = 2; i < prime; i++)
    reg.Insert(reinterpret_cast<void*>(i), 1, ctx);

  ASSERT_EQ(prime - 2, GetHighWaterMark(reg) - initial_water_mark);

  // Inserting one more entry should use a fresh cell again.
  reg.Insert(reinterpret_cast<void*>(prime), 1, ctx);
  ASSERT_EQ(prime - 1, GetHighWaterMark(reg) - initial_water_mark);
}

TEST_F(AllocationRegisterTest, ChangeContextAfterInsertion) {
  using Allocation = AllocationRegister::Allocation;
  AllocationRegister reg(kAllocationCapacity, kBacktraceCapacity);
  AllocationContext ctx;

  reg.Insert(reinterpret_cast<void*>(17), 1, ctx);
  reg.Insert(reinterpret_cast<void*>(19), 2, ctx);
  reg.Insert(reinterpret_cast<void*>(23), 3, ctx);

  Allocation a;

  // Looking up addresses that were not inserted should return null.
  // A null pointer lookup is a valid thing to do.
  EXPECT_FALSE(reg.Get(nullptr, &a));
  EXPECT_FALSE(reg.Get(reinterpret_cast<void*>(13), &a));

  EXPECT_TRUE(reg.Get(reinterpret_cast<void*>(17), &a));
  EXPECT_TRUE(reg.Get(reinterpret_cast<void*>(19), &a));
  EXPECT_TRUE(reg.Get(reinterpret_cast<void*>(23), &a));

  reg.Remove(reinterpret_cast<void*>(23));

  // Lookup should not find any garbage after removal.
  EXPECT_FALSE(reg.Get(reinterpret_cast<void*>(23), &a));

  reg.Remove(reinterpret_cast<void*>(17));
  reg.Remove(reinterpret_cast<void*>(19));

  EXPECT_FALSE(reg.Get(reinterpret_cast<void*>(17), &a));
  EXPECT_FALSE(reg.Get(reinterpret_cast<void*>(19), &a));
}

// Check that the process aborts due to hitting the guard page when inserting
// too many elements.
#if GTEST_HAS_DEATH_TEST
TEST_F(AllocationRegisterTest, OverflowDeathTest) {
  const size_t allocation_capacity = GetAllocationCapacityPerPage();
  AllocationRegister reg(allocation_capacity, kBacktraceCapacity);
  AllocationContext ctx;
  size_t i;

  // Fill up all of the memory allocated for the register's allocation map.
  for (i = 0; i < allocation_capacity; i++) {
    reg.Insert(reinterpret_cast<void*>(i + 1), 1, ctx);
  }

  // Adding just one extra element should cause overflow.
  ASSERT_DEATH(reg.Insert(reinterpret_cast<void*>(i + 1), 1, ctx), "");
}
#endif

}  // namespace trace_event
}  // namespace base
