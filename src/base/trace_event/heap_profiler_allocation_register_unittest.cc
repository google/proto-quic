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
  static const uint32_t kNumBuckets = AllocationRegister::kNumBuckets;

  // Returns the number of cells that the |AllocationRegister| can store per
  // system page.
  size_t GetNumCellsPerPage() {
    return GetPageSize() / sizeof(AllocationRegister::Cell);
  }

  uint32_t GetHighWaterMark(const AllocationRegister& reg) {
    return reg.next_unused_cell_;
  }

  uint32_t GetNumCells(const AllocationRegister& reg) {
    return reg.num_cells_;
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
  AllocationRegister reg;
  AllocationContext ctx = AllocationContext::Empty();

  EXPECT_EQ(0u, OrAllAddresses(reg));

  reg.Insert(reinterpret_cast<void*>(1), 0, ctx);

  EXPECT_EQ(1u, OrAllAddresses(reg));

  reg.Insert(reinterpret_cast<void*>(2), 0, ctx);

  EXPECT_EQ(3u, OrAllAddresses(reg));

  reg.Insert(reinterpret_cast<void*>(4), 0, ctx);

  EXPECT_EQ(7u, OrAllAddresses(reg));

  reg.Remove(reinterpret_cast<void*>(2));

  EXPECT_EQ(5u, OrAllAddresses(reg));

  reg.Remove(reinterpret_cast<void*>(4));

  EXPECT_EQ(1u, OrAllAddresses(reg));

  reg.Remove(reinterpret_cast<void*>(1));

  EXPECT_EQ(0u, OrAllAddresses(reg));
}

TEST_F(AllocationRegisterTest, DoubleFreeIsAllowed) {
  AllocationRegister reg;
  AllocationContext ctx = AllocationContext::Empty();

  reg.Insert(reinterpret_cast<void*>(1), 0, ctx);
  reg.Insert(reinterpret_cast<void*>(2), 0, ctx);
  reg.Remove(reinterpret_cast<void*>(1));
  reg.Remove(reinterpret_cast<void*>(1));  // Remove for the second time.
  reg.Remove(reinterpret_cast<void*>(4));  // Remove never inserted address.

  EXPECT_EQ(2u, OrAllAddresses(reg));
}

TEST_F(AllocationRegisterTest, DoubleInsertOverwrites) {
  // TODO(ruuda): Although double insert happens in practice, it should not.
  // Find out the cause and ban double insert if possible.
  AllocationRegister reg;
  AllocationContext ctx = AllocationContext::Empty();
  StackFrame frame1 = "Foo";
  StackFrame frame2 = "Bar";

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
  AllocationRegister reg;
  AllocationContext ctx = AllocationContext::Empty();

  // By inserting 100 more entries than the number of buckets, there will be at
  // least 100 collisions.
  for (uintptr_t i = 1; i <= kNumBuckets + 100; i++) {
    size_t size = i % 31;
    expected_sum += size;
    reg.Insert(reinterpret_cast<void*>(i), size, ctx);

    // Don't check the sum on every iteration to keep the test fast.
    if (i % (1 << 14) == 0)
      EXPECT_EQ(expected_sum, SumAllSizes(reg));
  }

  EXPECT_EQ(expected_sum, SumAllSizes(reg));

  for (uintptr_t i = 1; i <= kNumBuckets + 100; i++) {
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
  AllocationRegister reg;
  AllocationContext ctx = AllocationContext::Empty();

  uintptr_t generator = 3;
  uintptr_t prime = 1013;
  uint32_t initial_water_mark = GetHighWaterMark(reg);

  for (uintptr_t i = 2; i < prime; i++) {
    size_t size = i % 31;
    expected_sum += size;
    reg.Insert(reinterpret_cast<void*>(i), size, ctx);
  }

  // This should have used a fresh slot for each of the |prime - 2| inserts.
  ASSERT_EQ(prime - 2, GetHighWaterMark(reg) - initial_water_mark);

  // Iterate the numbers 2, 3, ..., prime - 1 in pseudorandom order.
  for (uintptr_t i = generator; i != 1; i = (i * generator) % prime) {
    size_t size = i % 31;
    expected_sum -= size;
    reg.Remove(reinterpret_cast<void*>(i));
    EXPECT_EQ(expected_sum, SumAllSizes(reg));
  }

  ASSERT_EQ(0u, expected_sum);

  // Insert |prime - 2| entries again. This should use cells from the free list,
  // so the |next_unused_cell_| index should not change.
  for (uintptr_t i = 2; i < prime; i++)
    reg.Insert(reinterpret_cast<void*>(i), 0, ctx);

  ASSERT_EQ(prime - 2, GetHighWaterMark(reg) - initial_water_mark);

  // Inserting one more entry should use a fresh cell again.
  reg.Insert(reinterpret_cast<void*>(prime), 0, ctx);
  ASSERT_EQ(prime - 1, GetHighWaterMark(reg) - initial_water_mark);
}

TEST_F(AllocationRegisterTest, ChangeContextAfterInsertion) {
  using Allocation = AllocationRegister::Allocation;
  const char kStdString[] = "std::string";
  AllocationRegister reg;
  AllocationContext ctx = AllocationContext::Empty();

  reg.Insert(reinterpret_cast<void*>(17), 1, ctx);
  reg.Insert(reinterpret_cast<void*>(19), 2, ctx);
  reg.Insert(reinterpret_cast<void*>(23), 3, ctx);

  // Looking up addresses that were not inserted should return null.
  // A null pointer lookup is a valid thing to do.
  EXPECT_EQ(nullptr, reg.Get(nullptr));
  EXPECT_EQ(nullptr, reg.Get(reinterpret_cast<void*>(13)));

  Allocation* a17 = reg.Get(reinterpret_cast<void*>(17));
  Allocation* a19 = reg.Get(reinterpret_cast<void*>(19));
  Allocation* a23 = reg.Get(reinterpret_cast<void*>(23));

  EXPECT_NE(nullptr, a17);
  EXPECT_NE(nullptr, a19);
  EXPECT_NE(nullptr, a23);

  a17->size = 100;
  a19->context.type_name = kStdString;

  reg.Remove(reinterpret_cast<void*>(23));

  // Lookup should not find any garbage after removal.
  EXPECT_EQ(nullptr, reg.Get(reinterpret_cast<void*>(23)));

  // Mutating allocations should have modified the allocations in the register.
  for (const Allocation& allocation : reg) {
     if (allocation.address == reinterpret_cast<void*>(17))
       EXPECT_EQ(100u, allocation.size);
     if (allocation.address == reinterpret_cast<void*>(19))
       EXPECT_EQ(kStdString, allocation.context.type_name);
  }

  reg.Remove(reinterpret_cast<void*>(17));
  reg.Remove(reinterpret_cast<void*>(19));

  EXPECT_EQ(nullptr, reg.Get(reinterpret_cast<void*>(17)));
  EXPECT_EQ(nullptr, reg.Get(reinterpret_cast<void*>(19)));
}

// Check that the process aborts due to hitting the guard page when inserting
// too many elements.
#if GTEST_HAS_DEATH_TEST
TEST_F(AllocationRegisterTest, OverflowDeathTest) {
  // Use a smaller register to prevent OOM errors on low-end devices.
  AllocationRegister reg(static_cast<uint32_t>(GetNumCellsPerPage()));
  AllocationContext ctx = AllocationContext::Empty();
  uintptr_t i;

  // Fill up all of the memory allocated for the register. |GetNumCells(reg)|
  // minus 1 elements are inserted, because cell 0 is unused, so this should
  // fill up the available cells exactly.
  for (i = 1; i < GetNumCells(reg); i++) {
    reg.Insert(reinterpret_cast<void*>(i), 0, ctx);
  }

  // Adding just one extra element might still work because the allocated memory
  // is rounded up to the page size. Adding a page full of elements should cause
  // overflow.
  const size_t cells_per_page = GetNumCellsPerPage();

  ASSERT_DEATH(for (size_t j = 0; j < cells_per_page; j++) {
    reg.Insert(reinterpret_cast<void*>(i + j), 0, ctx);
  }, "");
}
#endif

}  // namespace trace_event
}  // namespace base
