// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/process_memory_dump.h"

#include <stddef.h>

#include "base/memory/aligned_memory.h"
#include "base/memory/ptr_util.h"
#include "base/process/process_metrics.h"
#include "base/trace_event/memory_allocator_dump_guid.h"
#include "base/trace_event/memory_infra_background_whitelist.h"
#include "base/trace_event/trace_event_argument.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

namespace {

const MemoryDumpArgs kDetailedDumpArgs = {MemoryDumpLevelOfDetail::DETAILED};
const char* const kTestDumpNameWhitelist[] = {
    "Whitelisted/TestName", "Whitelisted/TestName_0x?",
    "Whitelisted/0x?/TestName", nullptr};

TracedValue* GetHeapDump(const ProcessMemoryDump& pmd, const char* name) {
  auto it = pmd.heap_dumps().find(name);
  return it == pmd.heap_dumps().end() ? nullptr : it->second.get();
}

}  // namespace

TEST(ProcessMemoryDumpTest, Clear) {
  std::unique_ptr<ProcessMemoryDump> pmd1(
      new ProcessMemoryDump(nullptr, kDetailedDumpArgs));
  pmd1->CreateAllocatorDump("mad1");
  pmd1->CreateAllocatorDump("mad2");
  ASSERT_FALSE(pmd1->allocator_dumps().empty());

  pmd1->process_totals()->set_resident_set_bytes(42);
  pmd1->set_has_process_totals();

  pmd1->process_mmaps()->AddVMRegion(ProcessMemoryMaps::VMRegion());
  pmd1->set_has_process_mmaps();

  pmd1->AddOwnershipEdge(MemoryAllocatorDumpGuid(42),
                         MemoryAllocatorDumpGuid(4242));

  MemoryAllocatorDumpGuid shared_mad_guid1(1);
  MemoryAllocatorDumpGuid shared_mad_guid2(2);
  pmd1->CreateSharedGlobalAllocatorDump(shared_mad_guid1);
  pmd1->CreateSharedGlobalAllocatorDump(shared_mad_guid2);

  pmd1->Clear();
  ASSERT_TRUE(pmd1->allocator_dumps().empty());
  ASSERT_TRUE(pmd1->allocator_dumps_edges().empty());
  ASSERT_EQ(nullptr, pmd1->GetAllocatorDump("mad1"));
  ASSERT_EQ(nullptr, pmd1->GetAllocatorDump("mad2"));
  ASSERT_FALSE(pmd1->has_process_totals());
  ASSERT_FALSE(pmd1->has_process_mmaps());
  ASSERT_TRUE(pmd1->process_mmaps()->vm_regions().empty());
  ASSERT_EQ(nullptr, pmd1->GetSharedGlobalAllocatorDump(shared_mad_guid1));
  ASSERT_EQ(nullptr, pmd1->GetSharedGlobalAllocatorDump(shared_mad_guid2));

  // Check that calling AsValueInto() doesn't cause a crash.
  std::unique_ptr<TracedValue> traced_value(new TracedValue);
  pmd1->AsValueInto(traced_value.get());

  // Check that the pmd can be reused and behaves as expected.
  auto* mad1 = pmd1->CreateAllocatorDump("mad1");
  auto* mad3 = pmd1->CreateAllocatorDump("mad3");
  auto* shared_mad1 = pmd1->CreateSharedGlobalAllocatorDump(shared_mad_guid1);
  auto* shared_mad2 =
      pmd1->CreateWeakSharedGlobalAllocatorDump(shared_mad_guid2);
  ASSERT_EQ(4u, pmd1->allocator_dumps().size());
  ASSERT_EQ(mad1, pmd1->GetAllocatorDump("mad1"));
  ASSERT_EQ(nullptr, pmd1->GetAllocatorDump("mad2"));
  ASSERT_EQ(mad3, pmd1->GetAllocatorDump("mad3"));
  ASSERT_EQ(shared_mad1, pmd1->GetSharedGlobalAllocatorDump(shared_mad_guid1));
  ASSERT_EQ(MemoryAllocatorDump::Flags::DEFAULT, shared_mad1->flags());
  ASSERT_EQ(shared_mad2, pmd1->GetSharedGlobalAllocatorDump(shared_mad_guid2));
  ASSERT_EQ(MemoryAllocatorDump::Flags::WEAK, shared_mad2->flags());

  traced_value.reset(new TracedValue);
  pmd1->AsValueInto(traced_value.get());

  pmd1.reset();
}

TEST(ProcessMemoryDumpTest, TakeAllDumpsFrom) {
  std::unique_ptr<TracedValue> traced_value(new TracedValue);
  std::unordered_map<AllocationContext, AllocationMetrics> metrics_by_context;
  metrics_by_context[AllocationContext()] = { 1, 1 };
  TraceEventMemoryOverhead overhead;

  scoped_refptr<HeapProfilerSerializationState>
      heap_profiler_serialization_state = new HeapProfilerSerializationState;
  heap_profiler_serialization_state->SetStackFrameDeduplicator(
      WrapUnique(new StackFrameDeduplicator));
  heap_profiler_serialization_state->SetTypeNameDeduplicator(
      WrapUnique(new TypeNameDeduplicator));
  std::unique_ptr<ProcessMemoryDump> pmd1(new ProcessMemoryDump(
      heap_profiler_serialization_state.get(), kDetailedDumpArgs));
  auto* mad1_1 = pmd1->CreateAllocatorDump("pmd1/mad1");
  auto* mad1_2 = pmd1->CreateAllocatorDump("pmd1/mad2");
  pmd1->AddOwnershipEdge(mad1_1->guid(), mad1_2->guid());
  pmd1->DumpHeapUsage(metrics_by_context, overhead, "pmd1/heap_dump1");
  pmd1->DumpHeapUsage(metrics_by_context, overhead, "pmd1/heap_dump2");

  std::unique_ptr<ProcessMemoryDump> pmd2(new ProcessMemoryDump(
      heap_profiler_serialization_state.get(), kDetailedDumpArgs));
  auto* mad2_1 = pmd2->CreateAllocatorDump("pmd2/mad1");
  auto* mad2_2 = pmd2->CreateAllocatorDump("pmd2/mad2");
  pmd2->AddOwnershipEdge(mad2_1->guid(), mad2_2->guid());
  pmd2->DumpHeapUsage(metrics_by_context, overhead, "pmd2/heap_dump1");
  pmd2->DumpHeapUsage(metrics_by_context, overhead, "pmd2/heap_dump2");

  MemoryAllocatorDumpGuid shared_mad_guid1(1);
  MemoryAllocatorDumpGuid shared_mad_guid2(2);
  auto* shared_mad1 = pmd2->CreateSharedGlobalAllocatorDump(shared_mad_guid1);
  auto* shared_mad2 =
      pmd2->CreateWeakSharedGlobalAllocatorDump(shared_mad_guid2);

  pmd1->TakeAllDumpsFrom(pmd2.get());

  // Make sure that pmd2 is empty but still usable after it has been emptied.
  ASSERT_TRUE(pmd2->allocator_dumps().empty());
  ASSERT_TRUE(pmd2->allocator_dumps_edges().empty());
  ASSERT_TRUE(pmd2->heap_dumps().empty());
  pmd2->CreateAllocatorDump("pmd2/this_mad_stays_with_pmd2");
  ASSERT_EQ(1u, pmd2->allocator_dumps().size());
  ASSERT_EQ(1u, pmd2->allocator_dumps().count("pmd2/this_mad_stays_with_pmd2"));
  pmd2->AddOwnershipEdge(MemoryAllocatorDumpGuid(42),
                         MemoryAllocatorDumpGuid(4242));

  // Check that calling AsValueInto() doesn't cause a crash.
  pmd2->AsValueInto(traced_value.get());

  // Free the |pmd2| to check that the memory ownership of the two MAD(s)
  // has been transferred to |pmd1|.
  pmd2.reset();

  // Now check that |pmd1| has been effectively merged.
  ASSERT_EQ(6u, pmd1->allocator_dumps().size());
  ASSERT_EQ(1u, pmd1->allocator_dumps().count("pmd1/mad1"));
  ASSERT_EQ(1u, pmd1->allocator_dumps().count("pmd1/mad2"));
  ASSERT_EQ(1u, pmd1->allocator_dumps().count("pmd2/mad1"));
  ASSERT_EQ(1u, pmd1->allocator_dumps().count("pmd1/mad2"));
  ASSERT_EQ(2u, pmd1->allocator_dumps_edges().size());
  ASSERT_EQ(shared_mad1, pmd1->GetSharedGlobalAllocatorDump(shared_mad_guid1));
  ASSERT_EQ(shared_mad2, pmd1->GetSharedGlobalAllocatorDump(shared_mad_guid2));
  ASSERT_TRUE(MemoryAllocatorDump::Flags::WEAK & shared_mad2->flags());
  ASSERT_EQ(4u, pmd1->heap_dumps().size());
  ASSERT_TRUE(GetHeapDump(*pmd1, "pmd1/heap_dump1") != nullptr);
  ASSERT_TRUE(GetHeapDump(*pmd1, "pmd1/heap_dump2") != nullptr);
  ASSERT_TRUE(GetHeapDump(*pmd1, "pmd2/heap_dump1") != nullptr);
  ASSERT_TRUE(GetHeapDump(*pmd1, "pmd2/heap_dump2") != nullptr);

  // Check that calling AsValueInto() doesn't cause a crash.
  traced_value.reset(new TracedValue);
  pmd1->AsValueInto(traced_value.get());

  pmd1.reset();
}

TEST(ProcessMemoryDumpTest, Suballocations) {
  std::unique_ptr<ProcessMemoryDump> pmd(
      new ProcessMemoryDump(nullptr, kDetailedDumpArgs));
  const std::string allocator_dump_name = "fakealloc/allocated_objects";
  pmd->CreateAllocatorDump(allocator_dump_name);

  // Create one allocation with an auto-assigned guid and mark it as a
  // suballocation of "fakealloc/allocated_objects".
  auto* pic1_dump = pmd->CreateAllocatorDump("picturemanager/picture1");
  pmd->AddSuballocation(pic1_dump->guid(), allocator_dump_name);

  // Same here, but this time create an allocation with an explicit guid.
  auto* pic2_dump = pmd->CreateAllocatorDump("picturemanager/picture2",
                                            MemoryAllocatorDumpGuid(0x42));
  pmd->AddSuballocation(pic2_dump->guid(), allocator_dump_name);

  // Now check that AddSuballocation() has created anonymous child dumps under
  // "fakealloc/allocated_objects".
  auto anon_node_1_it = pmd->allocator_dumps().find(
      allocator_dump_name + "/__" + pic1_dump->guid().ToString());
  ASSERT_NE(pmd->allocator_dumps().end(), anon_node_1_it);

  auto anon_node_2_it =
      pmd->allocator_dumps().find(allocator_dump_name + "/__42");
  ASSERT_NE(pmd->allocator_dumps().end(), anon_node_2_it);

  // Finally check that AddSuballocation() has created also the
  // edges between the pictures and the anonymous allocator child dumps.
  bool found_edge[2]{false, false};
  for (const auto& e : pmd->allocator_dumps_edges()) {
    found_edge[0] |= (e.source == pic1_dump->guid() &&
                      e.target == anon_node_1_it->second->guid());
    found_edge[1] |= (e.source == pic2_dump->guid() &&
                      e.target == anon_node_2_it->second->guid());
  }
  ASSERT_TRUE(found_edge[0]);
  ASSERT_TRUE(found_edge[1]);

  // Check that calling AsValueInto() doesn't cause a crash.
  std::unique_ptr<TracedValue> traced_value(new TracedValue);
  pmd->AsValueInto(traced_value.get());

  pmd.reset();
}

TEST(ProcessMemoryDumpTest, GlobalAllocatorDumpTest) {
  std::unique_ptr<ProcessMemoryDump> pmd(
      new ProcessMemoryDump(nullptr, kDetailedDumpArgs));
  MemoryAllocatorDumpGuid shared_mad_guid(1);
  auto* shared_mad1 = pmd->CreateWeakSharedGlobalAllocatorDump(shared_mad_guid);
  ASSERT_EQ(shared_mad_guid, shared_mad1->guid());
  ASSERT_EQ(MemoryAllocatorDump::Flags::WEAK, shared_mad1->flags());

  auto* shared_mad2 = pmd->GetSharedGlobalAllocatorDump(shared_mad_guid);
  ASSERT_EQ(shared_mad1, shared_mad2);
  ASSERT_EQ(MemoryAllocatorDump::Flags::WEAK, shared_mad1->flags());

  auto* shared_mad3 = pmd->CreateWeakSharedGlobalAllocatorDump(shared_mad_guid);
  ASSERT_EQ(shared_mad1, shared_mad3);
  ASSERT_EQ(MemoryAllocatorDump::Flags::WEAK, shared_mad1->flags());

  auto* shared_mad4 = pmd->CreateSharedGlobalAllocatorDump(shared_mad_guid);
  ASSERT_EQ(shared_mad1, shared_mad4);
  ASSERT_EQ(MemoryAllocatorDump::Flags::DEFAULT, shared_mad1->flags());

  auto* shared_mad5 = pmd->CreateWeakSharedGlobalAllocatorDump(shared_mad_guid);
  ASSERT_EQ(shared_mad1, shared_mad5);
  ASSERT_EQ(MemoryAllocatorDump::Flags::DEFAULT, shared_mad1->flags());
}

TEST(ProcessMemoryDumpTest, BackgroundModeTest) {
  MemoryDumpArgs background_args = {MemoryDumpLevelOfDetail::BACKGROUND};
  std::unique_ptr<ProcessMemoryDump> pmd(
      new ProcessMemoryDump(nullptr, background_args));
  ProcessMemoryDump::is_black_hole_non_fatal_for_testing_ = true;
  SetAllocatorDumpNameWhitelistForTesting(kTestDumpNameWhitelist);
  MemoryAllocatorDump* black_hole_mad = pmd->GetBlackHoleMad();

  // Invalid dump names.
  EXPECT_EQ(black_hole_mad,
            pmd->CreateAllocatorDump("NotWhitelisted/TestName"));
  EXPECT_EQ(black_hole_mad, pmd->CreateAllocatorDump("TestName"));
  EXPECT_EQ(black_hole_mad, pmd->CreateAllocatorDump("Whitelisted/Test"));
  EXPECT_EQ(black_hole_mad,
            pmd->CreateAllocatorDump("Not/Whitelisted/TestName"));
  EXPECT_EQ(black_hole_mad,
            pmd->CreateAllocatorDump("Whitelisted/TestName/Google"));
  EXPECT_EQ(black_hole_mad,
            pmd->CreateAllocatorDump("Whitelisted/TestName/0x1a2Google"));
  EXPECT_EQ(black_hole_mad,
            pmd->CreateAllocatorDump("Whitelisted/TestName/__12/Google"));

  // Global dumps.
  MemoryAllocatorDumpGuid guid(1);
  EXPECT_EQ(black_hole_mad, pmd->CreateSharedGlobalAllocatorDump(guid));
  EXPECT_EQ(black_hole_mad, pmd->CreateWeakSharedGlobalAllocatorDump(guid));
  EXPECT_EQ(black_hole_mad, pmd->GetSharedGlobalAllocatorDump(guid));

  // Suballocations.
  pmd->AddSuballocation(guid, "malloc/allocated_objects");
  EXPECT_EQ(0u, pmd->allocator_dumps_edges_.size());
  EXPECT_EQ(0u, pmd->allocator_dumps_.size());

  // Valid dump names.
  EXPECT_NE(black_hole_mad, pmd->CreateAllocatorDump("Whitelisted/TestName"));
  EXPECT_NE(black_hole_mad,
            pmd->CreateAllocatorDump("Whitelisted/TestName_0xA1b2"));
  EXPECT_NE(black_hole_mad,
            pmd->CreateAllocatorDump("Whitelisted/0xaB/TestName"));

  // GetAllocatorDump is consistent.
  EXPECT_EQ(black_hole_mad, pmd->GetAllocatorDump("NotWhitelisted/TestName"));
  EXPECT_NE(black_hole_mad, pmd->GetAllocatorDump("Whitelisted/TestName"));
}

#if defined(COUNT_RESIDENT_BYTES_SUPPORTED)
TEST(ProcessMemoryDumpTest, CountResidentBytes) {
  const size_t page_size = ProcessMemoryDump::GetSystemPageSize();

  // Allocate few page of dirty memory and check if it is resident.
  const size_t size1 = 5 * page_size;
  std::unique_ptr<char, base::AlignedFreeDeleter> memory1(
      static_cast<char*>(base::AlignedAlloc(size1, page_size)));
  memset(memory1.get(), 0, size1);
  size_t res1 = ProcessMemoryDump::CountResidentBytes(memory1.get(), size1);
  ASSERT_EQ(res1, size1);

  // Allocate a large memory segment (> 8Mib).
  const size_t kVeryLargeMemorySize = 15 * 1024 * 1024;
  std::unique_ptr<char, base::AlignedFreeDeleter> memory2(
      static_cast<char*>(base::AlignedAlloc(kVeryLargeMemorySize, page_size)));
  memset(memory2.get(), 0, kVeryLargeMemorySize);
  size_t res2 = ProcessMemoryDump::CountResidentBytes(memory2.get(),
                                                      kVeryLargeMemorySize);
  ASSERT_EQ(res2, kVeryLargeMemorySize);
}
#endif  // defined(COUNT_RESIDENT_BYTES_SUPPORTED)

}  // namespace trace_event
}  // namespace base
