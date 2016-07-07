// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/malloc_dump_provider.h"

#include <stddef.h>

#include "base/allocator/allocator_extension.h"
#include "base/allocator/allocator_shim.h"
#include "base/allocator/features.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"
#include "base/trace_event/heap_profiler_allocation_register.h"
#include "base/trace_event/heap_profiler_heap_dump_writer.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event_argument.h"
#include "build/build_config.h"

#if defined(OS_MACOSX)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

namespace base {
namespace trace_event {

#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
namespace {

using allocator::AllocatorDispatch;

void* HookAlloc(const AllocatorDispatch* self, size_t size) {
  const AllocatorDispatch* const next = self->next;
  void* ptr = next->alloc_function(next, size);
  if (ptr)
    MallocDumpProvider::GetInstance()->InsertAllocation(ptr, size);
  return ptr;
}

void* HookZeroInitAlloc(const AllocatorDispatch* self, size_t n, size_t size) {
  const AllocatorDispatch* const next = self->next;
  void* ptr = next->alloc_zero_initialized_function(next, n, size);
  if (ptr)
    MallocDumpProvider::GetInstance()->InsertAllocation(ptr, n * size);
  return ptr;
}

void* HookllocAligned(const AllocatorDispatch* self,
                      size_t alignment,
                      size_t size) {
  const AllocatorDispatch* const next = self->next;
  void* ptr = next->alloc_aligned_function(next, alignment, size);
  if (ptr)
    MallocDumpProvider::GetInstance()->InsertAllocation(ptr, size);
  return ptr;
}

void* HookRealloc(const AllocatorDispatch* self, void* address, size_t size) {
  const AllocatorDispatch* const next = self->next;
  void* ptr = next->realloc_function(next, address, size);
  MallocDumpProvider::GetInstance()->RemoveAllocation(address);
  if (size > 0)  // realloc(size == 0) means free().
    MallocDumpProvider::GetInstance()->InsertAllocation(ptr, size);
  return ptr;
}

void HookFree(const AllocatorDispatch* self, void* address) {
  if (address)
    MallocDumpProvider::GetInstance()->RemoveAllocation(address);
  const AllocatorDispatch* const next = self->next;
  next->free_function(next, address);
}

AllocatorDispatch g_allocator_hooks = {
    &HookAlloc,         /* alloc_function */
    &HookZeroInitAlloc, /* alloc_zero_initialized_function */
    &HookllocAligned,   /* alloc_aligned_function */
    &HookRealloc,       /* realloc_function */
    &HookFree,          /* free_function */
    nullptr,            /* next */
};

}  // namespace
#endif  // BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)

// static
const char MallocDumpProvider::kAllocatedObjects[] = "malloc/allocated_objects";

// static
MallocDumpProvider* MallocDumpProvider::GetInstance() {
  return Singleton<MallocDumpProvider,
                   LeakySingletonTraits<MallocDumpProvider>>::get();
}

MallocDumpProvider::MallocDumpProvider()
    : heap_profiler_enabled_(false), tid_dumping_heap_(kInvalidThreadId) {}

MallocDumpProvider::~MallocDumpProvider() {}

// Called at trace dump point time. Creates a snapshot the memory counters for
// the current process.
bool MallocDumpProvider::OnMemoryDump(const MemoryDumpArgs& args,
                                      ProcessMemoryDump* pmd) {
  size_t total_virtual_size = 0;
  size_t resident_size = 0;
  size_t allocated_objects_size = 0;
#if defined(USE_TCMALLOC)
  bool res =
      allocator::GetNumericProperty("generic.heap_size", &total_virtual_size);
  DCHECK(res);
  res = allocator::GetNumericProperty("generic.total_physical_bytes",
                                      &resident_size);
  DCHECK(res);
  res = allocator::GetNumericProperty("generic.current_allocated_bytes",
                                      &allocated_objects_size);
  DCHECK(res);
#elif defined(OS_MACOSX) || defined(OS_IOS)
  malloc_statistics_t stats = {0};
  malloc_zone_statistics(nullptr, &stats);
  total_virtual_size = stats.size_allocated;
  allocated_objects_size = stats.size_in_use;

  // The resident size is approximated to the max size in use, which would count
  // the total size of all regions other than the free bytes at the end of each
  // region. In each allocation region the allocations are rounded off to a
  // fixed quantum, so the excess region will not be resident.
  // See crrev.com/1531463004 for detailed explanation.
  resident_size = stats.max_size_in_use;
#else
  struct mallinfo info = mallinfo();
  DCHECK_GE(info.arena + info.hblkhd, info.uordblks);

  // In case of Android's jemalloc |arena| is 0 and the outer pages size is
  // reported by |hblkhd|. In case of dlmalloc the total is given by
  // |arena| + |hblkhd|. For more details see link: http://goo.gl/fMR8lF.
  total_virtual_size = info.arena + info.hblkhd;
  resident_size = info.uordblks;
  allocated_objects_size = info.uordblks;
#endif

  MemoryAllocatorDump* outer_dump = pmd->CreateAllocatorDump("malloc");
  outer_dump->AddScalar("virtual_size", MemoryAllocatorDump::kUnitsBytes,
                        total_virtual_size);
  outer_dump->AddScalar(MemoryAllocatorDump::kNameSize,
                        MemoryAllocatorDump::kUnitsBytes, resident_size);

  // Total allocated space is given by |uordblks|.
  MemoryAllocatorDump* inner_dump = pmd->CreateAllocatorDump(kAllocatedObjects);
  inner_dump->AddScalar(MemoryAllocatorDump::kNameSize,
                        MemoryAllocatorDump::kUnitsBytes,
                        allocated_objects_size);

  if (resident_size - allocated_objects_size > 0) {
    // Explicitly specify why is extra memory resident. In tcmalloc it accounts
    // for free lists and caches. In mac and ios it accounts for the
    // fragmentation and metadata.
    MemoryAllocatorDump* other_dump =
        pmd->CreateAllocatorDump("malloc/metadata_fragmentation_caches");
    other_dump->AddScalar(MemoryAllocatorDump::kNameSize,
                          MemoryAllocatorDump::kUnitsBytes,
                          resident_size - allocated_objects_size);
  }

  // Heap profiler dumps.
  if (!heap_profiler_enabled_)
    return true;

  // The dumps of the heap profiler should be created only when heap profiling
  // was enabled (--enable-heap-profiling) AND a DETAILED dump is requested.
  // However, when enabled, the overhead of the heap profiler should be always
  // reported to avoid oscillations of the malloc total in LIGHT dumps.

  tid_dumping_heap_ = PlatformThread::CurrentId();
  // At this point the Insert/RemoveAllocation hooks will ignore this thread.
  // Enclosing all the temporariy data structures in a scope, so that the heap
  // profiler does not see unabalanced malloc/free calls from these containers.
  {
    TraceEventMemoryOverhead overhead;
    hash_map<AllocationContext, AllocationMetrics> metrics_by_context;
    {
      AutoLock lock(allocation_register_lock_);
      if (allocation_register_) {
        if (args.level_of_detail == MemoryDumpLevelOfDetail::DETAILED) {
          for (const auto& alloc_size : *allocation_register_) {
            AllocationMetrics& metrics = metrics_by_context[alloc_size.context];
            metrics.size += alloc_size.size;
            metrics.count++;
          }
        }
        allocation_register_->EstimateTraceMemoryOverhead(&overhead);
      }
    }  // lock(allocation_register_lock_)
    pmd->DumpHeapUsage(metrics_by_context, overhead, "malloc");
  }
  tid_dumping_heap_ = kInvalidThreadId;

  return true;
}

void MallocDumpProvider::OnHeapProfilingEnabled(bool enabled) {
#if BUILDFLAG(USE_EXPERIMENTAL_ALLOCATOR_SHIM)
  if (enabled) {
    {
      AutoLock lock(allocation_register_lock_);
      allocation_register_.reset(new AllocationRegister());
    }
    allocator::InsertAllocatorDispatch(&g_allocator_hooks);
  } else {
    AutoLock lock(allocation_register_lock_);
    allocation_register_.reset();
    // Insert/RemoveAllocation below will no-op if the register is torn down.
    // Once disabled, heap profiling will not re-enabled anymore for the
    // lifetime of the process.
  }
#endif
  heap_profiler_enabled_ = enabled;
}

void MallocDumpProvider::InsertAllocation(void* address, size_t size) {
  // CurrentId() can be a slow operation (crbug.com/497226). This apparently
  // redundant condition short circuits the CurrentID() calls when unnecessary.
  if (tid_dumping_heap_ != kInvalidThreadId &&
      tid_dumping_heap_ == PlatformThread::CurrentId())
    return;

  // AllocationContextTracker will return nullptr when called re-reentrantly.
  // This is the case of GetInstanceForCurrentThread() being called for the
  // first time, which causes a new() inside the tracker which re-enters the
  // heap profiler, in which case we just want to early out.
  auto* tracker = AllocationContextTracker::GetInstanceForCurrentThread();
  if (!tracker)
    return;
  AllocationContext context = tracker->GetContextSnapshot();

  AutoLock lock(allocation_register_lock_);
  if (!allocation_register_)
    return;

  allocation_register_->Insert(address, size, context);
}

void MallocDumpProvider::RemoveAllocation(void* address) {
  // No re-entrancy is expected here as none of the calls below should
  // cause a free()-s (|allocation_register_| does its own heap management).
  if (tid_dumping_heap_ != kInvalidThreadId &&
      tid_dumping_heap_ == PlatformThread::CurrentId())
    return;
  AutoLock lock(allocation_register_lock_);
  if (!allocation_register_)
    return;
  allocation_register_->Remove(address);
}

}  // namespace trace_event
}  // namespace base
