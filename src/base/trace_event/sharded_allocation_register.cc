// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/sharded_allocation_register.h"

#include "base/trace_event/trace_event_memory_overhead.h"
#include "build/build_config.h"

namespace base {
namespace trace_event {

// This number affects the bucket and capacity counts of AllocationRegister at
// "base/trace_event/heap_profiler_allocation_register.h".
#if defined(OS_ANDROID) || defined(OS_IOS)
const size_t ShardCount = 1;
#elif defined(OS_WIN)
// Using ShardCount = 64 adds about 1.6GB of committed memory, which triggers
// the sandbox's committed memory limit.
const size_t ShardCount = 16;
#else
const size_t ShardCount = 64;
#endif

ShardedAllocationRegister::ShardedAllocationRegister() : enabled_(false) {}

ShardedAllocationRegister::~ShardedAllocationRegister() = default;

void ShardedAllocationRegister::SetEnabled() {
  if (!allocation_registers_)
    allocation_registers_.reset(new RegisterAndLock[ShardCount]);
  base::subtle::Release_Store(&enabled_, 1);
}

void ShardedAllocationRegister::SetDisabled() {
  base::subtle::Release_Store(&enabled_, 0);
}

bool ShardedAllocationRegister::Insert(const void* address,
                                       size_t size,
                                       const AllocationContext& context) {
  AllocationRegister::AddressHasher hasher;
  size_t index = hasher(address) % ShardCount;
  RegisterAndLock& ral = allocation_registers_[index];
  AutoLock lock(ral.lock);
  return ral.allocation_register.Insert(address, size, context);
}

void ShardedAllocationRegister::Remove(const void* address) {
  AllocationRegister::AddressHasher hasher;
  size_t index = hasher(address) % ShardCount;
  RegisterAndLock& ral = allocation_registers_[index];
  AutoLock lock(ral.lock);
  return ral.allocation_register.Remove(address);
}

void ShardedAllocationRegister::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) const {
  size_t allocated = 0;
  size_t resident = 0;
  for (size_t i = 0; i < ShardCount; ++i) {
    RegisterAndLock& ral = allocation_registers_[i];
    AutoLock lock(ral.lock);
    allocated += ral.allocation_register.EstimateAllocatedMemory();
    resident += ral.allocation_register.EstimateResidentMemory();
  }

  overhead->Add(TraceEventMemoryOverhead::kHeapProfilerAllocationRegister,
                allocated, resident);
}

void ShardedAllocationRegister::VisitAllocations(
    const AllocationVisitor& visitor) const {
  for (size_t i = 0; i < ShardCount; ++i) {
    RegisterAndLock& ral = allocation_registers_[i];
    AutoLock lock(ral.lock);
    for (const auto& alloc : ral.allocation_register) {
      visitor.Run(alloc);
    }
  }
}

ShardedAllocationRegister::RegisterAndLock::RegisterAndLock() = default;
ShardedAllocationRegister::RegisterAndLock::~RegisterAndLock() = default;

}  // namespace trace_event
}  // namespace base
