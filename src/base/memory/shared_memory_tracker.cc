// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/shared_memory_tracker.h"

#include "base/memory/shared_memory.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/process_memory_dump.h"

namespace base {

SharedMemoryTracker::Usage::Usage() = default;

SharedMemoryTracker::Usage::Usage(const Usage& rhs) = default;

SharedMemoryTracker::Usage::~Usage() = default;

// static
SharedMemoryTracker* SharedMemoryTracker::GetInstance() {
  static SharedMemoryTracker* instance = new SharedMemoryTracker;
  return instance;
}

void SharedMemoryTracker::IncrementMemoryUsage(
    const SharedMemory& shared_memory) {
  Usage usage;
  // |shared_memory|'s unique ID must be generated here and it'd be too late at
  // OnMemoryDump. An ID is generated with a SharedMemoryHandle, but the handle
  // might already be closed at that time. Now IncrementMemoryUsage is called
  // just after mmap and the handle must live then. See the discussion at
  // crbug.com/604726#c30.
  SharedMemory::UniqueId id;
  if (!shared_memory.GetUniqueId(&id))
    return;
  usage.unique_id = id;
  usage.size = shared_memory.mapped_size();
  AutoLock hold(usages_lock_);
  usages_[&shared_memory] = usage;
}

void SharedMemoryTracker::DecrementMemoryUsage(
    const SharedMemory& shared_memory) {
  AutoLock hold(usages_lock_);
  usages_.erase(&shared_memory);
}

bool SharedMemoryTracker::OnMemoryDump(const trace_event::MemoryDumpArgs& args,
                                       trace_event::ProcessMemoryDump* pmd) {
  std::unordered_map<SharedMemory::UniqueId, size_t, SharedMemory::UniqueIdHash>
      sizes;
  {
    AutoLock hold(usages_lock_);
    for (const auto& usage : usages_)
      sizes[usage.second.unique_id] += usage.second.size;
  }
  for (auto& size : sizes) {
    const SharedMemory::UniqueId& id = size.first;
    std::string dump_name = StringPrintf("%s/%lld.%lld", "shared_memory",
                                         static_cast<long long>(id.first),
                                         static_cast<long long>(id.second));
    auto guid = trace_event::MemoryAllocatorDumpGuid(dump_name);
    trace_event::MemoryAllocatorDump* local_dump =
        pmd->CreateAllocatorDump(dump_name);
    // TODO(hajimehoshi): The size is not resident size but virtual size so far.
    // Fix this to record resident size.
    local_dump->AddScalar(trace_event::MemoryAllocatorDump::kNameSize,
                          trace_event::MemoryAllocatorDump::kUnitsBytes,
                          size.second);
    trace_event::MemoryAllocatorDump* global_dump =
        pmd->CreateSharedGlobalAllocatorDump(guid);
    global_dump->AddScalar(trace_event::MemoryAllocatorDump::kNameSize,
                           trace_event::MemoryAllocatorDump::kUnitsBytes,
                           size.second);
    // TOOD(hajimehoshi): Detect which the shared memory comes from browser,
    // renderer or GPU process.
    // TODO(hajimehoshi): Shared memory reported by GPU and discardable is
    // currently double-counted. Add ownership edges to avoid this.
    pmd->AddOwnershipEdge(local_dump->guid(), global_dump->guid());
  }
  return true;
}

SharedMemoryTracker::SharedMemoryTracker() {
  trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      this, "SharedMemoryTracker", nullptr);
}

SharedMemoryTracker::~SharedMemoryTracker() = default;

}  // namespace
