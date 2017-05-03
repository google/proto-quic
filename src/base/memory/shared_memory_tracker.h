// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_MEMORY_SHARED_MEMORY_TRACKER_H_
#define BASE_MEMORY_SHARED_MEMORY_TRACKER_H_

#include <unordered_map>

#include "base/memory/shared_memory.h"
#include "base/synchronization/lock.h"
#include "base/trace_event/memory_dump_provider.h"

namespace base {

namespace trace_event {
class ProcessMemoryDump;
}

// SharedMemoryTracker tracks shared memory usage.
class BASE_EXPORT SharedMemoryTracker
    : public base::trace_event::MemoryDumpProvider {
 public:
  // Returns a singleton instance.
  static SharedMemoryTracker* GetInstance();

  // Records shared memory usage on mapping.
  void IncrementMemoryUsage(const SharedMemory& shared_memory);

  // Records shared memory usage on unmapping.
  void DecrementMemoryUsage(const SharedMemory& shared_memory);

 private:
  struct Usage {
    Usage();
    Usage(const Usage& rhs);
    ~Usage();
    SharedMemory::UniqueId unique_id;
    size_t size;
  };

  SharedMemoryTracker();
  ~SharedMemoryTracker() override;

  // base::trace_event::MemoryDumpProvider implementation.
  bool OnMemoryDump(const base::trace_event::MemoryDumpArgs& args,
                    base::trace_event::ProcessMemoryDump* pmd) override;

  // Used to lock when |usages_| is modified or read.
  Lock usages_lock_;
  std::unordered_map<const SharedMemory*, Usage> usages_;

  DISALLOW_COPY_AND_ASSIGN(SharedMemoryTracker);
};

}  // namespace base

#endif  // BASE_MEMORY_SHARED_MEMORY_TRACKER_H_
