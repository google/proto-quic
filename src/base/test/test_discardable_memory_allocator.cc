// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/test_discardable_memory_allocator.h"

#include <cstdint>
#include <cstring>

#include "base/logging.h"
#include "base/memory/discardable_memory.h"
#include "base/memory/ptr_util.h"

namespace base {
namespace {

class DiscardableMemoryImpl : public DiscardableMemory {
 public:
  explicit DiscardableMemoryImpl(size_t size)
      : data_(new uint8_t[size]), size_(size) {}

  // Overridden from DiscardableMemory:
  bool Lock() override {
    DCHECK(!is_locked_);
    is_locked_ = true;
    return false;
  }

  void Unlock() override {
    DCHECK(is_locked_);
    is_locked_ = false;
    // Force eviction to catch clients not correctly checking the return value
    // of Lock().
    memset(data_.get(), 0, size_);
  }

  void* data() const override {
    DCHECK(is_locked_);
    return data_.get();
  }

  trace_event::MemoryAllocatorDump* CreateMemoryAllocatorDump(
      const char* name,
      trace_event::ProcessMemoryDump* pmd) const override {
    return nullptr;
  }

 private:
  bool is_locked_ = true;
  std::unique_ptr<uint8_t[]> data_;
  size_t size_;
};

}  // namespace

TestDiscardableMemoryAllocator::TestDiscardableMemoryAllocator() {
}

TestDiscardableMemoryAllocator::~TestDiscardableMemoryAllocator() {
}

std::unique_ptr<DiscardableMemory>
TestDiscardableMemoryAllocator::AllocateLockedDiscardableMemory(size_t size) {
  return MakeUnique<DiscardableMemoryImpl>(size);
}

}  // namespace base
