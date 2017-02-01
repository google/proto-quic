// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/memory.h"

#include "base/allocator/allocator_interception_mac.h"
#include "build/build_config.h"

namespace base {

void EnableTerminationOnHeapCorruption() {
#if !ARCH_CPU_64_BITS
  DLOG(WARNING) << "EnableTerminationOnHeapCorruption only works on 64-bit";
#endif
}

bool UncheckedMalloc(size_t size, void** result) {
  return allocator::UncheckedMallocMac(size, result);
}

bool UncheckedCalloc(size_t num_items, size_t size, void** result) {
  return allocator::UncheckedCallocMac(num_items, size, result);
}

void EnableTerminationOnOutOfMemory() {
  allocator::InterceptAllocationsMac();
}

}  // namespace base
