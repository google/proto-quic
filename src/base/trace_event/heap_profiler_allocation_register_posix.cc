// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_allocation_register.h"

#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

#include "base/bits.h"
#include "base/logging.h"
#include "base/process/process_metrics.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#if defined(OS_FUCHSIA)
#include <magenta/process.h>
#include <magenta/syscalls.h>
#endif  // OS_FUCHSIA

namespace base {
namespace trace_event {
namespace internal {

namespace {
size_t GetGuardSize() {
  return GetPageSize();
}
}

void* AllocateGuardedVirtualMemory(size_t size) {
  size = bits::Align(size, GetPageSize());

  // Add space for a guard page at the end.
  size_t map_size = size + GetGuardSize();

#if defined(OS_FUCHSIA)
  // Fuchsia does not currently support PROT_NONE, see MG-546 upstream. Instead,
  // create a virtual mapping with the size of the guard page unmapped after the
  // block.
  mx_handle_t vmo;
  CHECK(mx_vmo_create(size, 0, &vmo) == MX_OK);
  mx_handle_t vmar;
  uintptr_t addr_uint;
  CHECK(mx_vmar_allocate(mx_vmar_root_self(), 0, map_size,
                         MX_VM_FLAG_CAN_MAP_READ | MX_VM_FLAG_CAN_MAP_WRITE |
                             MX_VM_FLAG_CAN_MAP_SPECIFIC,
                         &vmar, &addr_uint) == MX_OK);
  CHECK(mx_vmar_map(
            vmar, 0, vmo, 0, size,
            MX_VM_FLAG_PERM_READ | MX_VM_FLAG_PERM_WRITE | MX_VM_FLAG_SPECIFIC,
            &addr_uint) == MX_OK);
  CHECK(mx_handle_close(vmar) == MX_OK);
  CHECK(mx_handle_close(vmo) == MX_OK);
  void* addr = reinterpret_cast<void*>(addr_uint);
#else
  void* addr = mmap(nullptr, map_size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  PCHECK(addr != MAP_FAILED);

  // Mark the last page of the allocated address space as inaccessible
  // (PROT_NONE). The read/write accessible space is still at least |size|
  // bytes.
  void* guard_addr =
      reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) + size);
  int result = mprotect(guard_addr, GetGuardSize(), PROT_NONE);
  PCHECK(result == 0);
#endif  // defined(OS_FUCHSIA)

  return addr;
}

void FreeGuardedVirtualMemory(void* address, size_t allocated_size) {
  size_t size = bits::Align(allocated_size, GetPageSize()) + GetGuardSize();
#if defined(OS_FUCHSIA)
  mx_status_t status = mx_vmar_unmap(
      mx_vmar_root_self(), reinterpret_cast<uintptr_t>(address), size);
  if (status != MX_OK) {
    DLOG(ERROR) << "mx_vmar_unmap failed, status=" << status;
  }
#else
  munmap(address, size);
#endif
}

}  // namespace internal
}  // namespace trace_event
}  // namespace base
