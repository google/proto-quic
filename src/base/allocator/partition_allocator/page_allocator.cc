// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/partition_allocator/page_allocator.h"

#include <limits.h>

#include "base/allocator/partition_allocator/address_space_randomization.h"
#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/logging.h"
#include "build/build_config.h"

#if defined(OS_POSIX)

#include <errno.h>
#include <sys/mman.h>

#ifndef MADV_FREE
#define MADV_FREE MADV_DONTNEED
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

// On POSIX |mmap| uses a nearby address if the hint address is blocked.
static const bool kHintIsAdvisory = true;
static volatile base::subtle::Atomic32 s_allocPageErrorCode = 0;

#elif defined(OS_WIN)

#include <windows.h>

// |VirtualAlloc| will fail if allocation at the hint address is blocked.
static const bool kHintIsAdvisory = false;
static base::subtle::Atomic32 s_allocPageErrorCode = ERROR_SUCCESS;

#else
#error Unknown OS
#endif  // defined(OS_POSIX)

namespace base {

// This internal function wraps the OS-specific page allocation call:
// |VirtualAlloc| on Windows, and |mmap| on POSIX.
static void* systemAllocPages(
    void* hint,
    size_t len,
    PageAccessibilityConfiguration pageAccessibility) {
  DCHECK(!(len & kPageAllocationGranularityOffsetMask));
  DCHECK(!(reinterpret_cast<uintptr_t>(hint) &
           kPageAllocationGranularityOffsetMask));
  void* ret;
#if defined(OS_WIN)
  DWORD accessFlag =
      pageAccessibility == PageAccessible ? PAGE_READWRITE : PAGE_NOACCESS;
  ret = VirtualAlloc(hint, len, MEM_RESERVE | MEM_COMMIT, accessFlag);
  if (!ret)
    base::subtle::Release_Store(&s_allocPageErrorCode, GetLastError());
#else
  int accessFlag = pageAccessibility == PageAccessible
                       ? (PROT_READ | PROT_WRITE)
                       : PROT_NONE;
  ret = mmap(hint, len, accessFlag, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (ret == MAP_FAILED) {
    base::subtle::Release_Store(&s_allocPageErrorCode, errno);
    ret = 0;
  }
#endif
  return ret;
}

// Trims base to given length and alignment. Windows returns null on failure and
// frees base.
static void* trimMapping(void* base,
                         size_t baseLen,
                         size_t trimLen,
                         uintptr_t align,
                         PageAccessibilityConfiguration pageAccessibility) {
  size_t preSlack = reinterpret_cast<uintptr_t>(base) & (align - 1);
  if (preSlack)
    preSlack = align - preSlack;
  size_t postSlack = baseLen - preSlack - trimLen;
  DCHECK(baseLen >= trimLen || preSlack || postSlack);
  DCHECK(preSlack < baseLen);
  DCHECK(postSlack < baseLen);
  void* ret = base;

#if defined(OS_POSIX)  // On POSIX we can resize the allocation run.
  (void)pageAccessibility;
  if (preSlack) {
    int res = munmap(base, preSlack);
    CHECK(!res);
    ret = reinterpret_cast<char*>(base) + preSlack;
  }
  if (postSlack) {
    int res = munmap(reinterpret_cast<char*>(ret) + trimLen, postSlack);
    CHECK(!res);
  }
#else  // On Windows we can't resize the allocation run.
  if (preSlack || postSlack) {
    ret = reinterpret_cast<char*>(base) + preSlack;
    freePages(base, baseLen);
    ret = systemAllocPages(ret, trimLen, pageAccessibility);
  }
#endif

  return ret;
}

void* allocPages(void* addr,
                 size_t len,
                 size_t align,
                 PageAccessibilityConfiguration pageAccessibility) {
  DCHECK(len >= kPageAllocationGranularity);
  DCHECK(!(len & kPageAllocationGranularityOffsetMask));
  DCHECK(align >= kPageAllocationGranularity);
  DCHECK(!(align & kPageAllocationGranularityOffsetMask));
  DCHECK(!(reinterpret_cast<uintptr_t>(addr) &
           kPageAllocationGranularityOffsetMask));
  uintptr_t alignOffsetMask = align - 1;
  uintptr_t alignBaseMask = ~alignOffsetMask;
  DCHECK(!(reinterpret_cast<uintptr_t>(addr) & alignOffsetMask));

  // If the client passed null as the address, choose a good one.
  if (!addr) {
    addr = getRandomPageBase();
    addr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) &
                                   alignBaseMask);
  }

  // First try to force an exact-size, aligned allocation from our random base.
  for (int count = 0; count < 3; ++count) {
    void* ret = systemAllocPages(addr, len, pageAccessibility);
    if (kHintIsAdvisory || ret) {
      // If the alignment is to our liking, we're done.
      if (!(reinterpret_cast<uintptr_t>(ret) & alignOffsetMask))
        return ret;
      freePages(ret, len);
#if defined(ARCH_CPU_32_BITS)
      addr = reinterpret_cast<void*>(
          (reinterpret_cast<uintptr_t>(ret) + align) & alignBaseMask);
#endif
    } else if (!addr) {  // We know we're OOM when an unhinted allocation fails.
      return nullptr;

    } else {
#if defined(ARCH_CPU_32_BITS)
      addr = reinterpret_cast<char*>(addr) + align;
#endif
    }

#if !defined(ARCH_CPU_32_BITS)
    // Keep trying random addresses on systems that have a large address space.
    addr = getRandomPageBase();
    addr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) &
                                   alignBaseMask);
#endif
  }

  // Map a larger allocation so we can force alignment, but continue randomizing
  // only on 64-bit POSIX.
  size_t tryLen = len + (align - kPageAllocationGranularity);
  CHECK(tryLen >= len);
  void* ret;

  do {
    // Don't continue to burn cycles on mandatory hints (Windows).
    addr = kHintIsAdvisory ? getRandomPageBase() : nullptr;
    ret = systemAllocPages(addr, tryLen, pageAccessibility);
    // The retries are for Windows, where a race can steal our mapping on
    // resize.
  } while (ret &&
           (ret = trimMapping(ret, tryLen, len, align, pageAccessibility)) ==
               nullptr);

  return ret;
}

void freePages(void* addr, size_t len) {
  DCHECK(!(reinterpret_cast<uintptr_t>(addr) &
           kPageAllocationGranularityOffsetMask));
  DCHECK(!(len & kPageAllocationGranularityOffsetMask));
#if defined(OS_POSIX)
  int ret = munmap(addr, len);
  CHECK(!ret);
#else
  BOOL ret = VirtualFree(addr, 0, MEM_RELEASE);
  CHECK(ret);
#endif
}

void setSystemPagesInaccessible(void* addr, size_t len) {
  DCHECK(!(len & kSystemPageOffsetMask));
#if defined(OS_POSIX)
  int ret = mprotect(addr, len, PROT_NONE);
  CHECK(!ret);
#else
  BOOL ret = VirtualFree(addr, len, MEM_DECOMMIT);
  CHECK(ret);
#endif
}

bool setSystemPagesAccessible(void* addr, size_t len) {
  DCHECK(!(len & kSystemPageOffsetMask));
#if defined(OS_POSIX)
  return !mprotect(addr, len, PROT_READ | PROT_WRITE);
#else
  return !!VirtualAlloc(addr, len, MEM_COMMIT, PAGE_READWRITE);
#endif
}

void decommitSystemPages(void* addr, size_t len) {
  DCHECK(!(len & kSystemPageOffsetMask));
#if defined(OS_POSIX)
  int ret = madvise(addr, len, MADV_FREE);
  if (ret != 0 && errno == EINVAL) {
    // MADV_FREE only works on Linux 4.5+ . If request failed,
    // retry with older MADV_DONTNEED . Note that MADV_FREE
    // being defined at compile time doesn't imply runtime support.
    ret = madvise(addr, len, MADV_DONTNEED);
  }
  CHECK(!ret);
#else
  setSystemPagesInaccessible(addr, len);
#endif
}

void recommitSystemPages(void* addr, size_t len) {
  DCHECK(!(len & kSystemPageOffsetMask));
#if defined(OS_POSIX)
  (void)addr;
#else
  CHECK(setSystemPagesAccessible(addr, len));
#endif
}

void discardSystemPages(void* addr, size_t len) {
  DCHECK(!(len & kSystemPageOffsetMask));
#if defined(OS_POSIX)
  // On POSIX, the implementation detail is that discard and decommit are the
  // same, and lead to pages that are returned to the system immediately and
  // get replaced with zeroed pages when touched. So we just call
  // decommitSystemPages() here to avoid code duplication.
  decommitSystemPages(addr, len);
#else
  // On Windows discarded pages are not returned to the system immediately and
  // not guaranteed to be zeroed when returned to the application.
  using DiscardVirtualMemoryFunction =
      DWORD(WINAPI*)(PVOID virtualAddress, SIZE_T size);
  static DiscardVirtualMemoryFunction discardVirtualMemory =
      reinterpret_cast<DiscardVirtualMemoryFunction>(-1);
  if (discardVirtualMemory ==
      reinterpret_cast<DiscardVirtualMemoryFunction>(-1))
    discardVirtualMemory =
        reinterpret_cast<DiscardVirtualMemoryFunction>(GetProcAddress(
            GetModuleHandle(L"Kernel32.dll"), "DiscardVirtualMemory"));
  // Use DiscardVirtualMemory when available because it releases faster than
  // MEM_RESET.
  DWORD ret = 1;
  if (discardVirtualMemory)
    ret = discardVirtualMemory(addr, len);
  // DiscardVirtualMemory is buggy in Win10 SP0, so fall back to MEM_RESET on
  // failure.
  if (ret) {
    void* ret = VirtualAlloc(addr, len, MEM_RESET, PAGE_READWRITE);
    CHECK(ret);
  }
#endif
}

uint32_t getAllocPageErrorCode() {
  return base::subtle::Acquire_Load(&s_allocPageErrorCode);
}

}  // namespace base
