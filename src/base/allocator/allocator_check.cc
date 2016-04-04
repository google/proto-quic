// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/allocator/allocator_check.h"

#include "build/build_config.h"

#if defined(OS_WIN)
#include "base/allocator/allocator_shim_win.h"
#endif

#if defined(OS_LINUX)
#include <malloc.h>
#endif

namespace base {
namespace allocator {

bool IsAllocatorInitialized() {
#if defined(OS_WIN) && defined(ALLOCATOR_SHIM)
  // Set by allocator_shim_win.cc when the shimmed _set_new_mode() is called.
  return g_is_win_shim_layer_initialized;
#elif defined(OS_LINUX) && defined(USE_TCMALLOC) && \
    !defined(MEMORY_TOOL_REPLACES_ALLOCATOR)
// From third_party/tcmalloc/chromium/src/gperftools/tcmalloc.h.
// TODO(primiano): replace with an include once base can depend on allocator.
#define TC_MALLOPT_IS_OVERRIDDEN_BY_TCMALLOC 0xbeef42
  return (mallopt(TC_MALLOPT_IS_OVERRIDDEN_BY_TCMALLOC, 0) ==
          TC_MALLOPT_IS_OVERRIDDEN_BY_TCMALLOC);
#else
  return true;
#endif
}

}  // namespace allocator
}  // namespace base
