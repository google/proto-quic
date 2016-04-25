// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_HEAP_PROFILER_H
#define BASE_TRACE_EVENT_HEAP_PROFILER_H

#include "base/compiler_specific.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"

// This header file defines the set of macros that are used to track memory
// usage in the heap profiler. This is in addition to the macros defined in
// trace_event.h and are specific to heap profiler. This file also defines
// implementation details of these macros.

// Implementation detail: heap profiler macros create temporary variables to
// keep instrumentation overhead low. These macros give each temporary variable
// a unique name based on the line number to prevent name collisions.
#define INTERNAL_HEAP_PROFILER_UID3(a, b) heap_profiler_unique_##a##b
#define INTERNAL_HEAP_PROFILER_UID2(a, b) INTERNAL_HEAP_PROFILER_UID3(a, b)
#define INTERNAL_HEAP_PROFILER_UID(name_prefix) \
  INTERNAL_HEAP_PROFILER_UID2(name_prefix, __LINE__)

// A scoped ignore event used to tell heap profiler to ignore all the
// allocations in the scope. It is useful to exclude allocations made for
// tracing from the heap profiler dumps.
#define HEAP_PROFILER_SCOPED_IGNORE                                          \
  trace_event_internal::HeapProfilerScopedIgnore INTERNAL_HEAP_PROFILER_UID( \
      scoped_ignore)

namespace trace_event_internal {

class BASE_EXPORT HeapProfilerScopedIgnore {
 public:
  inline HeapProfilerScopedIgnore() {
    if (UNLIKELY(
            base::trace_event::AllocationContextTracker::capture_enabled())) {
      base::trace_event::AllocationContextTracker::GetInstanceForCurrentThread()
          ->begin_ignore_scope();
    }
  }
  inline ~HeapProfilerScopedIgnore() {
    if (UNLIKELY(
            base::trace_event::AllocationContextTracker::capture_enabled())) {
      base::trace_event::AllocationContextTracker::GetInstanceForCurrentThread()
          ->end_ignore_scope();
    }
  }
};

}  // namespace trace_event_internal

#endif  // BASE_TRACE_EVENT_HEAP_PROFILER_H
