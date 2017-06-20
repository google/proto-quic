// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_serialization_state.h"

#include "base/memory/ptr_util.h"
#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"
#include "base/trace_event/heap_profiler_string_deduplicator.h"
#include "base/trace_event/heap_profiler_type_name_deduplicator.h"

namespace base {
namespace trace_event {

HeapProfilerSerializationState::HeapProfilerSerializationState()
    : heap_profiler_breakdown_threshold_bytes_(0) {}
HeapProfilerSerializationState::~HeapProfilerSerializationState() {}

void HeapProfilerSerializationState::CreateDeduplicators() {
  string_deduplicator_ = base::MakeUnique<StringDeduplicator>();
  stack_frame_deduplicator_ =
      base::MakeUnique<StackFrameDeduplicator>(string_deduplicator_.get());
  type_name_deduplicator_ =
      base::MakeUnique<TypeNameDeduplicator>(string_deduplicator_.get());
}

}  // namespace trace_event
}  // namespace base
