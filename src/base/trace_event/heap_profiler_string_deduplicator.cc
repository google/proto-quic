// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_string_deduplicator.h"

#include "base/trace_event/memory_usage_estimator.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/trace_event/trace_event_memory_overhead.h"

namespace base {
namespace trace_event {

StringDeduplicator::StringDeduplicator() : last_serialized_index_(0) {
  // Add implicit entry for id 0 (NULL strings).
  strings_.push_back("[null]");
}

StringDeduplicator::~StringDeduplicator() {}

int StringDeduplicator::Insert(StringPiece string) {
  if (!string.data()) {
    // NULL strings are mapped to id 0.
    return 0;
  }
  auto it = string_ids_.find(string);
  if (it != string_ids_.end())
    return it->second;

  // Insert new mapping. Note that |string_ids_| keys reference values
  // from |strings_|.
  int string_id = static_cast<int>(strings_.size());
  strings_.push_back(string.as_string());
  auto iter_and_flag = string_ids_.insert({strings_.back(), string_id});
  DCHECK(iter_and_flag.second);  // insert() must succeed
  return string_id;
}

void StringDeduplicator::SerializeIncrementally(TracedValue* traced_value) {
  for (; last_serialized_index_ != strings_.size(); ++last_serialized_index_) {
    traced_value->BeginDictionary();
    traced_value->SetInteger("id", last_serialized_index_);
    traced_value->SetString("string", strings_[last_serialized_index_]);
    traced_value->EndDictionary();
  }
}

void StringDeduplicator::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  size_t memory_usage =
      EstimateMemoryUsage(string_ids_) + EstimateMemoryUsage(strings_);
  overhead->Add(TraceEventMemoryOverhead::kHeapProfilerStringDeduplicator,
                sizeof(StringDeduplicator) + memory_usage);
}

}  // namespace trace_event
}  // namespace base
