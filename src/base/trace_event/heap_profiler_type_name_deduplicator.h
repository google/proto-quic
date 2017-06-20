// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_HEAP_PROFILER_TYPE_NAME_DEDUPLICATOR_H_
#define BASE_TRACE_EVENT_HEAP_PROFILER_TYPE_NAME_DEDUPLICATOR_H_

#include <map>
#include <string>
#include <vector>

#include "base/base_export.h"
#include "base/macros.h"

namespace base {
namespace trace_event {

class StringDeduplicator;
class TraceEventMemoryOverhead;
class TracedValue;

// Data structure that assigns a unique numeric ID to type names.
class BASE_EXPORT TypeNameDeduplicator {
 public:
  // |string_deduplication| is used during serialization, and is expected
  // to outlive instances of this class.
  explicit TypeNameDeduplicator(StringDeduplicator* string_deduplicator);
  ~TypeNameDeduplicator();

  // Inserts a type name and returns its ID.
  int Insert(const char* type_name);

  // Appends {ID -> type name} mappings that were added after the last call
  // to this function. |traced_value| must be in 'array' mode.
  void SerializeIncrementally(TracedValue* traced_value);

  // Estimates memory overhead including |sizeof(TypeNameDeduplicator)|.
  void EstimateTraceMemoryOverhead(TraceEventMemoryOverhead* overhead);

 private:
  StringDeduplicator* string_deduplicator_;

  // Map from type name to type ID. The reason this class has its own map
  // and does not use string_deduplicator_ in Insert() is that type names
  // are sometimes file names, and we need post-process them to extract
  // categories.
  using TypeMap = std::map<const char*, int>;
  TypeMap type_ids_;
  std::vector<const TypeMap::value_type*> new_type_ids_;

  DISALLOW_COPY_AND_ASSIGN(TypeNameDeduplicator);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_HEAP_PROFILER_TYPE_NAME_DEDUPLICATOR_H_
