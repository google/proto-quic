// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_HEAP_PROFILER_STRING_DEDUPLICATOR_H_
#define BASE_TRACE_EVENT_HEAP_PROFILER_STRING_DEDUPLICATOR_H_

#include <deque>
#include <string>
#include <unordered_map>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"

namespace base {
namespace trace_event {

class TraceEventMemoryOverhead;
class TracedValue;

// Data structure that assigns a unique numeric ID to |const char*|s.
class BASE_EXPORT StringDeduplicator {
 public:
  StringDeduplicator();
  ~StringDeduplicator();

  // Inserts a string and returns its ID.
  int Insert(StringPiece string);

  // Append {ID -> string} mappings that were added after the last call
  // to this function.
  void SerializeIncrementally(TracedValue* traced_value);

  // Estimates memory overhead including |sizeof(StringDeduplicator)|.
  void EstimateTraceMemoryOverhead(TraceEventMemoryOverhead* overhead);

 private:
  // StringPieces in the map reference values from |string_|.
  std::unordered_map<StringPiece, int, StringPieceHash> string_ids_;
  std::deque<std::string> strings_;
  size_t last_serialized_index_;

  DISALLOW_COPY_AND_ASSIGN(StringDeduplicator);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_HEAP_PROFILER_STRING_DEDUPLICATOR_H_
