// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_type_name_deduplicator.h"

#include <stddef.h>
#include <stdlib.h>
#include <string>
#include <utility>

#include "base/json/string_escape.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/trace_event_memory_overhead.h"

namespace base {
namespace trace_event {

TypeNameDeduplicator::TypeNameDeduplicator() {
  // A null pointer has type ID 0 ("unknown type");
  type_ids_.insert(std::make_pair(nullptr, 0));
}

TypeNameDeduplicator::~TypeNameDeduplicator() {}

int TypeNameDeduplicator::Insert(const char* type_name) {
  auto result = type_ids_.insert(std::make_pair(type_name, 0));
  auto& elem = result.first;
  bool did_not_exist_before = result.second;

  if (did_not_exist_before) {
    // The type IDs are assigned sequentially and they are zero-based, so
    // |size() - 1| is the ID of the new element.
    elem->second = static_cast<int>(type_ids_.size() - 1);
  }

  return elem->second;
}

void TypeNameDeduplicator::AppendAsTraceFormat(std::string* out) const {
  out->append("{");  // Begin the type names dictionary.

  auto it = type_ids_.begin();
  std::string buffer;

  // Write the first entry manually; the null pointer must not be dereferenced.
  // (The first entry is the null pointer because a |std::map| is ordered.)
  it++;
  out->append("\"0\":\"[unknown]\"");

  for (; it != type_ids_.end(); it++) {
    // Type IDs in the trace are strings, write them as stringified keys of
    // a dictionary.
    SStringPrintf(&buffer, ",\"%d\":", it->second);

    // |EscapeJSONString| appends, it does not overwrite |buffer|.
    bool put_in_quotes = true;
    EscapeJSONString(it->first, put_in_quotes, &buffer);
    out->append(buffer);
  }

  out->append("}");  // End the type names dictionary.
}

void TypeNameDeduplicator::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  // The size here is only an estimate; it fails to take into account the size
  // of the tree nodes for the map, but as an estimate this should be fine.
  size_t map_size = type_ids_.size() * sizeof(std::pair<const char*, int>);

  overhead->Add("TypeNameDeduplicator",
                sizeof(TypeNameDeduplicator) + map_size);
}

}  // namespace trace_event
}  // namespace base
