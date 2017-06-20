// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_HEAP_PROFILER_EVENT_WRITER_H_
#define BASE_TRACE_EVENT_HEAP_PROFILER_EVENT_WRITER_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <unordered_map>

#include "base/base_export.h"

/*
  Heap profile event data format.

  Input is:
    1. Per allocator AllocationRegister
    2. Per process deduplicators (for stack frames, types, strings)

  Formatting event data is done in two steps:
    1. Call SerializeHeapDump() on allocation registers and accumulate
       results in SerializedHeapDumpsMap. SerializeHeapDump() exports
       allocation register as "allocators/<allocator>" dictionary outlined
       below; serialization uses deduplicators from MemoryDumpSessionState.
    2. Call SerializeHeapProfileEventData() with SerializedHeapDumpsMap and
       MemoryDumpSessionState. This puts everything together:
       a. Entries from SerializedHeapDumpsMap are formatted as
          "allocators/<allocator>" nodes.
       b. Deduplicators from MemoryDumpSessionState are formatted as
          "maps/" nodes. Deduplicators are exported incrementally using
          their ExportIncrementally() methods.

  SerializeHeapDump() aggregates allocation register entries first by backtrace,
  then by type (i.e. creates map {(backtrace, type) -> AllocationMetrics}).
  During aggregation backtraces and types are deduplicated.

  Resulting event data format:
  {
    "version": 1,

    "allocators": {
      ["malloc", "partition_alloc", "blinkgc"]: {
        "nodes":  [<stack_frame_id1>, <stack_frame_id2>, ...],
        "types":  [<type_id1>,        <type_id2>,        ...],
        "counts": [<count1>,          <count2>,          ...],
        "sizes":  [<size1>,           <size2>,           ...]
      }
    },

    "maps": {
      "nodes": [
        {
          "id": <stack_frame_id>,
          "parent": <parent_id>,
          "name_sid": <name_string_id>
        },
        ...
      ],
      "types": [
        {
          "id": <type_id>,
          "name_sid": <name_string_id>
        }
      ],
      "strings": [
        {
          "id": <string_id>,
          "string": <string>
        }
      ]
    }
  }
*/

namespace base {
namespace trace_event {

class ShardedAllocationRegister;
class HeapProfilerSerializationState;
class TracedValue;

// Exports heap allocations as "allocators/<allocator>" dictionary described
// above. Return value is supposed to be added to SerializedHeapDumpsMap map
// and later passed to SerializeHeapProfileEventData().
BASE_EXPORT std::unique_ptr<TracedValue> SerializeHeapDump(
    const ShardedAllocationRegister& allocation_register,
    HeapProfilerSerializationState* serialization_state);

// Maps allocator name to its heap dump.
using SerializedHeapDumpsMap =
    std::unordered_map<std::string, std::unique_ptr<TracedValue>>;

// Exports event data according to the format described above.
BASE_EXPORT std::unique_ptr<TracedValue> SerializeHeapProfileEventData(
    const SerializedHeapDumpsMap& heap_dumps,
    HeapProfilerSerializationState* serialization_state);

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_HEAP_PROFILER_EVENT_WRITER_H_
