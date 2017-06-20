// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_event_writer.h"

#include <stdint.h>

#include <tuple>
#include <unordered_map>

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/safe_conversions.h"
#include "base/trace_event/heap_profiler_serialization_state.h"
#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"
#include "base/trace_event/heap_profiler_string_deduplicator.h"
#include "base/trace_event/heap_profiler_type_name_deduplicator.h"
#include "base/trace_event/sharded_allocation_register.h"
#include "base/trace_event/trace_event_argument.h"

namespace base {
namespace trace_event {

namespace {

struct AggregationKey {
  int backtrace_id;
  int type_id;

  struct Hasher {
    size_t operator()(const AggregationKey& key) const {
      return base::HashInts(key.backtrace_id, key.type_id);
    }
  };

  bool operator==(const AggregationKey& other) const {
    return backtrace_id == other.backtrace_id && type_id == other.type_id;
  }
};

}  // namespace

std::unique_ptr<TracedValue> SerializeHeapDump(
    const ShardedAllocationRegister& allocation_register,
    HeapProfilerSerializationState* serialization_state) {
  // Aggregate allocations by {backtrace_id, type_id} key.
  using MetricsMap = std::unordered_map<AggregationKey, AllocationMetrics,
                                        AggregationKey::Hasher>;
  MetricsMap metrics_by_key;

  auto visit_allocation =
      [](HeapProfilerSerializationState* serialization_state,
         MetricsMap* metrics_by_key,
         const AllocationRegister::Allocation& allocation) {
        int backtrace_id =
            serialization_state->stack_frame_deduplicator()->Insert(
                std::begin(allocation.context.backtrace.frames),
                std::begin(allocation.context.backtrace.frames) +
                    allocation.context.backtrace.frame_count);

        int type_id = serialization_state->type_name_deduplicator()->Insert(
            allocation.context.type_name);

        AggregationKey key = {backtrace_id, type_id};
        AllocationMetrics& metrics = (*metrics_by_key)[key];
        metrics.size += allocation.size;
        metrics.count += 1;
      };
  allocation_register.VisitAllocations(base::BindRepeating(
      visit_allocation, base::Unretained(serialization_state),
      base::Unretained(&metrics_by_key)));

  auto traced_value = MakeUnique<TracedValue>();

  traced_value->BeginArray("nodes");
  for (const auto& key_and_metrics : metrics_by_key)
    traced_value->AppendInteger(key_and_metrics.first.backtrace_id);
  traced_value->EndArray();

  traced_value->BeginArray("types");
  for (const auto& key_and_metrics : metrics_by_key)
    traced_value->AppendInteger(key_and_metrics.first.type_id);
  traced_value->EndArray();

  traced_value->BeginArray("counts");
  for (const auto& key_and_metrics : metrics_by_key)
    traced_value->AppendInteger(
        saturated_cast<int>(key_and_metrics.second.count));
  traced_value->EndArray();

  traced_value->BeginArray("sizes");
  for (const auto& key_and_metrics : metrics_by_key)
    traced_value->AppendInteger(
        saturated_cast<int>(key_and_metrics.second.size));
  traced_value->EndArray();

  return traced_value;
}

std::unique_ptr<TracedValue> SerializeHeapProfileEventData(
    const SerializedHeapDumpsMap& heap_dumps,
    HeapProfilerSerializationState* serialization_state) {
  auto traced_value = MakeUnique<TracedValue>();

  // See brief description of the format in the header file.
  traced_value->SetInteger("version", 1);

  traced_value->BeginDictionary("allocators");
  for (const auto& name_and_dump : heap_dumps) {
    traced_value->SetValueWithCopiedName(name_and_dump.first.c_str(),
                                         *name_and_dump.second);
  }
  traced_value->EndDictionary();

  traced_value->BeginDictionary("maps");

  if (auto* deduplicator = serialization_state->stack_frame_deduplicator()) {
    traced_value->BeginArray("nodes");
    deduplicator->SerializeIncrementally(&*traced_value);
    traced_value->EndArray();
  }

  if (auto* deduplicator = serialization_state->type_name_deduplicator()) {
    traced_value->BeginArray("types");
    deduplicator->SerializeIncrementally(&*traced_value);
    traced_value->EndArray();
  }

  if (auto* deduplicator = serialization_state->string_deduplicator()) {
    traced_value->BeginArray("strings");
    deduplicator->SerializeIncrementally(&*traced_value);
    traced_value->EndArray();
  }

  traced_value->EndDictionary();

  return traced_value;
}

}  // namespace trace_event
}  // namespace base
