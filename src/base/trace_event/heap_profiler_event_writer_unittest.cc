// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_event_writer.h"

#include <stdint.h>

#include <algorithm>

#include "base/memory/ptr_util.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "base/trace_event/heap_profiler_serialization_state.h"
#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"
#include "base/trace_event/heap_profiler_type_name_deduplicator.h"
#include "base/trace_event/sharded_allocation_register.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

namespace {

using base::trace_event::StackFrame;

// Define all strings once, because the deduplicator requires pointer equality,
// and string interning is unreliable.
StackFrame kBrowserMain = StackFrame::FromTraceEventName("BrowserMain");
StackFrame kRendererMain = StackFrame::FromTraceEventName("RendererMain");
StackFrame kCreateWidget = StackFrame::FromTraceEventName("CreateWidget");
StackFrame kInitialize = StackFrame::FromTraceEventName("Initialize");
StackFrame kGetBitmap = StackFrame::FromTraceEventName("GetBitmap");

const char kInt[] = "int";
const char kBool[] = "bool";

class AllocationRegisterHelper : public ShardedAllocationRegister {
 public:
  AllocationRegisterHelper() : next_address_(0x100000) { SetEnabled(); }

  void Allocate(size_t size,
                const char* type_name,
                std::initializer_list<StackFrame> backtrace) {
    AllocationContext context;
    context.backtrace.frame_count = backtrace.size();
    std::copy(backtrace.begin(), backtrace.end(),
              std::begin(context.backtrace.frames));
    context.type_name = type_name;
    Insert(reinterpret_cast<void*>(next_address_), size, context);
    next_address_ += size;
  }

 private:
  uintptr_t next_address_;
};

struct HeapDumpEntry {
  int backtrace_id;
  int type_id;
  int size;
  int count;

  bool operator==(const HeapDumpEntry& other) const {
    return backtrace_id == other.backtrace_id && type_id == other.type_id &&
           size == other.size && count == other.count;
  }
};

::testing::AssertionResult AssertHeapDump(
    const DictionaryValue& heap_dump,
    std::initializer_list<HeapDumpEntry> expected_entries) {
  auto get_list_value = [&](const char* list_name, size_t index,
                            int* value) -> ::testing::AssertionResult {
    const ListValue* list = nullptr;
    if (!heap_dump.GetList(list_name, &list)) {
      return ::testing::AssertionFailure()
             << "'" << list_name << "' doesn't exist or is not a list";
    }
    if (list->GetSize() != expected_entries.size()) {
      return ::testing::AssertionFailure()
             << "size of '" << list_name << "' is " << list->GetSize()
             << ", expected " << expected_entries.size();
    }
    if (!list->GetInteger(index, value)) {
      return ::testing::AssertionFailure()
             << "'" << list_name << "' value at index " << index
             << " is not an integer";
    }
    return ::testing::AssertionSuccess();
  };

  constexpr size_t kValueCount = 4;  // nodes, types, counts, sizes
  if (heap_dump.size() != kValueCount) {
    return ::testing::AssertionFailure()
           << "heap dump has " << heap_dump.size() << " values"
           << ", expected " << kValueCount;
  }

  for (size_t i = 0; i != expected_entries.size(); ++i) {
    HeapDumpEntry entry;

    ::testing::AssertionResult assertion = ::testing::AssertionSuccess();
    if (!(assertion = get_list_value("nodes", i, &entry.backtrace_id)) ||
        !(assertion = get_list_value("types", i, &entry.type_id)) ||
        !(assertion = get_list_value("sizes", i, &entry.size)) ||
        !(assertion = get_list_value("counts", i, &entry.count))) {
      return assertion;
    }

    auto* entry_iter =
        std::find(expected_entries.begin(), expected_entries.end(), entry);
    if (entry_iter == expected_entries.end()) {
      return ::testing::AssertionFailure()
             << "unexpected HeapDumpEntry{" << entry.backtrace_id << ", "
             << entry.type_id << ", " << entry.size << ", " << entry.count
             << "} at index " << i;
    }
  }

  return ::testing::AssertionSuccess();
}

std::unique_ptr<DictionaryValue> ToDictionary(
    const std::unique_ptr<TracedValue>& traced_value) {
  if (!traced_value) {
    return nullptr;
  }
  return DictionaryValue::From(traced_value->ToBaseValue());
}

}  // namespace

TEST(EventWriterTest, HeapDumpNoBacktraceNoType) {
  AllocationRegisterHelper allocation_register;
  auto bt = {kBrowserMain};
  std::initializer_list<StackFrame> empty_bt = {};
  allocation_register.Allocate(10, nullptr, bt);
  allocation_register.Allocate(100, kInt, empty_bt);
  allocation_register.Allocate(1000, nullptr, empty_bt);

  auto state = make_scoped_refptr(new HeapProfilerSerializationState);
  state->CreateDeduplicators();
  auto heap_dump =
      ToDictionary(SerializeHeapDump(allocation_register, state.get()));
  ASSERT_TRUE(heap_dump);

  int bt_id =
      state->stack_frame_deduplicator()->Insert(std::begin(bt), std::end(bt));
  int int_id = state->type_name_deduplicator()->Insert(kInt);

  // NULL type and empty backtrace IDs should be 0.
  auto expected_entries = {
      HeapDumpEntry{bt_id, 0, 10, 1},    // no type
      HeapDumpEntry{0, int_id, 100, 1},  // no backtrace
      HeapDumpEntry{0, 0, 1000, 1},      // no type, no backtrace
  };
  ASSERT_TRUE(AssertHeapDump(*heap_dump, expected_entries))
      << "heap_dump = " << *heap_dump;
}

TEST(EventWriterTest, HeapDumpAggregation) {
  //
  // |- (no backtrace)   int*1, int*2, bool*3,
  // |                   (no type)*4, (no type)*5
  // |
  // |- kBrowserMain     (no type)*6, (no type)*7, (no type)*8
  // |-- kCreateWidget   int*10, bool*20
  // |---- kGetBitmap    int*100, int*200, bool*300
  //
  // Aggregation is done by {backtrace_id, type_id}, so the following
  // entries should be aggregated:
  //  - int*1 + int*2
  //  - (no type)*4 + (no type)*5
  //  - (no type)*6 + (no type)*7 + (no type)*8
  //  - int*100 + int*200

  AllocationRegisterHelper allocation_register;

  std::initializer_list<StackFrame> empty_bt = {};
  allocation_register.Allocate(1, kInt, empty_bt);
  allocation_register.Allocate(2, kInt, empty_bt);
  allocation_register.Allocate(3, kBool, empty_bt);
  allocation_register.Allocate(4, nullptr, empty_bt);
  allocation_register.Allocate(5, nullptr, empty_bt);

  auto bt1 = {kBrowserMain};
  allocation_register.Allocate(6, nullptr, bt1);
  allocation_register.Allocate(7, nullptr, bt1);
  allocation_register.Allocate(8, nullptr, bt1);

  auto bt2 = {kBrowserMain, kCreateWidget};
  allocation_register.Allocate(10, kInt, bt2);
  allocation_register.Allocate(20, kBool, bt2);

  auto bt3 = {kBrowserMain, kCreateWidget, kGetBitmap};
  allocation_register.Allocate(100, kInt, bt3);
  allocation_register.Allocate(200, kInt, bt3);
  allocation_register.Allocate(300, kBool, bt3);

  auto state = make_scoped_refptr(new HeapProfilerSerializationState);
  state->CreateDeduplicators();

  auto heap_dump =
      ToDictionary(SerializeHeapDump(allocation_register, state.get()));
  ASSERT_TRUE(heap_dump);

  int bt1_id =
      state->stack_frame_deduplicator()->Insert(std::begin(bt1), std::end(bt1));
  int bt2_id =
      state->stack_frame_deduplicator()->Insert(std::begin(bt2), std::end(bt2));
  int bt3_id =
      state->stack_frame_deduplicator()->Insert(std::begin(bt3), std::end(bt3));

  int int_id = state->type_name_deduplicator()->Insert(kInt);
  int bool_id = state->type_name_deduplicator()->Insert(kBool);

  auto expected_entries = {
      HeapDumpEntry{0, int_id, 3, 2},
      HeapDumpEntry{0, bool_id, 3, 1},
      HeapDumpEntry{0, 0, 9, 2},
      HeapDumpEntry{bt1_id, 0, 21, 3},
      HeapDumpEntry{bt2_id, int_id, 10, 1},
      HeapDumpEntry{bt2_id, bool_id, 20, 1},
      HeapDumpEntry{bt3_id, int_id, 300, 2},
      HeapDumpEntry{bt3_id, bool_id, 300, 1},
  };
  ASSERT_TRUE(AssertHeapDump(*heap_dump, expected_entries))
      << "heap_dump = " << *heap_dump;
}

TEST(EventWriterTest, SerializeHeapProfileEventData) {
  AllocationRegisterHelper foo_register;
  foo_register.Allocate(10, "Widget", {kBrowserMain, kCreateWidget});
  foo_register.Allocate(16, "int[]", {kBrowserMain, kCreateWidget});

  AllocationRegisterHelper bar_register;
  bar_register.Allocate(10, "Widget", {kRendererMain, kCreateWidget});
  bar_register.Allocate(71, "char[]", {kRendererMain});

  auto state = make_scoped_refptr(new HeapProfilerSerializationState);
  state->CreateDeduplicators();

  SerializedHeapDumpsMap heap_dumps;
  heap_dumps["foo"] = SerializeHeapDump(foo_register, state.get());
  heap_dumps["bar"] = SerializeHeapDump(bar_register, state.get());

  auto event_data =
      ToDictionary(SerializeHeapProfileEventData(heap_dumps, state.get()));
  ASSERT_TRUE(event_data);

  constexpr size_t kTopCount = 3;  // version, allocators, maps
  ASSERT_EQ(kTopCount, event_data->size());

  int version;
  ASSERT_TRUE(event_data->GetInteger("version", &version));
  ASSERT_EQ(1, version);

  const DictionaryValue* allocators;
  ASSERT_TRUE(event_data->GetDictionary("allocators", &allocators));
  {
    constexpr size_t kAllocatorCount = 2;  // foo, bar
    ASSERT_EQ(kAllocatorCount, allocators->size());

    const DictionaryValue* foo_dump;
    ASSERT_TRUE(allocators->GetDictionary("foo", &foo_dump));
    ASSERT_TRUE(ToDictionary(heap_dumps["foo"])->Equals(foo_dump));

    const DictionaryValue* bar_dump;
    ASSERT_TRUE(allocators->GetDictionary("bar", &bar_dump));
    ASSERT_TRUE(ToDictionary(heap_dumps["bar"])->Equals(bar_dump));
  }

  const DictionaryValue* maps;
  ASSERT_TRUE(event_data->GetDictionary("maps", &maps));
  {
    constexpr size_t kMapCount = 3;  // nodes, types, strings
    ASSERT_EQ(kMapCount, maps->size());

    ASSERT_TRUE(maps->HasKey("nodes"));
    ASSERT_TRUE(maps->HasKey("types"));
    ASSERT_TRUE(maps->HasKey("strings"));
  }
}

}  // namespace trace_event
}  // namespace base
