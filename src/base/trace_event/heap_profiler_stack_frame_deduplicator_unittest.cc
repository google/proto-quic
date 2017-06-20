// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"

#include <iterator>
#include <memory>

#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "base/trace_event/heap_profiler_string_deduplicator.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

namespace {

constexpr static int kInvalidStackFrameIndex =
    StackFrameDeduplicator::FrameNode::kInvalidFrameIndex;

// Calls StackFrameDeduplicator::SerializeIncrementally() and returns
// ListValue with serialized entries.
std::unique_ptr<ListValue> SerializeEntriesIncrementally(
    StackFrameDeduplicator* dedup) {
  TracedValue traced_value;
  traced_value.BeginArray("");
  dedup->SerializeIncrementally(&traced_value);
  traced_value.EndArray();

  auto base_value = traced_value.ToBaseValue();
  DictionaryValue* dictionary;
  std::unique_ptr<Value> entries;
  if (!base_value->GetAsDictionary(&dictionary) ||
      !dictionary->Remove("", &entries)) {
    return nullptr;
  }
  return ListValue::From(std::move(entries));
}

struct StackFrameMapping {
  StackFrameMapping(int id,
                    StackFrame frame,
                    int parent_id = kInvalidStackFrameIndex)
      : id(id), parent_id(parent_id) {
    EXPECT_EQ(StackFrame::Type::TRACE_EVENT_NAME, frame.type);
    name = static_cast<const char*>(frame.value);
  }

  int id;
  const char* name;
  int parent_id;
};

std::unique_ptr<ListValue> SerializeMappingsAsEntries(
    StringDeduplicator* string_dedup,
    std::initializer_list<StackFrameMapping> mappings) {
  auto entries = MakeUnique<ListValue>();
  for (const auto& mapping : mappings) {
    auto entry = MakeUnique<DictionaryValue>();
    entry->SetInteger("id", mapping.id);
    entry->SetInteger("name_sid", string_dedup->Insert(mapping.name));
    if (mapping.parent_id != kInvalidStackFrameIndex) {
      entry->SetInteger("parent", mapping.parent_id);
    }
    entries->Append(std::move(entry));
  }
  return entries;
}

void ExpectIncrementalEntries(
    StackFrameDeduplicator* dedup,
    StringDeduplicator* string_dedup,
    std::initializer_list<StackFrameMapping> mappings) {
  auto entries = SerializeEntriesIncrementally(dedup);
  ASSERT_TRUE(entries);

  auto expected_entries = SerializeMappingsAsEntries(string_dedup, mappings);
  ASSERT_TRUE(expected_entries->Equals(entries.get()))
      << "expected_entries = " << *expected_entries << "entries = " << *entries;
}

}  // namespace

// Define all strings once, because the deduplicator requires pointer equality,
// and string interning is unreliable.
StackFrame kBrowserMain = StackFrame::FromTraceEventName("BrowserMain");
StackFrame kRendererMain = StackFrame::FromTraceEventName("RendererMain");
StackFrame kCreateWidget = StackFrame::FromTraceEventName("CreateWidget");
StackFrame kInitialize = StackFrame::FromTraceEventName("Initialize");
StackFrame kMalloc = StackFrame::FromTraceEventName("malloc");
StackFrame kNull = StackFrame::FromTraceEventName(nullptr);

TEST(StackFrameDeduplicatorTest, ImplicitId0) {
  StackFrame null_bt[] = {kNull};

  // Empty backtraces (begin == end) are mapped to an implicitly added
  // node #0. However, backtrace with a single null frame is not empty,
  // and should be mapped to some other id.

  StringDeduplicator string_dedup;
  StackFrameDeduplicator dedup(&string_dedup);

  // Node #0 is added implicitly and corresponds to an empty backtrace.
  ASSERT_EQ(dedup.begin() + 1, dedup.end());
  ASSERT_EQ(0, dedup.Insert(std::begin(null_bt), std::begin(null_bt)));

  // Placeholder entry for ID 0 is a frame with NULL name and no parent.
  // However inserting such a frame should yield a different ID.
  ExpectIncrementalEntries(&dedup, &string_dedup, {{0, kNull}});
  ASSERT_EQ(1, dedup.Insert(std::begin(null_bt), std::end(null_bt)));
}

TEST(StackFrameDeduplicatorTest, SingleBacktrace) {
  StackFrame bt[] = {kBrowserMain, kCreateWidget, kMalloc};

  // The call tree should look like this (index in brackets).
  //
  // BrowserMain [1]
  //   CreateWidget [2]
  //     malloc [3]

  StringDeduplicator string_dedup;
  StackFrameDeduplicator dedup(&string_dedup);
  ASSERT_EQ(3, dedup.Insert(std::begin(bt), std::end(bt)));

  auto iter = dedup.begin() + 1;  // skip implicit node #0
  ASSERT_EQ(kBrowserMain, (iter + 0)->frame);
  ASSERT_EQ(kInvalidStackFrameIndex, (iter + 0)->parent_frame_index);

  ASSERT_EQ(kCreateWidget, (iter + 1)->frame);
  ASSERT_EQ(1, (iter + 1)->parent_frame_index);

  ASSERT_EQ(kMalloc, (iter + 2)->frame);
  ASSERT_EQ(2, (iter + 2)->parent_frame_index);

  ASSERT_EQ(iter + 3, dedup.end());
}

TEST(StackFrameDeduplicatorTest, SingleBacktraceWithNull) {
  StackFrame null_frame = StackFrame::FromTraceEventName(nullptr);
  StackFrame bt[] = {kBrowserMain, null_frame, kMalloc};

  // Deduplicator doesn't care about what's inside StackFrames,
  // and handles nullptr StackFrame values as any other.
  //
  // So the call tree should look like this (index in brackets).
  //
  // BrowserMain [1]
  //   (null) [2]
  //     malloc [3]

  StringDeduplicator string_dedup;
  StackFrameDeduplicator dedup(&string_dedup);
  ASSERT_EQ(3, dedup.Insert(std::begin(bt), std::end(bt)));

  auto iter = dedup.begin() + 1;  // skip implicit node #0
  ASSERT_EQ(kBrowserMain, (iter + 0)->frame);
  ASSERT_EQ(kInvalidStackFrameIndex, (iter + 0)->parent_frame_index);

  ASSERT_EQ(null_frame, (iter + 1)->frame);
  ASSERT_EQ(1, (iter + 1)->parent_frame_index);

  ASSERT_EQ(kMalloc, (iter + 2)->frame);
  ASSERT_EQ(2, (iter + 2)->parent_frame_index);

  ASSERT_EQ(iter + 3, dedup.end());
}

// Test that there can be different call trees (there can be multiple bottom
// frames). Also verify that frames with the same name but a different caller
// are represented as distinct nodes.
TEST(StackFrameDeduplicatorTest, MultipleRoots) {
  StackFrame bt0[] = {kBrowserMain, kCreateWidget};
  StackFrame bt1[] = {kRendererMain, kCreateWidget};

  // The call tree should look like this (index in brackets).
  //
  // BrowserMain [1]
  //   CreateWidget [2]
  // RendererMain [3]
  //   CreateWidget [4]
  //
  // Note that there will be two instances of CreateWidget,
  // with different parents.

  StringDeduplicator string_dedup;
  StackFrameDeduplicator dedup(&string_dedup);
  ASSERT_EQ(2, dedup.Insert(std::begin(bt0), std::end(bt0)));
  ASSERT_EQ(4, dedup.Insert(std::begin(bt1), std::end(bt1)));

  auto iter = dedup.begin() + 1;  // skip implicit node #0
  ASSERT_EQ(kBrowserMain, (iter + 0)->frame);
  ASSERT_EQ(kInvalidStackFrameIndex, (iter + 0)->parent_frame_index);

  ASSERT_EQ(kCreateWidget, (iter + 1)->frame);
  ASSERT_EQ(1, (iter + 1)->parent_frame_index);

  ASSERT_EQ(kRendererMain, (iter + 2)->frame);
  ASSERT_EQ(kInvalidStackFrameIndex, (iter + 2)->parent_frame_index);

  ASSERT_EQ(kCreateWidget, (iter + 3)->frame);
  ASSERT_EQ(3, (iter + 3)->parent_frame_index);

  ASSERT_EQ(iter + 4, dedup.end());
}

TEST(StackFrameDeduplicatorTest, Deduplication) {
  StackFrame bt0[] = {kBrowserMain, kCreateWidget};
  StackFrame bt1[] = {kBrowserMain, kInitialize};

  // The call tree should look like this (index in brackets).
  //
  // BrowserMain [1]
  //   CreateWidget [2]
  //   Initialize [3]
  //
  // Note that BrowserMain will be re-used.

  StringDeduplicator string_dedup;
  StackFrameDeduplicator dedup(&string_dedup);
  ASSERT_EQ(2, dedup.Insert(std::begin(bt0), std::end(bt0)));
  ASSERT_EQ(3, dedup.Insert(std::begin(bt1), std::end(bt1)));

  auto iter = dedup.begin() + 1;  // skip implicit node #0
  ASSERT_EQ(kBrowserMain, (iter + 0)->frame);
  ASSERT_EQ(kInvalidStackFrameIndex, (iter + 0)->parent_frame_index);

  ASSERT_EQ(kCreateWidget, (iter + 1)->frame);
  ASSERT_EQ(1, (iter + 1)->parent_frame_index);

  ASSERT_EQ(kInitialize, (iter + 2)->frame);
  ASSERT_EQ(1, (iter + 2)->parent_frame_index);

  ASSERT_EQ(iter + 3, dedup.end());

  // Inserting the same backtrace again should return the index of the existing
  // node.
  ASSERT_EQ(2, dedup.Insert(std::begin(bt0), std::end(bt0)));
  ASSERT_EQ(3, dedup.Insert(std::begin(bt1), std::end(bt1)));
  ASSERT_EQ(4 /* 1 implicit + 3 added */, dedup.end() - dedup.begin());
}

TEST(StackFrameDeduplicatorTest, SerializeIncrementally) {
  StringDeduplicator string_dedup;
  StackFrameDeduplicator dedup(&string_dedup);

  StackFrame bt0[] = {kBrowserMain, kCreateWidget};
  ASSERT_EQ(2, dedup.Insert(std::begin(bt0), std::end(bt0)));

  ExpectIncrementalEntries(
      &dedup, &string_dedup,
      {{0, kNull}, {1, kBrowserMain}, {2, kCreateWidget, 1}});

  StackFrame bt1[] = {kBrowserMain, kInitialize};
  ASSERT_EQ(3, dedup.Insert(std::begin(bt1), std::end(bt1)));

  ExpectIncrementalEntries(&dedup, &string_dedup, {{3, kInitialize, 1}});

  ExpectIncrementalEntries(&dedup, &string_dedup, {});
}

}  // namespace trace_event
}  // namespace base
