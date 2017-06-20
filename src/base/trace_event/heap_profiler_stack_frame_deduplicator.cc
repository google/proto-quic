// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"

#include <inttypes.h>
#include <stddef.h>

#include <string>
#include <utility>

#include "base/strings/stringprintf.h"
#include "base/trace_event/heap_profiler_string_deduplicator.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/trace_event/trace_event_memory_overhead.h"

namespace base {
namespace trace_event {

StackFrameDeduplicator::FrameNode::FrameNode(StackFrame frame,
                                             int parent_frame_index)
    : frame(frame), parent_frame_index(parent_frame_index) {}
StackFrameDeduplicator::FrameNode::FrameNode(const FrameNode& other) = default;
StackFrameDeduplicator::FrameNode::~FrameNode() {}

size_t StackFrameDeduplicator::FrameNode::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(children);
}

StackFrameDeduplicator::StackFrameDeduplicator(
    StringDeduplicator* string_deduplicator)
    : string_deduplicator_(string_deduplicator), last_exported_index_(0) {
  // Add implicit entry for id 0 (empty backtraces).
  frames_.push_back(FrameNode(StackFrame::FromTraceEventName(nullptr),
                              FrameNode::kInvalidFrameIndex));
}
StackFrameDeduplicator::~StackFrameDeduplicator() {}

int StackFrameDeduplicator::Insert(const StackFrame* beginFrame,
                                   const StackFrame* endFrame) {
  if (beginFrame == endFrame) {
    // Empty backtraces are mapped to id 0.
    return 0;
  }

  int frame_index = FrameNode::kInvalidFrameIndex;
  std::map<StackFrame, int>* nodes = &roots_;

  // Loop through the frames, early out when a frame is null.
  for (const StackFrame* it = beginFrame; it != endFrame; it++) {
    StackFrame frame = *it;

    auto node = nodes->find(frame);
    if (node == nodes->end()) {
      // There is no tree node for this frame yet, create it. The parent node
      // is the node associated with the previous frame.
      FrameNode frame_node(frame, frame_index);

      // The new frame node will be appended, so its index is the current size
      // of the vector.
      frame_index = static_cast<int>(frames_.size());

      // Add the node to the trie so it will be found next time.
      nodes->insert(std::make_pair(frame, frame_index));

      // Append the node after modifying |nodes|, because the |frames_| vector
      // might need to resize, and this invalidates the |nodes| pointer.
      frames_.push_back(frame_node);
    } else {
      // A tree node for this frame exists. Look for the next one.
      frame_index = node->second;
    }

    nodes = &frames_[frame_index].children;
  }

  return frame_index;
}

void StackFrameDeduplicator::SerializeIncrementally(TracedValue* traced_value) {
  std::string stringify_buffer;

  for (; last_exported_index_ < frames_.size(); ++last_exported_index_) {
    const auto& frame_node = frames_[last_exported_index_];
    traced_value->BeginDictionary();

    traced_value->SetInteger("id", last_exported_index_);

    int name_string_id = 0;
    const StackFrame& frame = frame_node.frame;
    switch (frame.type) {
      case StackFrame::Type::TRACE_EVENT_NAME:
        name_string_id =
            string_deduplicator_->Insert(static_cast<const char*>(frame.value));
        break;
      case StackFrame::Type::THREAD_NAME:
        SStringPrintf(&stringify_buffer,
                      "[Thread: %s]",
                      static_cast<const char*>(frame.value));
        name_string_id = string_deduplicator_->Insert(stringify_buffer);
        break;
      case StackFrame::Type::PROGRAM_COUNTER:
        SStringPrintf(&stringify_buffer,
                      "pc:%" PRIxPTR,
                      reinterpret_cast<uintptr_t>(frame.value));
        name_string_id = string_deduplicator_->Insert(stringify_buffer);
        break;
    }
    traced_value->SetInteger("name_sid", name_string_id);

    if (frame_node.parent_frame_index != FrameNode::kInvalidFrameIndex) {
      traced_value->SetInteger("parent", frame_node.parent_frame_index);
    }

    traced_value->EndDictionary();
  }
}

void StackFrameDeduplicator::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  size_t memory_usage =
      EstimateMemoryUsage(frames_) + EstimateMemoryUsage(roots_);
  overhead->Add(TraceEventMemoryOverhead::kHeapProfilerStackFrameDeduplicator,
                sizeof(StackFrameDeduplicator) + memory_usage);
}

}  // namespace trace_event
}  // namespace base
