// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_HEAP_PROFILER_STACK_FRAME_DEDUPLICATOR_H_
#define BASE_TRACE_EVENT_HEAP_PROFILER_STACK_FRAME_DEDUPLICATOR_H_

#include <map>
#include <string>
#include <vector>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/trace_event/heap_profiler_allocation_context.h"

namespace base {
namespace trace_event {

class StringDeduplicator;
class TraceEventMemoryOverhead;
class TracedValue;

// A data structure that allows grouping a set of backtraces in a space-
// efficient manner by creating a call tree and writing it as a set of (node,
// parent) pairs. The tree nodes reference both parent and children. The parent
// is referenced by index into |frames_|. The children are referenced via a map
// of |StackFrame|s to index into |frames_|. So there is a trie for bottum-up
// lookup of a backtrace for deduplication, and a tree for compact storage in
// the trace log.
class BASE_EXPORT StackFrameDeduplicator {
 public:
  // A node in the call tree.
  struct FrameNode {
    FrameNode(StackFrame frame, int parent_frame_index);
    FrameNode(const FrameNode& other);
    ~FrameNode();

    size_t EstimateMemoryUsage() const;

    StackFrame frame;

    // The index of the parent stack frame in |frames_|, or kInvalidFrameIndex
    // if there is no parent frame (when it is at the bottom of the call stack).
    int parent_frame_index;
    constexpr static int kInvalidFrameIndex = -1;

    // Indices into |frames_| of frames called from the current frame.
    std::map<StackFrame, int> children;
  };

  using ConstIterator = std::vector<FrameNode>::const_iterator;

  // |string_deduplication| is used during serialization, and is expected
  // to outlive instances of this class.
  explicit StackFrameDeduplicator(StringDeduplicator* string_deduplicator);
  ~StackFrameDeduplicator();

  // Inserts a backtrace where |beginFrame| is a pointer to the bottom frame
  // (e.g. main) and |endFrame| is a pointer past the top frame (most recently
  // called function), and returns the index of its leaf node in |frames_|.
  // Returns -1 if the backtrace is empty.
  int Insert(const StackFrame* beginFrame, const StackFrame* endFrame);

  // Iterators over the frame nodes in the call tree.
  ConstIterator begin() const { return frames_.begin(); }
  ConstIterator end() const { return frames_.end(); }

  // Appends new |stackFrames| dictionary items that were added after the
  // last call to this function.
  void SerializeIncrementally(TracedValue* traced_value);

  // Estimates memory overhead including |sizeof(StackFrameDeduplicator)|.
  void EstimateTraceMemoryOverhead(TraceEventMemoryOverhead* overhead);

 private:
  StringDeduplicator* string_deduplicator_;

  std::map<StackFrame, int> roots_;
  std::vector<FrameNode> frames_;
  size_t last_exported_index_;

  DISALLOW_COPY_AND_ASSIGN(StackFrameDeduplicator);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_HEAP_PROFILER_STACK_FRAME_DEDUPLICATOR_H_
