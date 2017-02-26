// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_session_state.h"

namespace base {
namespace trace_event {

MemoryDumpSessionState::MemoryDumpSessionState() {}
MemoryDumpSessionState::~MemoryDumpSessionState() {}

void MemoryDumpSessionState::SetStackFrameDeduplicator(
    std::unique_ptr<StackFrameDeduplicator> stack_frame_deduplicator) {
  DCHECK(!stack_frame_deduplicator_);
  stack_frame_deduplicator_ = std::move(stack_frame_deduplicator);
}

void MemoryDumpSessionState::SetTypeNameDeduplicator(
    std::unique_ptr<TypeNameDeduplicator> type_name_deduplicator) {
  DCHECK(!type_name_deduplicator_);
  type_name_deduplicator_ = std::move(type_name_deduplicator);
}

void MemoryDumpSessionState::SetAllowedDumpModes(
    std::set<MemoryDumpLevelOfDetail> allowed_dump_modes) {
  allowed_dump_modes_ = allowed_dump_modes;
}

bool MemoryDumpSessionState::IsDumpModeAllowed(
    MemoryDumpLevelOfDetail dump_mode) const {
  return allowed_dump_modes_.count(dump_mode) != 0;
}

}  // namespace trace_event
}  // namespace base
