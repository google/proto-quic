// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_TRACING_OBSERVER_H_
#define BASE_TRACE_EVENT_MEMORY_TRACING_OBSERVER_H_

#include "base/macros.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"

namespace base {

namespace trace_event {

// Observes TraceLog for Enable/Disable events and when they occur Enables and
// Disables the MemoryDumpManager with the correct state based on reading the
// trace log. Also provides a method for adding a dump to the trace.
class BASE_EXPORT MemoryTracingObserver
    : public TraceLog::EnabledStateObserver {
 public:
  static const char* const kTraceCategory;

  MemoryTracingObserver(TraceLog*, MemoryDumpManager*);
  ~MemoryTracingObserver() override;

  // TraceLog::EnabledStateObserver implementation.
  void OnTraceLogEnabled() override;
  void OnTraceLogDisabled() override;

  bool AddDumpToTraceIfEnabled(const MemoryDumpRequestArgs*,
                               const ProcessId,
                               const ProcessMemoryDump*);

 private:
  // Returns true if the dump mode is allowed for current tracing session.
  bool IsDumpModeAllowed(MemoryDumpLevelOfDetail) const;

  MemoryDumpManager* const memory_dump_manager_;
  TraceLog* const trace_log_;
  std::unique_ptr<TraceConfig::MemoryDumpConfig> memory_dump_config_;

  DISALLOW_COPY_AND_ASSIGN(MemoryTracingObserver);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_MEMORY_TRACING_OBSERVER_H_
