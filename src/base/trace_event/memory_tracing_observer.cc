// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_tracing_observer.h"

#include "base/memory/ptr_util.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event_argument.h"

namespace base {
namespace trace_event {

namespace {

const int kTraceEventNumArgs = 1;
const char* kTraceEventArgNames[] = {"dumps"};
const unsigned char kTraceEventArgTypes[] = {TRACE_VALUE_TYPE_CONVERTABLE};

bool IsMemoryInfraTracingEnabled() {
  bool enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(MemoryDumpManager::kTraceCategory,
                                     &enabled);
  return enabled;
}

};  // namespace

MemoryTracingObserver::MemoryTracingObserver(
    TraceLog* trace_log,
    MemoryDumpManager* memory_dump_manager)
    : memory_dump_manager_(memory_dump_manager), trace_log_(trace_log) {
  // If tracing was enabled before initializing MemoryDumpManager, we missed the
  // OnTraceLogEnabled() event. Synthetize it so we can late-join the party.
  // IsEnabled is called before adding observer to avoid calling
  // OnTraceLogEnabled twice.
  bool is_tracing_already_enabled = trace_log_->IsEnabled();
  trace_log_->AddEnabledStateObserver(this);
  if (is_tracing_already_enabled)
    OnTraceLogEnabled();
}

MemoryTracingObserver::~MemoryTracingObserver() {
  trace_log_->RemoveEnabledStateObserver(this);
}

void MemoryTracingObserver::OnTraceLogEnabled() {
  if (!IsMemoryInfraTracingEnabled())
    return;

  // Initialize the TraceLog for the current thread. This is to avoids that the
  // TraceLog memory dump provider is registered lazily during the MDM
  // SetupForTracing().
  TraceLog::GetInstance()->InitializeThreadLocalEventBufferIfSupported();

  const TraceConfig& trace_config =
      TraceLog::GetInstance()->GetCurrentTraceConfig();
  const TraceConfig::MemoryDumpConfig& memory_dump_config =
      trace_config.memory_dump_config();

  memory_dump_config_ =
      MakeUnique<TraceConfig::MemoryDumpConfig>(memory_dump_config);

  memory_dump_manager_->SetupForTracing(memory_dump_config);
}

void MemoryTracingObserver::OnTraceLogDisabled() {
  memory_dump_manager_->TeardownForTracing();
  memory_dump_config_.reset();
}

bool MemoryTracingObserver::AddDumpToTraceIfEnabled(
    const MemoryDumpRequestArgs* req_args,
    const ProcessId pid,
    const ProcessMemoryDump* process_memory_dump) {
  // If tracing has been disabled early out to avoid the cost of serializing the
  // dump then ignoring the result.
  if (!IsMemoryInfraTracingEnabled())
    return false;
  // If the dump mode is too detailed don't add to trace to avoid accidentally
  // including PII.
  if (!IsDumpModeAllowed(req_args->level_of_detail))
    return false;

  CHECK_NE(MemoryDumpType::SUMMARY_ONLY, req_args->dump_type);

  const uint64_t dump_guid = req_args->dump_guid;

  std::unique_ptr<TracedValue> traced_value(new TracedValue);
  process_memory_dump->AsValueInto(traced_value.get());
  traced_value->SetString("level_of_detail", MemoryDumpLevelOfDetailToString(
                                                 req_args->level_of_detail));
  const char* const event_name = MemoryDumpTypeToString(req_args->dump_type);

  std::unique_ptr<ConvertableToTraceFormat> event_value(
      std::move(traced_value));
  TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_PROCESS_ID(
      TRACE_EVENT_PHASE_MEMORY_DUMP,
      TraceLog::GetCategoryGroupEnabled(MemoryDumpManager::kTraceCategory),
      event_name, trace_event_internal::kGlobalScope, dump_guid, pid,
      kTraceEventNumArgs, kTraceEventArgNames, kTraceEventArgTypes,
      nullptr /* arg_values */, &event_value, TRACE_EVENT_FLAG_HAS_ID);

  return true;
}

bool MemoryTracingObserver::IsDumpModeAllowed(
    MemoryDumpLevelOfDetail dump_mode) const {
  if (!memory_dump_config_)
    return false;
  return memory_dump_config_->allowed_dump_modes.count(dump_mode) != 0;
}

}  // namespace trace_event
}  // namespace base
