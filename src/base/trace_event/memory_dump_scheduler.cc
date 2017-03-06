// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_scheduler.h"

#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_dump_manager.h"
#include "build/build_config.h"

namespace base {
namespace trace_event {

namespace {
// Threshold on increase in memory from last dump beyond which a new dump must
// be triggered.
int64_t kMemoryIncreaseThreshold = 50 * 1024 * 1024;  // 50MiB
const uint32_t kMemoryTotalsPollingInterval = 25;
uint32_t g_polling_interval_ms_for_testing = 0;
}  // namespace

MemoryDumpScheduler::MemoryDumpScheduler(
    MemoryDumpManager* mdm,
    scoped_refptr<SingleThreadTaskRunner> polling_task_runner)
    : mdm_(mdm), polling_state_(polling_task_runner) {}

MemoryDumpScheduler::~MemoryDumpScheduler() {}

void MemoryDumpScheduler::AddTrigger(MemoryDumpType trigger_type,
                                     MemoryDumpLevelOfDetail level_of_detail,
                                     uint32_t min_time_between_dumps_ms) {
  if (trigger_type == MemoryDumpType::PEAK_MEMORY_USAGE) {
    DCHECK(!periodic_state_.is_configured);
    DCHECK(!polling_state_.is_configured);
    DCHECK_NE(0u, min_time_between_dumps_ms);

    polling_state_.level_of_detail = level_of_detail;
    polling_state_.min_polls_between_dumps =
        (min_time_between_dumps_ms + polling_state_.polling_interval_ms - 1) /
        polling_state_.polling_interval_ms;
    polling_state_.is_configured = true;
  } else if (trigger_type == MemoryDumpType::PERIODIC_INTERVAL) {
    DCHECK(!polling_state_.is_configured);
    periodic_state_.is_configured = true;
    DCHECK_NE(0u, min_time_between_dumps_ms);
    switch (level_of_detail) {
      case MemoryDumpLevelOfDetail::BACKGROUND:
        break;
      case MemoryDumpLevelOfDetail::LIGHT:
        DCHECK_EQ(0u, periodic_state_.light_dump_period_ms);
        periodic_state_.light_dump_period_ms = min_time_between_dumps_ms;
        break;
      case MemoryDumpLevelOfDetail::DETAILED:
        DCHECK_EQ(0u, periodic_state_.heavy_dump_period_ms);
        periodic_state_.heavy_dump_period_ms = min_time_between_dumps_ms;
        break;
    }

    periodic_state_.min_timer_period_ms = std::min(
        periodic_state_.min_timer_period_ms, min_time_between_dumps_ms);
    DCHECK_EQ(0u, periodic_state_.light_dump_period_ms %
                      periodic_state_.min_timer_period_ms);
    DCHECK_EQ(0u, periodic_state_.heavy_dump_period_ms %
                      periodic_state_.min_timer_period_ms);
  }
}

void MemoryDumpScheduler::NotifyPeriodicTriggerSupported() {
  if (!periodic_state_.is_configured || periodic_state_.timer.IsRunning())
    return;
  periodic_state_.light_dumps_rate = periodic_state_.light_dump_period_ms /
                                     periodic_state_.min_timer_period_ms;
  periodic_state_.heavy_dumps_rate = periodic_state_.heavy_dump_period_ms /
                                     periodic_state_.min_timer_period_ms;

  periodic_state_.dump_count = 0;
  periodic_state_.timer.Start(
      FROM_HERE,
      TimeDelta::FromMilliseconds(periodic_state_.min_timer_period_ms),
      Bind(&MemoryDumpScheduler::RequestPeriodicGlobalDump, Unretained(this)));
}

void MemoryDumpScheduler::NotifyPollingSupported() {
  if (!polling_state_.is_configured || polling_state_.is_polling_enabled)
    return;
  polling_state_.is_polling_enabled = true;
  polling_state_.num_polls_from_last_dump = 0;
  polling_state_.last_dump_memory_total = 0;
  polling_state_.polling_task_runner->PostTask(
      FROM_HERE,
      Bind(&MemoryDumpScheduler::PollMemoryOnPollingThread, Unretained(this)));
}

void MemoryDumpScheduler::DisableAllTriggers() {
  if (periodic_state_.timer.IsRunning())
    periodic_state_.timer.Stop();
  DisablePolling();
}

void MemoryDumpScheduler::DisablePolling() {
  if (ThreadTaskRunnerHandle::Get() != polling_state_.polling_task_runner) {
    if (polling_state_.polling_task_runner->PostTask(
            FROM_HERE,
            Bind(&MemoryDumpScheduler::DisablePolling, Unretained(this))))
      return;
  }
  polling_state_.is_polling_enabled = false;
  polling_state_.is_configured = false;
  polling_state_.polling_task_runner = nullptr;
}

// static
void MemoryDumpScheduler::SetPollingIntervalForTesting(uint32_t interval) {
  g_polling_interval_ms_for_testing = interval;
}

bool MemoryDumpScheduler::IsPeriodicTimerRunningForTesting() {
  return periodic_state_.timer.IsRunning();
}

void MemoryDumpScheduler::RequestPeriodicGlobalDump() {
  MemoryDumpLevelOfDetail level_of_detail = MemoryDumpLevelOfDetail::BACKGROUND;
  if (periodic_state_.light_dumps_rate > 0 &&
      periodic_state_.dump_count % periodic_state_.light_dumps_rate == 0)
    level_of_detail = MemoryDumpLevelOfDetail::LIGHT;
  if (periodic_state_.heavy_dumps_rate > 0 &&
      periodic_state_.dump_count % periodic_state_.heavy_dumps_rate == 0)
    level_of_detail = MemoryDumpLevelOfDetail::DETAILED;
  ++periodic_state_.dump_count;

  mdm_->RequestGlobalDump(MemoryDumpType::PERIODIC_INTERVAL, level_of_detail);
}

void MemoryDumpScheduler::PollMemoryOnPollingThread() {
  if (!polling_state_.is_configured)
    return;

  uint64_t polled_memory = 0;
  bool res = mdm_->PollFastMemoryTotal(&polled_memory);
  DCHECK(res);
  if (polling_state_.level_of_detail == MemoryDumpLevelOfDetail::DETAILED) {
    TRACE_COUNTER1(MemoryDumpManager::kTraceCategory, "PolledMemoryMB",
                   polled_memory / 1024 / 1024);
  }

  if (ShouldTriggerDump(polled_memory)) {
    TRACE_EVENT_INSTANT1(MemoryDumpManager::kTraceCategory,
                         "Peak memory dump Triggered",
                         TRACE_EVENT_SCOPE_PROCESS, "total_usage_MB",
                         polled_memory / 1024 / 1024);

    mdm_->RequestGlobalDump(MemoryDumpType::PEAK_MEMORY_USAGE,
                            polling_state_.level_of_detail);
  }

  // TODO(ssid): Use RequestSchedulerCallback, crbug.com/607533.
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      Bind(&MemoryDumpScheduler::PollMemoryOnPollingThread, Unretained(this)),
      TimeDelta::FromMilliseconds(polling_state_.polling_interval_ms));
}

bool MemoryDumpScheduler::ShouldTriggerDump(uint64_t current_memory_total) {
  // This function tries to detect peak memory usage as discussed in
  // https://goo.gl/0kOU4A.

  if (current_memory_total == 0)
    return false;

  bool should_dump = false;
  ++polling_state_.num_polls_from_last_dump;
  if (polling_state_.last_dump_memory_total == 0) {
    // If it's first sample then trigger memory dump.
    should_dump = true;
  } else if (polling_state_.min_polls_between_dumps >
             polling_state_.num_polls_from_last_dump) {
    return false;
  }

  int64_t increase_from_last_dump =
      current_memory_total - polling_state_.last_dump_memory_total;
  should_dump |= increase_from_last_dump > kMemoryIncreaseThreshold;
  if (should_dump) {
    polling_state_.last_dump_memory_total = current_memory_total;
    polling_state_.num_polls_from_last_dump = 0;
  }
  return should_dump;
}

MemoryDumpScheduler::PeriodicTriggerState::PeriodicTriggerState()
    : is_configured(false),
      dump_count(0),
      min_timer_period_ms(std::numeric_limits<uint32_t>::max()),
      light_dumps_rate(0),
      heavy_dumps_rate(0),
      light_dump_period_ms(0),
      heavy_dump_period_ms(0) {}

MemoryDumpScheduler::PeriodicTriggerState::~PeriodicTriggerState() {
  DCHECK(!timer.IsRunning());
}

MemoryDumpScheduler::PollingTriggerState::PollingTriggerState(
    scoped_refptr<SingleThreadTaskRunner> polling_task_runner)
    : is_configured(false),
      is_polling_enabled(false),
      level_of_detail(MemoryDumpLevelOfDetail::FIRST),
      polling_task_runner(polling_task_runner),
      polling_interval_ms(g_polling_interval_ms_for_testing
                              ? g_polling_interval_ms_for_testing
                              : kMemoryTotalsPollingInterval),
      min_polls_between_dumps(0),
      num_polls_from_last_dump(0),
      last_dump_memory_total(0) {}

MemoryDumpScheduler::PollingTriggerState::~PollingTriggerState() {
  DCHECK(!polling_task_runner);
}

}  // namespace trace_event
}  // namespace base
