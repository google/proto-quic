// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_scheduler.h"

#include "base/process/process_metrics.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_dump_manager.h"
#include "build/build_config.h"

namespace base {
namespace trace_event {

namespace {
// Threshold on increase in memory from last dump beyond which a new dump must
// be triggered.
int64_t kDefaultMemoryIncreaseThreshold = 50 * 1024 * 1024;  // 50MiB
const uint32_t kMemoryTotalsPollingInterval = 25;
uint32_t g_polling_interval_ms_for_testing = 0;
}  // namespace

// static
MemoryDumpScheduler* MemoryDumpScheduler::GetInstance() {
  static MemoryDumpScheduler* instance = new MemoryDumpScheduler();
  return instance;
}

MemoryDumpScheduler::MemoryDumpScheduler() : mdm_(nullptr), is_setup_(false) {}
MemoryDumpScheduler::~MemoryDumpScheduler() {}

void MemoryDumpScheduler::Setup(
    MemoryDumpManager* mdm,
    scoped_refptr<SingleThreadTaskRunner> polling_task_runner) {
  mdm_ = mdm;
  polling_task_runner_ = polling_task_runner;
  periodic_state_.reset(new PeriodicTriggerState);
  polling_state_.reset(new PollingTriggerState);
  is_setup_ = true;
}

void MemoryDumpScheduler::AddTrigger(MemoryDumpType trigger_type,
                                     MemoryDumpLevelOfDetail level_of_detail,
                                     uint32_t min_time_between_dumps_ms) {
  DCHECK(is_setup_);
  if (trigger_type == MemoryDumpType::PEAK_MEMORY_USAGE) {
    DCHECK(!periodic_state_->is_configured);
    DCHECK_EQ(PollingTriggerState::DISABLED, polling_state_->current_state);
    DCHECK_NE(0u, min_time_between_dumps_ms);

    polling_state_->level_of_detail = level_of_detail;
    polling_state_->min_polls_between_dumps =
        (min_time_between_dumps_ms + polling_state_->polling_interval_ms - 1) /
        polling_state_->polling_interval_ms;
    polling_state_->current_state = PollingTriggerState::CONFIGURED;
  } else if (trigger_type == MemoryDumpType::PERIODIC_INTERVAL) {
    DCHECK_EQ(PollingTriggerState::DISABLED, polling_state_->current_state);
    periodic_state_->is_configured = true;
    DCHECK_NE(0u, min_time_between_dumps_ms);
    switch (level_of_detail) {
      case MemoryDumpLevelOfDetail::BACKGROUND:
        break;
      case MemoryDumpLevelOfDetail::LIGHT:
        DCHECK_EQ(0u, periodic_state_->light_dump_period_ms);
        periodic_state_->light_dump_period_ms = min_time_between_dumps_ms;
        break;
      case MemoryDumpLevelOfDetail::DETAILED:
        DCHECK_EQ(0u, periodic_state_->heavy_dump_period_ms);
        periodic_state_->heavy_dump_period_ms = min_time_between_dumps_ms;
        break;
    }

    periodic_state_->min_timer_period_ms = std::min(
        periodic_state_->min_timer_period_ms, min_time_between_dumps_ms);
    DCHECK_EQ(0u, periodic_state_->light_dump_period_ms %
                      periodic_state_->min_timer_period_ms);
    DCHECK_EQ(0u, periodic_state_->heavy_dump_period_ms %
                      periodic_state_->min_timer_period_ms);
  }
}

void MemoryDumpScheduler::EnablePeriodicTriggerIfNeeded() {
  DCHECK(is_setup_);
  if (!periodic_state_->is_configured || periodic_state_->timer.IsRunning())
    return;
  periodic_state_->light_dumps_rate = periodic_state_->light_dump_period_ms /
                                      periodic_state_->min_timer_period_ms;
  periodic_state_->heavy_dumps_rate = periodic_state_->heavy_dump_period_ms /
                                      periodic_state_->min_timer_period_ms;

  periodic_state_->dump_count = 0;
  periodic_state_->timer.Start(
      FROM_HERE,
      TimeDelta::FromMilliseconds(periodic_state_->min_timer_period_ms),
      Bind(&MemoryDumpScheduler::RequestPeriodicGlobalDump, Unretained(this)));
}

void MemoryDumpScheduler::EnablePollingIfNeeded() {
  DCHECK(is_setup_);
  if (polling_state_->current_state != PollingTriggerState::CONFIGURED)
    return;

  polling_state_->current_state = PollingTriggerState::ENABLED;
  polling_state_->ResetTotals();

  polling_task_runner_->PostTask(
      FROM_HERE,
      Bind(&MemoryDumpScheduler::PollMemoryOnPollingThread, Unretained(this)));
}

void MemoryDumpScheduler::NotifyDumpTriggered() {
  if (polling_task_runner_ &&
      !polling_task_runner_->RunsTasksOnCurrentThread()) {
    polling_task_runner_->PostTask(
        FROM_HERE,
        Bind(&MemoryDumpScheduler::NotifyDumpTriggered, Unretained(this)));
    return;
  }

  if (!polling_state_ ||
      polling_state_->current_state != PollingTriggerState::ENABLED) {
    return;
  }

  polling_state_->ResetTotals();
}

void MemoryDumpScheduler::DisableAllTriggers() {
  if (periodic_state_) {
    if (periodic_state_->timer.IsRunning())
      periodic_state_->timer.Stop();
    periodic_state_.reset();
  }

  if (polling_task_runner_) {
    DCHECK(polling_state_);
    polling_task_runner_->PostTask(
        FROM_HERE, Bind(&MemoryDumpScheduler::DisablePollingOnPollingThread,
                        Unretained(this)));
    polling_task_runner_ = nullptr;
  }
  is_setup_ = false;
}

void MemoryDumpScheduler::DisablePollingOnPollingThread() {
  polling_state_->current_state = PollingTriggerState::DISABLED;
  polling_state_.reset();
}

// static
void MemoryDumpScheduler::SetPollingIntervalForTesting(uint32_t interval) {
  g_polling_interval_ms_for_testing = interval;
}

bool MemoryDumpScheduler::IsPeriodicTimerRunningForTesting() {
  return periodic_state_->timer.IsRunning();
}

void MemoryDumpScheduler::RequestPeriodicGlobalDump() {
  MemoryDumpLevelOfDetail level_of_detail = MemoryDumpLevelOfDetail::BACKGROUND;
  if (periodic_state_->light_dumps_rate > 0 &&
      periodic_state_->dump_count % periodic_state_->light_dumps_rate == 0)
    level_of_detail = MemoryDumpLevelOfDetail::LIGHT;
  if (periodic_state_->heavy_dumps_rate > 0 &&
      periodic_state_->dump_count % periodic_state_->heavy_dumps_rate == 0)
    level_of_detail = MemoryDumpLevelOfDetail::DETAILED;
  ++periodic_state_->dump_count;

  mdm_->RequestGlobalDump(MemoryDumpType::PERIODIC_INTERVAL, level_of_detail);
}

void MemoryDumpScheduler::PollMemoryOnPollingThread() {
  if (!polling_state_)
    return;

  DCHECK_EQ(PollingTriggerState::ENABLED, polling_state_->current_state);

  uint64_t polled_memory = 0;
  bool res = mdm_->PollFastMemoryTotal(&polled_memory);
  DCHECK(res);
  if (polling_state_->level_of_detail == MemoryDumpLevelOfDetail::DETAILED) {
    TRACE_COUNTER1(MemoryDumpManager::kTraceCategory, "PolledMemoryMB",
                   polled_memory / 1024 / 1024);
  }

  if (ShouldTriggerDump(polled_memory)) {
    TRACE_EVENT_INSTANT1(MemoryDumpManager::kTraceCategory,
                         "Peak memory dump Triggered",
                         TRACE_EVENT_SCOPE_PROCESS, "total_usage_MB",
                         polled_memory / 1024 / 1024);

    mdm_->RequestGlobalDump(MemoryDumpType::PEAK_MEMORY_USAGE,
                            polling_state_->level_of_detail);
  }

  // TODO(ssid): Use RequestSchedulerCallback, crbug.com/607533.
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      Bind(&MemoryDumpScheduler::PollMemoryOnPollingThread, Unretained(this)),
      TimeDelta::FromMilliseconds(polling_state_->polling_interval_ms));
}

bool MemoryDumpScheduler::ShouldTriggerDump(uint64_t current_memory_total) {
  // This function tries to detect peak memory usage as discussed in
  // https://goo.gl/0kOU4A.

  if (current_memory_total == 0)
    return false;

  bool should_dump = false;
  ++polling_state_->num_polls_from_last_dump;
  if (polling_state_->last_dump_memory_total == 0) {
    // If it's first sample then trigger memory dump.
    should_dump = true;
  } else if (polling_state_->min_polls_between_dumps >
             polling_state_->num_polls_from_last_dump) {
    return false;
  }

  int64_t increase_from_last_dump =
      current_memory_total - polling_state_->last_dump_memory_total;
  should_dump |=
      increase_from_last_dump > polling_state_->memory_increase_threshold;
  should_dump |= IsCurrentSamplePeak(current_memory_total);
  if (should_dump)
    polling_state_->ResetTotals();
  return should_dump;
}

bool MemoryDumpScheduler::IsCurrentSamplePeak(
    uint64_t current_memory_total_bytes) {
  uint64_t current_memory_total_kb = current_memory_total_bytes / 1024;
  polling_state_->last_memory_totals_kb_index =
      (polling_state_->last_memory_totals_kb_index + 1) %
      PollingTriggerState::kMaxNumMemorySamples;
  uint64_t mean = 0;
  for (uint32_t i = 0; i < PollingTriggerState::kMaxNumMemorySamples; ++i) {
    if (polling_state_->last_memory_totals_kb[i] == 0) {
      // Not enough samples to detect peaks.
      polling_state_
          ->last_memory_totals_kb[polling_state_->last_memory_totals_kb_index] =
          current_memory_total_kb;
      return false;
    }
    mean += polling_state_->last_memory_totals_kb[i];
  }
  mean = mean / PollingTriggerState::kMaxNumMemorySamples;
  uint64_t variance = 0;
  for (uint32_t i = 0; i < PollingTriggerState::kMaxNumMemorySamples; ++i) {
    variance += (polling_state_->last_memory_totals_kb[i] - mean) *
                (polling_state_->last_memory_totals_kb[i] - mean);
  }
  variance = variance / PollingTriggerState::kMaxNumMemorySamples;

  polling_state_
      ->last_memory_totals_kb[polling_state_->last_memory_totals_kb_index] =
      current_memory_total_kb;

  // If stddev is less than 0.2% then we consider that the process is inactive.
  bool is_stddev_low = variance < mean / 500 * mean / 500;
  if (is_stddev_low)
    return false;

  // (mean + 3.69 * stddev) corresponds to a value that is higher than current
  // sample with 99.99% probability.
  return (current_memory_total_kb - mean) * (current_memory_total_kb - mean) >
         (3.69 * 3.69 * variance);
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

MemoryDumpScheduler::PollingTriggerState::PollingTriggerState()
    : current_state(DISABLED),
      level_of_detail(MemoryDumpLevelOfDetail::FIRST),
      polling_interval_ms(g_polling_interval_ms_for_testing
                              ? g_polling_interval_ms_for_testing
                              : kMemoryTotalsPollingInterval),
      min_polls_between_dumps(0),
      num_polls_from_last_dump(-1),
      last_dump_memory_total(0),
      memory_increase_threshold(0),
      last_memory_totals_kb_index(0) {}

MemoryDumpScheduler::PollingTriggerState::~PollingTriggerState() {}

void MemoryDumpScheduler::PollingTriggerState::ResetTotals() {
  if (!memory_increase_threshold) {
    memory_increase_threshold = kDefaultMemoryIncreaseThreshold;
#if defined(OS_WIN) || defined(OS_MACOSX) || defined(OS_LINUX) || \
    defined(OS_ANDROID)
    // Set threshold to 1% of total system memory.
    SystemMemoryInfoKB meminfo;
    bool res = GetSystemMemoryInfo(&meminfo);
    if (res) {
      memory_increase_threshold =
          (static_cast<int64_t>(meminfo.total) / 100) * 1024;
    }
    DCHECK_GT(memory_increase_threshold, 0u);
#endif
  }

  // Update the |last_dump_memory_total|'s value from the totals if it's not
  // first poll.
  if (num_polls_from_last_dump >= 0 &&
      last_memory_totals_kb[last_memory_totals_kb_index]) {
    last_dump_memory_total =
        last_memory_totals_kb[last_memory_totals_kb_index] * 1024;
  }
  num_polls_from_last_dump = 0;
  for (uint32_t i = 0; i < kMaxNumMemorySamples; ++i)
    last_memory_totals_kb[i] = 0;
  last_memory_totals_kb_index = 0;
}

}  // namespace trace_event
}  // namespace base
