// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_SCHEDULER_H
#define BASE_TRACE_EVENT_MEMORY_DUMP_SCHEDULER_H

#include "base/base_export.h"
#include "base/gtest_prod_util.h"
#include "base/memory/ref_counted.h"
#include "base/timer/timer.h"
#include "base/trace_event/memory_dump_request_args.h"

namespace base {
class SingleThreadTaskRunner;

namespace trace_event {

class MemoryDumpManager;

// Schedules global dump requests based on the triggers added.
class BASE_EXPORT MemoryDumpScheduler {
 public:
  MemoryDumpScheduler(
      MemoryDumpManager* mdm_,
      scoped_refptr<SingleThreadTaskRunner> polling_task_runner);
  ~MemoryDumpScheduler();

  // Adds triggers for scheduling global dumps. Both periodic and peak triggers
  // cannot be added together. At the moment the periodic support is limited to
  // at most one periodic trigger per dump mode and peak triggers are limited to
  // at most one. All intervals should be an integeral multiple of the smallest
  // interval specified.
  void AddTrigger(MemoryDumpType trigger_type,
                  MemoryDumpLevelOfDetail level_of_detail,
                  uint32_t min_time_between_dumps_ms);

  // Starts periodic dumps.
  void NotifyPeriodicTriggerSupported();

  // Starts polling memory total.
  void NotifyPollingSupported();

  // Disables all triggers.
  void DisableAllTriggers();

 private:
  friend class MemoryDumpManagerTest;
  FRIEND_TEST_ALL_PREFIXES(MemoryDumpManagerTest, TestPollingOnDumpThread);

  // Helper class to schdule periodic memory dumps.
  struct PeriodicTriggerState {
    PeriodicTriggerState();
    ~PeriodicTriggerState();

    bool is_configured;

    RepeatingTimer timer;
    uint32_t dump_count;
    uint32_t min_timer_period_ms;
    uint32_t light_dumps_rate;
    uint32_t heavy_dumps_rate;

    uint32_t light_dump_period_ms;
    uint32_t heavy_dump_period_ms;

    DISALLOW_COPY_AND_ASSIGN(PeriodicTriggerState);
  };

  struct PollingTriggerState {
    explicit PollingTriggerState(
        scoped_refptr<SingleThreadTaskRunner> polling_task_runner);
    ~PollingTriggerState();

    bool is_configured;
    bool is_polling_enabled;
    MemoryDumpLevelOfDetail level_of_detail;

    scoped_refptr<SingleThreadTaskRunner> polling_task_runner;
    uint32_t polling_interval_ms;

    // Minimum numer of polls after the last dump at which next dump can be
    // triggered.
    int min_polls_between_dumps;
    int num_polls_from_last_dump;

    uint64_t last_dump_memory_total;

    DISALLOW_COPY_AND_ASSIGN(PollingTriggerState);
  };

  // Helper to set polling disabled on the polling thread.
  void DisablePolling();

  // Periodically called by the timer.
  void RequestPeriodicGlobalDump();

  // Called for polling memory usage and trigger dumps if peak is detected.
  void PollMemoryOnPollingThread();

  // Returns true if peak memory value is detected.
  bool ShouldTriggerDump(uint64_t current_memory_total);

  // Must be set before enabling tracing.
  static void SetPollingIntervalForTesting(uint32_t interval);

  // True if periodic dumping is enabled.
  bool IsPeriodicTimerRunningForTesting();

  MemoryDumpManager* mdm_;

  PeriodicTriggerState periodic_state_;
  PollingTriggerState polling_state_;

  DISALLOW_COPY_AND_ASSIGN(MemoryDumpScheduler);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_SCHEDULER_H
