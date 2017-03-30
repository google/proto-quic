// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_SCHEDULER_H
#define BASE_TRACE_EVENT_MEMORY_DUMP_SCHEDULER_H

#include <memory>

#include "base/base_export.h"
#include "base/gtest_prod_util.h"
#include "base/memory/ref_counted.h"
#include "base/timer/timer.h"
#include "base/trace_event/memory_dump_request_args.h"

namespace base {
class SingleThreadTaskRunner;

namespace trace_event {

class MemoryDumpManager;

// Schedules global dump requests based on the triggers added. The methods of
// this class are NOT thread safe and the client has to take care of invoking
// all the methods of the class safely.
class BASE_EXPORT MemoryDumpScheduler {
 public:
  static MemoryDumpScheduler* GetInstance();

  // Initializes the scheduler. NOT thread safe.
  void Setup(MemoryDumpManager* mdm_,
             scoped_refptr<SingleThreadTaskRunner> polling_task_runner);

  // Adds triggers for scheduling global dumps. Both periodic and peak triggers
  // cannot be added together. At the moment the periodic support is limited to
  // at most one periodic trigger per dump mode and peak triggers are limited to
  // at most one. All intervals should be an integeral multiple of the smallest
  // interval specified. NOT thread safe.
  void AddTrigger(MemoryDumpType trigger_type,
                  MemoryDumpLevelOfDetail level_of_detail,
                  uint32_t min_time_between_dumps_ms);

  // Starts periodic dumps. NOT thread safe and triggers must be added before
  // enabling.
  void EnablePeriodicTriggerIfNeeded();

  // Starts polling memory total. NOT thread safe and triggers must be added
  // before enabling.
  void EnablePollingIfNeeded();

  // Resets time for triggering dump to account for minimum time between the
  // dumps. NOT thread safe.
  void NotifyDumpTriggered();

  // Disables all triggers. NOT thread safe. This should be called before
  // polling thread is stopped to stop polling cleanly.
  void DisableAllTriggers();

 private:
  friend class MemoryDumpManagerTest;
  friend class MemoryDumpSchedulerPollingTest;
  FRIEND_TEST_ALL_PREFIXES(MemoryDumpManagerTest, TestPollingOnDumpThread);
  FRIEND_TEST_ALL_PREFIXES(MemoryDumpSchedulerPollingTest, NotifyDumpTriggered);

  // Helper class to schdule periodic memory dumps.
  struct BASE_EXPORT PeriodicTriggerState {
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

  struct BASE_EXPORT PollingTriggerState {
    enum State {
      CONFIGURED,  // Polling trigger was added.
      ENABLED,     // Polling is running.
      DISABLED     // Polling is disabled.
    };

    static const uint32_t kMaxNumMemorySamples = 50;

    PollingTriggerState();
    ~PollingTriggerState();

    // Helper to clear the tracked memory totals and poll count from last dump.
    void ResetTotals();

    State current_state;
    MemoryDumpLevelOfDetail level_of_detail;

    uint32_t polling_interval_ms;

    // Minimum numer of polls after the last dump at which next dump can be
    // triggered.
    int min_polls_between_dumps;
    int num_polls_from_last_dump;

    uint64_t last_dump_memory_total;
    int64_t memory_increase_threshold;
    uint64_t last_memory_totals_kb[kMaxNumMemorySamples];
    uint32_t last_memory_totals_kb_index;

    DISALLOW_COPY_AND_ASSIGN(PollingTriggerState);
  };

  MemoryDumpScheduler();
  ~MemoryDumpScheduler();

  // Helper to set polling disabled.
  void DisablePollingOnPollingThread();

  // Periodically called by the timer.
  void RequestPeriodicGlobalDump();

  // Called for polling memory usage and trigger dumps if peak is detected.
  void PollMemoryOnPollingThread();

  // Returns true if peak memory value is detected.
  bool ShouldTriggerDump(uint64_t current_memory_total);

  // Helper to detect peaks in memory usage.
  bool IsCurrentSamplePeak(uint64_t current_memory_total);

  // Must be set before enabling tracing.
  static void SetPollingIntervalForTesting(uint32_t interval);

  // True if periodic dumping is enabled.
  bool IsPeriodicTimerRunningForTesting();

  MemoryDumpManager* mdm_;

  // Accessed on the thread of the client before enabling and only accessed on
  // the thread that called "EnablePeriodicTriggersIfNeeded()" after enabling.
  std::unique_ptr<PeriodicTriggerState> periodic_state_;

  // Accessed on the thread of the client before enabling and only accessed on
  // the polling thread after enabling.
  std::unique_ptr<PollingTriggerState> polling_state_;

  // Accessed on the thread of the client only.
  scoped_refptr<SingleThreadTaskRunner> polling_task_runner_;

  // True when the scheduler is setup. Accessed on the thread of client only.
  bool is_setup_;

  DISALLOW_COPY_AND_ASSIGN(MemoryDumpScheduler);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_SCHEDULER_H
