// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_scheduler.h"

#include <memory>

#include "base/single_thread_task_runner.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

class MemoryDumpSchedulerPollingTest : public testing::Test {
 public:
  static const uint32_t kMinPollsToDump = 5;

  MemoryDumpSchedulerPollingTest()
      : testing::Test(),
        num_samples_tracked_(
            MemoryDumpScheduler::PollingTriggerState::kMaxNumMemorySamples) {}

  void SetUp() override {
    MemoryDumpScheduler::SetPollingIntervalForTesting(1);
    uint32_t kMinPollsToDump = 5;
    mds_ = MemoryDumpScheduler::GetInstance();
    mds_->Setup(nullptr, nullptr);
    mds_->AddTrigger(MemoryDumpType::PEAK_MEMORY_USAGE,
                     MemoryDumpLevelOfDetail::LIGHT, kMinPollsToDump);
    mds_->polling_state_->ResetTotals();
    mds_->polling_state_->current_state =
        MemoryDumpScheduler::PollingTriggerState::ENABLED;
  }

  void TearDown() override {
    mds_->polling_state_->current_state =
        MemoryDumpScheduler::PollingTriggerState::DISABLED;
  }

 protected:
  bool ShouldTriggerDump(uint64_t total) {
    return mds_->ShouldTriggerDump(total);
  }

  uint32_t num_samples_tracked_;
  MemoryDumpScheduler* mds_;
};

TEST_F(MemoryDumpSchedulerPollingTest, PeakDetection) {
  for (uint32_t i = 0; i < num_samples_tracked_ * 6; ++i) {
    // Memory is increased in steps and dumps must be triggered at every step.
    uint64_t total = (2 + (i / (2 * num_samples_tracked_))) * 1024 * 1204;
    bool did_trigger = ShouldTriggerDump(total);
    // Dumps must be triggered only at specific iterations.
    bool should_have_triggered = i == 0;
    should_have_triggered |=
        (i > num_samples_tracked_) && (i % (2 * num_samples_tracked_) == 1);
    if (should_have_triggered) {
      ASSERT_TRUE(did_trigger) << "Dump wasn't triggered at " << i;
    } else {
      ASSERT_FALSE(did_trigger) << "Unexpected dump at " << i;
    }
  }
}

TEST_F(MemoryDumpSchedulerPollingTest, SlowGrowthDetection) {
  for (uint32_t i = 0; i < 15; ++i) {
    // Record 1GiB of increase in each call. Dumps are triggered with 1% w.r.t
    // system's total memory.
    uint64_t total = static_cast<uint64_t>(i + 1) * 1024 * 1024 * 1024;
    bool did_trigger = ShouldTriggerDump(total);
    bool should_have_triggered = i % kMinPollsToDump == 0;
    if (should_have_triggered) {
      ASSERT_TRUE(did_trigger) << "Dump wasn't triggered at " << i;
    } else {
      ASSERT_FALSE(did_trigger) << "Unexpected dump at " << i;
    }
  }
}

TEST_F(MemoryDumpSchedulerPollingTest, NotifyDumpTriggered) {
  for (uint32_t i = 0; i < num_samples_tracked_ * 6; ++i) {
    uint64_t total = (2 + (i / (2 * num_samples_tracked_))) * 1024 * 1204;
    if (i % num_samples_tracked_ == 0)
      mds_->NotifyDumpTriggered();
    bool did_trigger = ShouldTriggerDump(total);
    // Dumps should never be triggered since NotifyDumpTriggered() is called
    // frequently.
    EXPECT_NE(0u, mds_->polling_state_->last_dump_memory_total);
    EXPECT_GT(num_samples_tracked_ - 1,
              mds_->polling_state_->last_memory_totals_kb_index);
    EXPECT_LT(static_cast<int64_t>(
                  total - mds_->polling_state_->last_dump_memory_total),
              mds_->polling_state_->memory_increase_threshold);
    ASSERT_FALSE(did_trigger && i) << "Unexpected dump at " << i;
  }
}

}  // namespace trace_event
}  // namespace base
