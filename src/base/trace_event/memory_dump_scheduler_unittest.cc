// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_scheduler.h"

#include <memory>

#include "base/bind.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/thread.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::Invoke;
using ::testing::_;

namespace base {
namespace trace_event {

namespace {

// Wrapper to use gmock on a callback.
struct CallbackWrapper {
  MOCK_METHOD1(OnTick, void(MemoryDumpLevelOfDetail));
};

}  // namespace

class MemoryDumpSchedulerTest : public testing::Test {
 public:
  struct FriendDeleter {
    void operator()(MemoryDumpScheduler* inst) { delete inst; }
  };

  MemoryDumpSchedulerTest() : testing::Test() {}

  void SetUp() override {
    bg_thread_.reset(new Thread("MemoryDumpSchedulerTest Thread"));
    bg_thread_->Start();
    scheduler_.reset(new MemoryDumpScheduler());
  }

  void TearDown() override {
    bg_thread_.reset();
    scheduler_.reset();
  }

 protected:
  std::unique_ptr<MemoryDumpScheduler, FriendDeleter> scheduler_;
  std::unique_ptr<Thread> bg_thread_;
  CallbackWrapper on_tick_;
};

TEST_F(MemoryDumpSchedulerTest, SingleTrigger) {
  const uint32_t kPeriodMs = 1;
  const auto kLevelOfDetail = MemoryDumpLevelOfDetail::DETAILED;
  const uint32_t kTicks = 5;
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  MemoryDumpScheduler::Config config;
  config.triggers.push_back({kLevelOfDetail, kPeriodMs});
  config.callback = Bind(&CallbackWrapper::OnTick, Unretained(&on_tick_));

  testing::InSequence sequence;
  EXPECT_CALL(on_tick_, OnTick(_)).Times(kTicks - 1);
  EXPECT_CALL(on_tick_, OnTick(_))
      .WillRepeatedly(Invoke(
          [&evt, kLevelOfDetail](MemoryDumpLevelOfDetail level_of_detail) {
            EXPECT_EQ(kLevelOfDetail, level_of_detail);
            evt.Signal();
          }));

  // Check that Stop() before Start() doesn't cause any error.
  scheduler_->Stop();

  const TimeTicks tstart = TimeTicks::Now();
  scheduler_->Start(config, bg_thread_->task_runner());
  evt.Wait();
  const double time_ms = (TimeTicks::Now() - tstart).InMillisecondsF();

  // It takes N-1 ms to perform N ticks of 1ms each.
  EXPECT_GE(time_ms, kPeriodMs * (kTicks - 1));

  // Check that stopping twice doesn't cause any problems.
  scheduler_->Stop();
  scheduler_->Stop();
}

TEST_F(MemoryDumpSchedulerTest, MultipleTriggers) {
  const uint32_t kPeriodLightMs = 3;
  const uint32_t kPeriodDetailedMs = 9;
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  MemoryDumpScheduler::Config config;
  const MemoryDumpLevelOfDetail kLight = MemoryDumpLevelOfDetail::LIGHT;
  const MemoryDumpLevelOfDetail kDetailed = MemoryDumpLevelOfDetail::DETAILED;
  config.triggers.push_back({kLight, kPeriodLightMs});
  config.triggers.push_back({kDetailed, kPeriodDetailedMs});
  config.callback = Bind(&CallbackWrapper::OnTick, Unretained(&on_tick_));

  TimeTicks t1, t2, t3;

  testing::InSequence sequence;
  EXPECT_CALL(on_tick_, OnTick(kDetailed))
      .WillOnce(
          Invoke([&t1](MemoryDumpLevelOfDetail) { t1 = TimeTicks::Now(); }));
  EXPECT_CALL(on_tick_, OnTick(kLight)).Times(1);
  EXPECT_CALL(on_tick_, OnTick(kLight)).Times(1);
  EXPECT_CALL(on_tick_, OnTick(kDetailed))
      .WillOnce(
          Invoke([&t2](MemoryDumpLevelOfDetail) { t2 = TimeTicks::Now(); }));
  EXPECT_CALL(on_tick_, OnTick(kLight))
      .WillOnce(
          Invoke([&t3](MemoryDumpLevelOfDetail) { t3 = TimeTicks::Now(); }));

  // Rationale for WillRepeatedly and not just WillOnce: Extra ticks might
  // happen if the Stop() takes time. Not an interesting case, but we need to
  // avoid gmock to shout in that case.
  EXPECT_CALL(on_tick_, OnTick(_))
      .WillRepeatedly(
          Invoke([&evt](MemoryDumpLevelOfDetail) { evt.Signal(); }));

  scheduler_->Start(config, bg_thread_->task_runner());
  evt.Wait();
  scheduler_->Stop();
  EXPECT_GE((t2 - t1).InMillisecondsF(), kPeriodDetailedMs);
  EXPECT_GE((t3 - t2).InMillisecondsF(), kPeriodLightMs);
}

TEST_F(MemoryDumpSchedulerTest, StartStopQuickly) {
  const uint32_t kPeriodMs = 1;
  const uint32_t kTicks = 10;
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  MemoryDumpScheduler::Config config;
  config.triggers.push_back({MemoryDumpLevelOfDetail::DETAILED, kPeriodMs});
  config.callback = Bind(&CallbackWrapper::OnTick, Unretained(&on_tick_));

  testing::InSequence sequence;
  EXPECT_CALL(on_tick_, OnTick(_)).Times(kTicks - 1);
  EXPECT_CALL(on_tick_, OnTick(_))
      .WillRepeatedly(
          Invoke([&evt](MemoryDumpLevelOfDetail) { evt.Signal(); }));

  const TimeTicks tstart = TimeTicks::Now();
  for (int i = 0; i < 5; i++) {
    scheduler_->Stop();
    scheduler_->Start(config, bg_thread_->task_runner());
  }
  evt.Wait();
  const double time_ms = (TimeTicks::Now() - tstart).InMillisecondsF();
  scheduler_->Stop();

  // It takes N-1 ms to perform N ticks of 1ms each.
  EXPECT_GE(time_ms, kPeriodMs * (kTicks - 1));
}

TEST_F(MemoryDumpSchedulerTest, StopAndStartOnAnotherThread) {
  const uint32_t kPeriodMs = 1;
  const uint32_t kTicks = 3;
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  MemoryDumpScheduler::Config config;
  config.triggers.push_back({MemoryDumpLevelOfDetail::DETAILED, kPeriodMs});
  config.callback = Bind(&CallbackWrapper::OnTick, Unretained(&on_tick_));

  scoped_refptr<TaskRunner> expected_task_runner = bg_thread_->task_runner();
  testing::InSequence sequence;
  EXPECT_CALL(on_tick_, OnTick(_)).Times(kTicks - 1);
  EXPECT_CALL(on_tick_, OnTick(_))
      .WillRepeatedly(
          Invoke([&evt, expected_task_runner](MemoryDumpLevelOfDetail) {
            EXPECT_TRUE(expected_task_runner->RunsTasksOnCurrentThread());
            evt.Signal();
          }));

  scheduler_->Start(config, bg_thread_->task_runner());
  evt.Wait();
  scheduler_->Stop();
  bg_thread_->Stop();

  bg_thread_.reset(new Thread("MemoryDumpSchedulerTest Thread 2"));
  bg_thread_->Start();
  evt.Reset();
  expected_task_runner = bg_thread_->task_runner();
  scheduler_->Start(config, bg_thread_->task_runner());
  EXPECT_CALL(on_tick_, OnTick(_)).Times(kTicks - 1);
  EXPECT_CALL(on_tick_, OnTick(_))
      .WillRepeatedly(
          Invoke([&evt, expected_task_runner](MemoryDumpLevelOfDetail) {
            EXPECT_TRUE(expected_task_runner->RunsTasksOnCurrentThread());
            evt.Signal();
          }));
  evt.Wait();
  scheduler_->Stop();
}

}  // namespace trace_event
}  // namespace base
