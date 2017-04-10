// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_peak_detector.h"

#include <memory>

#include "base/bind.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_dump_provider.h"
#include "base/trace_event/memory_dump_provider_info.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

namespace base {
namespace trace_event {

namespace {

class MockMemoryDumpProvider : public MemoryDumpProvider {
 public:
  bool OnMemoryDump(const MemoryDumpArgs&, ProcessMemoryDump*) override {
    NOTREACHED();
    return true;
  }

  MOCK_METHOD1(PollFastMemoryTotal, void(uint64_t*));
};

// Wrapper to use gmock on a callback.
struct OnPeakDetectedWrapper {
  MOCK_METHOD0(OnPeak, void());
};

}  // namespace

class MemoryPeakDetectorTest : public testing::Test {
 public:
  struct FriendDeleter {
    void operator()(MemoryPeakDetector* inst) { delete inst; }
  };

  MemoryPeakDetectorTest() : testing::Test() {}

  std::unique_ptr<MemoryPeakDetector, FriendDeleter> NewInstance() {
    return std::unique_ptr<MemoryPeakDetector, FriendDeleter>(
        new MemoryPeakDetector());
  }

  void RestartThreadAndReinitializePeakDetector() {
    bg_thread_.reset(new Thread("Peak Detector Test Thread"));
    bg_thread_->Start();
    peak_detector_ = NewInstance();
    peak_detector_->Setup(
        Bind(&MemoryPeakDetectorTest::MockGetDumpProviders, Unretained(this)),
        bg_thread_->task_runner(),
        Bind(&OnPeakDetectedWrapper::OnPeak, Unretained(&on_peak_callback_)));
  }

  void SetUp() override {
    get_mdp_call_count_ = 0;
    RestartThreadAndReinitializePeakDetector();
  }

  void TearDown() override {
    peak_detector_->TearDown();
    bg_thread_->FlushForTesting();
    EXPECT_EQ(MemoryPeakDetector::NOT_INITIALIZED, GetPeakDetectorState());
    dump_providers_.clear();
  }

  // Calls MemoryPeakDetector::state_for_testing() on the bg thread and returns
  // the result on the current thread.
  MemoryPeakDetector::State GetPeakDetectorState() {
    WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
    MemoryPeakDetector::State res = MemoryPeakDetector::NOT_INITIALIZED;
    auto get_fn = [](MemoryPeakDetector* peak_detector, WaitableEvent* evt,
                     MemoryPeakDetector::State* res) {
      *res = peak_detector->state_for_testing();
      evt->Signal();
    };
    bg_thread_->task_runner()->PostTask(
        FROM_HERE, Bind(get_fn, Unretained(&*peak_detector_), Unretained(&evt),
                        Unretained(&res)));
    evt.Wait();
    return res;
  }

  // Calls MemoryPeakDetector::poll_tasks_count_for_testing() on the bg thread
  // and returns the result on the current thread.
  uint32_t GetNumPollingTasksRan() {
    uint32_t res = 0;
    auto get_fn = [](MemoryPeakDetector* peak_detector, WaitableEvent* evt,
                     uint32_t* res) {
      *res = peak_detector->poll_tasks_count_for_testing();
      evt->Signal();
    };

    WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
    bg_thread_->task_runner()->PostTask(
        FROM_HERE, Bind(get_fn, Unretained(&*peak_detector_), Unretained(&evt),
                        Unretained(&res)));
    evt.Wait();
    return res;
  }

  // Called on the |bg_thread_|.
  void MockGetDumpProviders(MemoryPeakDetector::DumpProvidersList* mdps) {
    get_mdp_call_count_++;
    *mdps = dump_providers_;
  }

  uint32_t GetNumGetDumpProvidersCalls() {
    bg_thread_->FlushForTesting();
    return get_mdp_call_count_;
  }

  scoped_refptr<MemoryDumpProviderInfo> CreateMockDumpProvider() {
    std::unique_ptr<MockMemoryDumpProvider> mdp(new MockMemoryDumpProvider());
    MemoryDumpProvider::Options opt;
    opt.is_fast_polling_supported = true;
    scoped_refptr<MemoryDumpProviderInfo> mdp_info(
        new MemoryDumpProviderInfo(mdp.get(), "Mock MDP", nullptr, opt, false));

    // The |mdp| instance will be destroyed together with the |mdp_info|.
    mdp_info->owned_dump_provider = std::move(mdp);
    return mdp_info;
  }

  static MockMemoryDumpProvider& GetMockMDP(
      const scoped_refptr<MemoryDumpProviderInfo>& mdp_info) {
    return *static_cast<MockMemoryDumpProvider*>(mdp_info->dump_provider);
  }

 protected:
  MemoryPeakDetector::DumpProvidersList dump_providers_;
  uint32_t get_mdp_call_count_;
  std::unique_ptr<MemoryPeakDetector, FriendDeleter> peak_detector_;
  std::unique_ptr<Thread> bg_thread_;
  OnPeakDetectedWrapper on_peak_callback_;
};

TEST_F(MemoryPeakDetectorTest, GetDumpProvidersFunctionCalled) {
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  peak_detector_->Start();
  EXPECT_EQ(1u, GetNumGetDumpProvidersCalls());
  EXPECT_EQ(MemoryPeakDetector::ENABLED, GetPeakDetectorState());

  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  EXPECT_EQ(0u, GetNumPollingTasksRan());
}

TEST_F(MemoryPeakDetectorTest, NotifyBeforeInitialize) {
  peak_detector_->TearDown();

  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  scoped_refptr<MemoryDumpProviderInfo> mdp = CreateMockDumpProvider();
  EXPECT_CALL(GetMockMDP(mdp), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&evt](uint64_t*) { evt.Signal(); }));
  dump_providers_.push_back(mdp);
  peak_detector_->NotifyMemoryDumpProvidersChanged();
  EXPECT_EQ(MemoryPeakDetector::NOT_INITIALIZED, GetPeakDetectorState());
  RestartThreadAndReinitializePeakDetector();

  peak_detector_->Start();
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());
  evt.Wait();  // Wait for a PollFastMemoryTotal() call.

  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  EXPECT_EQ(1u, GetNumGetDumpProvidersCalls());
  EXPECT_GE(GetNumPollingTasksRan(), 1u);
}

TEST_F(MemoryPeakDetectorTest, DoubleStop) {
  peak_detector_->Start();
  EXPECT_EQ(MemoryPeakDetector::ENABLED, GetPeakDetectorState());

  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());

  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());

  EXPECT_EQ(1u, GetNumGetDumpProvidersCalls());
  EXPECT_EQ(0u, GetNumPollingTasksRan());
}

TEST_F(MemoryPeakDetectorTest, OneDumpProviderRegisteredBeforeStart) {
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  scoped_refptr<MemoryDumpProviderInfo> mdp = CreateMockDumpProvider();
  EXPECT_CALL(GetMockMDP(mdp), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&evt](uint64_t*) { evt.Signal(); }));
  dump_providers_.push_back(mdp);

  peak_detector_->Start();
  evt.Wait();  // Signaled when PollFastMemoryTotal() is called on the MockMDP.
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());

  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  EXPECT_EQ(1u, GetNumGetDumpProvidersCalls());
  EXPECT_GT(GetNumPollingTasksRan(), 0u);
}

TEST_F(MemoryPeakDetectorTest, ReInitializeAndRebindToNewThread) {
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  scoped_refptr<MemoryDumpProviderInfo> mdp = CreateMockDumpProvider();
  EXPECT_CALL(GetMockMDP(mdp), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&evt](uint64_t*) { evt.Signal(); }));
  dump_providers_.push_back(mdp);

  for (int i = 0; i < 5; ++i) {
    evt.Reset();
    peak_detector_->Start();
    evt.Wait();  // Wait for a PollFastMemoryTotal() call.
    // Check that calling TearDown implicitly does a Stop().
    peak_detector_->TearDown();

    // Reinitialize and re-bind to a new task runner.
    RestartThreadAndReinitializePeakDetector();
  }
}

TEST_F(MemoryPeakDetectorTest, OneDumpProviderRegisteredOutOfBand) {
  peak_detector_->Start();
  EXPECT_EQ(MemoryPeakDetector::ENABLED, GetPeakDetectorState());
  EXPECT_EQ(1u, GetNumGetDumpProvidersCalls());

  // Check that no poll tasks are posted before any dump provider is registered.
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  EXPECT_EQ(0u, GetNumPollingTasksRan());

  // Registed the MDP After Start() has been issued and expect that the
  // PeakDetector transitions ENABLED -> RUNNING on the next
  // NotifyMemoryDumpProvidersChanged() call.
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  scoped_refptr<MemoryDumpProviderInfo> mdp = CreateMockDumpProvider();
  EXPECT_CALL(GetMockMDP(mdp), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&evt](uint64_t*) { evt.Signal(); }));
  dump_providers_.push_back(mdp);
  peak_detector_->NotifyMemoryDumpProvidersChanged();

  evt.Wait();  // Signaled when PollFastMemoryTotal() is called on the MockMDP.
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());
  EXPECT_EQ(2u, GetNumGetDumpProvidersCalls());

  // Now simulate the unregisration and expect that the PeakDetector transitions
  // back to ENABLED.
  dump_providers_.clear();
  peak_detector_->NotifyMemoryDumpProvidersChanged();
  EXPECT_EQ(MemoryPeakDetector::ENABLED, GetPeakDetectorState());
  EXPECT_EQ(3u, GetNumGetDumpProvidersCalls());
  uint32_t num_poll_tasks = GetNumPollingTasksRan();
  EXPECT_GT(num_poll_tasks, 0u);

  // At this point, no more polling tasks should be posted.
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  EXPECT_EQ(num_poll_tasks, GetNumPollingTasksRan());
}

// Test that a sequence of Start()/Stop() back-to-back doesn't end up creating
// several outstanding timer tasks and instead respects the polling_interval_ms.
TEST_F(MemoryPeakDetectorTest, StartStopQuickly) {
  WaitableEvent evt(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED);
  scoped_refptr<MemoryDumpProviderInfo> mdp = CreateMockDumpProvider();
  dump_providers_.push_back(mdp);
  const uint32_t kNumPolls = 20;
  uint32_t polls_done = 0;
  EXPECT_CALL(GetMockMDP(mdp), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&polls_done, &evt, kNumPolls](uint64_t*) {
        if (++polls_done == kNumPolls)
          evt.Signal();
      }));

  const TimeTicks tstart = TimeTicks::Now();
  for (int i = 0; i < 5; i++) {
    peak_detector_->Start();
    peak_detector_->Stop();
  }
  peak_detector_->Start();
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());
  evt.Wait();  // Wait for kNumPolls.
  const double time_ms = (TimeTicks::Now() - tstart).InMillisecondsF();

  // TODO(primiano): this will become config.polling_interval_ms in the next CL.
  const uint32_t polling_interval_ms = 1;
  EXPECT_GE(time_ms, kNumPolls * polling_interval_ms);
  peak_detector_->Stop();
}

TEST_F(MemoryPeakDetectorTest, RegisterAndUnregisterTwoDumpProviders) {
  WaitableEvent evt1(WaitableEvent::ResetPolicy::MANUAL,
                     WaitableEvent::InitialState::NOT_SIGNALED);
  WaitableEvent evt2(WaitableEvent::ResetPolicy::MANUAL,
                     WaitableEvent::InitialState::NOT_SIGNALED);
  scoped_refptr<MemoryDumpProviderInfo> mdp1 = CreateMockDumpProvider();
  scoped_refptr<MemoryDumpProviderInfo> mdp2 = CreateMockDumpProvider();
  EXPECT_CALL(GetMockMDP(mdp1), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&evt1](uint64_t*) { evt1.Signal(); }));
  EXPECT_CALL(GetMockMDP(mdp2), PollFastMemoryTotal(_))
      .WillRepeatedly(Invoke([&evt2](uint64_t*) { evt2.Signal(); }));

  // Register only one MDP and start the detector.
  dump_providers_.push_back(mdp1);
  peak_detector_->Start();
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());

  // Wait for one poll task and then register also the other one.
  evt1.Wait();
  dump_providers_.push_back(mdp2);
  peak_detector_->NotifyMemoryDumpProvidersChanged();
  evt2.Wait();
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());

  // Now unregister the first MDP and check that everything is still running.
  dump_providers_.erase(dump_providers_.begin());
  peak_detector_->NotifyMemoryDumpProvidersChanged();
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());

  // Now unregister both and check that the detector goes to idle.
  dump_providers_.clear();
  peak_detector_->NotifyMemoryDumpProvidersChanged();
  EXPECT_EQ(MemoryPeakDetector::ENABLED, GetPeakDetectorState());

  // Now re-register both and check that the detector re-activates posting
  // new polling tasks.
  uint32_t num_poll_tasks = GetNumPollingTasksRan();
  evt1.Reset();
  evt2.Reset();
  dump_providers_.push_back(mdp1);
  dump_providers_.push_back(mdp2);
  peak_detector_->NotifyMemoryDumpProvidersChanged();
  evt1.Wait();
  evt2.Wait();
  EXPECT_EQ(MemoryPeakDetector::RUNNING, GetPeakDetectorState());
  EXPECT_GT(GetNumPollingTasksRan(), num_poll_tasks);

  // Stop everything, tear down the MDPs, restart the detector and check that
  // it detector doesn't accidentally try to re-access them.
  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  dump_providers_.clear();
  mdp1 = nullptr;
  mdp2 = nullptr;

  num_poll_tasks = GetNumPollingTasksRan();
  peak_detector_->Start();
  EXPECT_EQ(MemoryPeakDetector::ENABLED, GetPeakDetectorState());
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());

  peak_detector_->Stop();
  EXPECT_EQ(MemoryPeakDetector::DISABLED, GetPeakDetectorState());
  EXPECT_EQ(num_poll_tasks, GetNumPollingTasksRan());

  EXPECT_EQ(6u, GetNumGetDumpProvidersCalls());
}

}  // namespace trace_event
}  // namespace base
