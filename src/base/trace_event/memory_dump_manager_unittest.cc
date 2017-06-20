// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_manager.h"

#include <stdint.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted_memory.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/sequenced_worker_pool_owner.h"
#include "base/test/test_io_thread.h"
#include "base/test/trace_event_analyzer.h"
#include "base/threading/platform_thread.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_dump_manager_test_utils.h"
#include "base/trace_event/memory_dump_provider.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/memory_dump_scheduler.h"
#include "base/trace_event/memory_infra_background_whitelist.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_buffer.h"
#include "base/trace_event/trace_config_memory_test_util.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using testing::_;
using testing::AnyNumber;
using testing::AtMost;
using testing::Between;
using testing::Invoke;
using testing::Return;

namespace base {
namespace trace_event {

// GTest matchers for MemoryDumpRequestArgs arguments.
MATCHER(IsDetailedDump, "") {
  return arg.level_of_detail == MemoryDumpLevelOfDetail::DETAILED;
}

MATCHER(IsLightDump, "") {
  return arg.level_of_detail == MemoryDumpLevelOfDetail::LIGHT;
}

MATCHER(IsBackgroundDump, "") {
  return arg.level_of_detail == MemoryDumpLevelOfDetail::BACKGROUND;
}

namespace {

const char* kMDPName = "TestDumpProvider";
const char* kWhitelistedMDPName = "WhitelistedTestDumpProvider";
const char* kBackgroundButNotSummaryWhitelistedMDPName =
    "BackgroundButNotSummaryWhitelistedTestDumpProvider";
const char* const kTestMDPWhitelist[] = {
    kWhitelistedMDPName, kBackgroundButNotSummaryWhitelistedMDPName, nullptr};
const char* const kTestMDPWhitelistForSummary[] = {kWhitelistedMDPName,
                                                   nullptr};

void RegisterDumpProvider(
    MemoryDumpProvider* mdp,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    const MemoryDumpProvider::Options& options,
    const char* name = kMDPName) {
  MemoryDumpManager* mdm = MemoryDumpManager::GetInstance();
  mdm->set_dumper_registrations_ignored_for_testing(false);
  mdm->RegisterDumpProvider(mdp, name, std::move(task_runner), options);
  mdm->set_dumper_registrations_ignored_for_testing(true);
}

void RegisterDumpProvider(
    MemoryDumpProvider* mdp,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  RegisterDumpProvider(mdp, task_runner, MemoryDumpProvider::Options());
}

void RegisterDumpProviderWithSequencedTaskRunner(
    MemoryDumpProvider* mdp,
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    const MemoryDumpProvider::Options& options) {
  MemoryDumpManager* mdm = MemoryDumpManager::GetInstance();
  mdm->set_dumper_registrations_ignored_for_testing(false);
  mdm->RegisterDumpProviderWithSequencedTaskRunner(mdp, kMDPName, task_runner,
                                                   options);
  mdm->set_dumper_registrations_ignored_for_testing(true);
}

// Posts |task| to |task_runner| and blocks until it is executed.
void PostTaskAndWait(const tracked_objects::Location& from_here,
                     SequencedTaskRunner* task_runner,
                     base::OnceClosure task) {
  base::WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                            WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner->PostTask(from_here, std::move(task));
  task_runner->PostTask(FROM_HERE, base::BindOnce(&WaitableEvent::Signal,
                                                  base::Unretained(&event)));
  // The SequencedTaskRunner guarantees that |event| will only be signaled after
  // |task| is executed.
  event.Wait();
}

class MockMemoryDumpProvider : public MemoryDumpProvider {
 public:
  MOCK_METHOD0(Destructor, void());
  MOCK_METHOD2(OnMemoryDump,
               bool(const MemoryDumpArgs& args, ProcessMemoryDump* pmd));
  MOCK_METHOD1(PollFastMemoryTotal, void(uint64_t* memory_total));
  MOCK_METHOD0(SuspendFastMemoryPolling, void());

  MockMemoryDumpProvider() : enable_mock_destructor(false) {
    ON_CALL(*this, OnMemoryDump(_, _))
        .WillByDefault(
            Invoke([](const MemoryDumpArgs&, ProcessMemoryDump* pmd) -> bool {
              return true;
            }));

    ON_CALL(*this, PollFastMemoryTotal(_))
        .WillByDefault(
            Invoke([](uint64_t* memory_total) -> void { NOTREACHED(); }));
  }
  ~MockMemoryDumpProvider() override {
    if (enable_mock_destructor)
      Destructor();
  }

  bool enable_mock_destructor;
};

class TestSequencedTaskRunner : public SequencedTaskRunner {
 public:
  TestSequencedTaskRunner()
      : worker_pool_(2 /* max_threads */, "Test Task Runner"),
        enabled_(true),
        num_of_post_tasks_(0) {}

  void set_enabled(bool value) { enabled_ = value; }
  unsigned no_of_post_tasks() const { return num_of_post_tasks_; }

  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  OnceClosure task,
                                  TimeDelta delay) override {
    NOTREACHED();
    return false;
  }

  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure task,
                       TimeDelta delay) override {
    num_of_post_tasks_++;
    if (enabled_) {
      return worker_pool_.pool()->PostSequencedWorkerTask(token_, from_here,
                                                          std::move(task));
    }
    return false;
  }

  bool RunsTasksInCurrentSequence() const override {
    return worker_pool_.pool()->RunsTasksInCurrentSequence();
  }

 private:
  ~TestSequencedTaskRunner() override {}

  SequencedWorkerPoolOwner worker_pool_;
  const SequencedWorkerPool::SequenceToken token_;
  bool enabled_;
  unsigned num_of_post_tasks_;
};

std::unique_ptr<trace_analyzer::TraceAnalyzer> GetDeserializedTrace() {
  // Flush the trace into JSON.
  trace_event::TraceResultBuffer buffer;
  TraceResultBuffer::SimpleOutput trace_output;
  buffer.SetOutputCallback(trace_output.GetCallback());
  RunLoop run_loop;
  buffer.Start();
  auto on_trace_data_collected =
      [](Closure quit_closure, trace_event::TraceResultBuffer* buffer,
         const scoped_refptr<RefCountedString>& json, bool has_more_events) {
        buffer->AddFragment(json->data());
        if (!has_more_events)
          quit_closure.Run();
      };

  trace_event::TraceLog::GetInstance()->Flush(Bind(
      on_trace_data_collected, run_loop.QuitClosure(), Unretained(&buffer)));
  run_loop.Run();
  buffer.Finish();

  // Analyze the JSON.
  return WrapUnique(
      trace_analyzer::TraceAnalyzer::Create(trace_output.json_output));
}

}  // namespace

class MemoryDumpManagerTest : public testing::Test {
 public:
  MemoryDumpManagerTest() : testing::Test(), kDefaultOptions() {}

  void SetUp() override {
    message_loop_.reset(new MessageLoop());
    mdm_ = MemoryDumpManager::CreateInstanceForTesting();
    ASSERT_EQ(mdm_.get(), MemoryDumpManager::GetInstance());
  }

  void TearDown() override {
    mdm_.reset();
    message_loop_.reset();
    TraceLog::DeleteForTesting();
  }

 protected:
  // Blocks the current thread (spinning a nested message loop) until the
  // memory dump is complete. Returns:
  // - return value: the |success| from the CreateProcessDump() callback.
  // - (optional) |result|: the summarized metrics for TestSummaryComputation.
  bool RequestProcessDumpAndWait(
      MemoryDumpType dump_type,
      MemoryDumpLevelOfDetail level_of_detail,
      Optional<MemoryDumpCallbackResult>* result = nullptr) {
    RunLoop run_loop;
    bool success = false;
    static uint64_t test_guid = 1;
    test_guid++;
    MemoryDumpRequestArgs request_args{test_guid, dump_type, level_of_detail};

    // The signature of the callback delivered by MemoryDumpManager is:
    // void ProcessMemoryDumpCallback(uint64_t dump_guid,
    //                                bool success,
    //                                const Optional<MemoryDumpCallbackResult>&)
    // The extra arguments prepended to the |callback| below (the ones with the
    // "curried_" prefix) are just passed from the Bind(). This is just to get
    // around the limitation of Bind() in supporting only capture-less lambdas.
    ProcessMemoryDumpCallback callback = Bind(
        [](bool* curried_success, Closure curried_quit_closure,
           uint64_t curried_expected_guid,
           Optional<MemoryDumpCallbackResult>* curried_result,
           uint64_t dump_guid, bool success,
           const Optional<MemoryDumpCallbackResult>& callback_result) {
          *curried_success = success;
          EXPECT_EQ(curried_expected_guid, dump_guid);
          if (curried_result)
            *curried_result = callback_result;
          ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                                  curried_quit_closure);
        },
        Unretained(&success), run_loop.QuitClosure(), test_guid, result);

    mdm_->CreateProcessDump(request_args, callback);
    run_loop.Run();
    return success;
  }

  void EnableTracingWithLegacyCategories(const char* category) {
    TraceLog::GetInstance()->SetEnabled(TraceConfig(category, ""),
                                        TraceLog::RECORDING_MODE);
  }

  void EnableTracingWithTraceConfig(const std::string& trace_config) {
    TraceLog::GetInstance()->SetEnabled(TraceConfig(trace_config),
                                        TraceLog::RECORDING_MODE);
  }

  void DisableTracing() { TraceLog::GetInstance()->SetDisabled(); }

  bool IsPeriodicDumpingEnabled() const {
    return MemoryDumpScheduler::GetInstance()->is_enabled_for_testing();
  }

  int GetMaxConsecutiveFailuresCount() const {
    return MemoryDumpManager::kMaxConsecutiveFailuresCount;
  }

  const MemoryDumpProvider::Options kDefaultOptions;
  std::unique_ptr<MemoryDumpManager> mdm_;

 private:
  std::unique_ptr<MessageLoop> message_loop_;

  // To tear down the singleton instance after each test.
  ShadowingAtExitManager at_exit_manager_;
};

// Basic sanity checks. Registers a memory dump provider and checks that it is
// called.
TEST_F(MemoryDumpManagerTest, SingleDumper) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());

  // Now repeat enabling the memory category and check that the dumper is
  // invoked this time.
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(3);
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }
  DisableTracing();

  mdm_->UnregisterDumpProvider(&mdp);

  // Finally check the unregister logic: the global dump handler will be invoked
  // but not the dump provider, as it has been unregistered.
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(0);
  for (int i = 0; i < 3; ++i) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }
  DisableTracing();
}

// Checks that requesting dumps with high level of detail actually propagates
// the level of the detail properly to OnMemoryDump() call on dump providers.
TEST_F(MemoryDumpManagerTest, CheckMemoryDumpArgs) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;

  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp, OnMemoryDump(IsDetailedDump(), _));
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  DisableTracing();
  mdm_->UnregisterDumpProvider(&mdp);

  // Check that requesting dumps with low level of detail actually propagates to
  // OnMemoryDump() call on dump providers.
  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp, OnMemoryDump(IsLightDump(), _));
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::LIGHT));
  DisableTracing();
  mdm_->UnregisterDumpProvider(&mdp);
}

// Checks that the HeapProfilerSerializationState object is actually
// shared over time.
TEST_F(MemoryDumpManagerTest, HeapProfilerSerializationState) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp1;
  MockMemoryDumpProvider mdp2;
  RegisterDumpProvider(&mdp1, nullptr);
  RegisterDumpProvider(&mdp2, nullptr);

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  const HeapProfilerSerializationState* heap_profiler_serialization_state =
      mdm_->heap_profiler_serialization_state_for_testing().get();
  EXPECT_CALL(mdp1, OnMemoryDump(_, _))
      .Times(2)
      .WillRepeatedly(
          Invoke([heap_profiler_serialization_state](
                     const MemoryDumpArgs&, ProcessMemoryDump* pmd) -> bool {
            EXPECT_EQ(heap_profiler_serialization_state,
                      pmd->heap_profiler_serialization_state().get());
            return true;
          }));
  EXPECT_CALL(mdp2, OnMemoryDump(_, _))
      .Times(2)
      .WillRepeatedly(
          Invoke([heap_profiler_serialization_state](
                     const MemoryDumpArgs&, ProcessMemoryDump* pmd) -> bool {
            EXPECT_EQ(heap_profiler_serialization_state,
                      pmd->heap_profiler_serialization_state().get());
            return true;
          }));

  for (int i = 0; i < 2; ++i) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }

  DisableTracing();
}

// Checks that the (Un)RegisterDumpProvider logic behaves sanely.
TEST_F(MemoryDumpManagerTest, MultipleDumpers) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp1;
  MockMemoryDumpProvider mdp2;

  // Enable only mdp1.
  RegisterDumpProvider(&mdp1, ThreadTaskRunnerHandle::Get());
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp1, OnMemoryDump(_, _));
  EXPECT_CALL(mdp2, OnMemoryDump(_, _)).Times(0);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  DisableTracing();

  // Invert: enable mdp2 and disable mdp1.
  mdm_->UnregisterDumpProvider(&mdp1);
  RegisterDumpProvider(&mdp2, nullptr);
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp1, OnMemoryDump(_, _)).Times(0);
  EXPECT_CALL(mdp2, OnMemoryDump(_, _));
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  DisableTracing();

  // Enable both mdp1 and mdp2.
  RegisterDumpProvider(&mdp1, nullptr);
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp1, OnMemoryDump(_, _));
  EXPECT_CALL(mdp2, OnMemoryDump(_, _));
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  DisableTracing();
}

// Checks that the dump provider invocations depend only on the current
// registration state and not on previous registrations and dumps.
// Flaky on iOS, see crbug.com/706874
#if defined(OS_IOS)
#define MAYBE_RegistrationConsistency DISABLED_RegistrationConsistency
#else
#define MAYBE_RegistrationConsistency RegistrationConsistency
#endif
TEST_F(MemoryDumpManagerTest, MAYBE_RegistrationConsistency) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;

  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());

  {
    EXPECT_CALL(mdp, OnMemoryDump(_, _));
    EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
    DisableTracing();
  }

  mdm_->UnregisterDumpProvider(&mdp);

  {
    EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(0);
    EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
    DisableTracing();
  }

  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());
  mdm_->UnregisterDumpProvider(&mdp);

  {
    EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(0);
    EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
    DisableTracing();
  }

  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());
  mdm_->UnregisterDumpProvider(&mdp);
  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());

  {
    EXPECT_CALL(mdp, OnMemoryDump(_, _));
    EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
    DisableTracing();
  }
}

// Checks that the MemoryDumpManager respects the thread affinity when a
// MemoryDumpProvider specifies a task_runner(). The test starts creating 8
// threads and registering a MemoryDumpProvider on each of them. At each
// iteration, one thread is removed, to check the live unregistration logic.
TEST_F(MemoryDumpManagerTest, RespectTaskRunnerAffinity) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  const uint32_t kNumInitialThreads = 8;

  std::vector<std::unique_ptr<Thread>> threads;
  std::vector<std::unique_ptr<MockMemoryDumpProvider>> mdps;

  // Create the threads and setup the expectations. Given that at each iteration
  // we will pop out one thread/MemoryDumpProvider, each MDP is supposed to be
  // invoked a number of times equal to its index.
  for (uint32_t i = kNumInitialThreads; i > 0; --i) {
    threads.push_back(WrapUnique(new Thread("test thread")));
    auto* thread = threads.back().get();
    thread->Start();
    scoped_refptr<SingleThreadTaskRunner> task_runner = thread->task_runner();
    mdps.push_back(WrapUnique(new MockMemoryDumpProvider()));
    auto* mdp = mdps.back().get();
    RegisterDumpProvider(mdp, task_runner, kDefaultOptions);
    EXPECT_CALL(*mdp, OnMemoryDump(_, _))
        .Times(i)
        .WillRepeatedly(Invoke(
            [task_runner](const MemoryDumpArgs&, ProcessMemoryDump*) -> bool {
              EXPECT_TRUE(task_runner->RunsTasksOnCurrentThread());
              return true;
            }));
  }
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  while (!threads.empty()) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));

    // Unregister a MDP and destroy one thread at each iteration to check the
    // live unregistration logic. The unregistration needs to happen on the same
    // thread the MDP belongs to.
    {
      RunLoop run_loop;
      Closure unregistration =
          Bind(&MemoryDumpManager::UnregisterDumpProvider,
               Unretained(mdm_.get()), Unretained(mdps.back().get()));
      threads.back()->task_runner()->PostTaskAndReply(FROM_HERE, unregistration,
                                                      run_loop.QuitClosure());
      run_loop.Run();
    }
    mdps.pop_back();
    threads.back()->Stop();
    threads.pop_back();
  }

  DisableTracing();
}

// Check that the memory dump calls are always posted on task runner for
// SequencedTaskRunner case and that the dump provider gets disabled when
// PostTask fails, but the dump still succeeds.
TEST_F(MemoryDumpManagerTest, PostTaskForSequencedTaskRunner) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  std::vector<MockMemoryDumpProvider> mdps(3);
  scoped_refptr<TestSequencedTaskRunner> task_runner1(
      make_scoped_refptr(new TestSequencedTaskRunner()));
  scoped_refptr<TestSequencedTaskRunner> task_runner2(
      make_scoped_refptr(new TestSequencedTaskRunner()));
  RegisterDumpProviderWithSequencedTaskRunner(&mdps[0], task_runner1,
                                              kDefaultOptions);
  RegisterDumpProviderWithSequencedTaskRunner(&mdps[1], task_runner2,
                                              kDefaultOptions);
  RegisterDumpProviderWithSequencedTaskRunner(&mdps[2], task_runner2,
                                              kDefaultOptions);
  // |mdps[0]| should be disabled permanently after first dump.
  EXPECT_CALL(mdps[0], OnMemoryDump(_, _)).Times(0);
  EXPECT_CALL(mdps[1], OnMemoryDump(_, _)).Times(2);
  EXPECT_CALL(mdps[2], OnMemoryDump(_, _)).Times(2);

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  task_runner1->set_enabled(false);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  // Tasks should be individually posted even if |mdps[1]| and |mdps[2]| belong
  // to same task runner.
  EXPECT_EQ(1u, task_runner1->no_of_post_tasks());
  EXPECT_EQ(2u, task_runner2->no_of_post_tasks());

  task_runner1->set_enabled(true);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  EXPECT_EQ(2u, task_runner1->no_of_post_tasks());
  EXPECT_EQ(4u, task_runner2->no_of_post_tasks());
  DisableTracing();
}

// Checks that providers get disabled after 3 consecutive failures, but not
// otherwise (e.g., if interleaved).
TEST_F(MemoryDumpManagerTest, DisableFailingDumpers) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp1;
  MockMemoryDumpProvider mdp2;

  RegisterDumpProvider(&mdp1, nullptr);
  RegisterDumpProvider(&mdp2, nullptr);
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  EXPECT_CALL(mdp1, OnMemoryDump(_, _))
      .Times(GetMaxConsecutiveFailuresCount())
      .WillRepeatedly(Return(false));

  EXPECT_CALL(mdp2, OnMemoryDump(_, _))
      .WillOnce(Return(false))
      .WillOnce(Return(true))
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(true))
      .WillOnce(Return(false));

  const int kNumDumps = 2 * GetMaxConsecutiveFailuresCount();
  for (int i = 0; i < kNumDumps; i++) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }

  DisableTracing();
}

// Sneakily registers an extra memory dump provider while an existing one is
// dumping and expect it to take part in the already active tracing session.
TEST_F(MemoryDumpManagerTest, RegisterDumperWhileDumping) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp1;
  MockMemoryDumpProvider mdp2;

  RegisterDumpProvider(&mdp1, nullptr);
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  EXPECT_CALL(mdp1, OnMemoryDump(_, _))
      .Times(4)
      .WillOnce(Return(true))
      .WillOnce(
          Invoke([&mdp2](const MemoryDumpArgs&, ProcessMemoryDump*) -> bool {
            RegisterDumpProvider(&mdp2, nullptr);
            return true;
          }))
      .WillRepeatedly(Return(true));

  // Depending on the insertion order (before or after mdp1), mdp2 might be
  // called also immediately after it gets registered.
  EXPECT_CALL(mdp2, OnMemoryDump(_, _)).Times(Between(2, 3));

  for (int i = 0; i < 4; i++) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }

  DisableTracing();
}

// Like RegisterDumperWhileDumping, but unregister the dump provider instead.
TEST_F(MemoryDumpManagerTest, UnregisterDumperWhileDumping) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp1;
  MockMemoryDumpProvider mdp2;

  RegisterDumpProvider(&mdp1, ThreadTaskRunnerHandle::Get(), kDefaultOptions);
  RegisterDumpProvider(&mdp2, ThreadTaskRunnerHandle::Get(), kDefaultOptions);
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  EXPECT_CALL(mdp1, OnMemoryDump(_, _))
      .Times(4)
      .WillOnce(Return(true))
      .WillOnce(
          Invoke([&mdp2](const MemoryDumpArgs&, ProcessMemoryDump*) -> bool {
            MemoryDumpManager::GetInstance()->UnregisterDumpProvider(&mdp2);
            return true;
          }))
      .WillRepeatedly(Return(true));

  // Depending on the insertion order (before or after mdp1), mdp2 might have
  // been already called when UnregisterDumpProvider happens.
  EXPECT_CALL(mdp2, OnMemoryDump(_, _)).Times(Between(1, 2));

  for (int i = 0; i < 4; i++) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }

  DisableTracing();
}

// Checks that the dump does not abort when unregistering a provider while
// dumping from a different thread than the dumping thread.
TEST_F(MemoryDumpManagerTest, UnregisterDumperFromThreadWhileDumping) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  std::vector<std::unique_ptr<TestIOThread>> threads;
  std::vector<std::unique_ptr<MockMemoryDumpProvider>> mdps;

  for (int i = 0; i < 2; i++) {
    threads.push_back(
        WrapUnique(new TestIOThread(TestIOThread::kAutoStart)));
    mdps.push_back(WrapUnique(new MockMemoryDumpProvider()));
    RegisterDumpProvider(mdps.back().get(), threads.back()->task_runner(),
                         kDefaultOptions);
  }

  int on_memory_dump_call_count = 0;

  // When OnMemoryDump is called on either of the dump providers, it will
  // unregister the other one.
  for (const std::unique_ptr<MockMemoryDumpProvider>& mdp : mdps) {
    int other_idx = (mdps.front() == mdp);
    // TestIOThread's task runner must be obtained from the main thread but can
    // then be used from other threads.
    scoped_refptr<SingleThreadTaskRunner> other_runner =
        threads[other_idx]->task_runner();
    MockMemoryDumpProvider* other_mdp = mdps[other_idx].get();
    auto on_dump = [this, other_runner, other_mdp, &on_memory_dump_call_count](
                       const MemoryDumpArgs& args, ProcessMemoryDump* pmd) {
      PostTaskAndWait(FROM_HERE, other_runner.get(),
                      base::BindOnce(&MemoryDumpManager::UnregisterDumpProvider,
                                     base::Unretained(&*mdm_), other_mdp));
      on_memory_dump_call_count++;
      return true;
    };

    // OnMemoryDump is called once for the provider that dumps first, and zero
    // times for the other provider.
    EXPECT_CALL(*mdp, OnMemoryDump(_, _))
        .Times(AtMost(1))
        .WillOnce(Invoke(on_dump));
  }

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  ASSERT_EQ(1, on_memory_dump_call_count);

  DisableTracing();
}

TEST_F(MemoryDumpManagerTest, TestPollingOnDumpThread) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  std::unique_ptr<MockMemoryDumpProvider> mdp1(new MockMemoryDumpProvider());
  std::unique_ptr<MockMemoryDumpProvider> mdp2(new MockMemoryDumpProvider());
  mdp1->enable_mock_destructor = true;
  mdp2->enable_mock_destructor = true;
  EXPECT_CALL(*mdp1, Destructor());
  EXPECT_CALL(*mdp2, Destructor());

  MemoryDumpProvider::Options options;
  options.is_fast_polling_supported = true;
  RegisterDumpProvider(mdp1.get(), nullptr, options);

  RunLoop run_loop;
  auto test_task_runner = ThreadTaskRunnerHandle::Get();
  auto quit_closure = run_loop.QuitClosure();
  MemoryDumpManager* mdm = mdm_.get();

  EXPECT_CALL(*mdp1, PollFastMemoryTotal(_))
      .WillOnce(Invoke([&mdp2, options, this](uint64_t*) {
        RegisterDumpProvider(mdp2.get(), nullptr, options);
      }))
      .WillOnce(Return())
      .WillOnce(Invoke([mdm, &mdp2](uint64_t*) {
        mdm->UnregisterAndDeleteDumpProviderSoon(std::move(mdp2));
      }))
      .WillOnce(Invoke([test_task_runner, quit_closure](uint64_t*) {
        test_task_runner->PostTask(FROM_HERE, quit_closure);
      }))
      .WillRepeatedly(Return());

  // We expect a call to |mdp1| because it is still registered at the time the
  // Peak detector is Stop()-ed (upon OnTraceLogDisabled(). We do NOT expect
  // instead a call for |mdp2|, because that gets unregisterd before the Stop().
  EXPECT_CALL(*mdp1, SuspendFastMemoryPolling()).Times(1);
  EXPECT_CALL(*mdp2, SuspendFastMemoryPolling()).Times(0);

  // |mdp2| should invoke exactly twice:
  // - once after the registrarion, when |mdp1| hits the first Return()
  // - the 2nd time when |mdp1| unregisters |mdp1|. The unregistration is
  //   posted and will necessarily happen after the polling task.
  EXPECT_CALL(*mdp2, PollFastMemoryTotal(_)).Times(2).WillRepeatedly(Return());

  EnableTracingWithTraceConfig(
      TraceConfigMemoryTestUtil::GetTraceConfig_PeakDetectionTrigger(1));
  run_loop.Run();
  DisableTracing();
  mdm_->UnregisterAndDeleteDumpProviderSoon(std::move(mdp1));
}

// If a thread (with a dump provider living on it) is torn down during a dump
// its dump provider should be skipped but the dump itself should succeed.
TEST_F(MemoryDumpManagerTest, TearDownThreadWhileDumping) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  std::vector<std::unique_ptr<TestIOThread>> threads;
  std::vector<std::unique_ptr<MockMemoryDumpProvider>> mdps;

  for (int i = 0; i < 2; i++) {
    threads.push_back(
        WrapUnique(new TestIOThread(TestIOThread::kAutoStart)));
    mdps.push_back(WrapUnique(new MockMemoryDumpProvider()));
    RegisterDumpProvider(mdps.back().get(), threads.back()->task_runner(),
                         kDefaultOptions);
  }

  int on_memory_dump_call_count = 0;

  // When OnMemoryDump is called on either of the dump providers, it will
  // tear down the thread of the other one.
  for (const std::unique_ptr<MockMemoryDumpProvider>& mdp : mdps) {
    int other_idx = (mdps.front() == mdp);
    TestIOThread* other_thread = threads[other_idx].get();
    // TestIOThread isn't thread-safe and must be stopped on the |main_runner|.
    scoped_refptr<SequencedTaskRunner> main_runner =
        SequencedTaskRunnerHandle::Get();
    auto on_dump = [other_thread, main_runner, &on_memory_dump_call_count](
                       const MemoryDumpArgs& args, ProcessMemoryDump* pmd) {
      PostTaskAndWait(
          FROM_HERE, main_runner.get(),
          base::BindOnce(&TestIOThread::Stop, base::Unretained(other_thread)));
      on_memory_dump_call_count++;
      return true;
    };

    // OnMemoryDump is called once for the provider that dumps first, and zero
    // times for the other provider.
    EXPECT_CALL(*mdp, OnMemoryDump(_, _))
        .Times(AtMost(1))
        .WillOnce(Invoke(on_dump));
  }

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  ASSERT_EQ(1, on_memory_dump_call_count);

  DisableTracing();
}

// Checks that a NACK callback is invoked if CreateProcessDump() is called when
// tracing is not enabled.
TEST_F(MemoryDumpManagerTest, CallbackCalledOnFailure) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, nullptr);
  EXPECT_CALL(mdp, OnMemoryDump(_, _));
  EXPECT_FALSE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                         MemoryDumpLevelOfDetail::DETAILED));
}

// Checks that is the MemoryDumpManager is initialized after tracing already
// began, it will still late-join the party (real use case: startup tracing).
TEST_F(MemoryDumpManagerTest, InitializedAfterStartOfTracing) {
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, nullptr);
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  // First check that a CreateProcessDump() issued before the MemoryDumpManager
  // initialization gets NACK-ed cleanly.
  {
    testing::InSequence sequence;
    EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(0);
    EXPECT_FALSE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                           MemoryDumpLevelOfDetail::DETAILED));
  }

  // Now late-initialize the MemoryDumpManager and check that the
  // CreateProcessDump() completes successfully.
  {
    testing::InSequence sequence;
    InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
    EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(1);
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }
  DisableTracing();
}

// This test (and the MemoryDumpManagerTestCoordinator below) crystallizes the
// expectations of the chrome://tracing UI and chrome telemetry w.r.t. periodic
// dumps in memory-infra, handling gracefully the transition between the legacy
// and the new-style (JSON-based) TraceConfig.
TEST_F(MemoryDumpManagerTest, TraceConfigExpectations) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);

  // We don't need to create any dump in this test, only check whether the dumps
  // are requested or not.

  // Enabling memory-infra in a non-coordinator process should not trigger any
  // periodic dumps.
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_FALSE(IsPeriodicDumpingEnabled());
  DisableTracing();

  // Enabling memory-infra with the new (JSON) TraceConfig in a non-coordinator
  // process with a fully defined trigger config should NOT enable any periodic
  // dumps.
  EnableTracingWithTraceConfig(
      TraceConfigMemoryTestUtil::GetTraceConfig_PeriodicTriggers(1, 5));
  EXPECT_FALSE(IsPeriodicDumpingEnabled());
  DisableTracing();
}

TEST_F(MemoryDumpManagerTest, TraceConfigExpectationsWhenIsCoordinator) {
  InitializeMemoryDumpManagerForInProcessTesting(true /* is_coordinator */);

  // Enabling memory-infra with the legacy TraceConfig (category filter) in
  // a coordinator process should not enable periodic dumps.
  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_FALSE(IsPeriodicDumpingEnabled());
  DisableTracing();

  // Enabling memory-infra with the new (JSON) TraceConfig in a coordinator
  // process while specifying a "memory_dump_config" section should enable
  // periodic dumps. This is to preserve the behavior chrome://tracing UI, that
  // is: ticking memory-infra should dump periodically with an explicit config.
  EnableTracingWithTraceConfig(
      TraceConfigMemoryTestUtil::GetTraceConfig_PeriodicTriggers(100, 5));
  EXPECT_TRUE(IsPeriodicDumpingEnabled());
  DisableTracing();

  // Enabling memory-infra with the new (JSON) TraceConfig in a coordinator
  // process with an empty "memory_dump_config" should NOT enable periodic
  // dumps. This is the way telemetry is supposed to use memory-infra with
  // only explicitly triggered dumps.
  EnableTracingWithTraceConfig(
      TraceConfigMemoryTestUtil::GetTraceConfig_EmptyTriggers());
  EXPECT_FALSE(IsPeriodicDumpingEnabled());
  DisableTracing();

  // Enabling memory-infra with the new (JSON) TraceConfig in a coordinator
  // process with a fully defined trigger config should cause periodic dumps to
  // be performed in the correct order.
  RunLoop run_loop;
  auto test_task_runner = ThreadTaskRunnerHandle::Get();
  auto quit_closure = run_loop.QuitClosure();

  const int kHeavyDumpRate = 5;
  const int kLightDumpPeriodMs = 1;
  const int kHeavyDumpPeriodMs = kHeavyDumpRate * kLightDumpPeriodMs;

  // The expected sequence with light=1ms, heavy=5ms is H,L,L,L,L,H,...
  auto mdp = MakeUnique<MockMemoryDumpProvider>();
  RegisterDumpProvider(&*mdp, nullptr, kDefaultOptions, kWhitelistedMDPName);

  testing::InSequence sequence;
  EXPECT_CALL(*mdp, OnMemoryDump(IsDetailedDump(), _));
  EXPECT_CALL(*mdp, OnMemoryDump(IsLightDump(), _)).Times(kHeavyDumpRate - 1);
  EXPECT_CALL(*mdp, OnMemoryDump(IsDetailedDump(), _));
  EXPECT_CALL(*mdp, OnMemoryDump(IsLightDump(), _)).Times(kHeavyDumpRate - 2);
  EXPECT_CALL(*mdp, OnMemoryDump(IsLightDump(), _))
      .WillOnce(Invoke([test_task_runner, quit_closure](const MemoryDumpArgs&,
                                                        ProcessMemoryDump*) {
        test_task_runner->PostTask(FROM_HERE, quit_closure);
        return true;
      }));

  // Swallow all the final spurious calls until tracing gets disabled.
  EXPECT_CALL(*mdp, OnMemoryDump(_, _)).Times(AnyNumber());

  EnableTracingWithTraceConfig(
      TraceConfigMemoryTestUtil::GetTraceConfig_PeriodicTriggers(
          kLightDumpPeriodMs, kHeavyDumpPeriodMs));
  run_loop.Run();
  DisableTracing();
  mdm_->UnregisterAndDeleteDumpProviderSoon(std::move(mdp));
}

TEST_F(MemoryDumpManagerTest, DumpOnBehalfOfOtherProcess) {
  using trace_analyzer::Query;

  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);

  // Standard provider with default options (create dump for current process).
  MemoryDumpProvider::Options options;
  MockMemoryDumpProvider mdp1;
  RegisterDumpProvider(&mdp1, nullptr, options);

  // Provider with out-of-process dumping.
  MockMemoryDumpProvider mdp2;
  options.target_pid = 123;
  RegisterDumpProvider(&mdp2, nullptr, options);

  // Another provider with out-of-process dumping.
  MockMemoryDumpProvider mdp3;
  options.target_pid = 456;
  RegisterDumpProvider(&mdp3, nullptr, options);

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_CALL(mdp1, OnMemoryDump(_, _)).Times(1);
  EXPECT_CALL(mdp2, OnMemoryDump(_, _)).Times(1);
  EXPECT_CALL(mdp3, OnMemoryDump(_, _)).Times(1);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::DETAILED));
  DisableTracing();

  std::unique_ptr<trace_analyzer::TraceAnalyzer> analyzer =
      GetDeserializedTrace();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(Query::EventPhaseIs(TRACE_EVENT_PHASE_MEMORY_DUMP),
                       &events);

  ASSERT_EQ(3u, events.size());
  ASSERT_EQ(1u, trace_analyzer::CountMatches(events, Query::EventPidIs(123)));
  ASSERT_EQ(1u, trace_analyzer::CountMatches(events, Query::EventPidIs(456)));
  ASSERT_EQ(1u, trace_analyzer::CountMatches(
                    events, Query::EventPidIs(GetCurrentProcId())));
  ASSERT_EQ(events[0]->id, events[1]->id);
  ASSERT_EQ(events[0]->id, events[2]->id);
}

TEST_F(MemoryDumpManagerTest, SummaryOnlyWhitelisting) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);

  // Summary only MDPs are a subset of background MDPs.
  SetDumpProviderWhitelistForTesting(kTestMDPWhitelist);
  SetDumpProviderSummaryWhitelistForTesting(kTestMDPWhitelistForSummary);

  // Standard provider with default options (create dump for current process).
  MockMemoryDumpProvider summaryMdp;
  RegisterDumpProvider(&summaryMdp, nullptr, kDefaultOptions,
                       kWhitelistedMDPName);
  MockMemoryDumpProvider backgroundMdp;
  RegisterDumpProvider(&backgroundMdp, nullptr, kDefaultOptions,
                       kBackgroundButNotSummaryWhitelistedMDPName);

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  EXPECT_CALL(backgroundMdp, OnMemoryDump(_, _)).Times(0);
  EXPECT_CALL(summaryMdp, OnMemoryDump(_, _)).Times(1);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::SUMMARY_ONLY,
                                        MemoryDumpLevelOfDetail::BACKGROUND));
  DisableTracing();
}

TEST_F(MemoryDumpManagerTest, SummaryOnlyDumpsArentAddedToTrace) {
  using trace_analyzer::Query;

  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  SetDumpProviderSummaryWhitelistForTesting(kTestMDPWhitelistForSummary);
  SetDumpProviderWhitelistForTesting(kTestMDPWhitelist);

  // Standard provider with default options (create dump for current process).
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, nullptr, kDefaultOptions, kWhitelistedMDPName);

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);

  EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(2);
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::BACKGROUND));
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::SUMMARY_ONLY,
                                        MemoryDumpLevelOfDetail::BACKGROUND));
  DisableTracing();

  std::unique_ptr<trace_analyzer::TraceAnalyzer> analyzer =
      GetDeserializedTrace();
  trace_analyzer::TraceEventVector events;
  analyzer->FindEvents(Query::EventPhaseIs(TRACE_EVENT_PHASE_MEMORY_DUMP),
                       &events);

  ASSERT_EQ(1u, events.size());
  ASSERT_TRUE(trace_analyzer::CountMatches(
      events, Query::EventNameIs(MemoryDumpTypeToString(
                  MemoryDumpType::EXPLICITLY_TRIGGERED))));
}

// Tests the basics of the UnregisterAndDeleteDumpProviderSoon(): the
// unregistration should actually delete the providers and not leak them.
TEST_F(MemoryDumpManagerTest, UnregisterAndDeleteDumpProviderSoon) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  static const int kNumProviders = 3;
  int dtor_count = 0;
  std::vector<std::unique_ptr<MemoryDumpProvider>> mdps;
  for (int i = 0; i < kNumProviders; ++i) {
    std::unique_ptr<MockMemoryDumpProvider> mdp(new MockMemoryDumpProvider);
    mdp->enable_mock_destructor = true;
    EXPECT_CALL(*mdp, Destructor())
        .WillOnce(Invoke([&dtor_count]() { dtor_count++; }));
    RegisterDumpProvider(mdp.get(), nullptr, kDefaultOptions);
    mdps.push_back(std::move(mdp));
  }

  while (!mdps.empty()) {
    mdm_->UnregisterAndDeleteDumpProviderSoon(std::move(mdps.back()));
    mdps.pop_back();
  }

  ASSERT_EQ(kNumProviders, dtor_count);
}

// This test checks against races when unregistering an unbound dump provider
// from another thread while dumping. It registers one MDP and, when
// OnMemoryDump() is called, it invokes UnregisterAndDeleteDumpProviderSoon()
// from another thread. The OnMemoryDump() and the dtor call are expected to
// happen on the same thread (the MemoryDumpManager utility thread).
TEST_F(MemoryDumpManagerTest, UnregisterAndDeleteDumpProviderSoonDuringDump) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  std::unique_ptr<MockMemoryDumpProvider> mdp(new MockMemoryDumpProvider);
  mdp->enable_mock_destructor = true;
  RegisterDumpProvider(mdp.get(), nullptr, kDefaultOptions);

  base::PlatformThreadRef thread_ref;
  auto self_unregister_from_another_thread = [&mdp, &thread_ref](
      const MemoryDumpArgs&, ProcessMemoryDump*) -> bool {
    thread_ref = PlatformThread::CurrentRef();
    TestIOThread thread_for_unregistration(TestIOThread::kAutoStart);
    PostTaskAndWait(
        FROM_HERE, thread_for_unregistration.task_runner().get(),
        base::BindOnce(
            &MemoryDumpManager::UnregisterAndDeleteDumpProviderSoon,
            base::Unretained(MemoryDumpManager::GetInstance()),
            base::Passed(std::unique_ptr<MemoryDumpProvider>(std::move(mdp)))));
    thread_for_unregistration.Stop();
    return true;
  };
  EXPECT_CALL(*mdp, OnMemoryDump(_, _))
      .Times(1)
      .WillOnce(Invoke(self_unregister_from_another_thread));
  EXPECT_CALL(*mdp, Destructor())
      .Times(1)
      .WillOnce(Invoke([&thread_ref]() {
        EXPECT_EQ(thread_ref, PlatformThread::CurrentRef());
      }));

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  for (int i = 0; i < 2; ++i) {
    EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                          MemoryDumpLevelOfDetail::DETAILED));
  }
  DisableTracing();
}

TEST_F(MemoryDumpManagerTest, TestWhitelistingMDP) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  SetDumpProviderWhitelistForTesting(kTestMDPWhitelist);
  std::unique_ptr<MockMemoryDumpProvider> mdp1(new MockMemoryDumpProvider);
  RegisterDumpProvider(mdp1.get(), nullptr);
  std::unique_ptr<MockMemoryDumpProvider> mdp2(new MockMemoryDumpProvider);
  RegisterDumpProvider(mdp2.get(), nullptr, kDefaultOptions,
                       kWhitelistedMDPName);

  EXPECT_CALL(*mdp1, OnMemoryDump(_, _)).Times(0);
  EXPECT_CALL(*mdp2, OnMemoryDump(_, _)).Times(1);

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  EXPECT_FALSE(IsPeriodicDumpingEnabled());
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::BACKGROUND));
  DisableTracing();
}

// Configures periodic dumps with MemoryDumpLevelOfDetail::BACKGROUND triggers
// and tests that only BACKGROUND are added to the trace, but not LIGHT or
// DETAILED, even if requested explicitly.
TEST_F(MemoryDumpManagerTest, TestBackgroundTracingSetup) {
  InitializeMemoryDumpManagerForInProcessTesting(true /* is_coordinator */);

  SetDumpProviderWhitelistForTesting(kTestMDPWhitelist);
  auto mdp = MakeUnique<MockMemoryDumpProvider>();
  RegisterDumpProvider(&*mdp, nullptr, kDefaultOptions, kWhitelistedMDPName);

  RunLoop run_loop;
  auto test_task_runner = ThreadTaskRunnerHandle::Get();
  auto quit_closure = run_loop.QuitClosure();

  {
    testing::InSequence sequence;
    EXPECT_CALL(*mdp, OnMemoryDump(IsBackgroundDump(), _)).Times(3);
    EXPECT_CALL(*mdp, OnMemoryDump(IsBackgroundDump(), _))
        .WillOnce(Invoke([test_task_runner, quit_closure](const MemoryDumpArgs&,
                                                          ProcessMemoryDump*) {
          test_task_runner->PostTask(FROM_HERE, quit_closure);
          return true;
        }));
    EXPECT_CALL(*mdp, OnMemoryDump(IsBackgroundDump(), _)).Times(AnyNumber());
  }

  EnableTracingWithTraceConfig(
      TraceConfigMemoryTestUtil::GetTraceConfig_BackgroundTrigger(
          1 /* period_ms */));

  run_loop.Run();

  // When requesting non-BACKGROUND dumps the MDP will be invoked but the
  // data is expected to be dropped on the floor, hence the EXPECT_FALSE.
  EXPECT_CALL(*mdp, OnMemoryDump(IsLightDump(), _));
  EXPECT_FALSE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                         MemoryDumpLevelOfDetail::LIGHT));

  EXPECT_CALL(*mdp, OnMemoryDump(IsDetailedDump(), _));
  EXPECT_FALSE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                         MemoryDumpLevelOfDetail::DETAILED));

  ASSERT_TRUE(IsPeriodicDumpingEnabled());
  DisableTracing();
  mdm_->UnregisterAndDeleteDumpProviderSoon(std::move(mdp));
}

// Tests that the MemoryDumpProvider(s) are invoked even if tracing has not
// been initialized.
TEST_F(MemoryDumpManagerTest, DumpWithoutInitializingTracing) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());
  DisableTracing();
  EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(3);
  for (int i = 0; i < 3; ++i) {
    // The callback result will be false for the moment. true result means that
    // as well as the dump being successful we also managed to add the dump to
    // the trace. But the latter won't happen here.
    EXPECT_FALSE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                           MemoryDumpLevelOfDetail::DETAILED));
  }
  mdm_->UnregisterDumpProvider(&mdp);
}

// Similar to DumpWithoutInitializingTracing. Tracing is initialized but not
// enabled.
TEST_F(MemoryDumpManagerTest, DumpWithTracingInitializedButDisabled) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());

  DisableTracing();

  const TraceConfig& trace_config =
      TraceConfig(TraceConfigMemoryTestUtil::GetTraceConfig_NoTriggers());
  const TraceConfig::MemoryDumpConfig& memory_dump_config =
      trace_config.memory_dump_config();
  mdm_->SetupForTracing(memory_dump_config);

  EXPECT_CALL(mdp, OnMemoryDump(_, _)).Times(3);
  for (int i = 0; i < 3; ++i) {
    // Same as the above. Even if the MDP(s) are invoked, this will return false
    // while attempting to add the dump into the trace.
    EXPECT_FALSE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                           MemoryDumpLevelOfDetail::DETAILED));
  }
  mdm_->TeardownForTracing();
  mdm_->UnregisterDumpProvider(&mdp);
}

TEST_F(MemoryDumpManagerTest, TestSummaryComputation) {
  InitializeMemoryDumpManagerForInProcessTesting(false /* is_coordinator */);
  MockMemoryDumpProvider mdp;
  RegisterDumpProvider(&mdp, ThreadTaskRunnerHandle::Get());

  EXPECT_CALL(mdp, OnMemoryDump(_, _))
      .WillOnce(Invoke([](const MemoryDumpArgs&,
                          ProcessMemoryDump* pmd) -> bool {
        auto* size = MemoryAllocatorDump::kNameSize;
        auto* bytes = MemoryAllocatorDump::kUnitsBytes;
        const uint32_t kB = 1024;

        pmd->CreateAllocatorDump("malloc")->AddScalar(size, bytes, 1 * kB);
        pmd->CreateAllocatorDump("malloc/ignored")
            ->AddScalar(size, bytes, 99 * kB);

        pmd->CreateAllocatorDump("blink_gc")->AddScalar(size, bytes, 2 * kB);
        pmd->CreateAllocatorDump("blink_gc/ignored")
            ->AddScalar(size, bytes, 99 * kB);

        pmd->CreateAllocatorDump("v8/foo")->AddScalar(size, bytes, 1 * kB);
        pmd->CreateAllocatorDump("v8/bar")->AddScalar(size, bytes, 2 * kB);
        pmd->CreateAllocatorDump("v8")->AddScalar(size, bytes, 99 * kB);

        // All the 99 KB values here are expected to be ignored.
        pmd->CreateAllocatorDump("partition_alloc")
            ->AddScalar(size, bytes, 99 * kB);
        pmd->CreateAllocatorDump("partition_alloc/allocated_objects")
            ->AddScalar(size, bytes, 99 * kB);
        pmd->CreateAllocatorDump("partition_alloc/allocated_objects/ignored")
            ->AddScalar(size, bytes, 99 * kB);
        pmd->CreateAllocatorDump("partition_alloc/partitions")
            ->AddScalar(size, bytes, 99 * kB);
        pmd->CreateAllocatorDump("partition_alloc/partitions/not_ignored_1")
            ->AddScalar(size, bytes, 2 * kB);
        pmd->CreateAllocatorDump("partition_alloc/partitions/not_ignored_2")
            ->AddScalar(size, bytes, 2 * kB);
        pmd->process_totals()->set_resident_set_bytes(5 * kB);
        pmd->set_has_process_totals();
        return true;
      }));

  EnableTracingWithLegacyCategories(MemoryDumpManager::kTraceCategory);
  Optional<MemoryDumpCallbackResult> result;
  EXPECT_TRUE(RequestProcessDumpAndWait(MemoryDumpType::EXPLICITLY_TRIGGERED,
                                        MemoryDumpLevelOfDetail::LIGHT,
                                        &result));
  DisableTracing();

  ASSERT_TRUE(result);

  // For malloc we only count the root "malloc" not children "malloc/*".
  EXPECT_EQ(1u, result->chrome_dump.malloc_total_kb);

  // For blink_gc we only count the root "blink_gc" not children "blink_gc/*".
  EXPECT_EQ(2u, result->chrome_dump.blink_gc_total_kb);

  // For v8 we count the children ("v8/*") as the root total is not given.
  EXPECT_EQ(3u, result->chrome_dump.v8_total_kb);

  // partition_alloc has partition_alloc/allocated_objects/* which is a subset
  // of partition_alloc/partitions/* so we only count the latter.
  EXPECT_EQ(4u, result->chrome_dump.partition_alloc_total_kb);

  // resident_set_kb should read from process_totals.
  EXPECT_EQ(5u, result->os_dump.resident_set_kb);
};

}  // namespace trace_event
}  // namespace base
