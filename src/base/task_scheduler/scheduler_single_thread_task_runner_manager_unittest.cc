// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_single_thread_task_runner_manager.h"

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/synchronization/atomic_flag.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/task_scheduler/task_traits.h"
#include "base/test/gtest_util.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_WIN)
#include <windows.h>

#include "base/win/com_init_util.h"
#include "base/win/current_module.h"
#endif  // defined(OS_WIN)

namespace base {
namespace internal {

namespace {

class TaskSchedulerSingleThreadTaskRunnerManagerTest : public testing::Test {
 public:
  TaskSchedulerSingleThreadTaskRunnerManagerTest()
      : service_thread_("TaskSchedulerServiceThread") {}

  void SetUp() override {
    service_thread_.Start();
    delayed_task_manager_.Start(service_thread_.task_runner());
    single_thread_task_runner_manager_ =
        MakeUnique<SchedulerSingleThreadTaskRunnerManager>(
            &task_tracker_, &delayed_task_manager_);
    StartSingleThreadTaskRunnerManagerFromSetUp();
  }

  void TearDown() override {
    TearDownSingleThreadTaskRunnerManager();
    service_thread_.Stop();
  }

 protected:
  virtual void StartSingleThreadTaskRunnerManagerFromSetUp() {
    single_thread_task_runner_manager_->Start();
  }

  virtual void TearDownSingleThreadTaskRunnerManager() {
    single_thread_task_runner_manager_->JoinForTesting();
    single_thread_task_runner_manager_.reset();
  }

  std::unique_ptr<SchedulerSingleThreadTaskRunnerManager>
      single_thread_task_runner_manager_;
  TaskTracker task_tracker_;

 private:
  Thread service_thread_;
  DelayedTaskManager delayed_task_manager_;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerSingleThreadTaskRunnerManagerTest);
};

void CaptureThreadRef(PlatformThreadRef* thread_ref) {
  ASSERT_TRUE(thread_ref);
  *thread_ref = PlatformThread::CurrentRef();
}

void CaptureThreadPriority(ThreadPriority* thread_priority) {
  ASSERT_TRUE(thread_priority);
  *thread_priority = PlatformThread::GetCurrentThreadPriority();
}

void CaptureThreadName(std::string* thread_name) {
  *thread_name = PlatformThread::GetName();
}

void ShouldNotRun() {
  ADD_FAILURE() << "Ran a task that shouldn't run.";
}

}  // namespace

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, DifferentThreadsUsed) {
  scoped_refptr<SingleThreadTaskRunner> task_runner_1 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "A", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
              SingleThreadTaskRunnerThreadMode::DEDICATED);
  scoped_refptr<SingleThreadTaskRunner> task_runner_2 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "B", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
              SingleThreadTaskRunnerThreadMode::DEDICATED);

  PlatformThreadRef thread_ref_1;
  task_runner_1->PostTask(FROM_HERE,
                          BindOnce(&CaptureThreadRef, &thread_ref_1));
  PlatformThreadRef thread_ref_2;
  task_runner_2->PostTask(FROM_HERE,
                          BindOnce(&CaptureThreadRef, &thread_ref_2));

  task_tracker_.Shutdown();

  ASSERT_FALSE(thread_ref_1.is_null());
  ASSERT_FALSE(thread_ref_2.is_null());
  EXPECT_NE(thread_ref_1, thread_ref_2);
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, SameThreadUsed) {
  scoped_refptr<SingleThreadTaskRunner> task_runner_1 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "A", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
              SingleThreadTaskRunnerThreadMode::SHARED);
  scoped_refptr<SingleThreadTaskRunner> task_runner_2 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "B", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
              SingleThreadTaskRunnerThreadMode::SHARED);

  PlatformThreadRef thread_ref_1;
  task_runner_1->PostTask(FROM_HERE,
                          BindOnce(&CaptureThreadRef, &thread_ref_1));
  PlatformThreadRef thread_ref_2;
  task_runner_2->PostTask(FROM_HERE,
                          BindOnce(&CaptureThreadRef, &thread_ref_2));

  task_tracker_.Shutdown();

  ASSERT_FALSE(thread_ref_1.is_null());
  ASSERT_FALSE(thread_ref_2.is_null());
  EXPECT_EQ(thread_ref_1, thread_ref_2);
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest,
       RunsTasksInCurrentSequence) {
  scoped_refptr<SingleThreadTaskRunner> task_runner_1 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "A", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
              SingleThreadTaskRunnerThreadMode::DEDICATED);
  scoped_refptr<SingleThreadTaskRunner> task_runner_2 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "B", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
              SingleThreadTaskRunnerThreadMode::DEDICATED);

  EXPECT_FALSE(task_runner_1->RunsTasksInCurrentSequence());
  EXPECT_FALSE(task_runner_2->RunsTasksInCurrentSequence());

  task_runner_1->PostTask(
      FROM_HERE,
      BindOnce(
          [](scoped_refptr<SingleThreadTaskRunner> task_runner_1,
             scoped_refptr<SingleThreadTaskRunner> task_runner_2) {
            EXPECT_TRUE(task_runner_1->RunsTasksInCurrentSequence());
            EXPECT_FALSE(task_runner_2->RunsTasksInCurrentSequence());
          },
          task_runner_1, task_runner_2));

  task_runner_2->PostTask(
      FROM_HERE,
      BindOnce(
          [](scoped_refptr<SingleThreadTaskRunner> task_runner_1,
             scoped_refptr<SingleThreadTaskRunner> task_runner_2) {
            EXPECT_FALSE(task_runner_1->RunsTasksInCurrentSequence());
            EXPECT_TRUE(task_runner_2->RunsTasksInCurrentSequence());
          },
          task_runner_1, task_runner_2));

  task_tracker_.Shutdown();
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest,
       SharedWithBaseSyncPrimitivesDCHECKs) {
  EXPECT_DCHECK_DEATH({
    single_thread_task_runner_manager_->CreateSingleThreadTaskRunnerWithTraits(
        "A", {WithBaseSyncPrimitives()},
        SingleThreadTaskRunnerThreadMode::SHARED);
  });
}

namespace {

class TaskSchedulerSingleThreadTaskRunnerManagerCommonTest
    : public TaskSchedulerSingleThreadTaskRunnerManagerTest,
      public ::testing::WithParamInterface<SingleThreadTaskRunnerThreadMode> {
 public:
  TaskSchedulerSingleThreadTaskRunnerManagerCommonTest() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(
      TaskSchedulerSingleThreadTaskRunnerManagerCommonTest);
};

}  // namespace

TEST_P(TaskSchedulerSingleThreadTaskRunnerManagerCommonTest,
       PrioritySetCorrectly) {
  // Why are events used here instead of the task tracker?
  // Shutting down can cause priorities to get raised. This means we have to use
  // events to determine when a task is run.
  scoped_refptr<SingleThreadTaskRunner> task_runner_background =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "Background", {TaskPriority::BACKGROUND}, GetParam());
  scoped_refptr<SingleThreadTaskRunner> task_runner_normal =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              "Normal", {TaskPriority::USER_VISIBLE}, GetParam());

  ThreadPriority thread_priority_background;
  task_runner_background->PostTask(
      FROM_HERE, BindOnce(&CaptureThreadPriority, &thread_priority_background));
  WaitableEvent waitable_event_background(
      WaitableEvent::ResetPolicy::MANUAL,
      WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_background->PostTask(
      FROM_HERE,
      BindOnce(&WaitableEvent::Signal, Unretained(&waitable_event_background)));

  ThreadPriority thread_priority_normal;
  task_runner_normal->PostTask(
      FROM_HERE, BindOnce(&CaptureThreadPriority, &thread_priority_normal));
  WaitableEvent waitable_event_normal(
      WaitableEvent::ResetPolicy::MANUAL,
      WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_normal->PostTask(
      FROM_HERE,
      BindOnce(&WaitableEvent::Signal, Unretained(&waitable_event_normal)));

  waitable_event_background.Wait();
  waitable_event_normal.Wait();

  if (Lock::HandlesMultipleThreadPriorities())
    EXPECT_EQ(ThreadPriority::BACKGROUND, thread_priority_background);
  else
    EXPECT_EQ(ThreadPriority::NORMAL, thread_priority_background);
  EXPECT_EQ(ThreadPriority::NORMAL, thread_priority_normal);
}

TEST_P(TaskSchedulerSingleThreadTaskRunnerManagerCommonTest, ThreadNamesSet) {
  constexpr TaskTraits foo_traits = {TaskPriority::BACKGROUND,
                                     TaskShutdownBehavior::BLOCK_SHUTDOWN};
  scoped_refptr<SingleThreadTaskRunner> foo_task_runner =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits("MyName", foo_traits,
                                                   GetParam());
  std::string foo_captured_name;
  foo_task_runner->PostTask(FROM_HERE,
                            BindOnce(&CaptureThreadName, &foo_captured_name));

  constexpr TaskTraits user_blocking_traits = {
      TaskPriority::USER_BLOCKING, MayBlock(),
      TaskShutdownBehavior::BLOCK_SHUTDOWN};
  scoped_refptr<SingleThreadTaskRunner> user_blocking_task_runner =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits("A", user_blocking_traits,
                                                   GetParam());

  std::string user_blocking_captured_name;
  user_blocking_task_runner->PostTask(
      FROM_HERE, BindOnce(&CaptureThreadName, &user_blocking_captured_name));

  task_tracker_.Shutdown();

  EXPECT_NE(std::string::npos, foo_captured_name.find("MyName"));
  EXPECT_NE(std::string::npos,
            foo_captured_name.find(
                kEnvironmentParams[GetEnvironmentIndexForTraits(foo_traits)]
                    .name_suffix));
  EXPECT_NE(
      std::string::npos,
      user_blocking_captured_name.find(
          kEnvironmentParams[GetEnvironmentIndexForTraits(user_blocking_traits)]
              .name_suffix));

  if (GetParam() == SingleThreadTaskRunnerThreadMode::DEDICATED) {
    EXPECT_EQ(std::string::npos, foo_captured_name.find("Shared"));
    EXPECT_EQ(std::string::npos, user_blocking_captured_name.find("Shared"));
  } else {
    EXPECT_NE(std::string::npos, foo_captured_name.find("Shared"));
    EXPECT_NE(std::string::npos, user_blocking_captured_name.find("Shared"));
  }
}

TEST_P(TaskSchedulerSingleThreadTaskRunnerManagerCommonTest,
       PostTaskAfterShutdown) {
  auto task_runner = single_thread_task_runner_manager_
                         ->CreateSingleThreadTaskRunnerWithTraits(
                             "A", TaskTraits(), GetParam());
  task_tracker_.Shutdown();
  EXPECT_FALSE(task_runner->PostTask(FROM_HERE, BindOnce(&ShouldNotRun)));
}

// Verify that a Task runs shortly after its delay expires.
TEST_P(TaskSchedulerSingleThreadTaskRunnerManagerCommonTest, PostDelayedTask) {
  TimeTicks start_time = TimeTicks::Now();

  // Post a task with a short delay.
  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  auto task_runner = single_thread_task_runner_manager_
                         ->CreateSingleThreadTaskRunnerWithTraits(
                             "A", TaskTraits(), GetParam());
  EXPECT_TRUE(task_runner->PostDelayedTask(
      FROM_HERE, BindOnce(&WaitableEvent::Signal, Unretained(&task_ran)),
      TestTimeouts::tiny_timeout()));

  // Wait until the task runs.
  task_ran.Wait();

  // Expect the task to run after its delay expires, but not more than 250 ms
  // after that.
  const TimeDelta actual_delay = TimeTicks::Now() - start_time;
  EXPECT_GE(actual_delay, TestTimeouts::tiny_timeout());
  EXPECT_LT(actual_delay,
            TimeDelta::FromMilliseconds(250) + TestTimeouts::tiny_timeout());
}

INSTANTIATE_TEST_CASE_P(
    AllModes,
    TaskSchedulerSingleThreadTaskRunnerManagerCommonTest,
    ::testing::Values(SingleThreadTaskRunnerThreadMode::SHARED,
                      SingleThreadTaskRunnerThreadMode::DEDICATED));

namespace {

class CallJoinFromDifferentThread : public SimpleThread {
 public:
  CallJoinFromDifferentThread(
      SchedulerSingleThreadTaskRunnerManager* manager_to_join)
      : SimpleThread("SchedulerSingleThreadTaskRunnerManagerJoinThread"),
        manager_to_join_(manager_to_join),
        run_started_event_(WaitableEvent::ResetPolicy::MANUAL,
                           WaitableEvent::InitialState::NOT_SIGNALED) {}

  ~CallJoinFromDifferentThread() override = default;

  void Run() override {
    run_started_event_.Signal();
    manager_to_join_->JoinForTesting();
  }

  void WaitForRunToStart() { run_started_event_.Wait(); }

 private:
  SchedulerSingleThreadTaskRunnerManager* const manager_to_join_;
  WaitableEvent run_started_event_;

  DISALLOW_COPY_AND_ASSIGN(CallJoinFromDifferentThread);
};

class TaskSchedulerSingleThreadTaskRunnerManagerJoinTest
    : public TaskSchedulerSingleThreadTaskRunnerManagerTest {
 public:
  TaskSchedulerSingleThreadTaskRunnerManagerJoinTest() = default;
  ~TaskSchedulerSingleThreadTaskRunnerManagerJoinTest() override = default;

 protected:
  void TearDownSingleThreadTaskRunnerManager() override {
    // The tests themselves are responsible for calling JoinForTesting().
    single_thread_task_runner_manager_.reset();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerSingleThreadTaskRunnerManagerJoinTest);
};

}  // namespace

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerJoinTest, ConcurrentJoin) {
  // Exercises the codepath where the workers are unavailable for unregistration
  // because of a Join call.
  WaitableEvent task_running(WaitableEvent::ResetPolicy::MANUAL,
                             WaitableEvent::InitialState::NOT_SIGNALED);
  WaitableEvent task_blocking(WaitableEvent::ResetPolicy::MANUAL,
                              WaitableEvent::InitialState::NOT_SIGNALED);

  {
    auto task_runner = single_thread_task_runner_manager_
                           ->CreateSingleThreadTaskRunnerWithTraits(
                               "A", {WithBaseSyncPrimitives()},
                               SingleThreadTaskRunnerThreadMode::DEDICATED);
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE,
        BindOnce(&WaitableEvent::Signal, Unretained(&task_running))));
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE, BindOnce(&WaitableEvent::Wait, Unretained(&task_blocking))));
  }

  task_running.Wait();
  CallJoinFromDifferentThread join_from_different_thread(
      single_thread_task_runner_manager_.get());
  join_from_different_thread.Start();
  join_from_different_thread.WaitForRunToStart();
  task_blocking.Signal();
  join_from_different_thread.Join();
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerJoinTest,
       ConcurrentJoinExtraSkippedTask) {
  // Tests to make sure that tasks are properly cleaned up at Join, allowing
  // SingleThreadTaskRunners to unregister themselves.
  WaitableEvent task_running(WaitableEvent::ResetPolicy::MANUAL,
                             WaitableEvent::InitialState::NOT_SIGNALED);
  WaitableEvent task_blocking(WaitableEvent::ResetPolicy::MANUAL,
                              WaitableEvent::InitialState::NOT_SIGNALED);

  {
    auto task_runner = single_thread_task_runner_manager_
                           ->CreateSingleThreadTaskRunnerWithTraits(
                               "A", {WithBaseSyncPrimitives()},
                               SingleThreadTaskRunnerThreadMode::DEDICATED);
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE,
        BindOnce(&WaitableEvent::Signal, Unretained(&task_running))));
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE, BindOnce(&WaitableEvent::Wait, Unretained(&task_blocking))));
    EXPECT_TRUE(task_runner->PostTask(FROM_HERE, BindOnce(&DoNothing)));
  }

  task_running.Wait();
  CallJoinFromDifferentThread join_from_different_thread(
      single_thread_task_runner_manager_.get());
  join_from_different_thread.Start();
  join_from_different_thread.WaitForRunToStart();
  task_blocking.Signal();
  join_from_different_thread.Join();
}

#if defined(OS_WIN)

TEST_P(TaskSchedulerSingleThreadTaskRunnerManagerCommonTest,
       COMSTAInitialized) {
  scoped_refptr<SingleThreadTaskRunner> com_task_runner =
      single_thread_task_runner_manager_->CreateCOMSTATaskRunnerWithTraits(
          "A", {TaskShutdownBehavior::BLOCK_SHUTDOWN}, GetParam());

  com_task_runner->PostTask(FROM_HERE, BindOnce(&win::AssertComApartmentType,
                                                win::ComApartmentType::STA));

  task_tracker_.Shutdown();
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, COMSTASameThreadUsed) {
  scoped_refptr<SingleThreadTaskRunner> task_runner_1 =
      single_thread_task_runner_manager_->CreateCOMSTATaskRunnerWithTraits(
          "A", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
          SingleThreadTaskRunnerThreadMode::SHARED);
  scoped_refptr<SingleThreadTaskRunner> task_runner_2 =
      single_thread_task_runner_manager_->CreateCOMSTATaskRunnerWithTraits(
          "B", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
          SingleThreadTaskRunnerThreadMode::SHARED);

  PlatformThreadRef thread_ref_1;
  task_runner_1->PostTask(FROM_HERE,
                          BindOnce(&CaptureThreadRef, &thread_ref_1));
  PlatformThreadRef thread_ref_2;
  task_runner_2->PostTask(FROM_HERE,
                          BindOnce(&CaptureThreadRef, &thread_ref_2));

  task_tracker_.Shutdown();

  ASSERT_FALSE(thread_ref_1.is_null());
  ASSERT_FALSE(thread_ref_2.is_null());
  EXPECT_EQ(thread_ref_1, thread_ref_2);
}

namespace {

const wchar_t* const kTestWindowClassName =
    L"TaskSchedulerSingleThreadTaskRunnerManagerTestWinMessageWindow";

class TaskSchedulerSingleThreadTaskRunnerManagerTestWin
    : public TaskSchedulerSingleThreadTaskRunnerManagerTest {
 public:
  TaskSchedulerSingleThreadTaskRunnerManagerTestWin() = default;

  void SetUp() override {
    TaskSchedulerSingleThreadTaskRunnerManagerTest::SetUp();
    register_class_succeeded_ = RegisterTestWindowClass();
    ASSERT_TRUE(register_class_succeeded_);
  }

  void TearDown() override {
    if (register_class_succeeded_)
      ::UnregisterClass(kTestWindowClassName, CURRENT_MODULE());

    TaskSchedulerSingleThreadTaskRunnerManagerTest::TearDown();
  }

  HWND CreateTestWindow() {
    return CreateWindow(kTestWindowClassName, kTestWindowClassName, 0, 0, 0, 0,
                        0, HWND_MESSAGE, nullptr, CURRENT_MODULE(), nullptr);
  }

 private:
  bool RegisterTestWindowClass() {
    WNDCLASSEX window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = &::DefWindowProc;
    window_class.hInstance = CURRENT_MODULE();
    window_class.lpszClassName = kTestWindowClassName;
    return !!::RegisterClassEx(&window_class);
  }

  bool register_class_succeeded_ = false;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerSingleThreadTaskRunnerManagerTestWin);
};

}  // namespace

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTestWin, PumpsMessages) {
  scoped_refptr<SingleThreadTaskRunner> com_task_runner =
      single_thread_task_runner_manager_->CreateCOMSTATaskRunnerWithTraits(
          "A", {TaskShutdownBehavior::BLOCK_SHUTDOWN},
          SingleThreadTaskRunnerThreadMode::DEDICATED);
  HWND hwnd = nullptr;
  // HWNDs process messages on the thread that created them, so we have to
  // create them within the context of the task runner to properly simulate a
  // COM callback.
  com_task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](TaskSchedulerSingleThreadTaskRunnerManagerTestWin* test_harness,
             HWND* hwnd) { *hwnd = test_harness->CreateTestWindow(); },
          Unretained(this), &hwnd));

  task_tracker_.Flush();

  ASSERT_NE(hwnd, nullptr);
  // If the message pump isn't running, we will hang here. This simulates how
  // COM would receive a callback with its own message HWND.
  SendMessage(hwnd, WM_USER, 0, 0);

  com_task_runner->PostTask(
      FROM_HERE, BindOnce([](HWND hwnd) { ::DestroyWindow(hwnd); }, hwnd));

  task_tracker_.Shutdown();
}

#endif  // defined(OS_WIN)

namespace {

class TaskSchedulerSingleThreadTaskRunnerManagerStartTest
    : public TaskSchedulerSingleThreadTaskRunnerManagerTest {
 public:
  TaskSchedulerSingleThreadTaskRunnerManagerStartTest() = default;

 private:
  void StartSingleThreadTaskRunnerManagerFromSetUp() override {
    // Start() is called in the test body rather than in SetUp().
  }

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerSingleThreadTaskRunnerManagerStartTest);
};

}  // namespace

// Verify that a task posted before Start() doesn't run until Start() is called.
TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerStartTest,
       PostTaskBeforeStart) {
  AtomicFlag manager_started;
  WaitableEvent task_running(WaitableEvent::ResetPolicy::MANUAL,
                             WaitableEvent::InitialState::NOT_SIGNALED);
  single_thread_task_runner_manager_
      ->CreateSingleThreadTaskRunnerWithTraits(
          "A", TaskTraits(), SingleThreadTaskRunnerThreadMode::DEDICATED)
      ->PostTask(
          FROM_HERE,
          BindOnce(
              [](WaitableEvent* task_running, AtomicFlag* manager_started) {
                task_running->Signal();

                // The task should not run before Start().
                EXPECT_TRUE(manager_started->IsSet());
              },
              Unretained(&task_running), Unretained(&manager_started)));

  // Wait a little bit to make sure that the task isn't scheduled before start.
  // Note: This test won't catch a case where the task is scheduled between
  // setting |manager_started| and calling Start(). However, we expect the test
  // to be flaky if the tested code allows that to happen.
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  manager_started.Set();
  single_thread_task_runner_manager_->Start();

  // This should not hang if the task is scheduled after Start().
  task_running.Wait();
}

}  // namespace internal
}  // namespace base
