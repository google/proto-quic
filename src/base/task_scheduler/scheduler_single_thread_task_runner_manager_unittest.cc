// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_single_thread_task_runner_manager.h"

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/task_scheduler/task_traits.h"
#include "base/test/test_timeouts.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_WIN)
#include <windows.h>
#include <objbase.h>

#include "base/win/current_module.h"
#endif  // defined(OS_WIN)

namespace base {
namespace internal {

namespace {

enum WorkerPoolType : size_t {
  BACKGROUND_WORKER_POOL = 0,
  FOREGROUND_WORKER_POOL,
};

static size_t GetThreadPoolIndexForTraits(const TaskTraits& traits) {
  return traits.priority() == TaskPriority::BACKGROUND ? BACKGROUND_WORKER_POOL
                                                       : FOREGROUND_WORKER_POOL;
}

std::vector<SchedulerWorkerPoolParams> GetParamsVector() {
  using StandbyThreadPolicy = SchedulerWorkerPoolParams::StandbyThreadPolicy;

  std::vector<SchedulerWorkerPoolParams> params_vector;

  DCHECK_EQ(BACKGROUND_WORKER_POOL, params_vector.size());
  params_vector.emplace_back("Background", ThreadPriority::BACKGROUND,
                             StandbyThreadPolicy::LAZY, 1U, TimeDelta::Max());

  DCHECK_EQ(FOREGROUND_WORKER_POOL, params_vector.size());
  params_vector.emplace_back("Foreground", ThreadPriority::NORMAL,
                             StandbyThreadPolicy::LAZY, 1U, TimeDelta::Max());

  return params_vector;
}

class TaskSchedulerSingleThreadTaskRunnerManagerTest : public testing::Test {
 public:
  TaskSchedulerSingleThreadTaskRunnerManagerTest()
      : service_thread_("TaskSchedulerServiceThread") {}

  void SetUp() override {
    service_thread_.Start();

    delayed_task_manager_ =
        MakeUnique<DelayedTaskManager>(service_thread_.task_runner());
    single_thread_task_runner_manager_ =
        MakeUnique<SchedulerSingleThreadTaskRunnerManager>(
            GetParamsVector(), Bind(&GetThreadPoolIndexForTraits),
            &task_tracker_, delayed_task_manager_.get());
  }

  void TearDown() override {
    TearDownSingleThreadTaskRunnerManager();
    delayed_task_manager_.reset();
    service_thread_.Stop();
  }

 protected:
  virtual void TearDownSingleThreadTaskRunnerManager() {
    single_thread_task_runner_manager_->JoinForTesting();
    single_thread_task_runner_manager_.reset();
  }

  std::unique_ptr<SchedulerSingleThreadTaskRunnerManager>
      single_thread_task_runner_manager_;
  TaskTracker task_tracker_;

 private:
  Thread service_thread_;
  std::unique_ptr<DelayedTaskManager> delayed_task_manager_;

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

void ShouldNotRun() {
  ADD_FAILURE() << "Ran a task that shouldn't run.";
}

}  // namespace

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, DifferentThreadsUsed) {
  scoped_refptr<SingleThreadTaskRunner> task_runner_1 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits().WithShutdownBehavior(
                  TaskShutdownBehavior::BLOCK_SHUTDOWN));
  scoped_refptr<SingleThreadTaskRunner> task_runner_2 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits().WithShutdownBehavior(
                  TaskShutdownBehavior::BLOCK_SHUTDOWN));

  PlatformThreadRef thread_ref_1;
  task_runner_1->PostTask(FROM_HERE, Bind(&CaptureThreadRef, &thread_ref_1));
  PlatformThreadRef thread_ref_2;
  task_runner_2->PostTask(FROM_HERE, Bind(&CaptureThreadRef, &thread_ref_2));

  task_tracker_.Shutdown();

  ASSERT_FALSE(thread_ref_1.is_null());
  ASSERT_FALSE(thread_ref_2.is_null());
  EXPECT_NE(thread_ref_1, thread_ref_2);
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, PrioritySetCorrectly) {
  // Why are events used here instead of the task tracker?
  // Shutting down can cause priorities to get raised. This means we have to use
  // events to determine when a task is run.
  scoped_refptr<SingleThreadTaskRunner> task_runner_background =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits().WithPriority(TaskPriority::BACKGROUND));
  scoped_refptr<SingleThreadTaskRunner> task_runner_user_visible =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits().WithPriority(TaskPriority::USER_VISIBLE));
  scoped_refptr<SingleThreadTaskRunner> task_runner_user_blocking =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits()
                  .WithPriority(TaskPriority::USER_BLOCKING)
                  .WithShutdownBehavior(TaskShutdownBehavior::BLOCK_SHUTDOWN));

  ThreadPriority thread_priority_background;
  task_runner_background->PostTask(
      FROM_HERE, Bind(&CaptureThreadPriority, &thread_priority_background));
  WaitableEvent waitable_event_background(
      WaitableEvent::ResetPolicy::MANUAL,
      WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_background->PostTask(
      FROM_HERE,
      Bind(&WaitableEvent::Signal, Unretained(&waitable_event_background)));

  ThreadPriority thread_priority_user_visible;
  task_runner_user_visible->PostTask(
      FROM_HERE, Bind(&CaptureThreadPriority, &thread_priority_user_visible));
  WaitableEvent waitable_event_user_visible(
      WaitableEvent::ResetPolicy::MANUAL,
      WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_user_visible->PostTask(
      FROM_HERE,
      Bind(&WaitableEvent::Signal, Unretained(&waitable_event_user_visible)));

  ThreadPriority thread_priority_user_blocking;
  task_runner_user_blocking->PostTask(
      FROM_HERE, Bind(&CaptureThreadPriority, &thread_priority_user_blocking));
  WaitableEvent waitable_event_user_blocking(
      WaitableEvent::ResetPolicy::MANUAL,
      WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_user_blocking->PostTask(
      FROM_HERE,
      Bind(&WaitableEvent::Signal, Unretained(&waitable_event_user_blocking)));

  waitable_event_background.Wait();
  waitable_event_user_visible.Wait();
  waitable_event_user_blocking.Wait();

  if (Lock::HandlesMultipleThreadPriorities())
    EXPECT_EQ(ThreadPriority::BACKGROUND, thread_priority_background);
  else
    EXPECT_EQ(ThreadPriority::NORMAL, thread_priority_background);
  EXPECT_EQ(ThreadPriority::NORMAL, thread_priority_user_visible);
  EXPECT_EQ(ThreadPriority::NORMAL, thread_priority_user_blocking);
}

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, PostTaskAfterShutdown) {
  auto task_runner = single_thread_task_runner_manager_
                         ->CreateSingleThreadTaskRunnerWithTraits(TaskTraits());
  task_tracker_.Shutdown();
  EXPECT_FALSE(task_runner->PostTask(FROM_HERE, Bind(&ShouldNotRun)));
}

// Verify that a Task runs shortly after its delay expires.
TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, PostDelayedTask) {
  TimeTicks start_time = TimeTicks::Now();

  // Post a task with a short delay.
  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  auto task_runner = single_thread_task_runner_manager_
                         ->CreateSingleThreadTaskRunnerWithTraits(TaskTraits());
  EXPECT_TRUE(task_runner->PostDelayedTask(
      FROM_HERE, Bind(&WaitableEvent::Signal, Unretained(&task_ran)),
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

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest,
       RunsTasksOnCurrentThread) {
  scoped_refptr<SingleThreadTaskRunner> task_runner_1 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits().WithShutdownBehavior(
                  TaskShutdownBehavior::BLOCK_SHUTDOWN));
  scoped_refptr<SingleThreadTaskRunner> task_runner_2 =
      single_thread_task_runner_manager_
          ->CreateSingleThreadTaskRunnerWithTraits(
              TaskTraits().WithShutdownBehavior(
                  TaskShutdownBehavior::BLOCK_SHUTDOWN));

  EXPECT_FALSE(task_runner_1->RunsTasksOnCurrentThread());
  EXPECT_FALSE(task_runner_2->RunsTasksOnCurrentThread());

  task_runner_1->PostTask(
      FROM_HERE, Bind(
                     [](scoped_refptr<SingleThreadTaskRunner> task_runner_1,
                        scoped_refptr<SingleThreadTaskRunner> task_runner_2) {
                       EXPECT_TRUE(task_runner_1->RunsTasksOnCurrentThread());
                       EXPECT_FALSE(task_runner_2->RunsTasksOnCurrentThread());
                     },
                     task_runner_1, task_runner_2));

  task_runner_2->PostTask(
      FROM_HERE, Bind(
                     [](scoped_refptr<SingleThreadTaskRunner> task_runner_1,
                        scoped_refptr<SingleThreadTaskRunner> task_runner_2) {
                       EXPECT_FALSE(task_runner_1->RunsTasksOnCurrentThread());
                       EXPECT_TRUE(task_runner_2->RunsTasksOnCurrentThread());
                     },
                     task_runner_1, task_runner_2));

  task_tracker_.Shutdown();
}

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
                               TaskTraits().WithBaseSyncPrimitives());
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE, Bind(&WaitableEvent::Signal, Unretained(&task_running))));
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE, Bind(&WaitableEvent::Wait, Unretained(&task_blocking))));
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
                               TaskTraits().WithBaseSyncPrimitives());
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE, Bind(&WaitableEvent::Signal, Unretained(&task_running))));
    EXPECT_TRUE(task_runner->PostTask(
        FROM_HERE, Bind(&WaitableEvent::Wait, Unretained(&task_blocking))));
    EXPECT_TRUE(task_runner->PostTask(FROM_HERE, Bind(&DoNothing)));
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

TEST_F(TaskSchedulerSingleThreadTaskRunnerManagerTest, COMSTAInitialized) {
  scoped_refptr<SingleThreadTaskRunner> com_task_runner =
      single_thread_task_runner_manager_->CreateCOMSTATaskRunnerWithTraits(
          TaskTraits().WithShutdownBehavior(
              TaskShutdownBehavior::BLOCK_SHUTDOWN));

  com_task_runner->PostTask(
      FROM_HERE, Bind([]() {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr)) {
          ADD_FAILURE() << "COM STA was not initialized on this thread";
          CoUninitialize();
        }
      }));

  task_tracker_.Shutdown();
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
          TaskTraits().WithShutdownBehavior(
              TaskShutdownBehavior::BLOCK_SHUTDOWN));
  HWND hwnd = nullptr;
  // HWNDs process messages on the thread that created them, so we have to
  // create them within the context of the task runner to properly simulate a
  // COM callback.
  com_task_runner->PostTask(
      FROM_HERE,
      Bind([](TaskSchedulerSingleThreadTaskRunnerManagerTestWin* test_harness,
              HWND* hwnd) { *hwnd = test_harness->CreateTestWindow(); },
           Unretained(this), &hwnd));

  task_tracker_.Flush();

  ASSERT_NE(hwnd, nullptr);
  // If the message pump isn't running, we will hang here. This simulates how
  // COM would receive a callback with its own message HWND.
  SendMessage(hwnd, WM_USER, 0, 0);

  com_task_runner->PostTask(
      FROM_HERE, Bind([](HWND hwnd) { ::DestroyWindow(hwnd); }, hwnd));

  task_tracker_.Shutdown();
}

#endif  // defined(OS_WIN)

}  // namespace internal
}  // namespace base
