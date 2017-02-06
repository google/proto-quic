// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_scheduler_impl.h"

#include <stddef.h>

#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/task_traits.h"
#include "base/task_scheduler/test_task_factory.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

namespace {

struct TraitsExecutionModePair {
  TraitsExecutionModePair(const TaskTraits& traits,
                          test::ExecutionMode execution_mode)
      : traits(traits), execution_mode(execution_mode) {}

  TaskTraits traits;
  test::ExecutionMode execution_mode;
};

#if DCHECK_IS_ON()
// Returns whether I/O calls are allowed on the current thread.
bool GetIOAllowed() {
  const bool previous_value = ThreadRestrictions::SetIOAllowed(true);
  ThreadRestrictions::SetIOAllowed(previous_value);
  return previous_value;
}
#endif

// Verify that the current thread priority and I/O restrictions are appropriate
// to run a Task with |traits|.
// Note: ExecutionMode is verified inside TestTaskFactory.
void VerifyTaskEnvironment(const TaskTraits& traits) {
  const bool supports_background_priority =
      Lock::HandlesMultipleThreadPriorities() &&
      PlatformThread::CanIncreaseCurrentThreadPriority();

  EXPECT_EQ(supports_background_priority &&
                    traits.priority() == TaskPriority::BACKGROUND
                ? ThreadPriority::BACKGROUND
                : ThreadPriority::NORMAL,
            PlatformThread::GetCurrentThreadPriority());

#if DCHECK_IS_ON()
  // The #if above is required because GetIOAllowed() always returns true when
  // !DCHECK_IS_ON(), even when |traits| don't allow file I/O.
  EXPECT_EQ(traits.may_block(), GetIOAllowed());
#endif

  // Verify that the thread the task is running on is named as expected.
  const std::string current_thread_name(PlatformThread::GetName());
  EXPECT_NE(std::string::npos, current_thread_name.find("TaskScheduler"));
  EXPECT_NE(std::string::npos,
            current_thread_name.find(
                traits.priority() == TaskPriority::BACKGROUND ? "Background"
                                                              : "Foreground"));
  EXPECT_EQ(traits.may_block(),
            current_thread_name.find("Blocking") != std::string::npos);
}

void VerifyTaskEnvironmentAndSignalEvent(const TaskTraits& traits,
                                         WaitableEvent* event) {
  DCHECK(event);
  VerifyTaskEnvironment(traits);
  event->Signal();
}

void VerifyTimeAndTaskEnvironmentAndSignalEvent(const TaskTraits& traits,
                                                TimeTicks expected_time,
                                                WaitableEvent* event) {
  DCHECK(event);
  EXPECT_LE(expected_time, TimeTicks::Now());
  VerifyTaskEnvironment(traits);
  event->Signal();
}

scoped_refptr<TaskRunner> CreateTaskRunnerWithTraitsAndExecutionMode(
    TaskScheduler* scheduler,
    const TaskTraits& traits,
    test::ExecutionMode execution_mode) {
  switch (execution_mode) {
    case test::ExecutionMode::PARALLEL:
      return scheduler->CreateTaskRunnerWithTraits(traits);
    case test::ExecutionMode::SEQUENCED:
      return scheduler->CreateSequencedTaskRunnerWithTraits(traits);
    case test::ExecutionMode::SINGLE_THREADED:
      return scheduler->CreateSingleThreadTaskRunnerWithTraits(traits);
  }
  ADD_FAILURE() << "Unknown ExecutionMode";
  return nullptr;
}

class ThreadPostingTasks : public SimpleThread {
 public:
  // Creates a thread that posts Tasks to |scheduler| with |traits| and
  // |execution_mode|.
  ThreadPostingTasks(TaskSchedulerImpl* scheduler,
                     const TaskTraits& traits,
                     test::ExecutionMode execution_mode)
      : SimpleThread("ThreadPostingTasks"),
        traits_(traits),
        factory_(CreateTaskRunnerWithTraitsAndExecutionMode(scheduler,
                                                            traits,
                                                            execution_mode),
                 execution_mode) {}

  void WaitForAllTasksToRun() { factory_.WaitForAllTasksToRun(); }

 private:
  void Run() override {
    EXPECT_FALSE(factory_.task_runner()->RunsTasksOnCurrentThread());

    const size_t kNumTasksPerThread = 150;
    for (size_t i = 0; i < kNumTasksPerThread; ++i) {
      factory_.PostTask(test::TestTaskFactory::PostNestedTask::NO,
                        Bind(&VerifyTaskEnvironment, traits_));
    }
  }

  const TaskTraits traits_;
  test::TestTaskFactory factory_;

  DISALLOW_COPY_AND_ASSIGN(ThreadPostingTasks);
};

// Returns a vector with a TraitsExecutionModePair for each valid
// combination of {ExecutionMode, TaskPriority, MayBlock()}.
std::vector<TraitsExecutionModePair> GetTraitsExecutionModePairs() {
  std::vector<TraitsExecutionModePair> params;

  const test::ExecutionMode execution_modes[] = {
      test::ExecutionMode::PARALLEL, test::ExecutionMode::SEQUENCED,
      test::ExecutionMode::SINGLE_THREADED};

  for (test::ExecutionMode execution_mode : execution_modes) {
    for (size_t priority_index = static_cast<size_t>(TaskPriority::LOWEST);
         priority_index <= static_cast<size_t>(TaskPriority::HIGHEST);
         ++priority_index) {
      const TaskPriority priority = static_cast<TaskPriority>(priority_index);
      params.push_back(TraitsExecutionModePair(
          TaskTraits().WithPriority(priority), execution_mode));
      params.push_back(TraitsExecutionModePair(
          TaskTraits().WithPriority(priority).MayBlock(), execution_mode));
    }
  }

  return params;
}

enum WorkerPoolType {
  BACKGROUND_WORKER_POOL = 0,
  BACKGROUND_BLOCKING_WORKER_POOL,
  FOREGROUND_WORKER_POOL,
  FOREGROUND_BLOCKING_WORKER_POOL,
};

size_t GetThreadPoolIndexForTraits(const TaskTraits& traits) {
  if (traits.may_block()) {
    return traits.priority() == TaskPriority::BACKGROUND
               ? BACKGROUND_BLOCKING_WORKER_POOL
               : FOREGROUND_BLOCKING_WORKER_POOL;
  }
  return traits.priority() == TaskPriority::BACKGROUND ? BACKGROUND_WORKER_POOL
                                                       : FOREGROUND_WORKER_POOL;
}

class TaskSchedulerImplTest
    : public testing::TestWithParam<TraitsExecutionModePair> {
 protected:
  TaskSchedulerImplTest() = default;

  void SetUp() override {
    using StandbyThreadPolicy = SchedulerWorkerPoolParams::StandbyThreadPolicy;

    std::vector<SchedulerWorkerPoolParams> params_vector;

    ASSERT_EQ(BACKGROUND_WORKER_POOL, params_vector.size());
    params_vector.emplace_back("Background", ThreadPriority::BACKGROUND,
                               StandbyThreadPolicy::LAZY, 1U, TimeDelta::Max());

    ASSERT_EQ(BACKGROUND_BLOCKING_WORKER_POOL, params_vector.size());
    params_vector.emplace_back("BackgroundBlocking", ThreadPriority::BACKGROUND,
                               StandbyThreadPolicy::LAZY, 3U, TimeDelta::Max());

    ASSERT_EQ(FOREGROUND_WORKER_POOL, params_vector.size());
    params_vector.emplace_back("Foreground", ThreadPriority::NORMAL,
                               StandbyThreadPolicy::LAZY, 4U, TimeDelta::Max());

    ASSERT_EQ(FOREGROUND_BLOCKING_WORKER_POOL, params_vector.size());
    params_vector.emplace_back("ForegroundBlocking", ThreadPriority::NORMAL,
                               StandbyThreadPolicy::LAZY, 12U,
                               TimeDelta::Max());

    scheduler_ = TaskSchedulerImpl::Create(params_vector,
                                           Bind(&GetThreadPoolIndexForTraits));
    ASSERT_TRUE(scheduler_);
  }

  void TearDown() override { scheduler_->JoinForTesting(); }

  std::unique_ptr<TaskSchedulerImpl> scheduler_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerImplTest);
};

}  // namespace

// Verifies that a Task posted via PostDelayedTaskWithTraits with parameterized
// TaskTraits and no delay runs on a thread with the expected priority and I/O
// restrictions. The ExecutionMode parameter is ignored by this test.
TEST_P(TaskSchedulerImplTest, PostDelayedTaskWithTraitsNoDelay) {
  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  scheduler_->PostDelayedTaskWithTraits(
      FROM_HERE, GetParam().traits,
      Bind(&VerifyTaskEnvironmentAndSignalEvent, GetParam().traits,
           Unretained(&task_ran)),
      TimeDelta());
  task_ran.Wait();
}

// Verifies that a Task posted via PostDelayedTaskWithTraits with parameterized
// TaskTraits and a non-zero delay runs on a thread with the expected priority
// and I/O restrictions after the delay expires. The ExecutionMode parameter is
// ignored by this test.
TEST_P(TaskSchedulerImplTest, PostDelayedTaskWithTraitsWithDelay) {
  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  scheduler_->PostDelayedTaskWithTraits(
      FROM_HERE, GetParam().traits,
      Bind(&VerifyTimeAndTaskEnvironmentAndSignalEvent, GetParam().traits,
           TimeTicks::Now() + TestTimeouts::tiny_timeout(),
           Unretained(&task_ran)),
      TestTimeouts::tiny_timeout());
  task_ran.Wait();
}

// Verifies that Tasks posted via a TaskRunner with parameterized TaskTraits and
// ExecutionMode run on a thread with the expected priority and I/O restrictions
// and respect the characteristics of their ExecutionMode.
TEST_P(TaskSchedulerImplTest, PostTasksViaTaskRunner) {
  test::TestTaskFactory factory(
      CreateTaskRunnerWithTraitsAndExecutionMode(
          scheduler_.get(), GetParam().traits, GetParam().execution_mode),
      GetParam().execution_mode);
  EXPECT_FALSE(factory.task_runner()->RunsTasksOnCurrentThread());

  const size_t kNumTasksPerTest = 150;
  for (size_t i = 0; i < kNumTasksPerTest; ++i) {
    factory.PostTask(test::TestTaskFactory::PostNestedTask::NO,
                     Bind(&VerifyTaskEnvironment, GetParam().traits));
  }

  factory.WaitForAllTasksToRun();
}

INSTANTIATE_TEST_CASE_P(OneTraitsExecutionModePair,
                        TaskSchedulerImplTest,
                        ::testing::ValuesIn(GetTraitsExecutionModePairs()));

// Spawns threads that simultaneously post Tasks to TaskRunners with various
// TaskTraits and ExecutionModes. Verifies that each Task runs on a thread with
// the expected priority and I/O restrictions and respects the characteristics
// of its ExecutionMode.
TEST_F(TaskSchedulerImplTest, MultipleTraitsExecutionModePairs) {
  std::vector<std::unique_ptr<ThreadPostingTasks>> threads_posting_tasks;
  for (const auto& traits_execution_mode_pair : GetTraitsExecutionModePairs()) {
    threads_posting_tasks.push_back(WrapUnique(new ThreadPostingTasks(
        scheduler_.get(), traits_execution_mode_pair.traits,
        traits_execution_mode_pair.execution_mode)));
    threads_posting_tasks.back()->Start();
  }

  for (const auto& thread : threads_posting_tasks) {
    thread->WaitForAllTasksToRun();
    thread->Join();
  }
}

TEST_F(TaskSchedulerImplTest, GetMaxConcurrentTasksWithTraitsDeprecated) {
  EXPECT_EQ(1, scheduler_->GetMaxConcurrentTasksWithTraitsDeprecated(
                   TaskTraits().WithPriority(TaskPriority::BACKGROUND)));
  EXPECT_EQ(
      3, scheduler_->GetMaxConcurrentTasksWithTraitsDeprecated(
             TaskTraits().WithPriority(TaskPriority::BACKGROUND).MayBlock()));
  EXPECT_EQ(4, scheduler_->GetMaxConcurrentTasksWithTraitsDeprecated(
                   TaskTraits().WithPriority(TaskPriority::USER_VISIBLE)));
  EXPECT_EQ(
      12,
      scheduler_->GetMaxConcurrentTasksWithTraitsDeprecated(
          TaskTraits().WithPriority(TaskPriority::USER_VISIBLE).MayBlock()));
  EXPECT_EQ(4, scheduler_->GetMaxConcurrentTasksWithTraitsDeprecated(
                   TaskTraits().WithPriority(TaskPriority::USER_BLOCKING)));
  EXPECT_EQ(
      12,
      scheduler_->GetMaxConcurrentTasksWithTraitsDeprecated(
          TaskTraits().WithPriority(TaskPriority::USER_BLOCKING).MayBlock()));
}

}  // namespace internal
}  // namespace base
