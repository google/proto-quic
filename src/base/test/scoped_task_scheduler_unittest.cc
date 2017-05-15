// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_scheduler.h"

#include "base/bind.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/run_loop.h"
#include "base/sequence_checker.h"
#include "base/task_scheduler/post_task.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/test_utils.h"
#include "base/test/scoped_mock_time_message_loop_task_runner.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_WIN)
#include <objbase.h>
#endif  // defined(OS_WIN)

namespace base {
namespace test {

TEST(ScopedTaskSchedulerTest, PostTask) {
  ScopedTaskScheduler scoped_task_scheduler;

  bool first_task_ran = false;
  bool second_task_ran = false;

  SequenceCheckerImpl sequence_checker;
  ThreadCheckerImpl thread_checker;

  // Detach |sequence_checker| and |thread_checker|. Otherwise, they are bound
  // to the current thread without a SequenceToken or TaskToken (i.e.
  // CalledOnValidSequence/Thread() will always return true on the current
  // thread, even when the SequenceToken or TaskToken changes).
  sequence_checker.DetachFromSequence();
  thread_checker.DetachFromThread();

  PostTask(FROM_HERE,
           BindOnce(
               [](SequenceCheckerImpl* sequence_checker,
                  ThreadCheckerImpl* thread_checker, bool* first_task_ran) {
                 EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
                 EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
                 EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
                 EXPECT_TRUE(thread_checker->CalledOnValidThread());
                 *first_task_ran = true;
               },
               Unretained(&sequence_checker), Unretained(&thread_checker),
               Unretained(&first_task_ran)));

  PostTask(FROM_HERE,
           BindOnce(
               [](SequenceCheckerImpl* sequence_checker,
                  ThreadCheckerImpl* thread_checker, bool* second_task_ran) {
                 EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
                 EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
                 EXPECT_FALSE(sequence_checker->CalledOnValidSequence());
                 EXPECT_FALSE(thread_checker->CalledOnValidThread());
                 *second_task_ran = true;
               },
               Unretained(&sequence_checker), Unretained(&thread_checker),
               Unretained(&second_task_ran)));

  RunLoop().RunUntilIdle();

  EXPECT_TRUE(first_task_ran);
  EXPECT_TRUE(second_task_ran);
}

TEST(ScopedTaskSchedulerTest, CreateTaskRunnerAndPostTask) {
  ScopedTaskScheduler scoped_task_scheduler;
  auto task_runner = CreateTaskRunnerWithTraits(TaskTraits());

  bool first_task_ran = false;
  bool second_task_ran = false;

  SequenceCheckerImpl sequence_checker;
  ThreadCheckerImpl thread_checker;

  // Detach |sequence_checker| and |thread_checker|. Otherwise, they are bound
  // to the current thread without a SequenceToken or TaskToken (i.e.
  // CalledOnValidSequence/Thread() will always return true on the current
  // thread, even when the SequenceToken or TaskToken changes).
  sequence_checker.DetachFromSequence();
  thread_checker.DetachFromThread();

  task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](SequenceCheckerImpl* sequence_checker,
             ThreadCheckerImpl* thread_checker, bool* first_task_ran) {
            EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
            EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
            EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
            EXPECT_TRUE(thread_checker->CalledOnValidThread());
            *first_task_ran = true;
          },
          Unretained(&sequence_checker), Unretained(&thread_checker),
          Unretained(&first_task_ran)));

  task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](SequenceCheckerImpl* sequence_checker,
             ThreadCheckerImpl* thread_checker, bool* second_task_ran) {
            EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
            EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
            EXPECT_FALSE(sequence_checker->CalledOnValidSequence());
            EXPECT_FALSE(thread_checker->CalledOnValidThread());
            *second_task_ran = true;
          },
          Unretained(&sequence_checker), Unretained(&thread_checker),
          Unretained(&second_task_ran)));

  RunLoop().RunUntilIdle();

  EXPECT_TRUE(first_task_ran);
  EXPECT_TRUE(second_task_ran);
}

TEST(ScopedTaskSchedulerTest, CreateSequencedTaskRunnerAndPostTask) {
  ScopedTaskScheduler scoped_task_scheduler;
  auto task_runner = CreateSequencedTaskRunnerWithTraits(TaskTraits());

  bool first_task_ran = false;
  bool second_task_ran = false;

  SequenceCheckerImpl sequence_checker;
  ThreadCheckerImpl thread_checker;

  // Detach |sequence_checker| and |thread_checker|. Otherwise, they are bound
  // to the current thread without a SequenceToken or TaskToken (i.e.
  // CalledOnValidSequence/Thread() will always return true on the current
  // thread, even when the SequenceToken or TaskToken changes).
  sequence_checker.DetachFromSequence();
  thread_checker.DetachFromThread();

  task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](SequenceCheckerImpl* sequence_checker,
             ThreadCheckerImpl* thread_checker, bool* first_task_ran) {
            EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
            EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
            EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
            EXPECT_TRUE(thread_checker->CalledOnValidThread());
            *first_task_ran = true;
          },
          Unretained(&sequence_checker), Unretained(&thread_checker),
          Unretained(&first_task_ran)));

  task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](SequenceCheckerImpl* sequence_checker,
             ThreadCheckerImpl* thread_checker, bool* second_task_ran) {
            EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
            EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
            EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
            EXPECT_FALSE(thread_checker->CalledOnValidThread());
            *second_task_ran = true;
          },
          Unretained(&sequence_checker), Unretained(&thread_checker),
          Unretained(&second_task_ran)));

  RunLoop().RunUntilIdle();

  EXPECT_TRUE(first_task_ran);
  EXPECT_TRUE(second_task_ran);
}

TEST(ScopedTaskSchedulerTest, CreateSingleThreadTaskRunnerAndPostTask) {
  ScopedTaskScheduler scoped_task_scheduler;
  auto task_runner = CreateSingleThreadTaskRunnerWithTraits(TaskTraits());

  bool first_task_ran = false;
  bool second_task_ran = false;

  SequenceCheckerImpl sequence_checker;
  ThreadCheckerImpl thread_checker;

  // Detach |sequence_checker| and |thread_checker|. Otherwise, they are bound
  // to the current thread without a SequenceToken or TaskToken (i.e.
  // CalledOnValidSequence/Thread() will always return true on the current
  // thread, even when the SequenceToken or TaskToken changes).
  sequence_checker.DetachFromSequence();
  thread_checker.DetachFromThread();

  task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](SequenceCheckerImpl* sequence_checker,
             ThreadCheckerImpl* thread_checker, bool* first_task_ran) {
            EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
            EXPECT_TRUE(ThreadTaskRunnerHandle::IsSet());
            EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
            EXPECT_TRUE(thread_checker->CalledOnValidThread());
            *first_task_ran = true;
          },
          Unretained(&sequence_checker), Unretained(&thread_checker),
          Unretained(&first_task_ran)));

  task_runner->PostTask(
      FROM_HERE,
      BindOnce(
          [](SequenceCheckerImpl* sequence_checker,
             ThreadCheckerImpl* thread_checker, bool* second_task_ran) {
            EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
            EXPECT_TRUE(ThreadTaskRunnerHandle::IsSet());
            EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
            EXPECT_TRUE(thread_checker->CalledOnValidThread());
            *second_task_ran = true;
          },
          Unretained(&sequence_checker), Unretained(&thread_checker),
          Unretained(&second_task_ran)));

  RunLoop().RunUntilIdle();

  EXPECT_TRUE(first_task_ran);
  EXPECT_TRUE(second_task_ran);
}

#if defined(OS_WIN)
// Verify that COM STAs work correctly from the ScopedTaskScheduler.
TEST(ScopedTaskSchedulerTest, COMSTAAvailable) {
  ScopedTaskScheduler scoped_task_scheduler;
  auto com_task_runner = CreateCOMSTATaskRunnerWithTraits(TaskTraits());

  bool com_task_ran = false;
  com_task_runner->PostTask(
      FROM_HERE,
      Bind(
          [](bool* com_task_ran) {
            *com_task_ran = true;
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(hr)) {
              ADD_FAILURE() << "COM STA was not initialized on this thread";
              CoUninitialize();
            }
          },
          &com_task_ran));

  RunLoop().RunUntilIdle();

  EXPECT_TRUE(com_task_ran);
}
#endif  // defined(OS_WIN)

TEST(ScopedTaskSchedulerTest, NonBlockShutdownTasksPostedAfterShutdownDontRun) {
  ScopedTaskScheduler scoped_task_scheduler;
  TaskScheduler::GetInstance()->Shutdown();
  PostTaskWithTraits(FROM_HERE, {TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
                     BindOnce([]() {
                       ADD_FAILURE()
                           << "CONTINUE_ON_SHUTDOWN task should not run";
                     }));
  PostTaskWithTraits(FROM_HERE, {TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
                     BindOnce([]() {
                       ADD_FAILURE() << "SKIP_ON_SHUTDOWN task should not run";
                     }));

  // This should not run anything.
  RunLoop().RunUntilIdle();
}

TEST(ScopedTaskSchedulerTest, DestructorRunsBlockShutdownTasksOnly) {
  bool block_shutdown_task_ran = false;
  {
    ScopedTaskScheduler scoped_task_scheduler;
    PostTaskWithTraits(FROM_HERE, {TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
                       BindOnce([]() {
                         ADD_FAILURE()
                             << "CONTINUE_ON_SHUTDOWN task should not run";
                       }));
    PostTaskWithTraits(FROM_HERE, {TaskShutdownBehavior::SKIP_ON_SHUTDOWN},
                       BindOnce([]() {
                         ADD_FAILURE()
                             << "SKIP_ON_SHUTDOWN task should not run";
                       }));
    PostTaskWithTraits(FROM_HERE, {TaskShutdownBehavior::BLOCK_SHUTDOWN},
                       BindOnce(
                           [](bool* block_shutdown_task_ran) {
                             *block_shutdown_task_ran = true;
                           },
                           Unretained(&block_shutdown_task_ran)));
  }
  EXPECT_TRUE(block_shutdown_task_ran);
}

TEST(ScopedTaskSchedulerTest, ReassignCurrentTaskRunner) {
  bool first_task_ran = false;
  bool second_task_ran = false;

  auto TestTaskRan = [](bool* task_ran) { *task_ran = true; };

  ScopedTaskScheduler scoped_task_scheduler;
  {
    ScopedMockTimeMessageLoopTaskRunner mock_time_task_runner;
    PostDelayedTask(FROM_HERE,
                    BindOnce(TestTaskRan, Unretained(&first_task_ran)),
                    TimeDelta::FromSeconds(1));

    // The delayed task should be queued on |mock_time_task_runner|, not the
    // default task runner.
    EXPECT_TRUE(mock_time_task_runner.task_runner()->HasPendingTask());
  }

  PostDelayedTask(FROM_HERE,
                  BindOnce(TestTaskRan, Unretained(&second_task_ran)),
                  TimeDelta());

  RunLoop().RunUntilIdle();

  // We never pumped |mock_time_task_runner| so the first task should not have
  // run.
  EXPECT_FALSE(first_task_ran);
  EXPECT_TRUE(second_task_ran);
}

// Verify that a task can be posted from a task running in ScopedTaskScheduler.
TEST(ScopedTaskSchedulerTest, ReentrantTaskRunner) {
  bool task_ran = false;
  ScopedTaskScheduler scoped_task_scheduler;
  PostTask(FROM_HERE,
           BindOnce(
               [](bool* task_ran) {
                 PostTask(FROM_HERE,
                          BindOnce([](bool* task_ran) { *task_ran = true; },
                                   Unretained(task_ran)));
               },
               Unretained(&task_ran)));
  RunLoop().RunUntilIdle();
  EXPECT_TRUE(task_ran);
}

}  // namespace test
}  // namespace base
