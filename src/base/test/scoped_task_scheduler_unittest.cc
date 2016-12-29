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
#include "base/task_scheduler/test_utils.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread_checker.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

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
           Bind(
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
           Bind(
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
      Bind(
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
      Bind(
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
      Bind(
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
      Bind(
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
      Bind(
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
      Bind(
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

TEST(ScopedTaskSchedulerTest, ShutdownBehavior) {
  bool block_shutdown_task_ran = false;
  {
    ScopedTaskScheduler scoped_task_scheduler;
    PostTaskWithTraits(
        FROM_HERE, TaskTraits().WithShutdownBehavior(
                       TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN),
        Bind([]() {
          ADD_FAILURE() << "CONTINUE_ON_SHUTDOWN task should not run";
        }));
    PostTaskWithTraits(FROM_HERE, TaskTraits().WithShutdownBehavior(
                                      TaskShutdownBehavior::SKIP_ON_SHUTDOWN),
                       Bind([]() {
                         ADD_FAILURE()
                             << "SKIP_ON_SHUTDOWN task should not run";
                       }));
    PostTaskWithTraits(FROM_HERE, TaskTraits().WithShutdownBehavior(
                                      TaskShutdownBehavior::BLOCK_SHUTDOWN),
                       Bind(
                           [](bool* block_shutdown_task_ran) {
                             *block_shutdown_task_ran = true;
                           },
                           Unretained(&block_shutdown_task_ran)));
  }
  EXPECT_TRUE(block_shutdown_task_ran);
}

}  // namespace test
}  // namespace base
