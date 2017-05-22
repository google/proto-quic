// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/run_loop.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/post_task.h"
#include "base/test/scoped_task_environment.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

void QuitWhenIdleTask(RunLoop* run_loop, int* counter) {
  run_loop->QuitWhenIdle();
  ++(*counter);
}

void ShouldRunTask(int* counter) {
  ++(*counter);
}

void ShouldNotRunTask() {
  ADD_FAILURE() << "Ran a task that shouldn't run.";
}

void RunNestedLoopTask(int* counter) {
  RunLoop nested_run_loop;

  // This task should quit |nested_run_loop| but not the main RunLoop.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&QuitWhenIdleTask, Unretained(&nested_run_loop),
                          Unretained(counter)));

  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, BindOnce(&ShouldNotRunTask), TimeDelta::FromDays(1));

  MessageLoop::ScopedNestableTaskAllower allower(MessageLoop::current());
  nested_run_loop.Run();

  ++(*counter);
}

class RunLoopTest : public testing::Test {
 protected:
  RunLoopTest() = default;

  test::ScopedTaskEnvironment task_environment_;
  RunLoop run_loop_;
  int counter_ = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(RunLoopTest);
};

}  // namespace

TEST_F(RunLoopTest, QuitWhenIdle) {
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&QuitWhenIdleTask, Unretained(&run_loop_),
                          Unretained(&counter_)));
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&ShouldRunTask, Unretained(&counter_)));
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, BindOnce(&ShouldNotRunTask), TimeDelta::FromDays(1));

  run_loop_.Run();
  EXPECT_EQ(2, counter_);
}

TEST_F(RunLoopTest, QuitWhenIdleNestedLoop) {
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&RunNestedLoopTask, Unretained(&counter_)));
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&QuitWhenIdleTask, Unretained(&run_loop_),
                          Unretained(&counter_)));
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&ShouldRunTask, Unretained(&counter_)));
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, BindOnce(&ShouldNotRunTask), TimeDelta::FromDays(1));

  run_loop_.Run();
  EXPECT_EQ(4, counter_);
}

TEST_F(RunLoopTest, QuitWhenIdleClosure) {
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                          run_loop_.QuitWhenIdleClosure());
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&ShouldRunTask, Unretained(&counter_)));
  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, BindOnce(&ShouldNotRunTask), TimeDelta::FromDays(1));

  run_loop_.Run();
  EXPECT_EQ(1, counter_);
}

// Verify that the QuitWhenIdleClosure() can run after the RunLoop has been
// deleted. It should have no effect.
TEST_F(RunLoopTest, QuitWhenIdleClosureAfterRunLoopScope) {
  Closure quit_when_idle_closure;
  {
    RunLoop run_loop;
    quit_when_idle_closure = run_loop.QuitWhenIdleClosure();
    run_loop.RunUntilIdle();
  }
  quit_when_idle_closure.Run();
}

// Verify that Quit can be executed from another sequence.
TEST_F(RunLoopTest, QuitFromOtherSequence) {
  scoped_refptr<SequencedTaskRunner> other_sequence =
      CreateSequencedTaskRunnerWithTraits({});

  // Always expected to run before asynchronous Quit() kicks in.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  WaitableEvent loop_was_quit(WaitableEvent::ResetPolicy::MANUAL,
                              WaitableEvent::InitialState::NOT_SIGNALED);
  other_sequence->PostTask(
      FROM_HERE, base::BindOnce([](RunLoop* run_loop) { run_loop->Quit(); },
                                Unretained(&run_loop_)));
  other_sequence->PostTask(
      FROM_HERE,
      base::BindOnce(&WaitableEvent::Signal, base::Unretained(&loop_was_quit)));

  // Anything that's posted after the Quit closure was posted back to this
  // sequence shouldn't get a chance to run.
  loop_was_quit.Wait();
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that QuitClosure can be executed from another sequence.
TEST_F(RunLoopTest, QuitFromOtherSequenceWithClosure) {
  scoped_refptr<SequencedTaskRunner> other_sequence =
      CreateSequencedTaskRunnerWithTraits({});

  // Always expected to run before asynchronous Quit() kicks in.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  WaitableEvent loop_was_quit(WaitableEvent::ResetPolicy::MANUAL,
                              WaitableEvent::InitialState::NOT_SIGNALED);
  other_sequence->PostTask(FROM_HERE, run_loop_.QuitClosure());
  other_sequence->PostTask(
      FROM_HERE,
      base::BindOnce(&WaitableEvent::Signal, base::Unretained(&loop_was_quit)));

  // Anything that's posted after the Quit closure was posted back to this
  // sequence shouldn't get a chance to run.
  loop_was_quit.Wait();
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that Quit can be executed from another sequence even when the
// Quit is racing with Run() -- i.e. forgo the WaitableEvent used above.
TEST_F(RunLoopTest, QuitFromOtherSequenceRacy) {
  scoped_refptr<SequencedTaskRunner> other_sequence =
      CreateSequencedTaskRunnerWithTraits({});

  // Always expected to run before asynchronous Quit() kicks in.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  other_sequence->PostTask(
      FROM_HERE, base::BindOnce([](RunLoop* run_loop) { run_loop->Quit(); },
                                Unretained(&run_loop_)));

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that QuitClosure can be executed from another sequence even when the
// Quit is racing with Run() -- i.e. forgo the WaitableEvent used above.
TEST_F(RunLoopTest, QuitFromOtherSequenceRacyWithClosure) {
  scoped_refptr<SequencedTaskRunner> other_sequence =
      CreateSequencedTaskRunnerWithTraits({});

  // Always expected to run before asynchronous Quit() kicks in.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  other_sequence->PostTask(FROM_HERE, run_loop_.QuitClosure());

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that QuitWhenIdle can be executed from another sequence.
TEST_F(RunLoopTest, QuitWhenIdleFromOtherSequence) {
  scoped_refptr<SequencedTaskRunner> other_sequence =
      CreateSequencedTaskRunnerWithTraits({});

  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  other_sequence->PostTask(
      FROM_HERE,
      base::BindOnce([](RunLoop* run_loop) { run_loop->QuitWhenIdle(); },
                     Unretained(&run_loop_)));

  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  run_loop_.Run();

  // Regardless of the outcome of the race this thread shouldn't have been idle
  // until the counter was ticked twice.
  EXPECT_EQ(2, counter_);
}

// Verify that QuitWhenIdleClosure can be executed from another sequence.
TEST_F(RunLoopTest, QuitWhenIdleFromOtherSequenceWithClosure) {
  scoped_refptr<SequencedTaskRunner> other_sequence =
      CreateSequencedTaskRunnerWithTraits({});

  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  other_sequence->PostTask(FROM_HERE, run_loop_.QuitWhenIdleClosure());

  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  run_loop_.Run();

  // Regardless of the outcome of the race this thread shouldn't have been idle
  // until the counter was ticked twice.
  EXPECT_EQ(2, counter_);
}

TEST_F(RunLoopTest, IsRunningOnCurrentThread) {
  EXPECT_FALSE(RunLoop::IsRunningOnCurrentThread());
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      Bind([]() { EXPECT_TRUE(RunLoop::IsRunningOnCurrentThread()); }));
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, run_loop_.QuitClosure());
  run_loop_.Run();
}

TEST_F(RunLoopTest, IsNestedOnCurrentThread) {
  EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());

  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, Bind([]() {
        EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());

        RunLoop nested_run_loop;

        ThreadTaskRunnerHandle::Get()->PostTask(
            FROM_HERE,
            Bind([]() { EXPECT_TRUE(RunLoop::IsNestedOnCurrentThread()); }));
        ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                                nested_run_loop.QuitClosure());

        EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());
        MessageLoop::ScopedNestableTaskAllower allower(MessageLoop::current());
        nested_run_loop.Run();
        EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());
      }));

  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, run_loop_.QuitClosure());
  run_loop_.Run();
}

class MockNestingObserver : public RunLoop::NestingObserver {
 public:
  MockNestingObserver() = default;

  // RunLoop::NestingObserver:
  MOCK_METHOD0(OnBeginNestedRunLoop, void());

 private:
  DISALLOW_COPY_AND_ASSIGN(MockNestingObserver);
};

TEST_F(RunLoopTest, NestingObservers) {
  EXPECT_TRUE(RunLoop::IsNestingAllowedOnCurrentThread());

  testing::StrictMock<MockNestingObserver> nesting_observer;

  RunLoop::AddNestingObserverOnCurrentThread(&nesting_observer);

  const RepeatingClosure run_nested_loop = Bind([]() {
    RunLoop nested_run_loop;
    ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, Bind([]() {
          EXPECT_TRUE(RunLoop::IsNestingAllowedOnCurrentThread());
        }));
    ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                            nested_run_loop.QuitClosure());
    MessageLoop::ScopedNestableTaskAllower allower(MessageLoop::current());
    nested_run_loop.Run();
  });

  // Generate a stack of nested RunLoops, an OnBeginNestedRunLoop() is
  // expected when beginning each nesting depth.
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, run_nested_loop);
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, run_nested_loop);
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, run_loop_.QuitClosure());

  EXPECT_CALL(nesting_observer, OnBeginNestedRunLoop()).Times(2);
  run_loop_.Run();

  RunLoop::RemoveNestingObserverOnCurrentThread(&nesting_observer);
}

// Disabled on Android per http://crbug.com/643760.
#if defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)
TEST_F(RunLoopTest, DisallowWaitingDeathTest) {
  EXPECT_TRUE(RunLoop::IsNestingAllowedOnCurrentThread());
  RunLoop::DisallowNestingOnCurrentThread();
  EXPECT_FALSE(RunLoop::IsNestingAllowedOnCurrentThread());

  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, Bind([]() {
                                            RunLoop nested_run_loop;
                                            nested_run_loop.RunUntilIdle();
                                          }));
  EXPECT_DEATH({ run_loop_.RunUntilIdle(); }, "");
}
#endif  // defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

}  // namespace base
