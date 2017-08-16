// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/run_loop.h"

#include <queue>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/gtest_util.h"
#include "base/test/scoped_task_environment.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread.h"
#include "base/threading/thread_checker_impl.h"
#include "base/threading/thread_task_runner_handle.h"
#include "build/build_config.h"
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
  RunLoop nested_run_loop(RunLoop::Type::kNestableTasksAllowed);

  // This task should quit |nested_run_loop| but not the main RunLoop.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(&QuitWhenIdleTask, Unretained(&nested_run_loop),
                          Unretained(counter)));

  ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, BindOnce(&ShouldNotRunTask), TimeDelta::FromDays(1));

  nested_run_loop.Run();

  ++(*counter);
}

// A simple SingleThreadTaskRunner that just queues undelayed tasks (and ignores
// delayed tasks). Tasks can then be processed one by one by ProcessTask() which
// will return true if it processed a task and false otherwise.
class SimpleSingleThreadTaskRunner : public SingleThreadTaskRunner {
 public:
  SimpleSingleThreadTaskRunner() = default;

  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure task,
                       base::TimeDelta delay) override {
    if (delay > base::TimeDelta())
      return false;
    AutoLock auto_lock(tasks_lock_);
    pending_tasks_.push(std::move(task));
    return true;
  }

  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  OnceClosure task,
                                  base::TimeDelta delay) override {
    return PostDelayedTask(from_here, std::move(task), delay);
  }

  bool RunsTasksInCurrentSequence() const override {
    return origin_thread_checker_.CalledOnValidThread();
  }

  bool ProcessTask() {
    OnceClosure task;
    {
      AutoLock auto_lock(tasks_lock_);
      if (pending_tasks_.empty())
        return false;
      task = std::move(pending_tasks_.front());
      pending_tasks_.pop();
    }
    // It's important to Run() after pop() and outside the lock as |task| may
    // run a nested loop which will re-enter ProcessTask().
    std::move(task).Run();
    return true;
  }

 private:
  ~SimpleSingleThreadTaskRunner() override = default;

  Lock tasks_lock_;
  std::queue<OnceClosure> pending_tasks_;

  // RunLoop relies on RunsTasksInCurrentSequence() signal. Use a
  // ThreadCheckerImpl to be able to reliably provide that signal even in
  // non-dcheck builds.
  ThreadCheckerImpl origin_thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(SimpleSingleThreadTaskRunner);
};

// A simple test RunLoop::Delegate to exercise Runloop logic independent of any
// other base constructs.
class TestDelegate : public RunLoop::Delegate {
 public:
  TestDelegate() = default;

  void BindToCurrentThread() {
    thread_task_runner_handle_ =
        MakeUnique<ThreadTaskRunnerHandle>(simple_task_runner_);
    run_loop_client_ = RunLoop::RegisterDelegateForCurrentThread(this);
  }

  // Runs |closure| on the TestDelegate thread as part of Run(). Useful to
  // inject code in an otherwise livelocked Run() state.
  void RunClosureOnDelegate(OnceClosure closure) {
    AutoLock auto_lock(closure_lock_);
    closure_ = std::move(closure);
  }

 private:
  void Run() override {
    if (nested_run_allowing_tasks_incoming_) {
      EXPECT_TRUE(run_loop_client_->IsNested());
      EXPECT_TRUE(run_loop_client_->ProcessingTasksAllowed());
    } else if (run_loop_client_->IsNested()) {
      EXPECT_FALSE(run_loop_client_->ProcessingTasksAllowed());
    }
    nested_run_allowing_tasks_incoming_ = false;

    while (!should_quit_) {
      if (run_loop_client_->ProcessingTasksAllowed() &&
          simple_task_runner_->ProcessTask()) {
        continue;
      }

      if (run_loop_client_->ShouldQuitWhenIdle())
        break;

      {
        AutoLock auto_lock(closure_lock_);
        if (!closure_.is_null()) {
          std::move(closure_).Run();
          continue;
        }
      }

      PlatformThread::YieldCurrentThread();
    }
    should_quit_ = false;
  }

  void Quit() override { should_quit_ = true; }

  void EnsureWorkScheduled() override {
    nested_run_allowing_tasks_incoming_ = true;
  }

  // True if the next invocation of Run() is expected to be from a
  // kNestableTasksAllowed RunLoop.
  bool nested_run_allowing_tasks_incoming_ = false;

  scoped_refptr<SimpleSingleThreadTaskRunner> simple_task_runner_ =
      MakeRefCounted<SimpleSingleThreadTaskRunner>();
  std::unique_ptr<ThreadTaskRunnerHandle> thread_task_runner_handle_;

  bool should_quit_ = false;

  Lock closure_lock_;
  OnceClosure closure_;

  RunLoop::Delegate::Client* run_loop_client_ = nullptr;
};

enum class RunLoopTestType {
  // Runs all RunLoopTests under a ScopedTaskEnvironment to make sure real world
  // scenarios work.
  kRealEnvironment,

  // Runs all RunLoopTests under a test RunLoop::Delegate to make sure the
  // delegate interface fully works standalone.
  kTestDelegate,
};

// The task environment for the RunLoopTest of a given type. A separate class
// so it can be instantiated on the stack in the RunLoopTest fixture.
class RunLoopTestEnvironment {
 public:
  RunLoopTestEnvironment(RunLoopTestType type) {
    switch (type) {
      case RunLoopTestType::kRealEnvironment:
        task_environment_ = base::MakeUnique<test::ScopedTaskEnvironment>();
        break;
      case RunLoopTestType::kTestDelegate:
        test_delegate_ = base::MakeUnique<TestDelegate>();
        test_delegate_->BindToCurrentThread();
        break;
    }
  }

 private:
  // Instantiates one or the other based on the RunLoopTestType.
  std::unique_ptr<test::ScopedTaskEnvironment> task_environment_;
  std::unique_ptr<TestDelegate> test_delegate_;
};

class RunLoopTest : public testing::TestWithParam<RunLoopTestType> {
 protected:
  RunLoopTest() : test_environment_(GetParam()) {}

  RunLoopTestEnvironment test_environment_;
  RunLoop run_loop_;
  int counter_ = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(RunLoopTest);
};

}  // namespace

TEST_P(RunLoopTest, QuitWhenIdle) {
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

TEST_P(RunLoopTest, QuitWhenIdleNestedLoop) {
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

TEST_P(RunLoopTest, QuitWhenIdleClosure) {
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
TEST_P(RunLoopTest, QuitWhenIdleClosureAfterRunLoopScope) {
  Closure quit_when_idle_closure;
  {
    RunLoop run_loop;
    quit_when_idle_closure = run_loop.QuitWhenIdleClosure();
    run_loop.RunUntilIdle();
  }
  quit_when_idle_closure.Run();
}

// Verify that Quit can be executed from another sequence.
TEST_P(RunLoopTest, QuitFromOtherSequence) {
  Thread other_thread("test");
  other_thread.Start();
  scoped_refptr<SequencedTaskRunner> other_sequence =
      other_thread.task_runner();

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
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                          base::BindOnce(&ShouldNotRunTask));

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that QuitClosure can be executed from another sequence.
TEST_P(RunLoopTest, QuitFromOtherSequenceWithClosure) {
  Thread other_thread("test");
  other_thread.Start();
  scoped_refptr<SequencedTaskRunner> other_sequence =
      other_thread.task_runner();

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
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                          base::BindOnce(&ShouldNotRunTask));

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that Quit can be executed from another sequence even when the
// Quit is racing with Run() -- i.e. forgo the WaitableEvent used above.
TEST_P(RunLoopTest, QuitFromOtherSequenceRacy) {
  Thread other_thread("test");
  other_thread.Start();
  scoped_refptr<SequencedTaskRunner> other_sequence =
      other_thread.task_runner();

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
TEST_P(RunLoopTest, QuitFromOtherSequenceRacyWithClosure) {
  Thread other_thread("test");
  other_thread.Start();
  scoped_refptr<SequencedTaskRunner> other_sequence =
      other_thread.task_runner();

  // Always expected to run before asynchronous Quit() kicks in.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&ShouldRunTask, Unretained(&counter_)));

  other_sequence->PostTask(FROM_HERE, run_loop_.QuitClosure());

  run_loop_.Run();

  EXPECT_EQ(1, counter_);
}

// Verify that QuitWhenIdle can be executed from another sequence.
TEST_P(RunLoopTest, QuitWhenIdleFromOtherSequence) {
  Thread other_thread("test");
  other_thread.Start();
  scoped_refptr<SequencedTaskRunner> other_sequence =
      other_thread.task_runner();

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
TEST_P(RunLoopTest, QuitWhenIdleFromOtherSequenceWithClosure) {
  Thread other_thread("test");
  other_thread.Start();
  scoped_refptr<SequencedTaskRunner> other_sequence =
      other_thread.task_runner();

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

TEST_P(RunLoopTest, IsRunningOnCurrentThread) {
  EXPECT_FALSE(RunLoop::IsRunningOnCurrentThread());
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      BindOnce([]() { EXPECT_TRUE(RunLoop::IsRunningOnCurrentThread()); }));
  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, run_loop_.QuitClosure());
  run_loop_.Run();
}

TEST_P(RunLoopTest, IsNestedOnCurrentThread) {
  EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());

  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce([]() {
        EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());

        RunLoop nested_run_loop(RunLoop::Type::kNestableTasksAllowed);

        ThreadTaskRunnerHandle::Get()->PostTask(
            FROM_HERE, BindOnce([]() {
              EXPECT_TRUE(RunLoop::IsNestedOnCurrentThread());
            }));
        ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                                nested_run_loop.QuitClosure());

        EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());
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

TEST_P(RunLoopTest, NestingObservers) {
  EXPECT_TRUE(RunLoop::IsNestingAllowedOnCurrentThread());

  testing::StrictMock<MockNestingObserver> nesting_observer;

  RunLoop::AddNestingObserverOnCurrentThread(&nesting_observer);

  const RepeatingClosure run_nested_loop = Bind([]() {
    RunLoop nested_run_loop(RunLoop::Type::kNestableTasksAllowed);
    ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, BindOnce([]() {
          EXPECT_TRUE(RunLoop::IsNestingAllowedOnCurrentThread());
        }));
    ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE,
                                            nested_run_loop.QuitClosure());
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
TEST_P(RunLoopTest, DisallowNestingDeathTest) {
  EXPECT_TRUE(RunLoop::IsNestingAllowedOnCurrentThread());
  RunLoop::DisallowNestingOnCurrentThread();
  EXPECT_FALSE(RunLoop::IsNestingAllowedOnCurrentThread());

  ThreadTaskRunnerHandle::Get()->PostTask(FROM_HERE, BindOnce([]() {
                                            RunLoop nested_run_loop;
                                            nested_run_loop.RunUntilIdle();
                                          }));
  EXPECT_DEATH({ run_loop_.RunUntilIdle(); }, "");
}
#endif  // defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

INSTANTIATE_TEST_CASE_P(Real,
                        RunLoopTest,
                        testing::Values(RunLoopTestType::kRealEnvironment));
INSTANTIATE_TEST_CASE_P(Mock,
                        RunLoopTest,
                        testing::Values(RunLoopTestType::kTestDelegate));

TEST(RunLoopDeathTest, MustRegisterBeforeInstantiating) {
  TestDelegate unbound_test_delegate_;
  // Exercise the DCHECK in RunLoop::RunLoop().
  EXPECT_DCHECK_DEATH({ RunLoop(); });
}

TEST(RunLoopDelegateTest, NestableTasksDontRunInDefaultNestedLoops) {
  TestDelegate test_delegate;
  test_delegate.BindToCurrentThread();

  base::Thread other_thread("test");
  other_thread.Start();

  RunLoop main_loop;
  // A nested run loop which isn't kNestableTasksAllowed.
  RunLoop nested_run_loop(RunLoop::Type::kDefault);

  bool nested_run_loop_ended = false;

  // The first task on the main loop will result in a nested run loop. Since
  // it's not kNestableTasksAllowed, no further task should be processed until
  // it's quit.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      BindOnce([](RunLoop* nested_run_loop) { nested_run_loop->Run(); },
               Unretained(&nested_run_loop)));

  // Post a task that will fail if it runs inside the nested run loop.
  ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, BindOnce(
                     [](const bool& nested_run_loop_ended,
                        OnceClosure continuation_callback) {
                       EXPECT_TRUE(nested_run_loop_ended);
                       EXPECT_FALSE(RunLoop::IsNestedOnCurrentThread());
                       std::move(continuation_callback).Run();
                     },
                     ConstRef(nested_run_loop_ended), main_loop.QuitClosure()));

  // Post a task flipping the boolean bit for extra verification right before
  // quitting |nested_run_loop|.
  other_thread.task_runner()->PostDelayedTask(
      FROM_HERE,
      BindOnce(
          [](bool* nested_run_loop_ended) {
            EXPECT_FALSE(*nested_run_loop_ended);
            *nested_run_loop_ended = true;
          },
          Unretained(&nested_run_loop_ended)),
      TestTimeouts::tiny_timeout());
  // Post an async delayed task to exit the run loop when idle. This confirms
  // that (1) the test task only ran in the main loop after the nested loop
  // exited and (2) the nested run loop actually considers itself idle while
  // spinning. Note: The quit closure needs to be injected directly on the
  // delegate as invoking QuitWhenIdle() off-thread results in a thread bounce
  // which will not processed because of the very logic under test (nestable
  // tasks don't run in |nested_run_loop|).
  other_thread.task_runner()->PostDelayedTask(
      FROM_HERE,
      BindOnce(
          [](TestDelegate* test_delegate, OnceClosure injected_closure) {
            test_delegate->RunClosureOnDelegate(std::move(injected_closure));
          },
          Unretained(&test_delegate), nested_run_loop.QuitWhenIdleClosure()),
      TestTimeouts::tiny_timeout());

  main_loop.Run();
}

}  // namespace base
