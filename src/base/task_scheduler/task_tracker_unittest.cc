// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_tracker.h"

#include <stdint.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/sequence_token.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/atomic_flag.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_traits.h"
#include "base/test/gtest_util.h"
#include "base/test/test_simple_task_runner.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

namespace {

constexpr size_t kLoadTestNumIterations = 100;

// Invokes a closure asynchronously.
class CallbackThread : public SimpleThread {
 public:
  explicit CallbackThread(const Closure& closure)
      : SimpleThread("CallbackThread"), closure_(closure) {}

  // Returns true once the callback returns.
  bool has_returned() { return has_returned_.IsSet(); }

 private:
  void Run() override {
    closure_.Run();
    has_returned_.Set();
  }

  const Closure closure_;
  AtomicFlag has_returned_;

  DISALLOW_COPY_AND_ASSIGN(CallbackThread);
};

class ThreadPostingAndRunningTask : public SimpleThread {
 public:
  enum class Action {
    WILL_POST,
    RUN,
    WILL_POST_AND_RUN,
  };

  ThreadPostingAndRunningTask(TaskTracker* tracker,
                              Task* task,
                              Action action,
                              bool expect_post_succeeds)
      : SimpleThread("ThreadPostingAndRunningTask"),
        tracker_(tracker),
        task_(task),
        action_(action),
        expect_post_succeeds_(expect_post_succeeds) {
    EXPECT_TRUE(task_);

    // Ownership of the Task is required to run it.
    EXPECT_NE(Action::RUN, action_);
    EXPECT_NE(Action::WILL_POST_AND_RUN, action_);
  }

  ThreadPostingAndRunningTask(TaskTracker* tracker,
                              std::unique_ptr<Task> task,
                              Action action,
                              bool expect_post_succeeds)
      : SimpleThread("ThreadPostingAndRunningTask"),
        tracker_(tracker),
        task_(task.get()),
        owned_task_(std::move(task)),
        action_(action),
        expect_post_succeeds_(expect_post_succeeds) {
    EXPECT_TRUE(task_);
  }

 private:
  void Run() override {
    bool post_succeeded = true;
    if (action_ == Action::WILL_POST || action_ == Action::WILL_POST_AND_RUN) {
      post_succeeded = tracker_->WillPostTask(task_);
      EXPECT_EQ(expect_post_succeeds_, post_succeeded);
    }
    if (post_succeeded &&
        (action_ == Action::RUN || action_ == Action::WILL_POST_AND_RUN)) {
      EXPECT_TRUE(owned_task_);
      tracker_->RunTask(std::move(owned_task_), SequenceToken::Create());
    }
  }

  TaskTracker* const tracker_;
  Task* const task_;
  std::unique_ptr<Task> owned_task_;
  const Action action_;
  const bool expect_post_succeeds_;

  DISALLOW_COPY_AND_ASSIGN(ThreadPostingAndRunningTask);
};

class ScopedSetSingletonAllowed {
 public:
  ScopedSetSingletonAllowed(bool singleton_allowed)
      : previous_value_(
            ThreadRestrictions::SetSingletonAllowed(singleton_allowed)) {}
  ~ScopedSetSingletonAllowed() {
    ThreadRestrictions::SetSingletonAllowed(previous_value_);
  }

 private:
  const bool previous_value_;
};

class TaskSchedulerTaskTrackerTest
    : public testing::TestWithParam<TaskShutdownBehavior> {
 protected:
  TaskSchedulerTaskTrackerTest() = default;

  // Creates a task with |shutdown_behavior|.
  std::unique_ptr<Task> CreateTask(TaskShutdownBehavior shutdown_behavior) {
    return MakeUnique<Task>(
        FROM_HERE,
        Bind(&TaskSchedulerTaskTrackerTest::RunTaskCallback, Unretained(this)),
        TaskTraits().WithShutdownBehavior(shutdown_behavior), TimeDelta());
  }

  // Calls tracker_->Shutdown() on a new thread. When this returns, Shutdown()
  // method has been entered on the new thread, but it hasn't necessarily
  // returned.
  void CallShutdownAsync() {
    ASSERT_FALSE(thread_calling_shutdown_);
    thread_calling_shutdown_.reset(new CallbackThread(
        Bind(&TaskTracker::Shutdown, Unretained(&tracker_))));
    thread_calling_shutdown_->Start();
    while (!tracker_.HasShutdownStarted())
      PlatformThread::YieldCurrentThread();
  }

  void WaitForAsyncIsShutdownComplete() {
    ASSERT_TRUE(thread_calling_shutdown_);
    thread_calling_shutdown_->Join();
    EXPECT_TRUE(thread_calling_shutdown_->has_returned());
    EXPECT_TRUE(tracker_.IsShutdownComplete());
  }

  void VerifyAsyncShutdownInProgress() {
    ASSERT_TRUE(thread_calling_shutdown_);
    EXPECT_FALSE(thread_calling_shutdown_->has_returned());
    EXPECT_TRUE(tracker_.HasShutdownStarted());
    EXPECT_FALSE(tracker_.IsShutdownComplete());
  }

  // Calls tracker_->Flush() on a new thread.
  void CallFlushAsync() {
    ASSERT_FALSE(thread_calling_flush_);
    thread_calling_flush_.reset(
        new CallbackThread(Bind(&TaskTracker::Flush, Unretained(&tracker_))));
    thread_calling_flush_->Start();
  }

  void WaitForAsyncFlushReturned() {
    ASSERT_TRUE(thread_calling_flush_);
    thread_calling_flush_->Join();
    EXPECT_TRUE(thread_calling_flush_->has_returned());
  }

  void VerifyAsyncFlushInProgress() {
    ASSERT_TRUE(thread_calling_flush_);
    EXPECT_FALSE(thread_calling_flush_->has_returned());
  }

  size_t NumTasksExecuted() {
    AutoSchedulerLock auto_lock(lock_);
    return num_tasks_executed_;
  }

  TaskTracker tracker_;

 private:
  void RunTaskCallback() {
    AutoSchedulerLock auto_lock(lock_);
    ++num_tasks_executed_;
  }

  std::unique_ptr<CallbackThread> thread_calling_shutdown_;
  std::unique_ptr<CallbackThread> thread_calling_flush_;

  // Synchronizes accesses to |num_tasks_executed_|.
  SchedulerLock lock_;

  size_t num_tasks_executed_ = 0;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerTaskTrackerTest);
};

#define WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED() \
  do {                                      \
    SCOPED_TRACE("");                       \
    WaitForAsyncIsShutdownComplete();       \
  } while (false)

#define VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS() \
  do {                                      \
    SCOPED_TRACE("");                       \
    VerifyAsyncShutdownInProgress();        \
  } while (false)

#define WAIT_FOR_ASYNC_FLUSH_RETURNED() \
  do {                                  \
    SCOPED_TRACE("");                   \
    WaitForAsyncFlushReturned();        \
  } while (false)

#define VERIFY_ASYNC_FLUSH_IN_PROGRESS() \
  do {                                   \
    SCOPED_TRACE("");                    \
    VerifyAsyncFlushInProgress();        \
  } while (false)

}  // namespace

TEST_P(TaskSchedulerTaskTrackerTest, WillPostAndRunBeforeShutdown) {
  std::unique_ptr<Task> task(CreateTask(GetParam()));

  // Inform |task_tracker_| that |task| will be posted.
  EXPECT_TRUE(tracker_.WillPostTask(task.get()));

  // Run the task.
  EXPECT_EQ(0U, NumTasksExecuted());
  EXPECT_TRUE(tracker_.RunTask(std::move(task), SequenceToken::Create()));
  EXPECT_EQ(1U, NumTasksExecuted());

  // Shutdown() shouldn't block.
  tracker_.Shutdown();
}

TEST_P(TaskSchedulerTaskTrackerTest, WillPostAndRunLongTaskBeforeShutdown) {
  // Create a task that will block until |event| is signaled.
  WaitableEvent event(WaitableEvent::ResetPolicy::AUTOMATIC,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  auto blocked_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&WaitableEvent::Wait, Unretained(&event)),
      TaskTraits().WithWait().WithShutdownBehavior(GetParam()), TimeDelta());

  // Inform |task_tracker_| that |blocked_task| will be posted.
  EXPECT_TRUE(tracker_.WillPostTask(blocked_task.get()));

  // Run the task asynchronouly.
  ThreadPostingAndRunningTask thread_running_task(
      &tracker_, std::move(blocked_task),
      ThreadPostingAndRunningTask::Action::RUN, false);
  thread_running_task.Start();

  // Initiate shutdown while the task is running.
  CallShutdownAsync();

  if (GetParam() == TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN) {
    // Shutdown should complete even with a CONTINUE_ON_SHUTDOWN in progress.
    WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();
  } else {
    // Shutdown should block with any non CONTINUE_ON_SHUTDOWN task in progress.
    VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();
  }

  // Unblock the task.
  event.Signal();
  thread_running_task.Join();

  // Shutdown should now complete for a non CONTINUE_ON_SHUTDOWN task.
  if (GetParam() != TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN)
    WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();
}

TEST_P(TaskSchedulerTaskTrackerTest, WillPostBeforeShutdownRunDuringShutdown) {
  // Inform |task_tracker_| that a task will be posted.
  std::unique_ptr<Task> task(CreateTask(GetParam()));
  EXPECT_TRUE(tracker_.WillPostTask(task.get()));

  // Inform |task_tracker_| that a BLOCK_SHUTDOWN task will be posted just to
  // block shutdown.
  std::unique_ptr<Task> block_shutdown_task(
      CreateTask(TaskShutdownBehavior::BLOCK_SHUTDOWN));
  EXPECT_TRUE(tracker_.WillPostTask(block_shutdown_task.get()));

  // Call Shutdown() asynchronously.
  CallShutdownAsync();
  VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();

  // Try to run |task|. It should only run it it's BLOCK_SHUTDOWN. Otherwise it
  // should be discarded.
  EXPECT_EQ(0U, NumTasksExecuted());
  const bool should_run = GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN;
  EXPECT_EQ(should_run,
            tracker_.RunTask(std::move(task), SequenceToken::Create()));
  EXPECT_EQ(should_run ? 1U : 0U, NumTasksExecuted());
  VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();

  // Unblock shutdown by running the remaining BLOCK_SHUTDOWN task.
  EXPECT_TRUE(tracker_.RunTask(std::move(block_shutdown_task),
                               SequenceToken::Create()));
  EXPECT_EQ(should_run ? 2U : 1U, NumTasksExecuted());
  WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();
}

TEST_P(TaskSchedulerTaskTrackerTest, WillPostBeforeShutdownRunAfterShutdown) {
  // Inform |task_tracker_| that a task will be posted.
  std::unique_ptr<Task> task(CreateTask(GetParam()));
  EXPECT_TRUE(tracker_.WillPostTask(task.get()));

  // Call Shutdown() asynchronously.
  CallShutdownAsync();
  EXPECT_EQ(0U, NumTasksExecuted());

  if (GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN) {
    VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();

    // Run the task to unblock shutdown.
    EXPECT_TRUE(tracker_.RunTask(std::move(task), SequenceToken::Create()));
    EXPECT_EQ(1U, NumTasksExecuted());
    WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();

    // It is not possible to test running a BLOCK_SHUTDOWN task posted before
    // shutdown after shutdown because Shutdown() won't return if there are
    // pending BLOCK_SHUTDOWN tasks.
  } else {
    WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();

    // The task shouldn't be allowed to run after shutdown.
    EXPECT_FALSE(tracker_.RunTask(std::move(task), SequenceToken::Create()));
    EXPECT_EQ(0U, NumTasksExecuted());
  }
}

TEST_P(TaskSchedulerTaskTrackerTest, WillPostAndRunDuringShutdown) {
  // Inform |task_tracker_| that a BLOCK_SHUTDOWN task will be posted just to
  // block shutdown.
  std::unique_ptr<Task> block_shutdown_task(
      CreateTask(TaskShutdownBehavior::BLOCK_SHUTDOWN));
  EXPECT_TRUE(tracker_.WillPostTask(block_shutdown_task.get()));

  // Call Shutdown() asynchronously.
  CallShutdownAsync();
  VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();

  if (GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN) {
    // Inform |task_tracker_| that a BLOCK_SHUTDOWN task will be posted.
    std::unique_ptr<Task> task(CreateTask(GetParam()));
    EXPECT_TRUE(tracker_.WillPostTask(task.get()));

    // Run the BLOCK_SHUTDOWN task.
    EXPECT_EQ(0U, NumTasksExecuted());
    EXPECT_TRUE(tracker_.RunTask(std::move(task), SequenceToken::Create()));
    EXPECT_EQ(1U, NumTasksExecuted());
  } else {
    // It shouldn't be allowed to post a non BLOCK_SHUTDOWN task.
    std::unique_ptr<Task> task(CreateTask(GetParam()));
    EXPECT_FALSE(tracker_.WillPostTask(task.get()));

    // Don't try to run the task, because it wasn't allowed to be posted.
  }

  // Unblock shutdown by running |block_shutdown_task|.
  VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();
  EXPECT_TRUE(tracker_.RunTask(std::move(block_shutdown_task),
                               SequenceToken::Create()));
  EXPECT_EQ(GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN ? 2U : 1U,
            NumTasksExecuted());
  WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();
}

TEST_P(TaskSchedulerTaskTrackerTest, WillPostAfterShutdown) {
  tracker_.Shutdown();

  std::unique_ptr<Task> task(CreateTask(GetParam()));

  // |task_tracker_| shouldn't allow a task to be posted after shutdown.
  if (GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN) {
    EXPECT_DCHECK_DEATH({ tracker_.WillPostTask(task.get()); });
  } else {
    EXPECT_FALSE(tracker_.WillPostTask(task.get()));
  }
}

// Verify that BLOCK_SHUTDOWN and SKIP_ON_SHUTDOWN tasks can
// AssertSingletonAllowed() but CONTINUE_ON_SHUTDOWN tasks can't.
TEST_P(TaskSchedulerTaskTrackerTest, SingletonAllowed) {
  const bool can_use_singletons =
      (GetParam() != TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN);

  TaskTracker tracker;
  std::unique_ptr<Task> task(
      new Task(FROM_HERE, Bind(&ThreadRestrictions::AssertSingletonAllowed),
               TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta()));
  EXPECT_TRUE(tracker.WillPostTask(task.get()));

  // Set the singleton allowed bit to the opposite of what it is expected to be
  // when |tracker| runs |task| to verify that |tracker| actually sets the
  // correct value.
  ScopedSetSingletonAllowed scoped_singleton_allowed(!can_use_singletons);

  // Running the task should fail iff the task isn't allowed to use singletons.
  if (can_use_singletons) {
    EXPECT_TRUE(tracker.RunTask(std::move(task), SequenceToken::Create()));
  } else {
    EXPECT_DCHECK_DEATH(
        { tracker.RunTask(std::move(task), SequenceToken::Create()); });
  }
}

static void RunTaskRunnerHandleVerificationTask(
    TaskTracker* tracker,
    std::unique_ptr<Task> verify_task) {
  // Pretend |verify_task| is posted to respect TaskTracker's contract.
  EXPECT_TRUE(tracker->WillPostTask(verify_task.get()));

  // Confirm that the test conditions are right (no TaskRunnerHandles set
  // already).
  EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
  EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());

  EXPECT_TRUE(
      tracker->RunTask(std::move(verify_task), SequenceToken::Create()));

  // TaskRunnerHandle state is reset outside of task's scope.
  EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
  EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
}

static void VerifyNoTaskRunnerHandle() {
  EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
  EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
}

TEST_P(TaskSchedulerTaskTrackerTest, TaskRunnerHandleIsNotSetOnParallel) {
  // Create a task that will verify that TaskRunnerHandles are not set in its
  // scope per no TaskRunner ref being set to it.
  std::unique_ptr<Task> verify_task(
      new Task(FROM_HERE, Bind(&VerifyNoTaskRunnerHandle),
               TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta()));

  RunTaskRunnerHandleVerificationTask(&tracker_, std::move(verify_task));
}

static void VerifySequencedTaskRunnerHandle(
    const SequencedTaskRunner* expected_task_runner) {
  EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
  EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
  EXPECT_EQ(expected_task_runner, SequencedTaskRunnerHandle::Get());
}

TEST_P(TaskSchedulerTaskTrackerTest,
       SequencedTaskRunnerHandleIsSetOnSequenced) {
  scoped_refptr<SequencedTaskRunner> test_task_runner(new TestSimpleTaskRunner);

  // Create a task that will verify that SequencedTaskRunnerHandle is properly
  // set to |test_task_runner| in its scope per |sequenced_task_runner_ref|
  // being set to it.
  std::unique_ptr<Task> verify_task(
      new Task(FROM_HERE, Bind(&VerifySequencedTaskRunnerHandle,
                               base::Unretained(test_task_runner.get())),
               TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta()));
  verify_task->sequenced_task_runner_ref = test_task_runner;

  RunTaskRunnerHandleVerificationTask(&tracker_, std::move(verify_task));
}

static void VerifyThreadTaskRunnerHandle(
    const SingleThreadTaskRunner* expected_task_runner) {
  EXPECT_TRUE(ThreadTaskRunnerHandle::IsSet());
  // SequencedTaskRunnerHandle inherits ThreadTaskRunnerHandle for thread.
  EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
  EXPECT_EQ(expected_task_runner, ThreadTaskRunnerHandle::Get());
}

TEST_P(TaskSchedulerTaskTrackerTest,
       ThreadTaskRunnerHandleIsSetOnSingleThreaded) {
  scoped_refptr<SingleThreadTaskRunner> test_task_runner(
      new TestSimpleTaskRunner);

  // Create a task that will verify that ThreadTaskRunnerHandle is properly set
  // to |test_task_runner| in its scope per |single_thread_task_runner_ref|
  // being set on it.
  std::unique_ptr<Task> verify_task(
      new Task(FROM_HERE, Bind(&VerifyThreadTaskRunnerHandle,
                               base::Unretained(test_task_runner.get())),
               TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta()));
  verify_task->single_thread_task_runner_ref = test_task_runner;

  RunTaskRunnerHandleVerificationTask(&tracker_, std::move(verify_task));
}

TEST_P(TaskSchedulerTaskTrackerTest, FlushPendingDelayedTask) {
  const Task delayed_task(FROM_HERE, Bind(&DoNothing),
                          TaskTraits().WithShutdownBehavior(GetParam()),
                          TimeDelta::FromDays(1));
  tracker_.WillPostTask(&delayed_task);
  // Flush() should return even if the delayed task didn't run.
  tracker_.Flush();
}

TEST_P(TaskSchedulerTaskTrackerTest, FlushPendingUndelayedTask) {
  auto undelayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta());
  tracker_.WillPostTask(undelayed_task.get());

  // Flush() shouldn't return before the undelayed task runs.
  CallFlushAsync();
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  VERIFY_ASYNC_FLUSH_IN_PROGRESS();

  // Flush() should return after the undelayed task runs.
  tracker_.RunTask(std::move(undelayed_task), SequenceToken::Create());
  WAIT_FOR_ASYNC_FLUSH_RETURNED();
}

TEST_P(TaskSchedulerTaskTrackerTest, PostTaskDuringFlush) {
  auto undelayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta());
  tracker_.WillPostTask(undelayed_task.get());

  // Flush() shouldn't return before the undelayed task runs.
  CallFlushAsync();
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  VERIFY_ASYNC_FLUSH_IN_PROGRESS();

  // Simulate posting another undelayed task.
  auto other_undelayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta());
  tracker_.WillPostTask(other_undelayed_task.get());

  // Run the first undelayed task.
  tracker_.RunTask(std::move(undelayed_task), SequenceToken::Create());

  // Flush() shouldn't return before the second undelayed task runs.
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  VERIFY_ASYNC_FLUSH_IN_PROGRESS();

  // Flush() should return after the second undelayed task runs.
  tracker_.RunTask(std::move(other_undelayed_task), SequenceToken::Create());
  WAIT_FOR_ASYNC_FLUSH_RETURNED();
}

TEST_P(TaskSchedulerTaskTrackerTest, RunDelayedTaskDuringFlush) {
  // Simulate posting a delayed and an undelayed task.
  auto delayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta::FromDays(1));
  tracker_.WillPostTask(delayed_task.get());
  auto undelayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta());
  tracker_.WillPostTask(undelayed_task.get());

  // Flush() shouldn't return before the undelayed task runs.
  CallFlushAsync();
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  VERIFY_ASYNC_FLUSH_IN_PROGRESS();

  // Run the delayed task.
  tracker_.RunTask(std::move(delayed_task), SequenceToken::Create());

  // Flush() shouldn't return since there is still a pending undelayed
  // task.
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  VERIFY_ASYNC_FLUSH_IN_PROGRESS();

  // Run the undelayed task.
  tracker_.RunTask(std::move(undelayed_task), SequenceToken::Create());

  // Flush() should now return.
  WAIT_FOR_ASYNC_FLUSH_RETURNED();
}

TEST_P(TaskSchedulerTaskTrackerTest, FlushAfterShutdown) {
  if (GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN)
    return;

  // Simulate posting a task.
  auto undelayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta());
  tracker_.WillPostTask(undelayed_task.get());

  // Shutdown() should return immediately since there are no pending
  // BLOCK_SHUTDOWN tasks.
  tracker_.Shutdown();

  // Flush() should return immediately after shutdown, even if an
  // undelayed task hasn't run.
  tracker_.Flush();
}

TEST_P(TaskSchedulerTaskTrackerTest, ShutdownDuringFlush) {
  if (GetParam() == TaskShutdownBehavior::BLOCK_SHUTDOWN)
    return;

  // Simulate posting a task.
  auto undelayed_task = base::MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing),
      TaskTraits().WithShutdownBehavior(GetParam()), TimeDelta());
  tracker_.WillPostTask(undelayed_task.get());

  // Flush() shouldn't return before the undelayed task runs or
  // shutdown completes.
  CallFlushAsync();
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  VERIFY_ASYNC_FLUSH_IN_PROGRESS();

  // Shutdown() should return immediately since there are no pending
  // BLOCK_SHUTDOWN tasks.
  tracker_.Shutdown();

  // Flush() should now return, even if an undelayed task hasn't run.
  WAIT_FOR_ASYNC_FLUSH_RETURNED();
}

INSTANTIATE_TEST_CASE_P(
    ContinueOnShutdown,
    TaskSchedulerTaskTrackerTest,
    ::testing::Values(TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN));
INSTANTIATE_TEST_CASE_P(
    SkipOnShutdown,
    TaskSchedulerTaskTrackerTest,
    ::testing::Values(TaskShutdownBehavior::SKIP_ON_SHUTDOWN));
INSTANTIATE_TEST_CASE_P(
    BlockShutdown,
    TaskSchedulerTaskTrackerTest,
    ::testing::Values(TaskShutdownBehavior::BLOCK_SHUTDOWN));

namespace {

void ExpectSequenceToken(SequenceToken sequence_token) {
  EXPECT_EQ(sequence_token, SequenceToken::GetForCurrentThread());
}

}  // namespace

// Verify that SequenceToken::GetForCurrentThread() returns the Sequence's token
// when a Task runs.
TEST_F(TaskSchedulerTaskTrackerTest, CurrentSequenceToken) {
  const SequenceToken sequence_token(SequenceToken::Create());
  auto task = base::MakeUnique<Task>(FROM_HERE,
                                     Bind(&ExpectSequenceToken, sequence_token),
                                     TaskTraits(), TimeDelta());
  tracker_.WillPostTask(task.get());

  EXPECT_FALSE(SequenceToken::GetForCurrentThread().IsValid());
  EXPECT_TRUE(tracker_.RunTask(std::move(task), sequence_token));
  EXPECT_FALSE(SequenceToken::GetForCurrentThread().IsValid());
}

TEST_F(TaskSchedulerTaskTrackerTest, LoadWillPostAndRunBeforeShutdown) {
  // Post and run tasks asynchronously.
  std::vector<std::unique_ptr<ThreadPostingAndRunningTask>> threads;

  for (size_t i = 0; i < kLoadTestNumIterations; ++i) {
    threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, CreateTask(TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN),
        ThreadPostingAndRunningTask::Action::WILL_POST_AND_RUN, true));
    threads.back()->Start();

    threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, CreateTask(TaskShutdownBehavior::SKIP_ON_SHUTDOWN),
        ThreadPostingAndRunningTask::Action::WILL_POST_AND_RUN, true));
    threads.back()->Start();

    threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, CreateTask(TaskShutdownBehavior::BLOCK_SHUTDOWN),
        ThreadPostingAndRunningTask::Action::WILL_POST_AND_RUN, true));
    threads.back()->Start();
  }

  for (const auto& thread : threads)
    thread->Join();

  // Expect all tasks to be executed.
  EXPECT_EQ(kLoadTestNumIterations * 3, NumTasksExecuted());

  // Should return immediately because no tasks are blocking shutdown.
  tracker_.Shutdown();
}

TEST_F(TaskSchedulerTaskTrackerTest,
       LoadWillPostBeforeShutdownAndRunDuringShutdown) {
  // Post tasks asynchronously.
  std::vector<std::unique_ptr<Task>> tasks;
  std::vector<std::unique_ptr<ThreadPostingAndRunningTask>> post_threads;

  for (size_t i = 0; i < kLoadTestNumIterations; ++i) {
    tasks.push_back(CreateTask(TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN));
    post_threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, tasks.back().get(),
        ThreadPostingAndRunningTask::Action::WILL_POST, true));
    post_threads.back()->Start();

    tasks.push_back(CreateTask(TaskShutdownBehavior::SKIP_ON_SHUTDOWN));
    post_threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, tasks.back().get(),
        ThreadPostingAndRunningTask::Action::WILL_POST, true));
    post_threads.back()->Start();

    tasks.push_back(CreateTask(TaskShutdownBehavior::BLOCK_SHUTDOWN));
    post_threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, tasks.back().get(),
        ThreadPostingAndRunningTask::Action::WILL_POST, true));
    post_threads.back()->Start();
  }

  for (const auto& thread : post_threads)
    thread->Join();

  // Call Shutdown() asynchronously.
  CallShutdownAsync();

  // Run tasks asynchronously.
  std::vector<std::unique_ptr<ThreadPostingAndRunningTask>> run_threads;

  for (auto& task : tasks) {
    run_threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, std::move(task), ThreadPostingAndRunningTask::Action::RUN,
        false));
    run_threads.back()->Start();
  }

  for (const auto& thread : run_threads)
    thread->Join();

  WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();

  // Expect BLOCK_SHUTDOWN tasks to have been executed.
  EXPECT_EQ(kLoadTestNumIterations, NumTasksExecuted());
}

TEST_F(TaskSchedulerTaskTrackerTest, LoadWillPostAndRunDuringShutdown) {
  // Inform |task_tracker_| that a BLOCK_SHUTDOWN task will be posted just to
  // block shutdown.
  std::unique_ptr<Task> block_shutdown_task(
      CreateTask(TaskShutdownBehavior::BLOCK_SHUTDOWN));
  EXPECT_TRUE(tracker_.WillPostTask(block_shutdown_task.get()));

  // Call Shutdown() asynchronously.
  CallShutdownAsync();

  // Post and run tasks asynchronously.
  std::vector<std::unique_ptr<ThreadPostingAndRunningTask>> threads;

  for (size_t i = 0; i < kLoadTestNumIterations; ++i) {
    threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, CreateTask(TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN),
        ThreadPostingAndRunningTask::Action::WILL_POST_AND_RUN, false));
    threads.back()->Start();

    threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, CreateTask(TaskShutdownBehavior::SKIP_ON_SHUTDOWN),
        ThreadPostingAndRunningTask::Action::WILL_POST_AND_RUN, false));
    threads.back()->Start();

    threads.push_back(MakeUnique<ThreadPostingAndRunningTask>(
        &tracker_, CreateTask(TaskShutdownBehavior::BLOCK_SHUTDOWN),
        ThreadPostingAndRunningTask::Action::WILL_POST_AND_RUN, true));
    threads.back()->Start();
  }

  for (const auto& thread : threads)
    thread->Join();

  // Expect BLOCK_SHUTDOWN tasks to have been executed.
  EXPECT_EQ(kLoadTestNumIterations, NumTasksExecuted());

  // Shutdown() shouldn't return before |block_shutdown_task| is executed.
  VERIFY_ASYNC_SHUTDOWN_IN_PROGRESS();

  // Unblock shutdown by running |block_shutdown_task|.
  EXPECT_TRUE(tracker_.RunTask(std::move(block_shutdown_task),
                               SequenceToken::Create()));
  EXPECT_EQ(kLoadTestNumIterations + 1, NumTasksExecuted());
  WAIT_FOR_ASYNC_SHUTDOWN_COMPLETED();
}

namespace {

class WaitAllowedTestThread : public SimpleThread {
 public:
  WaitAllowedTestThread() : SimpleThread("WaitAllowedTestThread") {}

 private:
  void Run() override {
    TaskTracker tracker;

    // Waiting is allowed by default. Expect TaskTracker to disallow it before
    // running a task without the WithWait() trait.
    ThreadRestrictions::AssertWaitAllowed();
    auto task_without_wait = MakeUnique<Task>(
        FROM_HERE, Bind([]() {
          EXPECT_DCHECK_DEATH({ ThreadRestrictions::AssertWaitAllowed(); });
        }),
        TaskTraits(), TimeDelta());
    EXPECT_TRUE(tracker.WillPostTask(task_without_wait.get()));
    tracker.RunTask(std::move(task_without_wait), SequenceToken::Create());

    // Disallow waiting. Expect TaskTracker to allow it before running a task
    // with the WithWait() trait.
    ThreadRestrictions::DisallowWaiting();
    auto task_with_wait =
        MakeUnique<Task>(FROM_HERE, Bind([]() {
                           // Shouldn't fail.
                           ThreadRestrictions::AssertWaitAllowed();
                         }),
                         TaskTraits().WithWait(), TimeDelta());
    EXPECT_TRUE(tracker.WillPostTask(task_with_wait.get()));
    tracker.RunTask(std::move(task_with_wait), SequenceToken::Create());
  }

  DISALLOW_COPY_AND_ASSIGN(WaitAllowedTestThread);
};

}  // namespace

// Verify that AssertIOAllowed() succeeds for a WithWait() task.
TEST(TaskSchedulerTaskTrackerWaitAllowedTest, WaitAllowed) {
  // Run the test on the separate thread since it is not possible to reset the
  // "wait allowed" bit of a thread without being a friend of
  // ThreadRestrictions.
  WaitAllowedTestThread wait_allowed_test_thread;
  wait_allowed_test_thread.Start();
  wait_allowed_test_thread.Join();
}

}  // namespace internal
}  // namespace base
