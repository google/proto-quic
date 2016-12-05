// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker_pool_impl.h"

#include <stddef.h>

#include <memory>
#include <unordered_set>
#include <vector>

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_samples.h"
#include "base/metrics/statistics_recorder.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_runner.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/sequence_sort_key.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/task_scheduler/test_task_factory.h"
#include "base/task_scheduler/test_utils.h"
#include "base/test/gtest_util.h"
#include "base/test/test_simple_task_runner.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread.h"
#include "base/threading/thread_checker_impl.h"
#include "base/threading/thread_local_storage.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {
namespace {

constexpr size_t kNumWorkersInWorkerPool = 4;
constexpr size_t kNumThreadsPostingTasks = 4;
constexpr size_t kNumTasksPostedPerThread = 150;
// This can't be lower because Windows' WaitableEvent wakes up too early when a
// small timeout is used. This results in many spurious wake ups before a worker
// is allowed to detach.
constexpr TimeDelta kReclaimTimeForDetachTests =
    TimeDelta::FromMilliseconds(500);
constexpr TimeDelta kExtraTimeToWaitForDetach =
    TimeDelta::FromSeconds(1);

using IORestriction = SchedulerWorkerPoolParams::IORestriction;
using StandbyThreadPolicy = SchedulerWorkerPoolParams::StandbyThreadPolicy;

class TaskSchedulerWorkerPoolImplTest
    : public testing::TestWithParam<test::ExecutionMode> {
 protected:
  TaskSchedulerWorkerPoolImplTest()
      : service_thread_("TaskSchedulerServiceThread") {}

  void SetUp() override {
    InitializeWorkerPool(TimeDelta::Max(), kNumWorkersInWorkerPool);
  }

  void TearDown() override {
    service_thread_.Stop();
    worker_pool_->WaitForAllWorkersIdleForTesting();
    worker_pool_->JoinForTesting();
  }

  void InitializeWorkerPool(const TimeDelta& suggested_reclaim_time,
                            size_t num_workers) {
    ASSERT_FALSE(worker_pool_);
    ASSERT_FALSE(delayed_task_manager_);
    service_thread_.Start();
    delayed_task_manager_ =
        base::MakeUnique<DelayedTaskManager>(service_thread_.task_runner());
    worker_pool_ = SchedulerWorkerPoolImpl::Create(
        SchedulerWorkerPoolParams(
            "TestWorkerPool", ThreadPriority::NORMAL, IORestriction::ALLOWED,
            StandbyThreadPolicy::LAZY, num_workers, suggested_reclaim_time),
        Bind(&TaskSchedulerWorkerPoolImplTest::ReEnqueueSequenceCallback,
             Unretained(this)),
        &task_tracker_, delayed_task_manager_.get());
    ASSERT_TRUE(worker_pool_);
  }

  std::unique_ptr<SchedulerWorkerPoolImpl> worker_pool_;

  TaskTracker task_tracker_;
  Thread service_thread_;
  std::unique_ptr<DelayedTaskManager> delayed_task_manager_;

 private:
  void ReEnqueueSequenceCallback(scoped_refptr<Sequence> sequence) {
    // In production code, this callback would be implemented by the
    // TaskScheduler which would first determine which PriorityQueue the
    // sequence must be re-enqueued.
    const SequenceSortKey sort_key(sequence->GetSortKey());
    worker_pool_->ReEnqueueSequence(std::move(sequence), sort_key);
  }

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolImplTest);
};

scoped_refptr<TaskRunner> CreateTaskRunnerWithExecutionMode(
    SchedulerWorkerPoolImpl* worker_pool,
    test::ExecutionMode execution_mode) {
  // Allow tasks posted to the returned TaskRunner to wait on a WaitableEvent.
  const TaskTraits traits = TaskTraits().WithWait();
  switch (execution_mode) {
    case test::ExecutionMode::PARALLEL:
      return worker_pool->CreateTaskRunnerWithTraits(traits);
    case test::ExecutionMode::SEQUENCED:
      return worker_pool->CreateSequencedTaskRunnerWithTraits(traits);
    case test::ExecutionMode::SINGLE_THREADED:
      return worker_pool->CreateSingleThreadTaskRunnerWithTraits(traits);
  }
  ADD_FAILURE() << "Unknown ExecutionMode";
  return nullptr;
}

using PostNestedTask = test::TestTaskFactory::PostNestedTask;

class ThreadPostingTasks : public SimpleThread {
 public:
  enum class WaitBeforePostTask {
    NO_WAIT,
    WAIT_FOR_ALL_WORKERS_IDLE,
  };

  // Constructs a thread that posts tasks to |worker_pool| through an
  // |execution_mode| task runner. If |wait_before_post_task| is
  // WAIT_FOR_ALL_WORKERS_IDLE, the thread waits until all workers in
  // |worker_pool| are idle before posting a new task. If |post_nested_task| is
  // YES, each task posted by this thread posts another task when it runs.
  ThreadPostingTasks(SchedulerWorkerPoolImpl* worker_pool,
                     test::ExecutionMode execution_mode,
                     WaitBeforePostTask wait_before_post_task,
                     PostNestedTask post_nested_task)
      : SimpleThread("ThreadPostingTasks"),
        worker_pool_(worker_pool),
        wait_before_post_task_(wait_before_post_task),
        post_nested_task_(post_nested_task),
        factory_(CreateTaskRunnerWithExecutionMode(worker_pool, execution_mode),
                 execution_mode) {
    DCHECK(worker_pool_);
  }

  const test::TestTaskFactory* factory() const { return &factory_; }

 private:
  void Run() override {
    EXPECT_FALSE(factory_.task_runner()->RunsTasksOnCurrentThread());

    for (size_t i = 0; i < kNumTasksPostedPerThread; ++i) {
      if (wait_before_post_task_ ==
          WaitBeforePostTask::WAIT_FOR_ALL_WORKERS_IDLE) {
        worker_pool_->WaitForAllWorkersIdleForTesting();
      }
      EXPECT_TRUE(factory_.PostTask(post_nested_task_, Closure()));
    }
  }

  SchedulerWorkerPoolImpl* const worker_pool_;
  const scoped_refptr<TaskRunner> task_runner_;
  const WaitBeforePostTask wait_before_post_task_;
  const PostNestedTask post_nested_task_;
  test::TestTaskFactory factory_;

  DISALLOW_COPY_AND_ASSIGN(ThreadPostingTasks);
};

using WaitBeforePostTask = ThreadPostingTasks::WaitBeforePostTask;

void ShouldNotRunCallback() {
  ADD_FAILURE() << "Ran a task that shouldn't run.";
}

}  // namespace

TEST_P(TaskSchedulerWorkerPoolImplTest, PostTasks) {
  // Create threads to post tasks.
  std::vector<std::unique_ptr<ThreadPostingTasks>> threads_posting_tasks;
  for (size_t i = 0; i < kNumThreadsPostingTasks; ++i) {
    threads_posting_tasks.push_back(MakeUnique<ThreadPostingTasks>(
        worker_pool_.get(), GetParam(), WaitBeforePostTask::NO_WAIT,
        PostNestedTask::NO));
    threads_posting_tasks.back()->Start();
  }

  // Wait for all tasks to run.
  for (const auto& thread_posting_tasks : threads_posting_tasks) {
    thread_posting_tasks->Join();
    thread_posting_tasks->factory()->WaitForAllTasksToRun();
  }

  // Wait until all workers are idle to be sure that no task accesses
  // its TestTaskFactory after |thread_posting_tasks| is destroyed.
  worker_pool_->WaitForAllWorkersIdleForTesting();
}

TEST_P(TaskSchedulerWorkerPoolImplTest, PostTasksWaitAllWorkersIdle) {
  // Create threads to post tasks. To verify that workers can sleep and be woken
  // up when new tasks are posted, wait for all workers to become idle before
  // posting a new task.
  std::vector<std::unique_ptr<ThreadPostingTasks>> threads_posting_tasks;
  for (size_t i = 0; i < kNumThreadsPostingTasks; ++i) {
    threads_posting_tasks.push_back(MakeUnique<ThreadPostingTasks>(
        worker_pool_.get(), GetParam(),
        WaitBeforePostTask::WAIT_FOR_ALL_WORKERS_IDLE, PostNestedTask::NO));
    threads_posting_tasks.back()->Start();
  }

  // Wait for all tasks to run.
  for (const auto& thread_posting_tasks : threads_posting_tasks) {
    thread_posting_tasks->Join();
    thread_posting_tasks->factory()->WaitForAllTasksToRun();
  }

  // Wait until all workers are idle to be sure that no task accesses its
  // TestTaskFactory after |thread_posting_tasks| is destroyed.
  worker_pool_->WaitForAllWorkersIdleForTesting();
}

TEST_P(TaskSchedulerWorkerPoolImplTest, NestedPostTasks) {
  // Create threads to post tasks. Each task posted by these threads will post
  // another task when it runs.
  std::vector<std::unique_ptr<ThreadPostingTasks>> threads_posting_tasks;
  for (size_t i = 0; i < kNumThreadsPostingTasks; ++i) {
    threads_posting_tasks.push_back(MakeUnique<ThreadPostingTasks>(
        worker_pool_.get(), GetParam(), WaitBeforePostTask::NO_WAIT,
        PostNestedTask::YES));
    threads_posting_tasks.back()->Start();
  }

  // Wait for all tasks to run.
  for (const auto& thread_posting_tasks : threads_posting_tasks) {
    thread_posting_tasks->Join();
    thread_posting_tasks->factory()->WaitForAllTasksToRun();
  }

  // Wait until all workers are idle to be sure that no task accesses its
  // TestTaskFactory after |thread_posting_tasks| is destroyed.
  worker_pool_->WaitForAllWorkersIdleForTesting();
}

TEST_P(TaskSchedulerWorkerPoolImplTest, PostTasksWithOneAvailableWorker) {
  // Post blocking tasks to keep all workers busy except one until |event| is
  // signaled. Use different factories so that tasks are added to different
  // sequences and can run simultaneously when the execution mode is SEQUENCED.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  std::vector<std::unique_ptr<test::TestTaskFactory>> blocked_task_factories;
  for (size_t i = 0; i < (kNumWorkersInWorkerPool - 1); ++i) {
    blocked_task_factories.push_back(MakeUnique<test::TestTaskFactory>(
        CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam()),
        GetParam()));
    EXPECT_TRUE(blocked_task_factories.back()->PostTask(
        PostNestedTask::NO, Bind(&WaitableEvent::Wait, Unretained(&event))));
    blocked_task_factories.back()->WaitForAllTasksToRun();
  }

  // Post |kNumTasksPostedPerThread| tasks that should all run despite the fact
  // that only one worker in |worker_pool_| isn't busy.
  test::TestTaskFactory short_task_factory(
      CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam()),
      GetParam());
  for (size_t i = 0; i < kNumTasksPostedPerThread; ++i)
    EXPECT_TRUE(short_task_factory.PostTask(PostNestedTask::NO, Closure()));
  short_task_factory.WaitForAllTasksToRun();

  // Release tasks waiting on |event|.
  event.Signal();

  // Wait until all workers are idle to be sure that no task accesses
  // its TestTaskFactory after it is destroyed.
  worker_pool_->WaitForAllWorkersIdleForTesting();
}

TEST_P(TaskSchedulerWorkerPoolImplTest, Saturate) {
  // Verify that it is possible to have |kNumWorkersInWorkerPool|
  // tasks/sequences running simultaneously. Use different factories so that the
  // blocking tasks are added to different sequences and can run simultaneously
  // when the execution mode is SEQUENCED.
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  std::vector<std::unique_ptr<test::TestTaskFactory>> factories;
  for (size_t i = 0; i < kNumWorkersInWorkerPool; ++i) {
    factories.push_back(MakeUnique<test::TestTaskFactory>(
        CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam()),
        GetParam()));
    EXPECT_TRUE(factories.back()->PostTask(
        PostNestedTask::NO, Bind(&WaitableEvent::Wait, Unretained(&event))));
    factories.back()->WaitForAllTasksToRun();
  }

  // Release tasks waiting on |event|.
  event.Signal();

  // Wait until all workers are idle to be sure that no task accesses
  // its TestTaskFactory after it is destroyed.
  worker_pool_->WaitForAllWorkersIdleForTesting();
}

// Verify that a Task can't be posted after shutdown.
TEST_P(TaskSchedulerWorkerPoolImplTest, PostTaskAfterShutdown) {
  auto task_runner =
      CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam());
  task_tracker_.Shutdown();
  EXPECT_FALSE(task_runner->PostTask(FROM_HERE, Bind(&ShouldNotRunCallback)));
}

// Verify that a Task runs shortly after its delay expires.
TEST_P(TaskSchedulerWorkerPoolImplTest, PostDelayedTask) {
  TimeTicks start_time = TimeTicks::Now();

  // Post a task with a short delay.
  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  EXPECT_TRUE(CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam())
                  ->PostDelayedTask(FROM_HERE, Bind(&WaitableEvent::Signal,
                                                    Unretained(&task_ran)),
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

// Verify that the RunsTasksOnCurrentThread() method of a SEQUENCED TaskRunner
// returns false when called from a task that isn't part of the sequence. Note:
// Tests that use TestTaskFactory already verify that RunsTasksOnCurrentThread()
// returns true when appropriate so this method complements it to get full
// coverage of that method.
TEST_P(TaskSchedulerWorkerPoolImplTest, SequencedRunsTasksOnCurrentThread) {
  scoped_refptr<TaskRunner> task_runner(
      CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam()));
  scoped_refptr<SequencedTaskRunner> sequenced_task_runner(
      worker_pool_->CreateSequencedTaskRunnerWithTraits(TaskTraits()));

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner->PostTask(
      FROM_HERE,
      Bind(
          [](scoped_refptr<TaskRunner> sequenced_task_runner,
             WaitableEvent* task_ran) {
            EXPECT_FALSE(sequenced_task_runner->RunsTasksOnCurrentThread());
            task_ran->Signal();
          },
          sequenced_task_runner, Unretained(&task_ran)));
  task_ran.Wait();
}

INSTANTIATE_TEST_CASE_P(Parallel,
                        TaskSchedulerWorkerPoolImplTest,
                        ::testing::Values(test::ExecutionMode::PARALLEL));
INSTANTIATE_TEST_CASE_P(Sequenced,
                        TaskSchedulerWorkerPoolImplTest,
                        ::testing::Values(test::ExecutionMode::SEQUENCED));
INSTANTIATE_TEST_CASE_P(
    SingleThreaded,
    TaskSchedulerWorkerPoolImplTest,
    ::testing::Values(test::ExecutionMode::SINGLE_THREADED));

namespace {

// Same as TaskSchedulerWorkerPoolImplTest but its SchedulerWorkerPoolImpl
// instance uses |max_threads == 1|.
class TaskSchedulerWorkerPoolImplSingleWorkerTest
    : public TaskSchedulerWorkerPoolImplTest {
 public:
  TaskSchedulerWorkerPoolImplSingleWorkerTest() = default;

 protected:
  void SetUp() override {
    InitializeWorkerPool(TimeDelta::Max(), 1);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolImplSingleWorkerTest);
};

}  // namespace

// Verify that the RunsTasksOnCurrentThread() method of a
// SchedulerSingleThreadTaskRunner returns false when called from a task that
// isn't part of its sequence even though it's running on that
// SchedulerSingleThreadTaskRunner's assigned worker. Note: Tests that use
// TestTaskFactory already verify that RunsTasksOnCurrentThread() returns true
// when appropriate so this method complements it to get full coverage of that
// method.
TEST_P(TaskSchedulerWorkerPoolImplSingleWorkerTest,
       SingleThreadRunsTasksOnCurrentThread) {
  scoped_refptr<TaskRunner> task_runner(
      CreateTaskRunnerWithExecutionMode(worker_pool_.get(), GetParam()));
  scoped_refptr<SingleThreadTaskRunner> single_thread_task_runner(
      worker_pool_->CreateSingleThreadTaskRunnerWithTraits(TaskTraits()));

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner->PostTask(
      FROM_HERE,
      Bind(
          [](scoped_refptr<TaskRunner> single_thread_task_runner,
             WaitableEvent* task_ran) {
            EXPECT_FALSE(single_thread_task_runner->RunsTasksOnCurrentThread());
            task_ran->Signal();
          },
          single_thread_task_runner, Unretained(&task_ran)));
  task_ran.Wait();
}

INSTANTIATE_TEST_CASE_P(Parallel,
                        TaskSchedulerWorkerPoolImplSingleWorkerTest,
                        ::testing::Values(test::ExecutionMode::PARALLEL));
INSTANTIATE_TEST_CASE_P(Sequenced,
                        TaskSchedulerWorkerPoolImplSingleWorkerTest,
                        ::testing::Values(test::ExecutionMode::SEQUENCED));
INSTANTIATE_TEST_CASE_P(
    SingleThreaded,
    TaskSchedulerWorkerPoolImplSingleWorkerTest,
    ::testing::Values(test::ExecutionMode::SINGLE_THREADED));

namespace {

void NotReachedReEnqueueSequenceCallback(scoped_refptr<Sequence> sequence) {
  ADD_FAILURE()
      << "Unexpected invocation of NotReachedReEnqueueSequenceCallback.";
}

// Verifies that the current thread allows I/O if |io_restriction| is ALLOWED
// and disallows it otherwise. Signals |event| before returning.
void ExpectIORestriction(IORestriction io_restriction, WaitableEvent* event) {
  DCHECK(event);

  if (io_restriction == IORestriction::ALLOWED) {
    ThreadRestrictions::AssertIOAllowed();
  } else {
    EXPECT_DCHECK_DEATH({ ThreadRestrictions::AssertIOAllowed(); });
  }

  event->Signal();
}

class TaskSchedulerWorkerPoolImplIORestrictionTest
    : public testing::TestWithParam<IORestriction> {
 public:
  TaskSchedulerWorkerPoolImplIORestrictionTest() = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolImplIORestrictionTest);
};

}  // namespace

TEST_P(TaskSchedulerWorkerPoolImplIORestrictionTest, IORestriction) {
  TaskTracker task_tracker;
  DelayedTaskManager delayed_task_manager(
      make_scoped_refptr(new TestSimpleTaskRunner));

  auto worker_pool = SchedulerWorkerPoolImpl::Create(
      SchedulerWorkerPoolParams(
          "TestWorkerPoolWithParam", ThreadPriority::NORMAL, GetParam(),
          StandbyThreadPolicy::LAZY, 1U, TimeDelta::Max()),
      Bind(&NotReachedReEnqueueSequenceCallback), &task_tracker,
      &delayed_task_manager);
  ASSERT_TRUE(worker_pool);

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  worker_pool->CreateTaskRunnerWithTraits(TaskTraits())
      ->PostTask(FROM_HERE, Bind(&ExpectIORestriction, GetParam(), &task_ran));
  task_ran.Wait();

  worker_pool->JoinForTesting();
}

INSTANTIATE_TEST_CASE_P(IOAllowed,
                        TaskSchedulerWorkerPoolImplIORestrictionTest,
                        ::testing::Values(IORestriction::ALLOWED));
INSTANTIATE_TEST_CASE_P(IODisallowed,
                        TaskSchedulerWorkerPoolImplIORestrictionTest,
                        ::testing::Values(IORestriction::DISALLOWED));

namespace {

class TaskSchedulerWorkerPoolSingleThreadedTest
    : public TaskSchedulerWorkerPoolImplTest {
 public:
  void InitializeThreadChecker() {
    thread_checker_.reset(new ThreadCheckerImpl());
  }

  void CheckValidThread() {
    EXPECT_TRUE(thread_checker_->CalledOnValidThread());
  }

 protected:
  void SetUp() override {
    InitializeWorkerPool(kReclaimTimeForDetachTests, kNumWorkersInWorkerPool);
  }

  TaskSchedulerWorkerPoolSingleThreadedTest() = default;

 private:
  std::unique_ptr<ThreadCheckerImpl> thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolSingleThreadedTest);
};

}  // namespace

// Verify that thread resources for a single thread remain.
TEST_F(TaskSchedulerWorkerPoolSingleThreadedTest, SingleThreadTask) {
  auto single_thread_task_runner =
      worker_pool_->CreateSingleThreadTaskRunnerWithTraits(
          TaskTraits().WithShutdownBehavior(
              TaskShutdownBehavior::BLOCK_SHUTDOWN));
  single_thread_task_runner->PostTask(
      FROM_HERE,
      Bind(&TaskSchedulerWorkerPoolSingleThreadedTest::InitializeThreadChecker,
           Unretained(this)));
  WaitableEvent task_waiter(WaitableEvent::ResetPolicy::AUTOMATIC,
                            WaitableEvent::InitialState::NOT_SIGNALED);
  single_thread_task_runner->PostTask(
      FROM_HERE, Bind(&WaitableEvent::Signal, Unretained(&task_waiter)));
  task_waiter.Wait();
  worker_pool_->WaitForAllWorkersIdleForTesting();

  // Give the worker pool a chance to reclaim its threads.
  PlatformThread::Sleep(kReclaimTimeForDetachTests + kExtraTimeToWaitForDetach);

  worker_pool_->DisallowWorkerDetachmentForTesting();

  single_thread_task_runner->PostTask(
      FROM_HERE,
      Bind(&TaskSchedulerWorkerPoolSingleThreadedTest::CheckValidThread,
           Unretained(this)));
  single_thread_task_runner->PostTask(
      FROM_HERE, Bind(&WaitableEvent::Signal, Unretained(&task_waiter)));
  task_waiter.Wait();
}

namespace {

constexpr size_t kMagicTlsValue = 42;

class TaskSchedulerWorkerPoolCheckTlsReuse
    : public TaskSchedulerWorkerPoolImplTest {
 public:
  void SetTlsValueAndWait() {
    slot_.Set(reinterpret_cast<void*>(kMagicTlsValue));
    waiter_.Wait();
  }

  void CountZeroTlsValuesAndWait(WaitableEvent* count_waiter) {
    if (!slot_.Get())
      subtle::NoBarrier_AtomicIncrement(&zero_tls_values_, 1);

    count_waiter->Signal();
    waiter_.Wait();
  }

 protected:
  TaskSchedulerWorkerPoolCheckTlsReuse() :
      waiter_(WaitableEvent::ResetPolicy::MANUAL,
              WaitableEvent::InitialState::NOT_SIGNALED) {}

  void SetUp() override {
    InitializeWorkerPool(kReclaimTimeForDetachTests, kNumWorkersInWorkerPool);
  }

  subtle::Atomic32 zero_tls_values_ = 0;

  WaitableEvent waiter_;

 private:
  ThreadLocalStorage::Slot slot_;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolCheckTlsReuse);
};

}  // namespace

// Checks that at least one thread has detached by checking the TLS.
TEST_F(TaskSchedulerWorkerPoolCheckTlsReuse, CheckDetachedThreads) {
  // Saturate the threads and mark each thread with a magic TLS value.
  std::vector<std::unique_ptr<test::TestTaskFactory>> factories;
  for (size_t i = 0; i < kNumWorkersInWorkerPool; ++i) {
    factories.push_back(MakeUnique<test::TestTaskFactory>(
        worker_pool_->CreateTaskRunnerWithTraits(TaskTraits().WithWait()),
        test::ExecutionMode::PARALLEL));
    ASSERT_TRUE(factories.back()->PostTask(
        PostNestedTask::NO,
        Bind(&TaskSchedulerWorkerPoolCheckTlsReuse::SetTlsValueAndWait,
             Unretained(this))));
    factories.back()->WaitForAllTasksToRun();
  }

  // Release tasks waiting on |waiter_|.
  waiter_.Signal();
  worker_pool_->WaitForAllWorkersIdleForTesting();

  // All threads should be done running by now, so reset for the next phase.
  waiter_.Reset();

  // Give the worker pool a chance to detach its threads.
  PlatformThread::Sleep(kReclaimTimeForDetachTests + kExtraTimeToWaitForDetach);

  worker_pool_->DisallowWorkerDetachmentForTesting();

  // Saturate and count the threads that do not have the magic TLS value. If the
  // value is not there, that means we're at a new thread.
  std::vector<std::unique_ptr<WaitableEvent>> count_waiters;
  for (auto& factory : factories) {
    count_waiters.push_back(WrapUnique(new WaitableEvent(
        WaitableEvent::ResetPolicy::MANUAL,
        WaitableEvent::InitialState::NOT_SIGNALED)));
    ASSERT_TRUE(factory->PostTask(
          PostNestedTask::NO,
          Bind(&TaskSchedulerWorkerPoolCheckTlsReuse::CountZeroTlsValuesAndWait,
               Unretained(this),
               count_waiters.back().get())));
    factory->WaitForAllTasksToRun();
  }

  // Wait for all counters to complete.
  for (auto& count_waiter : count_waiters)
    count_waiter->Wait();

  EXPECT_GT(subtle::NoBarrier_Load(&zero_tls_values_), 0);

  // Release tasks waiting on |waiter_|.
  waiter_.Signal();
}

namespace {

class TaskSchedulerWorkerPoolHistogramTest
    : public TaskSchedulerWorkerPoolImplTest {
 public:
  TaskSchedulerWorkerPoolHistogramTest() = default;

 protected:
  // Override SetUp() to allow every test case to initialize a worker pool with
  // its own arguments.
  void SetUp() override {}

 private:
  std::unique_ptr<StatisticsRecorder> statistics_recorder_ =
      StatisticsRecorder::CreateTemporaryForTesting();

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolHistogramTest);
};

}  // namespace

TEST_F(TaskSchedulerWorkerPoolHistogramTest, NumTasksBetweenWaits) {
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  InitializeWorkerPool(TimeDelta::Max(), kNumWorkersInWorkerPool);
  auto task_runner = worker_pool_->CreateSequencedTaskRunnerWithTraits(
      TaskTraits().WithWait());

  // Post a task.
  task_runner->PostTask(FROM_HERE,
                        Bind(&WaitableEvent::Wait, Unretained(&event)));

  // Post 2 more tasks while the first task hasn't completed its execution. It
  // is guaranteed that these tasks will run immediately after the first task,
  // without allowing the worker to sleep.
  task_runner->PostTask(FROM_HERE, Bind(&DoNothing));
  task_runner->PostTask(FROM_HERE, Bind(&DoNothing));

  // Allow tasks to run and wait until the SchedulerWorker is idle.
  event.Signal();
  worker_pool_->WaitForAllWorkersIdleForTesting();

  // Wake up the SchedulerWorker that just became idle by posting a task and
  // wait until it becomes idle again. The SchedulerWorker should record the
  // TaskScheduler.NumTasksBetweenWaits.* histogram on wake up.
  task_runner->PostTask(FROM_HERE, Bind(&DoNothing));
  worker_pool_->WaitForAllWorkersIdleForTesting();

  // Verify that counts were recorded to the histogram as expected.
  const auto* histogram = worker_pool_->num_tasks_between_waits_histogram();
  EXPECT_EQ(0, histogram->SnapshotSamples()->GetCount(0));
  EXPECT_EQ(1, histogram->SnapshotSamples()->GetCount(3));
  EXPECT_EQ(0, histogram->SnapshotSamples()->GetCount(10));
}

namespace {

void SignalAndWaitEvent(WaitableEvent* signal_event,
                        WaitableEvent* wait_event) {
  signal_event->Signal();
  wait_event->Wait();
}

}  // namespace

TEST_F(TaskSchedulerWorkerPoolHistogramTest, NumTasksBetweenWaitsWithDetach) {
  WaitableEvent tasks_can_exit_event(WaitableEvent::ResetPolicy::MANUAL,
                                     WaitableEvent::InitialState::NOT_SIGNALED);
  InitializeWorkerPool(kReclaimTimeForDetachTests, kNumWorkersInWorkerPool);
  auto task_runner =
      worker_pool_->CreateTaskRunnerWithTraits(TaskTraits().WithWait());

  // Post tasks to saturate the pool.
  std::vector<std::unique_ptr<WaitableEvent>> task_started_events;
  for (size_t i = 0; i < kNumWorkersInWorkerPool; ++i) {
    task_started_events.push_back(
        MakeUnique<WaitableEvent>(WaitableEvent::ResetPolicy::MANUAL,
                                  WaitableEvent::InitialState::NOT_SIGNALED));
    task_runner->PostTask(
        FROM_HERE,
        Bind(&SignalAndWaitEvent, Unretained(task_started_events.back().get()),
             Unretained(&tasks_can_exit_event)));
  }
  for (const auto& task_started_event : task_started_events)
    task_started_event->Wait();

  // Allow tasks to complete their execution and wait to allow workers to
  // detach.
  tasks_can_exit_event.Signal();
  worker_pool_->WaitForAllWorkersIdleForTesting();
  PlatformThread::Sleep(kReclaimTimeForDetachTests + kExtraTimeToWaitForDetach);

  // Wake up SchedulerWorkers by posting tasks. They should record the
  // TaskScheduler.NumTasksBetweenWaits.* histogram on wake up.
  tasks_can_exit_event.Reset();
  task_started_events.clear();
  for (size_t i = 0; i < kNumWorkersInWorkerPool; ++i) {
    task_started_events.push_back(
        MakeUnique<WaitableEvent>(WaitableEvent::ResetPolicy::MANUAL,
                                  WaitableEvent::InitialState::NOT_SIGNALED));
    task_runner->PostTask(
        FROM_HERE,
        Bind(&SignalAndWaitEvent, Unretained(task_started_events.back().get()),
             Unretained(&tasks_can_exit_event)));
  }
  for (const auto& task_started_event : task_started_events)
    task_started_event->Wait();

  const auto* histogram = worker_pool_->num_tasks_between_waits_histogram();

  // Verify that counts were recorded to the histogram as expected.
  // - The "0" bucket has a count of at least 1 because the SchedulerWorker on
  //   top of the idle stack isn't allowed to detach when its sleep timeout
  //   expires. Instead, it waits on its WaitableEvent again without running a
  //   task. The count may be higher than 1 because of spurious wake ups before
  //   the sleep timeout expires.
  EXPECT_GE(histogram->SnapshotSamples()->GetCount(0), 1);
  // - The "1" bucket has a count of |kNumWorkersInWorkerPool| because each
  //   SchedulerWorker ran a task before waiting on its WaitableEvent at the
  //   beginning of the test.
  EXPECT_EQ(static_cast<int>(kNumWorkersInWorkerPool),
            histogram->SnapshotSamples()->GetCount(1));
  EXPECT_EQ(0, histogram->SnapshotSamples()->GetCount(10));

  tasks_can_exit_event.Signal();
  worker_pool_->WaitForAllWorkersIdleForTesting();
  worker_pool_->DisallowWorkerDetachmentForTesting();
}

namespace {

void CaptureThreadId(PlatformThreadId* thread_id) {
  ASSERT_TRUE(thread_id);
  *thread_id = PlatformThread::CurrentId();
}

void VerifyThreadIdIsNot(PlatformThreadId thread_id) {
  EXPECT_NE(thread_id, PlatformThread::CurrentId());
}

}  // namespace

TEST_F(TaskSchedulerWorkerPoolHistogramTest, NumTasksBeforeDetach) {
  InitializeWorkerPool(kReclaimTimeForDetachTests, kNumWorkersInWorkerPool);

  // This test assumes that the TaskRunners aren't assigned to the same worker.
  auto task_runner =
      worker_pool_->CreateSingleThreadTaskRunnerWithTraits(TaskTraits());
  auto other_task_runner =
      worker_pool_->CreateSingleThreadTaskRunnerWithTraits(TaskTraits());

  // Post 3 tasks and wait until they run.
  PlatformThreadId thread_id;
  task_runner->PostTask(FROM_HERE,
                        Bind(&CaptureThreadId, Unretained(&thread_id)));
  task_runner->PostTask(FROM_HERE, Bind(&DoNothing));
  task_runner->PostTask(FROM_HERE, Bind(&DoNothing));
  worker_pool_->WaitForAllWorkersIdleForTesting();

  // To allow the SchedulerWorker associated with |task_runner| to detach:
  // - Make sure it isn't on top of the idle stack by waking up another
  //   SchedulerWorker and waiting until it goes back to sleep.
  // - Release |task_runner|.
  other_task_runner->PostTask(FROM_HERE, Bind(&VerifyThreadIdIsNot, thread_id));
  worker_pool_->WaitForAllWorkersIdleForTesting();
  task_runner = nullptr;

  // Allow the SchedulerWorker that was associated with |task_runner| to detach.
  PlatformThread::Sleep(kReclaimTimeForDetachTests + kExtraTimeToWaitForDetach);
  worker_pool_->DisallowWorkerDetachmentForTesting();

  // Verify that counts were recorded to the histogram as expected.
  const auto* histogram = worker_pool_->num_tasks_before_detach_histogram();
  EXPECT_EQ(0, histogram->SnapshotSamples()->GetCount(0));
  EXPECT_EQ(1, histogram->SnapshotSamples()->GetCount(3));
  EXPECT_EQ(0, histogram->SnapshotSamples()->GetCount(10));
}

TEST(TaskSchedulerWorkerPoolStandbyPolicyTest, InitLazy) {
  TaskTracker task_tracker;
  DelayedTaskManager delayed_task_manager(
      make_scoped_refptr(new TestSimpleTaskRunner));
  auto worker_pool = SchedulerWorkerPoolImpl::Create(
      SchedulerWorkerPoolParams("LazyPolicyWorkerPool", ThreadPriority::NORMAL,
                                IORestriction::DISALLOWED,
                                StandbyThreadPolicy::LAZY, 8U,
                                TimeDelta::Max()),
      Bind(&NotReachedReEnqueueSequenceCallback), &task_tracker,
      &delayed_task_manager);
  ASSERT_TRUE(worker_pool);
  EXPECT_EQ(0U, worker_pool->NumberOfAliveWorkersForTesting());
  worker_pool->JoinForTesting();
}

TEST(TaskSchedulerWorkerPoolStandbyPolicyTest, InitOne) {
  TaskTracker task_tracker;
  DelayedTaskManager delayed_task_manager(
      make_scoped_refptr(new TestSimpleTaskRunner));
  auto worker_pool = SchedulerWorkerPoolImpl::Create(
      SchedulerWorkerPoolParams("LazyPolicyWorkerPool", ThreadPriority::NORMAL,
                                IORestriction::DISALLOWED,
                                StandbyThreadPolicy::ONE, 8U, TimeDelta::Max()),
      Bind(&NotReachedReEnqueueSequenceCallback), &task_tracker,
      &delayed_task_manager);
  ASSERT_TRUE(worker_pool);
  EXPECT_EQ(1U, worker_pool->NumberOfAliveWorkersForTesting());
  worker_pool->JoinForTesting();
}

}  // namespace internal
}  // namespace base
