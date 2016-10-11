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
#include "base/test/gtest_util.h"
#include "base/threading/platform_thread.h"
#include "base/threading/simple_thread.h"
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

class TestDelayedTaskManager : public DelayedTaskManager {
 public:
  TestDelayedTaskManager() : DelayedTaskManager(Bind(&DoNothing)) {}

  void SetCurrentTime(TimeTicks now) { now_ = now; }

  // DelayedTaskManager:
  TimeTicks Now() const override { return now_; }

 private:
  TimeTicks now_ = TimeTicks::Now();

  DISALLOW_COPY_AND_ASSIGN(TestDelayedTaskManager);
};

class TaskSchedulerWorkerPoolImplTest
    : public testing::TestWithParam<ExecutionMode> {
 protected:
  TaskSchedulerWorkerPoolImplTest() = default;

  void SetUp() override {
    InitializeWorkerPool(TimeDelta::Max(), kNumWorkersInWorkerPool);
  }

  void TearDown() override {
    worker_pool_->WaitForAllWorkersIdleForTesting();
    worker_pool_->JoinForTesting();
  }

  void InitializeWorkerPool(const TimeDelta& suggested_reclaim_time,
                            size_t num_workers) {
    worker_pool_ = SchedulerWorkerPoolImpl::Create(
        SchedulerWorkerPoolParams("TestWorkerPool", ThreadPriority::NORMAL,
                                  IORestriction::ALLOWED, num_workers,
                                  suggested_reclaim_time),
        Bind(&TaskSchedulerWorkerPoolImplTest::ReEnqueueSequenceCallback,
             Unretained(this)),
        &task_tracker_, &delayed_task_manager_);
    ASSERT_TRUE(worker_pool_);
  }

  std::unique_ptr<SchedulerWorkerPoolImpl> worker_pool_;

  TaskTracker task_tracker_;
  TestDelayedTaskManager delayed_task_manager_;

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
                     ExecutionMode execution_mode,
                     WaitBeforePostTask wait_before_post_task,
                     PostNestedTask post_nested_task)
      : SimpleThread("ThreadPostingTasks"),
        worker_pool_(worker_pool),
        wait_before_post_task_(wait_before_post_task),
        post_nested_task_(post_nested_task),
        factory_(worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(),
                                                          execution_mode),
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
        worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(), GetParam()),
        GetParam()));
    EXPECT_TRUE(blocked_task_factories.back()->PostTask(
        PostNestedTask::NO, Bind(&WaitableEvent::Wait, Unretained(&event))));
    blocked_task_factories.back()->WaitForAllTasksToRun();
  }

  // Post |kNumTasksPostedPerThread| tasks that should all run despite the fact
  // that only one worker in |worker_pool_| isn't busy.
  test::TestTaskFactory short_task_factory(
      worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(), GetParam()),
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
        worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(), GetParam()),
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
      worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(), GetParam());
  task_tracker_.Shutdown();
  EXPECT_FALSE(task_runner->PostTask(FROM_HERE, Bind(&ShouldNotRunCallback)));
}

// Verify that a Task posted with a delay is added to the DelayedTaskManager and
// doesn't run before its delay expires.
TEST_P(TaskSchedulerWorkerPoolImplTest, PostDelayedTask) {
  EXPECT_TRUE(delayed_task_manager_.GetDelayedRunTime().is_null());

  // Post a delayed task.
  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  EXPECT_TRUE(worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(), GetParam())
                  ->PostDelayedTask(FROM_HERE, Bind(&WaitableEvent::Signal,
                                                    Unretained(&task_ran)),
                                    TimeDelta::FromSeconds(10)));

  // The task should have been added to the DelayedTaskManager.
  EXPECT_FALSE(delayed_task_manager_.GetDelayedRunTime().is_null());

  // The task shouldn't run.
  EXPECT_FALSE(task_ran.IsSignaled());

  // Fast-forward time and post tasks that are ripe for execution.
  delayed_task_manager_.SetCurrentTime(
      delayed_task_manager_.GetDelayedRunTime());
  delayed_task_manager_.PostReadyTasks();

  // The task should run.
  task_ran.Wait();
}

// Verify that the RunsTasksOnCurrentThread() method of a SEQUENCED TaskRunner
// returns false when called from a task that isn't part of the sequence.
TEST_P(TaskSchedulerWorkerPoolImplTest, SequencedRunsTasksOnCurrentThread) {
  scoped_refptr<TaskRunner> task_runner(
      worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(), GetParam()));
  scoped_refptr<TaskRunner> sequenced_task_runner(
      worker_pool_->CreateTaskRunnerWithTraits(TaskTraits(),
                                               ExecutionMode::SEQUENCED));

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner->PostTask(
      FROM_HERE,
      Bind(
          [](scoped_refptr<TaskRunner> sequenced_task_runner,
             WaitableEvent* task_ran) {
            EXPECT_FALSE(sequenced_task_runner->RunsTasksOnCurrentThread());
            // Tests that use TestTaskFactory already verify that
            // RunsTasksOnCurrentThread() returns true when appropriate.
            task_ran->Signal();
          },
          sequenced_task_runner, Unretained(&task_ran)));
  task_ran.Wait();
}

INSTANTIATE_TEST_CASE_P(Parallel,
                        TaskSchedulerWorkerPoolImplTest,
                        ::testing::Values(ExecutionMode::PARALLEL));
INSTANTIATE_TEST_CASE_P(Sequenced,
                        TaskSchedulerWorkerPoolImplTest,
                        ::testing::Values(ExecutionMode::SEQUENCED));
INSTANTIATE_TEST_CASE_P(SingleThreaded,
                        TaskSchedulerWorkerPoolImplTest,
                        ::testing::Values(ExecutionMode::SINGLE_THREADED));

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
  DelayedTaskManager delayed_task_manager(Bind(&DoNothing));

  auto worker_pool = SchedulerWorkerPoolImpl::Create(
      SchedulerWorkerPoolParams("TestWorkerPoolWithParam",
                                ThreadPriority::NORMAL, GetParam(), 1U,
                                TimeDelta::Max()),
      Bind(&NotReachedReEnqueueSequenceCallback), &task_tracker,
      &delayed_task_manager);
  ASSERT_TRUE(worker_pool);

  WaitableEvent task_ran(WaitableEvent::ResetPolicy::MANUAL,
                         WaitableEvent::InitialState::NOT_SIGNALED);
  worker_pool->CreateTaskRunnerWithTraits(TaskTraits(), ExecutionMode::PARALLEL)
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
      worker_pool_->CreateTaskRunnerWithTraits(
          TaskTraits().
              WithShutdownBehavior(TaskShutdownBehavior::BLOCK_SHUTDOWN),
          ExecutionMode::SINGLE_THREADED);
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
    factories.push_back(WrapUnique(new test::TestTaskFactory(
        worker_pool_->CreateTaskRunnerWithTraits(
            TaskTraits(), ExecutionMode::PARALLEL),
        ExecutionMode::PARALLEL)));
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
  void SetUp() override {}

  void TearDown() override { worker_pool_->JoinForTesting(); }

 private:
  std::unique_ptr<StatisticsRecorder> statistics_recorder_ =
      StatisticsRecorder::CreateTemporaryForTesting();

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerPoolHistogramTest);
};

}  // namespace

TEST_F(TaskSchedulerWorkerPoolHistogramTest, NumTasksBetweenWaits) {
  WaitableEvent event(WaitableEvent::ResetPolicy::MANUAL,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  InitializeWorkerPool(TimeDelta::Max(), kNumWorkersInWorkerPool);
  auto task_runner = worker_pool_->CreateTaskRunnerWithTraits(
      TaskTraits(), ExecutionMode::SEQUENCED);

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
  EXPECT_EQ(0, worker_pool_->num_tasks_between_waits_histogram_for_testing()
                   ->SnapshotSamples()
                   ->GetCount(0));
  EXPECT_EQ(1, worker_pool_->num_tasks_between_waits_histogram_for_testing()
                   ->SnapshotSamples()
                   ->GetCount(3));
  EXPECT_EQ(0, worker_pool_->num_tasks_between_waits_histogram_for_testing()
                   ->SnapshotSamples()
                   ->GetCount(10));
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
  auto task_runner = worker_pool_->CreateTaskRunnerWithTraits(
      TaskTraits(), ExecutionMode::PARALLEL);

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

  // Verify that counts were recorded to the histogram as expected.
  // - The "0" bucket has a count of at least 1 because the SchedulerWorker on
  //   top of the idle stack isn't allowed to detach when its sleep timeout
  //   expires. Instead, it waits on its WaitableEvent again without running a
  //   task. The count may be higher than 1 because of spurious wake ups before
  //   the sleep timeout expires.
  EXPECT_GE(worker_pool_->num_tasks_between_waits_histogram_for_testing()
                ->SnapshotSamples()
                ->GetCount(0),
            1);
  // - The "1" bucket has a count of |kNumWorkersInWorkerPool| because each
  //   SchedulerWorker ran a task before waiting on its WaitableEvent at the
  //   beginning of the test.
  EXPECT_EQ(static_cast<int>(kNumWorkersInWorkerPool),
            worker_pool_->num_tasks_between_waits_histogram_for_testing()
                ->SnapshotSamples()
                ->GetCount(1));
  EXPECT_EQ(0, worker_pool_->num_tasks_between_waits_histogram_for_testing()
                   ->SnapshotSamples()
                   ->GetCount(10));

  tasks_can_exit_event.Signal();
  worker_pool_->WaitForAllWorkersIdleForTesting();
  worker_pool_->DisallowWorkerDetachmentForTesting();
}

}  // namespace internal
}  // namespace base
