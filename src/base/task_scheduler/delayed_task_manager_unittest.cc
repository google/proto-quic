// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/delayed_task_manager.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/scheduler_worker_pool.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {
namespace {

class TestDelayedTaskManager : public DelayedTaskManager {
 public:
  TestDelayedTaskManager()
      : DelayedTaskManager(
            Bind(&TestDelayedTaskManager::OnDelayedRunTimeUpdated,
                 Unretained(this))) {}

  void SetCurrentTime(TimeTicks now) { now_ = now; }

  // DelayedTaskManager:
  TimeTicks Now() const override { return now_; }

  MOCK_METHOD0(OnDelayedRunTimeUpdated, void());

 private:
  TimeTicks now_ = TimeTicks::Now();

  DISALLOW_COPY_AND_ASSIGN(TestDelayedTaskManager);
};

class MockSchedulerWorkerPool : public SchedulerWorkerPool {
 public:
  // SchedulerWorkerPool:
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits,
      ExecutionMode execution_mode) override {
    NOTREACHED();
    return nullptr;
  }

  void ReEnqueueSequence(scoped_refptr<Sequence> sequence,
                         const SequenceSortKey& sequence_sort_key) override {
    NOTREACHED();
  }

  bool PostTaskWithSequence(std::unique_ptr<Task> task,
                            scoped_refptr<Sequence> sequence,
                            SchedulerWorker* worker) override {
    NOTREACHED();
    return true;
  }

  void PostTaskWithSequenceNow(std::unique_ptr<Task> task,
                               scoped_refptr<Sequence> sequence,
                               SchedulerWorker* worker) override {
    PostTaskWithSequenceNowMock(task.get(), sequence.get(), worker);
  }

  MOCK_METHOD3(PostTaskWithSequenceNowMock,
               void(const Task*,
                    const Sequence*,
                    const SchedulerWorker* worker));
};

}  // namespace

// Verify that GetDelayedRunTime() returns a null TimeTicks when there are
// no pending delayed tasks.
TEST(TaskSchedulerDelayedTaskManagerTest,
     GetDelayedRunTimeNoPendingDelayedTasks) {
  TestDelayedTaskManager manager;
  EXPECT_EQ(TimeTicks(), manager.GetDelayedRunTime());
}

// Verify that a delayed task isn't posted before it is ripe for execution.
TEST(TaskSchedulerDelayedTaskManagerTest, PostReadyTaskBeforeDelayedRunTime) {
  testing::StrictMock<TestDelayedTaskManager> manager;

  std::unique_ptr<Task> task(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));
  task->delayed_run_time = manager.Now() + TimeDelta::FromSeconds(1);
  const Task* task_raw = task.get();
  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  // Add |task| to the DelayedTaskManager.
  EXPECT_CALL(manager, OnDelayedRunTimeUpdated());
  manager.AddDelayedTask(std::move(task), sequence, nullptr, &worker_pool);
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(task_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Ask the DelayedTaskManager to post tasks that are ripe for execution. Don't
  // expect any call to the mock method of |worker_pool|.
  manager.PostReadyTasks();

  // The delayed run time shouldn't have changed.
  EXPECT_EQ(task_raw->delayed_run_time, manager.GetDelayedRunTime());
}

// Verify that a delayed task is posted when PostReadyTasks() is called with the
// current time equal to the task's delayed run time.
TEST(TaskSchedulerDelayedTaskManagerTest, PostReadyTasksAtDelayedRunTime) {
  testing::StrictMock<TestDelayedTaskManager> manager;

  std::unique_ptr<Task> task(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));
  task->delayed_run_time = manager.Now() + TimeDelta::FromSeconds(1);
  const Task* task_raw = task.get();
  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  // Add |task| to the DelayedTaskManager.
  EXPECT_CALL(manager, OnDelayedRunTimeUpdated());
  manager.AddDelayedTask(std::move(task), sequence, nullptr, &worker_pool);
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(task_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Fast-forward time to |task_raw|'s delayed run time.
  manager.SetCurrentTime(task_raw->delayed_run_time);

  // Ask the DelayedTaskManager to post tasks that are ripe for execution.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_raw, sequence.get(), nullptr));
  manager.PostReadyTasks();
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(TimeTicks(), manager.GetDelayedRunTime());
}

// Verify that a delayed task is posted when PostReadyTasks() is called with the
// current time greater than the task's delayed run time.
TEST(TaskSchedulerDelayedTaskManagerTest, PostReadyTasksAfterDelayedRunTime) {
  testing::StrictMock<TestDelayedTaskManager> manager;

  std::unique_ptr<Task> task(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));
  task->delayed_run_time = manager.Now() + TimeDelta::FromSeconds(1);
  const Task* task_raw = task.get();
  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  // Add |task| to the DelayedTaskManager.
  EXPECT_CALL(manager, OnDelayedRunTimeUpdated());
  manager.AddDelayedTask(std::move(task), sequence, nullptr, &worker_pool);
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(task_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Fast-forward time to |task_raw|'s delayed run time.
  manager.SetCurrentTime(task_raw->delayed_run_time +
                         TimeDelta::FromSeconds(10));

  // Ask the DelayedTaskManager to post tasks that are ripe for execution.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_raw, sequence.get(), nullptr));
  manager.PostReadyTasks();
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(TimeTicks(), manager.GetDelayedRunTime());
}

// Verify that when multiple tasks are added to a DelayedTaskManager, they are
// posted when they become ripe for execution.
TEST(TaskSchedulerDelayedTaskManagerTest, AddAndPostReadyTasks) {
  testing::StrictMock<TestDelayedTaskManager> manager;

  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  std::unique_ptr<Task> task_a(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));
  task_a->delayed_run_time = manager.Now() + TimeDelta::FromSeconds(2);
  const Task* task_a_raw = task_a.get();

  std::unique_ptr<Task> task_b(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));
  task_b->delayed_run_time = manager.Now() + TimeDelta::FromSeconds(2);
  const Task* task_b_raw = task_b.get();

  std::unique_ptr<Task> task_c(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));
  task_c->delayed_run_time = manager.Now() + TimeDelta::FromSeconds(1);
  const Task* task_c_raw = task_c.get();

  // Add |task_a| to the DelayedTaskManager. The delayed run time should be
  // updated to |task_a|'s delayed run time.
  EXPECT_CALL(manager, OnDelayedRunTimeUpdated());
  manager.AddDelayedTask(std::move(task_a), sequence, nullptr, &worker_pool);
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(task_a_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Add |task_b| to the DelayedTaskManager. The delayed run time shouldn't
  // change.
  manager.AddDelayedTask(std::move(task_b), sequence, nullptr, &worker_pool);
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(task_a_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Add |task_c| to the DelayedTaskManager. The delayed run time should be
  // updated to |task_c|'s delayed run time.
  EXPECT_CALL(manager, OnDelayedRunTimeUpdated());
  manager.AddDelayedTask(std::move(task_c), sequence, nullptr, &worker_pool);
  testing::Mock::VerifyAndClear(&manager);
  EXPECT_EQ(task_c_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Fast-forward time to |task_c_raw|'s delayed run time.
  manager.SetCurrentTime(task_c_raw->delayed_run_time);

  // Ask the DelayedTaskManager to post tasks that are ripe for execution.
  // |task_c_raw| should be posted and the delayed run time should become
  // |task_a_raw|'s delayed run time.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_c_raw, sequence.get(), nullptr));
  manager.PostReadyTasks();
  testing::Mock::VerifyAndClear(&worker_pool);
  EXPECT_EQ(task_a_raw->delayed_run_time, manager.GetDelayedRunTime());

  // Fast-forward time to |task_a_raw|'s delayed run time.
  manager.SetCurrentTime(task_a_raw->delayed_run_time);

  // Ask the DelayedTaskManager to post tasks that are ripe for execution.
  // |task_a_raw| and |task_b_raw| should be posted and the delayed run time
  // should become a null TimeTicks.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_a_raw, sequence.get(), nullptr));
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_b_raw, sequence.get(), nullptr));
  manager.PostReadyTasks();
  testing::Mock::VerifyAndClear(&worker_pool);
  EXPECT_EQ(TimeTicks(), manager.GetDelayedRunTime());
}

}  // namespace internal
}  // namespace base
