// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/delayed_task_manager.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/memory/ref_counted.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/task_scheduler/scheduler_worker_pool.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {
namespace {

constexpr TimeDelta kLongDelay = TimeDelta::FromHours(1);

class MockSchedulerWorkerPool : public SchedulerWorkerPool {
 public:
  // SchedulerWorkerPool:
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits) override {
    ADD_FAILURE() << "Call to unimplemented method.";
    return nullptr;
  }

  scoped_refptr<SequencedTaskRunner> CreateSequencedTaskRunnerWithTraits(
      const TaskTraits& traits) override {
    ADD_FAILURE() << "Call to unimplemented method.";
    return nullptr;
  }

  scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
      const TaskTraits& traits) override {
    ADD_FAILURE() << "Call to unimplemented method.";
    return nullptr;
  }

  void ReEnqueueSequence(scoped_refptr<Sequence> sequence,
                         const SequenceSortKey& sequence_sort_key) override {
    ADD_FAILURE() << "Call to unimplemented method.";
  }

  bool PostTaskWithSequence(std::unique_ptr<Task> task,
                            scoped_refptr<Sequence> sequence,
                            SchedulerWorker* worker) override {
    ADD_FAILURE() << "Call to unimplemented method.";
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

// Verify that a delayed task isn't forwarded to its SchedulerWorkerPool before
// it is ripe for execution.
TEST(TaskSchedulerDelayedTaskManagerTest, DelayedTaskDoesNotRunTooEarly) {
  scoped_refptr<TestMockTimeTaskRunner> service_thread_task_runner(
      new TestMockTimeTaskRunner);
  DelayedTaskManager manager(service_thread_task_runner);

  std::unique_ptr<Task> task(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), kLongDelay));
  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  // Send |task| to the DelayedTaskManager.
  manager.AddDelayedTask(std::move(task), sequence, nullptr, &worker_pool);

  // Run tasks that are ripe for execution. Don't expect any call to the mock
  // method of |worker_pool|.
  service_thread_task_runner->RunUntilIdle();
}

// Verify that a delayed task is forwarded to its SchedulerWorkerPool when it is
// ripe for execution.
TEST(TaskSchedulerDelayedTaskManagerTest, DelayedTaskRunsAfterDelay) {
  scoped_refptr<TestMockTimeTaskRunner> service_thread_task_runner(
      new TestMockTimeTaskRunner);
  DelayedTaskManager manager(service_thread_task_runner);

  std::unique_ptr<Task> task(
      new Task(FROM_HERE, Bind(&DoNothing), TaskTraits(), kLongDelay));
  const Task* task_raw = task.get();
  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  // Send |task| to the DelayedTaskManager.
  manager.AddDelayedTask(std::move(task), sequence, nullptr, &worker_pool);

  // Fast-forward time. Expect a call to the mock method of |worker_pool|.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_raw, sequence.get(), nullptr));
  service_thread_task_runner->FastForwardBy(kLongDelay);
}

// Verify that multiple delayed task are forwarded to their SchedulerWorkerPool
// when they are ripe for execution.
TEST(TaskSchedulerDelayedTaskManagerTest, DelayedTasksRunAfterDelay) {
  scoped_refptr<TestMockTimeTaskRunner> service_thread_task_runner(
      new TestMockTimeTaskRunner);
  DelayedTaskManager manager(service_thread_task_runner);

  scoped_refptr<Sequence> sequence(new Sequence);
  testing::StrictMock<MockSchedulerWorkerPool> worker_pool;

  std::unique_ptr<Task> task_a(new Task(FROM_HERE, Bind(&DoNothing),
                                        TaskTraits(), TimeDelta::FromHours(1)));
  const Task* task_a_raw = task_a.get();

  std::unique_ptr<Task> task_b(new Task(FROM_HERE, Bind(&DoNothing),
                                        TaskTraits(), TimeDelta::FromHours(2)));
  const Task* task_b_raw = task_b.get();

  std::unique_ptr<Task> task_c(new Task(FROM_HERE, Bind(&DoNothing),
                                        TaskTraits(), TimeDelta::FromHours(1)));
  const Task* task_c_raw = task_c.get();

  // Send tasks to the DelayedTaskManager.
  manager.AddDelayedTask(std::move(task_a), sequence, nullptr, &worker_pool);
  manager.AddDelayedTask(std::move(task_b), sequence, nullptr, &worker_pool);
  manager.AddDelayedTask(std::move(task_c), sequence, nullptr, &worker_pool);

  // Run tasks that are ripe for execution on the service thread. Don't expect
  // any call to the mock method of |worker_pool|.
  service_thread_task_runner->RunUntilIdle();

  // Fast-forward time. Expect |task_a_raw| and |task_c_raw| to be forwarded to
  // the worker pool.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_a_raw, sequence.get(), nullptr));
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_c_raw, sequence.get(), nullptr));
  service_thread_task_runner->FastForwardBy(TimeDelta::FromHours(1));
  testing::Mock::VerifyAndClear(&worker_pool);

  // Fast-forward time. Expect |task_b_raw| to be forwarded to the worker pool.
  EXPECT_CALL(worker_pool,
              PostTaskWithSequenceNowMock(task_b_raw, sequence.get(), nullptr));
  service_thread_task_runner->FastForwardBy(TimeDelta::FromHours(1));
  testing::Mock::VerifyAndClear(&worker_pool);
}

}  // namespace internal
}  // namespace base
