// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/delayed_task_manager.h"

#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/task_scheduler/task.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {
namespace {

constexpr TimeDelta kLongDelay = TimeDelta::FromHours(1);

class MockTaskTarget {
 public:
  MockTaskTarget() = default;
  ~MockTaskTarget() = default;

  // gMock currently doesn't support move-only types, so PostTaskNowCallback()
  // handles the move-only type and forwards to the mocked method.
  MOCK_METHOD1(DoPostTaskNowCallback, void(const Task*));

  void PostTaskNowCallback(std::unique_ptr<Task> task) {
    DoPostTaskNowCallback(task.get());
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MockTaskTarget);
};

class TaskSchedulerDelayedTaskManagerTest : public testing::Test {
 public:
  TaskSchedulerDelayedTaskManagerTest()
      : delayed_task_manager_(service_thread_task_runner_->GetMockTickClock()) {
  }
  ~TaskSchedulerDelayedTaskManagerTest() override = default;

 protected:
  std::unique_ptr<Task> CreateTask(TimeDelta delay) {
    auto task =
        MakeUnique<Task>(FROM_HERE, BindOnce(&DoNothing), TaskTraits(), delay);

    // The constructor of Task computes |delayed_run_time| by adding |delay| to
    // the real time. Recompute it by adding |delay| to the mock time.
    task->delayed_run_time =
        service_thread_task_runner_->GetMockTickClock()->NowTicks() + delay;

    return task;
  }

  testing::StrictMock<MockTaskTarget> task_target_;
  const scoped_refptr<TestMockTimeTaskRunner> service_thread_task_runner_ =
      make_scoped_refptr(new TestMockTimeTaskRunner);
  DelayedTaskManager delayed_task_manager_;
  std::unique_ptr<Task> task_ = CreateTask(kLongDelay);
  Task* const task_raw_ = task_.get();

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerDelayedTaskManagerTest);
};

}  // namespace

// Verify that a delayed task isn't forwarded before Start().
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTaskDoesNotRunBeforeStart) {
  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                 Unretained(&task_target_)));

  // Fast-forward time until the task is ripe for execution. Since Start() has
  // not been called, the task should be forwarded to |task_target_|
  // (|task_target_| is a StrictMock without expectations, so the test will fail
  // if the task is forwarded to it).
  service_thread_task_runner_->FastForwardBy(kLongDelay);
}

// Verify that a delayed task added before Start() and whose delay expires after
// Start() is forwarded when its delay expires.
TEST_F(TaskSchedulerDelayedTaskManagerTest,
       DelayedTaskPostedBeforeStartExpiresAfterStartRunsOnExpire) {
  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                 Unretained(&task_target_)));

  delayed_task_manager_.Start(service_thread_task_runner_);

  // Run tasks on the service thread. Don't expect any forwarding to
  // |task_target_| since the task isn't ripe for execution.
  service_thread_task_runner_->RunUntilIdle();

  // Fast-forward time until the task is ripe for execution. Expect the task to
  // be forwarded to |task_target_|.
  EXPECT_CALL(task_target_, DoPostTaskNowCallback(task_raw_));
  service_thread_task_runner_->FastForwardBy(kLongDelay);
}

// Verify that a delayed task added before Start() and whose delay expires
// before Start() is forwarded when Start() is called.
TEST_F(TaskSchedulerDelayedTaskManagerTest,
       DelayedTaskPostedBeforeStartExpiresBeforeStartRunsOnStart) {
  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                 Unretained(&task_target_)));

  // Run tasks on the service thread. Don't expect any forwarding to
  // |task_target_| since the task isn't ripe for execution.
  service_thread_task_runner_->RunUntilIdle();

  // Fast-forward time until the task is ripe for execution. Don't expect the
  // task to be forwarded since Start() hasn't been called yet.
  service_thread_task_runner_->FastForwardBy(kLongDelay);

  // Start the DelayedTaskManager. Expect the task to be forwarded to
  // |task_target_|.
  EXPECT_CALL(task_target_, DoPostTaskNowCallback(task_raw_));
  delayed_task_manager_.Start(service_thread_task_runner_);
  service_thread_task_runner_->RunUntilIdle();
}

// Verify that a delayed task added after Start() isn't forwarded before it is
// ripe for execution.
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTaskDoesNotRunTooEarly) {
  delayed_task_manager_.Start(service_thread_task_runner_);

  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                 Unretained(&task_target_)));

  // Run tasks that are ripe for execution. Don't expect any forwarding to
  // |task_target_|.
  service_thread_task_runner_->RunUntilIdle();
}

// Verify that a delayed task added after Start() is forwarded when it is ripe
// for execution.
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTaskRunsAfterDelay) {
  delayed_task_manager_.Start(service_thread_task_runner_);

  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                 Unretained(&task_target_)));

  // Fast-forward time. Expect the task is forwarded to |task_target_|.
  EXPECT_CALL(task_target_, DoPostTaskNowCallback(task_raw_));
  service_thread_task_runner_->FastForwardBy(kLongDelay);
}

// Verify that multiple delayed tasks added after Start() are forwarded when
// they are ripe for execution.
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTasksRunAfterDelay) {
  delayed_task_manager_.Start(service_thread_task_runner_);
  auto task_a = MakeUnique<Task>(FROM_HERE, BindOnce(&DoNothing), TaskTraits(),
                                 TimeDelta::FromHours(1));
  const Task* task_a_raw = task_a.get();

  auto task_b = MakeUnique<Task>(FROM_HERE, BindOnce(&DoNothing), TaskTraits(),
                                 TimeDelta::FromHours(2));
  const Task* task_b_raw = task_b.get();

  auto task_c = MakeUnique<Task>(FROM_HERE, BindOnce(&DoNothing), TaskTraits(),
                                 TimeDelta::FromHours(1));
  const Task* task_c_raw = task_c.get();

  // Send tasks to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_a), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                  Unretained(&task_target_)));
  delayed_task_manager_.AddDelayedTask(
      std::move(task_b), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                  Unretained(&task_target_)));
  delayed_task_manager_.AddDelayedTask(
      std::move(task_c), BindOnce(&MockTaskTarget::PostTaskNowCallback,
                                  Unretained(&task_target_)));

  // Run tasks that are ripe for execution on the service thread. Don't expect
  // any call to |task_target_|.
  service_thread_task_runner_->RunUntilIdle();

  // Fast-forward time. Expect |task_a_raw| and |task_c_raw| to be forwarded to
  // |task_target_|.
  EXPECT_CALL(task_target_, DoPostTaskNowCallback(task_a_raw));
  EXPECT_CALL(task_target_, DoPostTaskNowCallback(task_c_raw));
  service_thread_task_runner_->FastForwardBy(TimeDelta::FromHours(1));
  testing::Mock::VerifyAndClear(&task_target_);

  // Fast-forward time. Expect |task_b_raw| to be forwarded to |task_target_|.
  EXPECT_CALL(task_target_, DoPostTaskNowCallback(task_b_raw));
  service_thread_task_runner_->FastForwardBy(TimeDelta::FromHours(1));
  testing::Mock::VerifyAndClear(&task_target_);
}

}  // namespace internal
}  // namespace base
