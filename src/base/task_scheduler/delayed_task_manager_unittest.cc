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
      : service_thread_task_runner_(new TestMockTimeTaskRunner),
        delayed_task_manager_(service_thread_task_runner_) {}
  ~TaskSchedulerDelayedTaskManagerTest() override = default;

 protected:
  scoped_refptr<TestMockTimeTaskRunner> service_thread_task_runner_;
  DelayedTaskManager delayed_task_manager_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerDelayedTaskManagerTest);
};

}  // namespace

// Verify that a delayed task isn't forwarded before it is ripe for execution.
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTaskDoesNotRunTooEarly) {
  auto task =
      MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(), kLongDelay);

  testing::StrictMock<MockTaskTarget> task_target;

  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task),
      Bind(&MockTaskTarget::PostTaskNowCallback, Unretained(&task_target)));

  // Run tasks that are ripe for execution. Don't expect any forwarding to
  // |task_target|.
  service_thread_task_runner_->RunUntilIdle();
}

// Verify that a delayed task is forwarded when it is ripe for execution.
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTaskRunsAfterDelay) {
  auto task =
      MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(), kLongDelay);
  const Task* task_raw = task.get();

  testing::StrictMock<MockTaskTarget> task_target;

  // Send |task| to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task),
      Bind(&MockTaskTarget::PostTaskNowCallback, Unretained(&task_target)));

  // Fast-forward time. Expect the task is forwarded to |task_target|.
  EXPECT_CALL(task_target, DoPostTaskNowCallback(task_raw));
  service_thread_task_runner_->FastForwardBy(kLongDelay);
}

// Verify that multiple delayed tasks are forwarded when they are ripe for
// execution.
TEST_F(TaskSchedulerDelayedTaskManagerTest, DelayedTasksRunAfterDelay) {
  auto task_a = MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(),
                                 TimeDelta::FromHours(1));
  const Task* task_a_raw = task_a.get();

  auto task_b = MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(),
                                 TimeDelta::FromHours(2));
  const Task* task_b_raw = task_b.get();

  auto task_c = MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(),
                                 TimeDelta::FromHours(1));
  const Task* task_c_raw = task_c.get();

  testing::StrictMock<MockTaskTarget> task_target;

  // Send tasks to the DelayedTaskManager.
  delayed_task_manager_.AddDelayedTask(
      std::move(task_a),
      Bind(&MockTaskTarget::PostTaskNowCallback, Unretained(&task_target)));
  delayed_task_manager_.AddDelayedTask(
      std::move(task_b),
      Bind(&MockTaskTarget::PostTaskNowCallback, Unretained(&task_target)));
  delayed_task_manager_.AddDelayedTask(
      std::move(task_c),
      Bind(&MockTaskTarget::PostTaskNowCallback, Unretained(&task_target)));

  // Run tasks that are ripe for execution on the service thread. Don't expect
  // any call to |task_target|.
  service_thread_task_runner_->RunUntilIdle();

  // Fast-forward time. Expect |task_a_raw| and |task_c_raw| to be forwarded to
  // |task_target|.
  EXPECT_CALL(task_target, DoPostTaskNowCallback(task_a_raw));
  EXPECT_CALL(task_target, DoPostTaskNowCallback(task_c_raw));
  service_thread_task_runner_->FastForwardBy(TimeDelta::FromHours(1));
  testing::Mock::VerifyAndClear(&task_target);

  // Fast-forward time. Expect |task_b_raw| to be forwarded to |task_target|.
  EXPECT_CALL(task_target, DoPostTaskNowCallback(task_b_raw));
  service_thread_task_runner_->FastForwardBy(TimeDelta::FromHours(1));
  testing::Mock::VerifyAndClear(&task_target);
}

}  // namespace internal
}  // namespace base
