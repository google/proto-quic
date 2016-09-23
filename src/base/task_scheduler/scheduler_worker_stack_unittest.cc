// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker_stack.h"

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/task_scheduler/scheduler_worker.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/test/gtest_util.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

namespace {

class MockSchedulerWorkerDelegate : public SchedulerWorker::Delegate {
 public:
  void OnMainEntry(SchedulerWorker* worker,
                   const TimeDelta& detach_duration) override {}
  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    return nullptr;
  }
  void DidRunTask(const Task* task, const TimeDelta& task_latency) override {
    ADD_FAILURE() << "Unexpected call to DidRunTask()";
  }
  void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override {
    ADD_FAILURE() << "Unexpected call to ReEnqueueSequence()";
  }
  TimeDelta GetSleepTimeout() override {
    return TimeDelta::Max();
  }
  bool CanDetach(SchedulerWorker* worker) override {
    return false;
  }
};

class TaskSchedulerWorkerStackTest : public testing::Test {
 protected:
  void SetUp() override {
    worker_a_ = SchedulerWorker::Create(
        ThreadPriority::NORMAL,
        WrapUnique(new MockSchedulerWorkerDelegate), &task_tracker_,
        SchedulerWorker::InitialState::ALIVE);
    ASSERT_TRUE(worker_a_);
    worker_b_ = SchedulerWorker::Create(
        ThreadPriority::NORMAL,
        WrapUnique(new MockSchedulerWorkerDelegate), &task_tracker_,
        SchedulerWorker::InitialState::ALIVE);
    ASSERT_TRUE(worker_b_);
    worker_c_ = SchedulerWorker::Create(
        ThreadPriority::NORMAL,
        WrapUnique(new MockSchedulerWorkerDelegate), &task_tracker_,
        SchedulerWorker::InitialState::ALIVE);
    ASSERT_TRUE(worker_c_);
  }

  void TearDown() override {
    worker_a_->JoinForTesting();
    worker_b_->JoinForTesting();
    worker_c_->JoinForTesting();
  }

  std::unique_ptr<SchedulerWorker> worker_a_;
  std::unique_ptr<SchedulerWorker> worker_b_;
  std::unique_ptr<SchedulerWorker> worker_c_;

 private:
  TaskTracker task_tracker_;
};

}  // namespace

// Verify that Push() and Pop() add/remove values in FIFO order.
TEST_F(TaskSchedulerWorkerStackTest, PushPop) {
  SchedulerWorkerStack stack;
  EXPECT_EQ(nullptr, stack.Pop());

  EXPECT_TRUE(stack.IsEmpty());
  EXPECT_EQ(0U, stack.Size());

  stack.Push(worker_a_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(1U, stack.Size());

  stack.Push(worker_b_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  stack.Push(worker_c_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(3U, stack.Size());

  EXPECT_EQ(worker_c_.get(), stack.Pop());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  stack.Push(worker_c_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(3U, stack.Size());

  EXPECT_EQ(worker_c_.get(), stack.Pop());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  EXPECT_EQ(worker_b_.get(), stack.Pop());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(1U, stack.Size());

  EXPECT_EQ(worker_a_.get(), stack.Pop());
  EXPECT_TRUE(stack.IsEmpty());
  EXPECT_EQ(0U, stack.Size());

  EXPECT_EQ(nullptr, stack.Pop());
}

// Verify that Peek() returns the correct values in FIFO order.
TEST_F(TaskSchedulerWorkerStackTest, PeekPop) {
  SchedulerWorkerStack stack;
  EXPECT_EQ(nullptr, stack.Peek());

  EXPECT_TRUE(stack.IsEmpty());
  EXPECT_EQ(0U, stack.Size());

  stack.Push(worker_a_.get());
  EXPECT_EQ(worker_a_.get(), stack.Peek());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(1U, stack.Size());

  stack.Push(worker_b_.get());
  EXPECT_EQ(worker_b_.get(), stack.Peek());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  stack.Push(worker_c_.get());
  EXPECT_EQ(worker_c_.get(), stack.Peek());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(3U, stack.Size());

  EXPECT_EQ(worker_c_.get(), stack.Pop());
  EXPECT_EQ(worker_b_.get(), stack.Peek());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  EXPECT_EQ(worker_b_.get(), stack.Pop());
  EXPECT_EQ(worker_a_.get(), stack.Peek());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(1U, stack.Size());

  EXPECT_EQ(worker_a_.get(), stack.Pop());
  EXPECT_TRUE(stack.IsEmpty());
  EXPECT_EQ(0U, stack.Size());

  EXPECT_EQ(nullptr, stack.Peek());
}

// Verify that Contains() returns true for workers on the stack.
TEST_F(TaskSchedulerWorkerStackTest, Contains) {
  SchedulerWorkerStack stack;
  EXPECT_FALSE(stack.Contains(worker_a_.get()));
  EXPECT_FALSE(stack.Contains(worker_b_.get()));
  EXPECT_FALSE(stack.Contains(worker_c_.get()));

  stack.Push(worker_a_.get());
  EXPECT_TRUE(stack.Contains(worker_a_.get()));
  EXPECT_FALSE(stack.Contains(worker_b_.get()));
  EXPECT_FALSE(stack.Contains(worker_c_.get()));

  stack.Push(worker_b_.get());
  EXPECT_TRUE(stack.Contains(worker_a_.get()));
  EXPECT_TRUE(stack.Contains(worker_b_.get()));
  EXPECT_FALSE(stack.Contains(worker_c_.get()));

  stack.Push(worker_c_.get());
  EXPECT_TRUE(stack.Contains(worker_a_.get()));
  EXPECT_TRUE(stack.Contains(worker_b_.get()));
  EXPECT_TRUE(stack.Contains(worker_c_.get()));

  stack.Pop();
  EXPECT_TRUE(stack.Contains(worker_a_.get()));
  EXPECT_TRUE(stack.Contains(worker_b_.get()));
  EXPECT_FALSE(stack.Contains(worker_c_.get()));

  stack.Pop();
  EXPECT_TRUE(stack.Contains(worker_a_.get()));
  EXPECT_FALSE(stack.Contains(worker_b_.get()));
  EXPECT_FALSE(stack.Contains(worker_c_.get()));

  stack.Pop();
  EXPECT_FALSE(stack.Contains(worker_a_.get()));
  EXPECT_FALSE(stack.Contains(worker_b_.get()));
  EXPECT_FALSE(stack.Contains(worker_c_.get()));
}

// Verify that a value can be removed by Remove().
TEST_F(TaskSchedulerWorkerStackTest, Remove) {
  SchedulerWorkerStack stack;
  EXPECT_TRUE(stack.IsEmpty());
  EXPECT_EQ(0U, stack.Size());

  stack.Push(worker_a_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(1U, stack.Size());

  stack.Push(worker_b_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  stack.Push(worker_c_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(3U, stack.Size());

  stack.Remove(worker_b_.get());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(2U, stack.Size());

  EXPECT_EQ(worker_c_.get(), stack.Pop());
  EXPECT_FALSE(stack.IsEmpty());
  EXPECT_EQ(1U, stack.Size());

  EXPECT_EQ(worker_a_.get(), stack.Pop());
  EXPECT_TRUE(stack.IsEmpty());
  EXPECT_EQ(0U, stack.Size());
}

// Verify that a value can be pushed again after it has been removed.
TEST_F(TaskSchedulerWorkerStackTest, PushAfterRemove) {
  SchedulerWorkerStack stack;
  EXPECT_EQ(0U, stack.Size());
  EXPECT_TRUE(stack.IsEmpty());

  stack.Push(worker_a_.get());
  EXPECT_EQ(1U, stack.Size());
  EXPECT_FALSE(stack.IsEmpty());

  stack.Remove(worker_a_.get());
  EXPECT_EQ(0U, stack.Size());
  EXPECT_TRUE(stack.IsEmpty());

  stack.Push(worker_a_.get());
  EXPECT_EQ(1U, stack.Size());
  EXPECT_FALSE(stack.IsEmpty());
}

// Verify that Push() DCHECKs when a value is inserted twice.
TEST_F(TaskSchedulerWorkerStackTest, PushTwice) {
  SchedulerWorkerStack stack;
  stack.Push(worker_a_.get());
  EXPECT_DCHECK_DEATH({ stack.Push(worker_a_.get()); });
}

}  // namespace internal
}  // namespace base
