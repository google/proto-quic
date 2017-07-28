// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/serial_worker.h"

#include "base/bind.h"
#include "base/location.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

class SerialWorkerTest : public testing::Test {
 public:
  // The class under test
  class TestSerialWorker : public SerialWorker {
   public:
    explicit TestSerialWorker(SerialWorkerTest* t)
      : test_(t) {}
    void DoWork() override {
      ASSERT_TRUE(test_);
      test_->OnWork();
    }
    void OnWorkFinished() override {
      ASSERT_TRUE(test_);
      test_->OnWorkFinished();
    }
   private:
    ~TestSerialWorker() override {}
    SerialWorkerTest* test_;
  };

  // Mocks

  void OnWork() {
    { // Check that OnWork is executed serially.
      base::AutoLock lock(work_lock_);
      EXPECT_FALSE(work_running_) << "DoRead is not called serially!";
      work_running_ = true;
    }
    BreakNow("OnWork");
    work_allowed_.Wait();
    // Calling from WorkerPool, but protected by work_allowed_/work_called_.
    output_value_ = input_value_;

    { // This lock might be destroyed after work_called_ is signalled.
      base::AutoLock lock(work_lock_);
      work_running_ = false;
    }
    work_called_.Signal();
  }

  void OnWorkFinished() {
    EXPECT_TRUE(message_loop_->task_runner()->BelongsToCurrentThread());
    EXPECT_EQ(output_value_, input_value_);
    BreakNow("OnWorkFinished");
  }

 protected:
  void BreakCallback(const std::string& breakpoint) {
    breakpoint_ = breakpoint;
    base::RunLoop::QuitCurrentDeprecated();
  }

  void BreakNow(const std::string& b) {
    message_loop_->task_runner()->PostTask(
        FROM_HERE, base::Bind(&SerialWorkerTest::BreakCallback,
                              base::Unretained(this), b));
  }

  void RunUntilBreak(const std::string& b) {
    base::RunLoop().Run();
    ASSERT_EQ(breakpoint_, b);
  }

  SerialWorkerTest()
      : input_value_(0),
        output_value_(-1),
        work_allowed_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                      base::WaitableEvent::InitialState::NOT_SIGNALED),
        work_called_(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                     base::WaitableEvent::InitialState::NOT_SIGNALED),
        work_running_(false) {}

  // Helpers for tests.

  // Lets OnWork run and waits for it to complete. Can only return if OnWork is
  // executed on a concurrent thread.
  void WaitForWork() {
    RunUntilBreak("OnWork");
    work_allowed_.Signal();
    work_called_.Wait();
  }

  // test::Test methods
  void SetUp() override {
    message_loop_ = base::MessageLoop::current();
    worker_ = new TestSerialWorker(this);
  }

  void TearDown() override {
    // Cancel the worker to catch if it makes a late DoWork call.
    worker_->Cancel();
    // Check if OnWork is stalled.
    EXPECT_FALSE(work_running_) << "OnWork should be done by TearDown";
    // Release it for cleanliness.
    if (work_running_) {
      WaitForWork();
    }
  }

  // Input value read on WorkerPool.
  int input_value_;
  // Output value written on WorkerPool.
  int output_value_;

  // read is called on WorkerPool so we need to synchronize with it.
  base::WaitableEvent work_allowed_;
  base::WaitableEvent work_called_;

  // Protected by read_lock_. Used to verify that read calls are serialized.
  bool work_running_;
  base::Lock work_lock_;

  // Loop for this thread.
  base::MessageLoop* message_loop_;

  // WatcherDelegate under test.
  scoped_refptr<TestSerialWorker> worker_;

  std::string breakpoint_;
};

TEST_F(SerialWorkerTest, ExecuteAndSerializeReads) {
  for (int i = 0; i < 3; ++i) {
    ++input_value_;
    worker_->WorkNow();
    WaitForWork();
    RunUntilBreak("OnWorkFinished");

    EXPECT_TRUE(message_loop_->IsIdleForTesting());
  }

  // Schedule two calls. OnWork checks if it is called serially.
  ++input_value_;
  worker_->WorkNow();
  // read is blocked, so this will have to induce re-work
  worker_->WorkNow();
  WaitForWork();
  WaitForWork();
  RunUntilBreak("OnWorkFinished");

  // No more tasks should remain.
  EXPECT_TRUE(message_loop_->IsIdleForTesting());
}

}  // namespace

}  // namespace net
