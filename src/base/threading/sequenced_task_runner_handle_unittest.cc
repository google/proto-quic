// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/sequenced_task_runner_handle.h"

#include <memory>

#include "base/bind.h"
#include "base/callback.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/sequence_checker_impl.h"
#include "base/sequenced_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/sequenced_worker_pool_owner.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace {

class SequencedTaskRunnerHandleTest : public ::testing::Test {
 protected:
  // Verifies that the context it runs on has a SequencedTaskRunnerHandle
  // and that posting to it results in the posted task running in that same
  // context (sequence). Runs |callback| on sequence when done.
  static void VerifyCurrentSequencedTaskRunner(const Closure& callback) {
    ASSERT_TRUE(SequencedTaskRunnerHandle::IsSet());
    scoped_refptr<SequencedTaskRunner> task_runner =
        SequencedTaskRunnerHandle::Get();
    ASSERT_TRUE(task_runner);

    // Use SequenceCheckerImpl to make sure it's not a no-op in Release builds.
    std::unique_ptr<SequenceCheckerImpl> sequence_checker(
        new SequenceCheckerImpl);
    task_runner->PostTask(
        FROM_HERE,
        base::Bind(&SequencedTaskRunnerHandleTest::CheckValidSequence,
                   base::Passed(&sequence_checker), callback));
  }

  // Verifies that there is no SequencedTaskRunnerHandle in the context it runs.
  // Runs |callback| when done.
  static void VerifyNoSequencedTaskRunner(const Closure& callback) {
    ASSERT_FALSE(SequencedTaskRunnerHandle::IsSet());
    callback.Run();
  }

 private:
  static void CheckValidSequence(
      std::unique_ptr<SequenceCheckerImpl> sequence_checker,
      const Closure& callback) {
    EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
    callback.Run();
  }

  MessageLoop message_loop_;
};

TEST_F(SequencedTaskRunnerHandleTest, FromMessageLoop) {
  RunLoop run_loop;
  VerifyCurrentSequencedTaskRunner(run_loop.QuitClosure());
  run_loop.Run();
}

TEST_F(SequencedTaskRunnerHandleTest, FromSequencedWorkerPoolTask) {
  // Wrap the SequencedWorkerPool to avoid leaks due to its asynchronous
  // destruction.
  SequencedWorkerPoolOwner owner(3, "Test");
  WaitableEvent event(WaitableEvent::ResetPolicy::AUTOMATIC,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  owner.pool()->PostSequencedWorkerTask(
      owner.pool()->GetSequenceToken(), FROM_HERE,
      base::Bind(
          &SequencedTaskRunnerHandleTest::VerifyCurrentSequencedTaskRunner,
          base::Bind(&WaitableEvent::Signal, base::Unretained(&event))));
  event.Wait();
}

TEST_F(SequencedTaskRunnerHandleTest, NoHandleFromUnsequencedTask) {
  // Wrap the SequencedWorkerPool to avoid leaks due to its asynchronous
  // destruction.
  SequencedWorkerPoolOwner owner(3, "Test");
  WaitableEvent event(WaitableEvent::ResetPolicy::AUTOMATIC,
                      WaitableEvent::InitialState::NOT_SIGNALED);
  owner.pool()->PostWorkerTask(
      FROM_HERE,
      base::Bind(
          &SequencedTaskRunnerHandleTest::VerifyNoSequencedTaskRunner,
          base::Bind(&WaitableEvent::Signal, base::Unretained(&event))));
  event.Wait();
}

TEST(SequencedTaskRunnerHandleTestWithoutMessageLoop, FromHandleInScope) {
  scoped_refptr<SequencedTaskRunner> test_task_runner(new TestSimpleTaskRunner);
  EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
  EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
  {
    SequencedTaskRunnerHandle handle(test_task_runner);
    EXPECT_TRUE(SequencedTaskRunnerHandle::IsSet());
    EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
    EXPECT_EQ(test_task_runner, SequencedTaskRunnerHandle::Get());
  }
  EXPECT_FALSE(SequencedTaskRunnerHandle::IsSet());
  EXPECT_FALSE(ThreadTaskRunnerHandle::IsSet());
}

}  // namespace
}  // namespace base
