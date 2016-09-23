// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/sequence_token.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/simple_thread.h"
#include "base/threading/thread_checker_impl.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace {

// A thread that runs a callback.
class RunCallbackThread : public SimpleThread {
 public:
  explicit RunCallbackThread(const Closure& callback)
      : SimpleThread("RunCallbackThread"), callback_(callback) {}

 private:
  // SimpleThread:
  void Run() override { callback_.Run(); }

  const Closure callback_;

  DISALLOW_COPY_AND_ASSIGN(RunCallbackThread);
};

// Runs a callback on a new thread synchronously.
void RunCallbackOnNewThreadSynchronously(const Closure& callback) {
  RunCallbackThread run_callback_thread(callback);
  run_callback_thread.Start();
  run_callback_thread.Join();
}

void ExpectCalledOnValidThread(ThreadCheckerImpl* thread_checker) {
  ASSERT_TRUE(thread_checker);

  // This should bind |thread_checker| to the current thread if it wasn't
  // already bound to a thread.
  EXPECT_TRUE(thread_checker->CalledOnValidThread());

  // Since |thread_checker| is now bound to the current thread, another call to
  // CalledOnValidThread() should return true.
  EXPECT_TRUE(thread_checker->CalledOnValidThread());
}

void ExpectNotCalledOnValidThread(ThreadCheckerImpl* thread_checker) {
  ASSERT_TRUE(thread_checker);
  EXPECT_FALSE(thread_checker->CalledOnValidThread());
}

void ExpectNotCalledOnValidThreadWithSequenceTokenAndThreadTaskRunnerHandle(
    ThreadCheckerImpl* thread_checker,
    SequenceToken sequence_token) {
  ThreadTaskRunnerHandle thread_task_runner_handle(
      make_scoped_refptr(new TestSimpleTaskRunner));
  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(sequence_token);
  ExpectNotCalledOnValidThread(thread_checker);
}

}  // namespace

TEST(ThreadCheckerTest, AllowedSameThreadNoSequenceToken) {
  ThreadCheckerImpl thread_checker;
  EXPECT_TRUE(thread_checker.CalledOnValidThread());
}

TEST(ThreadCheckerTest,
     AllowedSameThreadAndSequenceDifferentTasksWithThreadTaskRunnerHandle) {
  ThreadTaskRunnerHandle thread_task_runner_handle(
      make_scoped_refptr(new TestSimpleTaskRunner));

  std::unique_ptr<ThreadCheckerImpl> thread_checker;
  const SequenceToken sequence_token = SequenceToken::Create();

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(sequence_token);
    thread_checker.reset(new ThreadCheckerImpl);
  }

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(sequence_token);
    EXPECT_TRUE(thread_checker->CalledOnValidThread());
  }
}

TEST(ThreadCheckerTest,
     AllowedSameThreadSequenceAndTaskNoThreadTaskRunnerHandle) {
  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
  ThreadCheckerImpl thread_checker;
  EXPECT_TRUE(thread_checker.CalledOnValidThread());
}

TEST(ThreadCheckerTest,
     DisallowedSameThreadAndSequenceDifferentTasksNoThreadTaskRunnerHandle) {
  std::unique_ptr<ThreadCheckerImpl> thread_checker;

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    thread_checker.reset(new ThreadCheckerImpl);
  }

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    EXPECT_FALSE(thread_checker->CalledOnValidThread());
  }
}

TEST(ThreadCheckerTest, DisallowedDifferentThreadsNoSequenceToken) {
  ThreadCheckerImpl thread_checker;
  RunCallbackOnNewThreadSynchronously(
      Bind(&ExpectNotCalledOnValidThread, Unretained(&thread_checker)));
}

TEST(ThreadCheckerTest, DisallowedDifferentThreadsSameSequence) {
  ThreadTaskRunnerHandle thread_task_runner_handle(
      make_scoped_refptr(new TestSimpleTaskRunner));
  const SequenceToken sequence_token(SequenceToken::Create());

  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(sequence_token);
  ThreadCheckerImpl thread_checker;
  EXPECT_TRUE(thread_checker.CalledOnValidThread());

  RunCallbackOnNewThreadSynchronously(Bind(
      &ExpectNotCalledOnValidThreadWithSequenceTokenAndThreadTaskRunnerHandle,
      Unretained(&thread_checker), sequence_token));
}

TEST(ThreadCheckerTest, DisallowedSameThreadDifferentSequence) {
  std::unique_ptr<ThreadCheckerImpl> thread_checker;

  ThreadTaskRunnerHandle thread_task_runner_handle(
      make_scoped_refptr(new TestSimpleTaskRunner));

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    thread_checker.reset(new ThreadCheckerImpl);
  }

  {
    // Different SequenceToken.
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    EXPECT_FALSE(thread_checker->CalledOnValidThread());
  }

  // No SequenceToken.
  EXPECT_FALSE(thread_checker->CalledOnValidThread());
}

TEST(ThreadCheckerTest, DetachFromThread) {
  ThreadCheckerImpl thread_checker;
  thread_checker.DetachFromThread();

  // Verify that CalledOnValidThread() returns true when called on a different
  // thread after a call to DetachFromThread().
  RunCallbackOnNewThreadSynchronously(
      Bind(&ExpectCalledOnValidThread, Unretained(&thread_checker)));

  EXPECT_FALSE(thread_checker.CalledOnValidThread());
}

TEST(ThreadCheckerTest, DetachFromThreadWithSequenceToken) {
  ThreadTaskRunnerHandle thread_task_runner_handle(
      make_scoped_refptr(new TestSimpleTaskRunner));
  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
  ThreadCheckerImpl thread_checker;
  thread_checker.DetachFromThread();

  // Verify that CalledOnValidThread() returns true when called on a different
  // thread after a call to DetachFromThread().
  RunCallbackOnNewThreadSynchronously(
      Bind(&ExpectCalledOnValidThread, Unretained(&thread_checker)));

  EXPECT_FALSE(thread_checker.CalledOnValidThread());
}

}  // namespace base
