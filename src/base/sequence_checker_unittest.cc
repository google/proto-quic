// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/sequence_checker_impl.h"
#include "base/sequence_token.h"
#include "base/single_thread_task_runner.h"
#include "base/test/sequenced_worker_pool_owner.h"
#include "base/threading/simple_thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

constexpr size_t kNumWorkerThreads = 3;

// Runs a callback on another thread.
class RunCallbackThread : public SimpleThread {
 public:
  explicit RunCallbackThread(const Closure& callback)
      : SimpleThread("RunCallbackThread"), callback_(callback) {
    Start();
    Join();
  }

 private:
  // SimpleThread:
  void Run() override { callback_.Run(); }

  const Closure callback_;

  DISALLOW_COPY_AND_ASSIGN(RunCallbackThread);
};

class SequenceCheckerTest : public testing::Test {
 protected:
  SequenceCheckerTest() : pool_owner_(kNumWorkerThreads, "test") {}

  void PostToSequencedWorkerPool(const Closure& callback,
                                 const std::string& token_name) {
    pool_owner_.pool()->PostNamedSequencedWorkerTask(token_name, FROM_HERE,
                                                     callback);
  }

  void FlushSequencedWorkerPoolForTesting() {
    pool_owner_.pool()->FlushForTesting();
  }

 private:
  MessageLoop message_loop_;  // Needed by SequencedWorkerPool to function.
  SequencedWorkerPoolOwner pool_owner_;

  DISALLOW_COPY_AND_ASSIGN(SequenceCheckerTest);
};

void ExpectCalledOnValidSequence(SequenceCheckerImpl* sequence_checker) {
  ASSERT_TRUE(sequence_checker);

  // This should bind |sequence_checker| to the current sequence if it wasn't
  // already bound to a sequence.
  EXPECT_TRUE(sequence_checker->CalledOnValidSequence());

  // Since |sequence_checker| is now bound to the current sequence, another call
  // to CalledOnValidSequence() should return true.
  EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
}

void ExpectCalledOnValidSequenceWithSequenceToken(
    SequenceCheckerImpl* sequence_checker,
    SequenceToken sequence_token) {
  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(sequence_token);
  ExpectCalledOnValidSequence(sequence_checker);
}

void ExpectNotCalledOnValidSequence(SequenceCheckerImpl* sequence_checker) {
  ASSERT_TRUE(sequence_checker);
  EXPECT_FALSE(sequence_checker->CalledOnValidSequence());
}

}  // namespace

TEST_F(SequenceCheckerTest, CallsAllowedOnSameThreadNoSequenceToken) {
  SequenceCheckerImpl sequence_checker;
  EXPECT_TRUE(sequence_checker.CalledOnValidSequence());
}

TEST_F(SequenceCheckerTest, CallsAllowedOnSameThreadSameSequenceToken) {
  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
  SequenceCheckerImpl sequence_checker;
  EXPECT_TRUE(sequence_checker.CalledOnValidSequence());
}

TEST_F(SequenceCheckerTest, CallsDisallowedOnDifferentThreadsNoSequenceToken) {
  SequenceCheckerImpl sequence_checker;
  RunCallbackThread thread(
      Bind(&ExpectNotCalledOnValidSequence, Unretained(&sequence_checker)));
}

TEST_F(SequenceCheckerTest, CallsAllowedOnDifferentThreadsSameSequenceToken) {
  const SequenceToken sequence_token(SequenceToken::Create());

  ScopedSetSequenceTokenForCurrentThread
      scoped_set_sequence_token_for_current_thread(sequence_token);
  SequenceCheckerImpl sequence_checker;
  EXPECT_TRUE(sequence_checker.CalledOnValidSequence());

  RunCallbackThread thread(Bind(&ExpectCalledOnValidSequenceWithSequenceToken,
                                Unretained(&sequence_checker), sequence_token));
}

TEST_F(SequenceCheckerTest, CallsDisallowedOnSameThreadDifferentSequenceToken) {
  std::unique_ptr<SequenceCheckerImpl> sequence_checker;

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    sequence_checker.reset(new SequenceCheckerImpl);
  }

  {
    // Different SequenceToken.
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    EXPECT_FALSE(sequence_checker->CalledOnValidSequence());
  }

  // No SequenceToken.
  EXPECT_FALSE(sequence_checker->CalledOnValidSequence());
}

TEST_F(SequenceCheckerTest, DetachFromSequence) {
  std::unique_ptr<SequenceCheckerImpl> sequence_checker;

  {
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    sequence_checker.reset(new SequenceCheckerImpl);
  }

  sequence_checker->DetachFromSequence();

  {
    // Verify that CalledOnValidSequence() returns true when called with
    // a different sequence token after a call to DetachFromSequence().
    ScopedSetSequenceTokenForCurrentThread
        scoped_set_sequence_token_for_current_thread(SequenceToken::Create());
    EXPECT_TRUE(sequence_checker->CalledOnValidSequence());
  }
}

TEST_F(SequenceCheckerTest, DetachFromSequenceNoSequenceToken) {
  SequenceCheckerImpl sequence_checker;
  sequence_checker.DetachFromSequence();

  // Verify that CalledOnValidSequence() returns true when called on a
  // different thread after a call to DetachFromSequence().
  RunCallbackThread thread(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)));

  EXPECT_FALSE(sequence_checker.CalledOnValidSequence());
}

TEST_F(SequenceCheckerTest, SequencedWorkerPool_SameSequenceTokenValid) {
  SequenceCheckerImpl sequence_checker;
  sequence_checker.DetachFromSequence();

  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  FlushSequencedWorkerPoolForTesting();
}

TEST_F(SequenceCheckerTest, SequencedWorkerPool_DetachSequenceTokenValid) {
  SequenceCheckerImpl sequence_checker;
  sequence_checker.DetachFromSequence();

  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  FlushSequencedWorkerPoolForTesting();

  sequence_checker.DetachFromSequence();

  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "B");
  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "B");
  FlushSequencedWorkerPoolForTesting();
}

TEST_F(SequenceCheckerTest,
       SequencedWorkerPool_DifferentSequenceTokensInvalid) {
  SequenceCheckerImpl sequence_checker;
  sequence_checker.DetachFromSequence();

  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  FlushSequencedWorkerPoolForTesting();

  PostToSequencedWorkerPool(
      Bind(&ExpectNotCalledOnValidSequence, Unretained(&sequence_checker)),
      "B");
  PostToSequencedWorkerPool(
      Bind(&ExpectNotCalledOnValidSequence, Unretained(&sequence_checker)),
      "B");
  FlushSequencedWorkerPoolForTesting();
}

TEST_F(SequenceCheckerTest,
       SequencedWorkerPool_WorkerPoolAndSimpleThreadInvalid) {
  SequenceCheckerImpl sequence_checker;
  sequence_checker.DetachFromSequence();

  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  FlushSequencedWorkerPoolForTesting();

  EXPECT_FALSE(sequence_checker.CalledOnValidSequence());
}

TEST_F(SequenceCheckerTest,
       SequencedWorkerPool_TwoDifferentWorkerPoolsInvalid) {
  SequenceCheckerImpl sequence_checker;
  sequence_checker.DetachFromSequence();

  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  PostToSequencedWorkerPool(
      Bind(&ExpectCalledOnValidSequence, Unretained(&sequence_checker)), "A");
  FlushSequencedWorkerPoolForTesting();

  SequencedWorkerPoolOwner second_pool_owner(kNumWorkerThreads, "test2");
  second_pool_owner.pool()->PostNamedSequencedWorkerTask(
      "A", FROM_HERE, base::Bind(&ExpectNotCalledOnValidSequence,
                                 base::Unretained(&sequence_checker)));
  second_pool_owner.pool()->FlushForTesting();
}

}  // namespace base
