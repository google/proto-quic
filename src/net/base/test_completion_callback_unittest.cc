// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Illustrates how to use worker threads that issue completion callbacks

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/worker_pool.h"
#include "net/base/completion_callback.h"
#include "net/base/test_completion_callback.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace net {

namespace {

const int kMagicResult = 8888;

void CallClosureAfterCheckingResult(const base::Closure& closure,
                                    bool* did_check_result,
                                    int result) {
  DCHECK_EQ(result, kMagicResult);
  *did_check_result = true;
  closure.Run();
}

// ExampleEmployer is a toy version of HostResolver
// TODO: restore damage done in extracting example from real code
// (e.g. bring back real destructor, bring back comments)
class ExampleEmployer {
 public:
  ExampleEmployer();
  ~ExampleEmployer();

  // Do some imaginary work on a worker thread;
  // when done, worker posts callback on the original thread.
  // Returns true on success
  bool DoSomething(const CompletionCallback& callback);

 private:
  class ExampleWorker;
  friend class ExampleWorker;
  scoped_refptr<ExampleWorker> request_;
  DISALLOW_COPY_AND_ASSIGN(ExampleEmployer);
};

// Helper class; this is how ExampleEmployer puts work on a different thread
class ExampleEmployer::ExampleWorker
    : public base::RefCountedThreadSafe<ExampleWorker> {
 public:
  ExampleWorker(ExampleEmployer* employer, const CompletionCallback& callback)
      : employer_(employer),
        callback_(callback),
        origin_loop_(base::MessageLoop::current()) {}
  void DoWork();
  void DoCallback();
 private:
  friend class base::RefCountedThreadSafe<ExampleWorker>;

  ~ExampleWorker() {}

  // Only used on the origin thread (where DoSomething was called).
  ExampleEmployer* employer_;
  CompletionCallback callback_;
  // Used to post ourselves onto the origin thread.
  base::Lock origin_loop_lock_;
  base::MessageLoop* origin_loop_;
};

void ExampleEmployer::ExampleWorker::DoWork() {
  // Running on the worker thread
  // In a real worker thread, some work would be done here.
  // Pretend it is, and send the completion callback.

  // The origin loop could go away while we are trying to post to it, so we
  // need to call its PostTask method inside a lock.  See ~ExampleEmployer.
  {
    base::AutoLock locked(origin_loop_lock_);
    if (origin_loop_)
      origin_loop_->task_runner()->PostTask(
          FROM_HERE, base::Bind(&ExampleWorker::DoCallback, this));
  }
}

void ExampleEmployer::ExampleWorker::DoCallback() {
  // Running on the origin thread.

  // Drop the employer_'s reference to us.  Do this before running the
  // callback since the callback might result in the employer being
  // destroyed.
  employer_->request_ = NULL;

  callback_.Run(kMagicResult);
}

ExampleEmployer::ExampleEmployer() {
}

ExampleEmployer::~ExampleEmployer() {
}

bool ExampleEmployer::DoSomething(const CompletionCallback& callback) {
  DCHECK(!request_.get()) << "already in use";

  request_ = new ExampleWorker(this, callback);

  // Dispatch to worker thread...
  if (!base::WorkerPool::PostTask(
          FROM_HERE, base::Bind(&ExampleWorker::DoWork, request_), true)) {
    NOTREACHED();
    request_ = NULL;
    return false;
  }

  return true;
}

}  // namespace

typedef PlatformTest TestCompletionCallbackTest;

TEST_F(TestCompletionCallbackTest, Simple) {
  ExampleEmployer boss;
  TestCompletionCallback callback;
  bool queued = boss.DoSomething(callback.callback());
  EXPECT_TRUE(queued);
  int result = callback.WaitForResult();
  EXPECT_EQ(result, kMagicResult);
}

TEST_F(TestCompletionCallbackTest, Closure) {
  ExampleEmployer boss;
  TestClosure closure;
  bool did_check_result = false;
  CompletionCallback completion_callback =
      base::Bind(&CallClosureAfterCheckingResult, closure.closure(),
                 base::Unretained(&did_check_result));
  bool queued = boss.DoSomething(completion_callback);
  EXPECT_TRUE(queued);

  EXPECT_FALSE(did_check_result);
  closure.WaitForResult();
  EXPECT_TRUE(did_check_result);
}

// TODO: test deleting ExampleEmployer while work outstanding

}  // namespace net
