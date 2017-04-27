// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/sequenced_task_runner.h"

#include "base/bind.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/threading/thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace {

struct DeleteCounter {
  DeleteCounter(int* counter, scoped_refptr<SequencedTaskRunner> task_runner)
      : counter_(counter),
        task_runner_(std::move(task_runner)) {
  }
  ~DeleteCounter() {
    ++*counter_;
    EXPECT_TRUE(!task_runner_ || task_runner_->RunsTasksOnCurrentThread());
  }

  int* counter_;
  scoped_refptr<SequencedTaskRunner> task_runner_;
};

}  // namespace

TEST(SequencedTaskRunnerTest, OnTaskRunnerDeleter) {
  base::MessageLoop message_loop;
  base::Thread thread("Foreign");
  thread.Start();

  scoped_refptr<SequencedTaskRunner> current_thread =
      message_loop.task_runner();
  scoped_refptr<SequencedTaskRunner> foreign_thread =
      thread.task_runner();

  using SequenceBoundUniquePtr =
      std::unique_ptr<DeleteCounter, OnTaskRunnerDeleter>;

  int counter = 0;
  SequenceBoundUniquePtr ptr(new DeleteCounter(&counter, current_thread),
                             OnTaskRunnerDeleter(current_thread));
  EXPECT_EQ(0, counter);
  foreign_thread->PostTask(
      FROM_HERE, BindOnce([](SequenceBoundUniquePtr) {}, Passed(&ptr)));

  {
    RunLoop run_loop;
    foreign_thread->PostTaskAndReply(FROM_HERE, BindOnce([] {}),
                                     run_loop.QuitClosure());
    run_loop.Run();
  }
  EXPECT_EQ(1, counter);

  DeleteCounter* raw = new DeleteCounter(&counter, nullptr);
  SequenceBoundUniquePtr ptr2(raw, OnTaskRunnerDeleter(foreign_thread));
  EXPECT_EQ(1, counter);

  thread.Stop();
  ptr2 = nullptr;
  ASSERT_EQ(1, counter);

  delete raw;
  EXPECT_EQ(2, counter);
}

}  // namespace base
