// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/post_task_and_reply_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;

namespace base {
namespace internal {

namespace {

class PostTaskAndReplyTaskRunner : public internal::PostTaskAndReplyImpl {
 public:
  explicit PostTaskAndReplyTaskRunner(TaskRunner* destination)
      : destination_(destination) {}

 private:
  bool PostTask(const tracked_objects::Location& from_here,
                OnceClosure task) override {
    return destination_->PostTask(from_here, std::move(task));
  }

  // Non-owning.
  TaskRunner* const destination_;
};

class ObjectToDelete : public RefCounted<ObjectToDelete> {
 public:
  // |delete_flag| is set to true when this object is deleted
  ObjectToDelete(bool* delete_flag) : delete_flag_(delete_flag) {
    EXPECT_FALSE(*delete_flag_);
  }

 private:
  friend class RefCounted<ObjectToDelete>;
  ~ObjectToDelete() { *delete_flag_ = true; }

  bool* const delete_flag_;

  DISALLOW_COPY_AND_ASSIGN(ObjectToDelete);
};

class MockObject {
 public:
  MockObject() = default;

  MOCK_METHOD1(Task, void(scoped_refptr<ObjectToDelete>));
  MOCK_METHOD0(Reply, void());

 private:
  DISALLOW_COPY_AND_ASSIGN(MockObject);
};

}  // namespace

TEST(PostTaskAndReplyImplTest, PostTaskAndReply) {
  scoped_refptr<TestSimpleTaskRunner> post_runner(new TestSimpleTaskRunner);
  scoped_refptr<TestSimpleTaskRunner> reply_runner(new TestSimpleTaskRunner);
  ThreadTaskRunnerHandle task_runner_handle(reply_runner);

  testing::StrictMock<MockObject> mock_object;
  bool delete_flag = false;

  EXPECT_TRUE(
      PostTaskAndReplyTaskRunner(post_runner.get())
          .PostTaskAndReply(
              FROM_HERE,
              BindOnce(&MockObject::Task, Unretained(&mock_object),
                       make_scoped_refptr(new ObjectToDelete(&delete_flag))),
              BindOnce(&MockObject::Reply, Unretained(&mock_object))));

  // Expect the task to be posted to |post_runner|.
  EXPECT_TRUE(post_runner->HasPendingTask());
  EXPECT_FALSE(reply_runner->HasPendingTask());
  EXPECT_FALSE(delete_flag);

  EXPECT_CALL(mock_object, Task(_));
  post_runner->RunUntilIdle();
  testing::Mock::VerifyAndClear(&mock_object);

  // |task| should have been deleted right after being run.
  EXPECT_TRUE(delete_flag);

  // Expect the reply to be posted to |reply_runner|.
  EXPECT_FALSE(post_runner->HasPendingTask());
  EXPECT_TRUE(reply_runner->HasPendingTask());

  EXPECT_CALL(mock_object, Reply());
  reply_runner->RunUntilIdle();
  testing::Mock::VerifyAndClear(&mock_object);
  EXPECT_TRUE(delete_flag);

  // Expect no pending task in |post_runner| and |reply_runner|.
  EXPECT_FALSE(post_runner->HasPendingTask());
  EXPECT_FALSE(reply_runner->HasPendingTask());
}

}  // namespace internal
}  // namespace base
