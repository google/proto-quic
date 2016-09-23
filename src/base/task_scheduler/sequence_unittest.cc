// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/sequence.h"

#include <utility>

#include "base/bind.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

namespace {

// A class that pushes a Task to a Sequence in its destructor.
class PushTaskInDestructor {
 public:
  explicit PushTaskInDestructor(scoped_refptr<Sequence> sequence)
      : sequence_(std::move(sequence)) {}
  PushTaskInDestructor(PushTaskInDestructor&&) = default;
  PushTaskInDestructor& operator=(PushTaskInDestructor&&) = default;

  ~PushTaskInDestructor() {
    // |sequence_| may be nullptr in a temporary instance of this class.
    if (sequence_) {
      EXPECT_FALSE(sequence_->PeekTask());
      sequence_->PushTask(WrapUnique(
          new Task(FROM_HERE, Closure(), TaskTraits(), TimeDelta())));
    }
  }

 private:
  scoped_refptr<Sequence> sequence_;

  DISALLOW_COPY_AND_ASSIGN(PushTaskInDestructor);
};

void DoNothing(const PushTaskInDestructor&) {}

class TaskSchedulerSequenceTest : public testing::Test {
 public:
  TaskSchedulerSequenceTest()
      : task_a_owned_(
            new Task(FROM_HERE,
                     Closure(),
                     TaskTraits().WithPriority(TaskPriority::BACKGROUND),
                     TimeDelta())),
        task_b_owned_(
            new Task(FROM_HERE,
                     Closure(),
                     TaskTraits().WithPriority(TaskPriority::USER_VISIBLE),
                     TimeDelta())),
        task_c_owned_(
            new Task(FROM_HERE,
                     Closure(),
                     TaskTraits().WithPriority(TaskPriority::USER_BLOCKING),
                     TimeDelta())),
        task_d_owned_(
            new Task(FROM_HERE,
                     Closure(),
                     TaskTraits().WithPriority(TaskPriority::USER_BLOCKING),
                     TimeDelta())),
        task_e_owned_(
            new Task(FROM_HERE,
                     Closure(),
                     TaskTraits().WithPriority(TaskPriority::BACKGROUND),
                     TimeDelta())),
        task_a_(task_a_owned_.get()),
        task_b_(task_b_owned_.get()),
        task_c_(task_c_owned_.get()),
        task_d_(task_d_owned_.get()),
        task_e_(task_e_owned_.get()) {}

 protected:
  // Tasks to be handed off to a Sequence for testing.
  std::unique_ptr<Task> task_a_owned_;
  std::unique_ptr<Task> task_b_owned_;
  std::unique_ptr<Task> task_c_owned_;
  std::unique_ptr<Task> task_d_owned_;
  std::unique_ptr<Task> task_e_owned_;

  // Raw pointers to those same tasks for verification. This is needed because
  // the scoped_ptrs above no longer point to the tasks once they have been
  // moved into a Sequence.
  const Task* task_a_;
  const Task* task_b_;
  const Task* task_c_;
  const Task* task_d_;
  const Task* task_e_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerSequenceTest);
};

}  // namespace

TEST_F(TaskSchedulerSequenceTest, PushPopPeek) {
  scoped_refptr<Sequence> sequence(new Sequence);

  // Push task A in the sequence. Its sequenced time should be updated and it
  // should be in front of the sequence.
  EXPECT_TRUE(sequence->PushTask(std::move(task_a_owned_)));
  EXPECT_FALSE(task_a_->sequenced_time.is_null());
  EXPECT_EQ(task_a_, sequence->PeekTask());

  // Push task B, C and D in the sequence. Their sequenced time should be
  // updated and task A should always remain in front of the sequence.
  EXPECT_FALSE(sequence->PushTask(std::move(task_b_owned_)));
  EXPECT_FALSE(task_b_->sequenced_time.is_null());
  EXPECT_EQ(task_a_, sequence->PeekTask());

  EXPECT_FALSE(sequence->PushTask(std::move(task_c_owned_)));
  EXPECT_FALSE(task_c_->sequenced_time.is_null());
  EXPECT_EQ(task_a_, sequence->PeekTask());

  EXPECT_FALSE(sequence->PushTask(std::move(task_d_owned_)));
  EXPECT_FALSE(task_d_->sequenced_time.is_null());
  EXPECT_EQ(task_a_, sequence->PeekTask());

  // Pop task A. Task B should now be in front.
  EXPECT_FALSE(sequence->PopTask());
  EXPECT_EQ(task_b_, sequence->PeekTask());

  // Pop task B. Task C should now be in front.
  EXPECT_FALSE(sequence->PopTask());
  EXPECT_EQ(task_c_, sequence->PeekTask());

  // Pop task C. Task D should now be in front.
  EXPECT_FALSE(sequence->PopTask());
  EXPECT_EQ(task_d_, sequence->PeekTask());

  // Push task E in the sequence. Its sequenced time should be updated and
  // task D should remain in front.
  EXPECT_FALSE(sequence->PushTask(std::move(task_e_owned_)));
  EXPECT_FALSE(task_e_->sequenced_time.is_null());
  EXPECT_EQ(task_d_, sequence->PeekTask());

  // Pop task D. Task E should now be in front.
  EXPECT_FALSE(sequence->PopTask());
  EXPECT_EQ(task_e_, sequence->PeekTask());

  // Pop task E. The sequence should now be empty.
  EXPECT_TRUE(sequence->PopTask());
  EXPECT_EQ(nullptr, sequence->PeekTask());
}

TEST_F(TaskSchedulerSequenceTest, GetSortKey) {
  scoped_refptr<Sequence> sequence(new Sequence);

  // Push task A in the sequence. The highest priority is from task A
  // (BACKGROUND). Task A is in front of the sequence.
  sequence->PushTask(std::move(task_a_owned_));
  EXPECT_EQ(SequenceSortKey(TaskPriority::BACKGROUND, task_a_->sequenced_time),
            sequence->GetSortKey());

  // Push task B in the sequence. The highest priority is from task B
  // (USER_VISIBLE). Task A is still in front of the sequence.
  sequence->PushTask(std::move(task_b_owned_));
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_VISIBLE, task_a_->sequenced_time),
      sequence->GetSortKey());

  // Push task C in the sequence. The highest priority is from task C
  // (USER_BLOCKING). Task A is still in front of the sequence.
  sequence->PushTask(std::move(task_c_owned_));
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_a_->sequenced_time),
      sequence->GetSortKey());

  // Push task D in the sequence. The highest priority is from tasks C/D
  // (USER_BLOCKING). Task A is still in front of the sequence.
  sequence->PushTask(std::move(task_d_owned_));
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_a_->sequenced_time),
      sequence->GetSortKey());

  // Pop task A. The highest priority is still USER_BLOCKING. The task in front
  // of the sequence is now task B.
  sequence->PopTask();
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_b_->sequenced_time),
      sequence->GetSortKey());

  // Pop task B. The highest priority is still USER_BLOCKING. The task in front
  // of the sequence is now task C.
  sequence->PopTask();
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_c_->sequenced_time),
      sequence->GetSortKey());

  // Pop task C. The highest priority is still USER_BLOCKING. The task in front
  // of the sequence is now task D.
  sequence->PopTask();
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_d_->sequenced_time),
      sequence->GetSortKey());

  // Push task E in the sequence. The highest priority is still USER_BLOCKING.
  // The task in front of the sequence is still task D.
  sequence->PushTask(std::move(task_e_owned_));
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_d_->sequenced_time),
      sequence->GetSortKey());

  // Pop task D. The highest priority is now from task E (BACKGROUND). The
  // task in front of the sequence is now task E.
  sequence->PopTask();
  EXPECT_EQ(SequenceSortKey(TaskPriority::BACKGROUND, task_e_->sequenced_time),
            sequence->GetSortKey());
}

TEST_F(TaskSchedulerSequenceTest, CanPushTaskInTaskDestructor) {
  scoped_refptr<Sequence> sequence(new Sequence);
  sequence->PushTask(MakeUnique<Task>(
      FROM_HERE, Bind(&DoNothing, PushTaskInDestructor(sequence)), TaskTraits(),
      TimeDelta()));

  // PushTask() is invoked on |sequence| when the popped Task is destroyed. If
  // PopTask() destroys the Task outside the scope of its lock as expected, no
  // deadlock will occur when PushTask() tries to acquire the Sequence's lock.
  sequence->PopTask();

  // Verify that |sequence| contains exactly one Task.
  EXPECT_TRUE(sequence->PeekTask());
  EXPECT_TRUE(sequence->PopTask());
}

}  // namespace internal
}  // namespace base
