// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/sequence.h"

#include <utility>

#include "base/bind.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/test/gtest_util.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace internal {

namespace {


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
  // the unique_ptrs above no longer point to the tasks once they have been
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

TEST_F(TaskSchedulerSequenceTest, PushTakeRemove) {
  scoped_refptr<Sequence> sequence(new Sequence);

  // Push task A in the sequence. Its sequenced time should be updated and it
  // should be in front of the sequence.
  EXPECT_TRUE(sequence->PushTask(std::move(task_a_owned_)));
  EXPECT_FALSE(task_a_->sequenced_time.is_null());
  EXPECT_EQ(task_a_->traits.priority(), sequence->PeekTaskTraits().priority());

  // Push task B, C and D in the sequence. Their sequenced time should be
  // updated and task A should always remain in front of the sequence.
  EXPECT_FALSE(sequence->PushTask(std::move(task_b_owned_)));
  EXPECT_FALSE(task_b_->sequenced_time.is_null());
  EXPECT_EQ(task_a_->traits.priority(), sequence->PeekTaskTraits().priority());

  EXPECT_FALSE(sequence->PushTask(std::move(task_c_owned_)));
  EXPECT_FALSE(task_c_->sequenced_time.is_null());
  EXPECT_EQ(task_a_->traits.priority(), sequence->PeekTaskTraits().priority());

  EXPECT_FALSE(sequence->PushTask(std::move(task_d_owned_)));
  EXPECT_FALSE(task_d_->sequenced_time.is_null());
  EXPECT_EQ(task_a_->traits.priority(), sequence->PeekTaskTraits().priority());

  // Get the task in front of the sequence. It should be task A.
  EXPECT_EQ(task_a_, sequence->TakeTask().get());

  // Remove the empty slot. Task B should now be in front.
  EXPECT_FALSE(sequence->Pop());
  EXPECT_EQ(task_b_, sequence->TakeTask().get());

  // Remove the empty slot. Task C should now be in front.
  EXPECT_FALSE(sequence->Pop());
  EXPECT_EQ(task_c_, sequence->TakeTask().get());

  // Remove the empty slot. Task D should now be in front.
  EXPECT_FALSE(sequence->Pop());
  EXPECT_EQ(task_d_, sequence->TakeTask().get());

  // Push task E in the sequence. Its sequenced time should be updated.
  EXPECT_FALSE(sequence->PushTask(std::move(task_e_owned_)));
  EXPECT_FALSE(task_e_->sequenced_time.is_null());

  // Remove the empty slot. Task E should now be in front.
  EXPECT_FALSE(sequence->Pop());
  EXPECT_EQ(task_e_, sequence->TakeTask().get());

  // Remove the empty slot. The sequence should now be empty.
  EXPECT_TRUE(sequence->Pop());
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
  sequence->TakeTask();
  sequence->Pop();
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_b_->sequenced_time),
      sequence->GetSortKey());

  // Pop task B. The highest priority is still USER_BLOCKING. The task in front
  // of the sequence is now task C.
  sequence->TakeTask();
  sequence->Pop();
  EXPECT_EQ(
      SequenceSortKey(TaskPriority::USER_BLOCKING, task_c_->sequenced_time),
      sequence->GetSortKey());

  // Pop task C. The highest priority is still USER_BLOCKING. The task in front
  // of the sequence is now task D.
  sequence->TakeTask();
  sequence->Pop();
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
  sequence->TakeTask();
  sequence->Pop();
  EXPECT_EQ(SequenceSortKey(TaskPriority::BACKGROUND, task_e_->sequenced_time),
            sequence->GetSortKey());
}

// Verify that a DCHECK fires if Pop() is called on a sequence whose front slot
// isn't empty.
TEST_F(TaskSchedulerSequenceTest, PopNonEmptyFrontSlot) {
  scoped_refptr<Sequence> sequence(new Sequence);
  sequence->PushTask(
      MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));

  EXPECT_DCHECK_DEATH({ sequence->Pop(); });
}

// Verify that a DCHECK fires if TakeTask() is called on a sequence whose front
// slot is empty.
TEST_F(TaskSchedulerSequenceTest, TakeEmptyFrontSlot) {
  scoped_refptr<Sequence> sequence(new Sequence);
  sequence->PushTask(
      MakeUnique<Task>(FROM_HERE, Bind(&DoNothing), TaskTraits(), TimeDelta()));

  EXPECT_TRUE(sequence->TakeTask());
  EXPECT_DCHECK_DEATH({ sequence->TakeTask(); });
}

// Verify that a DCHECK fires if TakeTask() is called on an empty sequence.
TEST_F(TaskSchedulerSequenceTest, TakeEmptySequence) {
  scoped_refptr<Sequence> sequence(new Sequence);
  EXPECT_DCHECK_DEATH({ sequence->TakeTask(); });
}

}  // namespace internal
}  // namespace base
