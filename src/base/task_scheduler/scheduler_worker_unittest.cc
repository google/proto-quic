// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker.h"

#include <stddef.h>

#include <memory>
#include <vector>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/simple_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_WIN)
#include <objbase.h>
#endif

using testing::_;
using testing::Mock;
using testing::Ne;
using testing::StrictMock;

namespace base {
namespace internal {
namespace {

const size_t kNumSequencesPerTest = 150;

class SchedulerWorkerDefaultDelegate : public SchedulerWorker::Delegate {
 public:
  SchedulerWorkerDefaultDelegate() = default;

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker) override {}
  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    return nullptr;
  }
  void DidRunTask() override {
    ADD_FAILURE() << "Unexpected call to DidRunTask()";
  }
  void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override {
    ADD_FAILURE() << "Unexpected call to ReEnqueueSequence()";
  }
  TimeDelta GetSleepTimeout() override { return TimeDelta::Max(); }
  bool CanDetach(SchedulerWorker* worker) override { return false; }
  void OnDetach() override { ADD_FAILURE() << "Unexpected call to OnDetach()"; }

 private:
  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerDefaultDelegate);
};

// The test parameter is the number of Tasks per Sequence returned by GetWork().
class TaskSchedulerWorkerTest : public testing::TestWithParam<size_t> {
 protected:
  TaskSchedulerWorkerTest()
      : main_entry_called_(WaitableEvent::ResetPolicy::MANUAL,
                           WaitableEvent::InitialState::NOT_SIGNALED),
        num_get_work_cv_(lock_.CreateConditionVariable()),
        worker_set_(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED) {}

  void SetUp() override {
    worker_ = make_scoped_refptr(new SchedulerWorker(
        ThreadPriority::NORMAL, MakeUnique<TestSchedulerWorkerDelegate>(this),
        &task_tracker_));
    ASSERT_TRUE(worker_);
    worker_->Start();
    worker_set_.Signal();
    main_entry_called_.Wait();
  }

  void TearDown() override {
    worker_->JoinForTesting();
  }

  size_t TasksPerSequence() const { return GetParam(); }

  // Wait until GetWork() has been called |num_get_work| times.
  void WaitForNumGetWork(size_t num_get_work) {
    AutoSchedulerLock auto_lock(lock_);
    while (num_get_work_ < num_get_work)
      num_get_work_cv_->Wait();
  }

  void SetMaxGetWork(size_t max_get_work) {
    AutoSchedulerLock auto_lock(lock_);
    max_get_work_ = max_get_work;
  }

  void SetNumSequencesToCreate(size_t num_sequences_to_create) {
    AutoSchedulerLock auto_lock(lock_);
    EXPECT_EQ(0U, num_sequences_to_create_);
    num_sequences_to_create_ = num_sequences_to_create;
  }

  size_t NumRunTasks() {
    AutoSchedulerLock auto_lock(lock_);
    return num_run_tasks_;
  }

  std::vector<scoped_refptr<Sequence>> CreatedSequences() {
    AutoSchedulerLock auto_lock(lock_);
    return created_sequences_;
  }

  std::vector<scoped_refptr<Sequence>> EnqueuedSequences() {
    AutoSchedulerLock auto_lock(lock_);
    return re_enqueued_sequences_;
  }

  scoped_refptr<SchedulerWorker> worker_;

 private:
  class TestSchedulerWorkerDelegate : public SchedulerWorkerDefaultDelegate {
   public:
    TestSchedulerWorkerDelegate(TaskSchedulerWorkerTest* outer)
        : outer_(outer) {}

    ~TestSchedulerWorkerDelegate() override {
      EXPECT_FALSE(IsCallToDidRunTaskExpected());
    }

    // SchedulerWorker::Delegate:
    void OnMainEntry(SchedulerWorker* worker) override {
      outer_->worker_set_.Wait();
      EXPECT_EQ(outer_->worker_.get(), worker);
      EXPECT_FALSE(IsCallToDidRunTaskExpected());

      // Without synchronization, OnMainEntry() could be called twice without
      // generating an error.
      AutoSchedulerLock auto_lock(outer_->lock_);
      EXPECT_FALSE(outer_->main_entry_called_.IsSignaled());
      outer_->main_entry_called_.Signal();
    }

    scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
      EXPECT_FALSE(IsCallToDidRunTaskExpected());
      EXPECT_EQ(outer_->worker_.get(), worker);

      {
        AutoSchedulerLock auto_lock(outer_->lock_);

        // Increment the number of times that this method has been called.
        ++outer_->num_get_work_;
        outer_->num_get_work_cv_->Signal();

        // Verify that this method isn't called more times than expected.
        EXPECT_LE(outer_->num_get_work_, outer_->max_get_work_);

        // Check if a Sequence should be returned.
        if (outer_->num_sequences_to_create_ == 0)
          return nullptr;
        --outer_->num_sequences_to_create_;
      }

      // Create a Sequence with TasksPerSequence() Tasks.
      scoped_refptr<Sequence> sequence(new Sequence);
      for (size_t i = 0; i < outer_->TasksPerSequence(); ++i) {
        std::unique_ptr<Task> task(
            new Task(FROM_HERE,
                     BindOnce(&TaskSchedulerWorkerTest::RunTaskCallback,
                              Unretained(outer_)),
                     TaskTraits(), TimeDelta()));
        EXPECT_TRUE(outer_->task_tracker_.WillPostTask(task.get()));
        sequence->PushTask(std::move(task));
      }

      ExpectCallToDidRunTask();

      {
        // Add the Sequence to the vector of created Sequences.
        AutoSchedulerLock auto_lock(outer_->lock_);
        outer_->created_sequences_.push_back(sequence);
      }

      return sequence;
    }

    void DidRunTask() override {
      AutoSchedulerLock auto_lock(expect_did_run_task_lock_);
      EXPECT_TRUE(expect_did_run_task_);
      expect_did_run_task_ = false;
    }

    // This override verifies that |sequence| contains the expected number of
    // Tasks and adds it to |enqueued_sequences_|. Unlike a normal
    // EnqueueSequence implementation, it doesn't reinsert |sequence| into a
    // queue for further execution.
    void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override {
      EXPECT_FALSE(IsCallToDidRunTaskExpected());
      EXPECT_GT(outer_->TasksPerSequence(), 1U);

      // Verify that |sequence| contains TasksPerSequence() - 1 Tasks.
      for (size_t i = 0; i < outer_->TasksPerSequence() - 1; ++i) {
        EXPECT_TRUE(sequence->TakeTask());
        EXPECT_EQ(i == outer_->TasksPerSequence() - 2, sequence->Pop());
      }

      // Add |sequence| to |re_enqueued_sequences_|.
      AutoSchedulerLock auto_lock(outer_->lock_);
      outer_->re_enqueued_sequences_.push_back(std::move(sequence));
      EXPECT_LE(outer_->re_enqueued_sequences_.size(),
                outer_->created_sequences_.size());
    }

   private:
    // Expect a call to DidRunTask() before the next call to any other method of
    // this delegate.
    void ExpectCallToDidRunTask() {
      AutoSchedulerLock auto_lock(expect_did_run_task_lock_);
      expect_did_run_task_ = true;
    }

    bool IsCallToDidRunTaskExpected() const {
      AutoSchedulerLock auto_lock(expect_did_run_task_lock_);
      return expect_did_run_task_;
    }

    TaskSchedulerWorkerTest* outer_;

    // Synchronizes access to |expect_did_run_task_|.
    mutable SchedulerLock expect_did_run_task_lock_;

    // Whether the next method called on this delegate should be DidRunTask().
    bool expect_did_run_task_ = false;

    DISALLOW_COPY_AND_ASSIGN(TestSchedulerWorkerDelegate);
  };

  void RunTaskCallback() {
    AutoSchedulerLock auto_lock(lock_);
    ++num_run_tasks_;
    EXPECT_LE(num_run_tasks_, created_sequences_.size());
  }

  TaskTracker task_tracker_;

  // Synchronizes access to all members below.
  mutable SchedulerLock lock_;

  // Signaled once OnMainEntry() has been called.
  WaitableEvent main_entry_called_;

  // Number of Sequences that should be created by GetWork(). When this
  // is 0, GetWork() returns nullptr.
  size_t num_sequences_to_create_ = 0;

  // Number of times that GetWork() has been called.
  size_t num_get_work_ = 0;

  // Maximum number of times that GetWork() can be called.
  size_t max_get_work_ = 0;

  // Condition variable signaled when |num_get_work_| is incremented.
  std::unique_ptr<ConditionVariable> num_get_work_cv_;

  // Sequences created by GetWork().
  std::vector<scoped_refptr<Sequence>> created_sequences_;

  // Sequences passed to EnqueueSequence().
  std::vector<scoped_refptr<Sequence>> re_enqueued_sequences_;

  // Number of times that RunTaskCallback() has been called.
  size_t num_run_tasks_ = 0;

  // Signaled after |worker_| is set.
  WaitableEvent worker_set_;

  DISALLOW_COPY_AND_ASSIGN(TaskSchedulerWorkerTest);
};

}  // namespace

// Verify that when GetWork() continuously returns Sequences, all Tasks in these
// Sequences run successfully. The test wakes up the SchedulerWorker once.
TEST_P(TaskSchedulerWorkerTest, ContinuousWork) {
  // Set GetWork() to return |kNumSequencesPerTest| Sequences before starting to
  // return nullptr.
  SetNumSequencesToCreate(kNumSequencesPerTest);

  // Expect |kNumSequencesPerTest| calls to GetWork() in which it returns a
  // Sequence and one call in which its returns nullptr.
  const size_t kExpectedNumGetWork = kNumSequencesPerTest + 1;
  SetMaxGetWork(kExpectedNumGetWork);

  // Wake up |worker_| and wait until GetWork() has been invoked the
  // expected amount of times.
  worker_->WakeUp();
  WaitForNumGetWork(kExpectedNumGetWork);

  // All tasks should have run.
  EXPECT_EQ(kNumSequencesPerTest, NumRunTasks());

  // If Sequences returned by GetWork() contain more than one Task, they aren't
  // empty after the worker pops Tasks from them and thus should be returned to
  // EnqueueSequence().
  if (TasksPerSequence() > 1)
    EXPECT_EQ(CreatedSequences(), EnqueuedSequences());
  else
    EXPECT_TRUE(EnqueuedSequences().empty());
}

// Verify that when GetWork() alternates between returning a Sequence and
// returning nullptr, all Tasks in the returned Sequences run successfully. The
// test wakes up the SchedulerWorker once for each Sequence.
TEST_P(TaskSchedulerWorkerTest, IntermittentWork) {
  for (size_t i = 0; i < kNumSequencesPerTest; ++i) {
    // Set GetWork() to return 1 Sequence before starting to return
    // nullptr.
    SetNumSequencesToCreate(1);

    // Expect |i + 1| calls to GetWork() in which it returns a Sequence and
    // |i + 1| calls in which it returns nullptr.
    const size_t expected_num_get_work = 2 * (i + 1);
    SetMaxGetWork(expected_num_get_work);

    // Wake up |worker_| and wait until GetWork() has been invoked
    // the expected amount of times.
    worker_->WakeUp();
    WaitForNumGetWork(expected_num_get_work);

    // The Task should have run
    EXPECT_EQ(i + 1, NumRunTasks());

    // If Sequences returned by GetWork() contain more than one Task, they
    // aren't empty after the worker pops Tasks from them and thus should be
    // returned to EnqueueSequence().
    if (TasksPerSequence() > 1)
      EXPECT_EQ(CreatedSequences(), EnqueuedSequences());
    else
      EXPECT_TRUE(EnqueuedSequences().empty());
  }
}

INSTANTIATE_TEST_CASE_P(OneTaskPerSequence,
                        TaskSchedulerWorkerTest,
                        ::testing::Values(1));
INSTANTIATE_TEST_CASE_P(TwoTasksPerSequence,
                        TaskSchedulerWorkerTest,
                        ::testing::Values(2));

namespace {

class ControllableDetachDelegate : public SchedulerWorkerDefaultDelegate {
 public:
  class Controls : public RefCountedThreadSafe<Controls> {
   public:
    Controls()
        : work_running_(WaitableEvent::ResetPolicy::MANUAL,
                        WaitableEvent::InitialState::SIGNALED),
          work_processed_(WaitableEvent::ResetPolicy::MANUAL,
                          WaitableEvent::InitialState::NOT_SIGNALED),
          detach_requested_(WaitableEvent::ResetPolicy::MANUAL,
                            WaitableEvent::InitialState::NOT_SIGNALED),
          detached_(WaitableEvent::ResetPolicy::MANUAL,
                    WaitableEvent::InitialState::NOT_SIGNALED),
          can_detach_block_(WaitableEvent::ResetPolicy::MANUAL,
                            WaitableEvent::InitialState::SIGNALED),
          destroyed_(WaitableEvent::ResetPolicy::MANUAL,
                     WaitableEvent::InitialState::NOT_SIGNALED) {}

    void HaveWorkBlock() { work_running_.Reset(); }

    void UnblockWork() { work_running_.Signal(); }

    void MakeCanDetachBlock() { can_detach_block_.Reset(); }

    void UnblockCanDetach() { can_detach_block_.Signal(); }

    void WaitForWorkToRun() { work_processed_.Wait(); }

    void WaitForDetachRequest() { detach_requested_.Wait(); }

    void WaitForDetach() { detached_.Wait(); }

    void WaitForDelegateDestroy() { destroyed_.Wait(); }

    void set_expect_get_work(bool expect_get_work) {
      expect_get_work_ = expect_get_work;
    }

    void ResetState() {
      work_running_.Signal();
      work_processed_.Reset();
      detach_requested_.Reset();
      can_detach_block_.Signal();
      work_requested_ = false;
    }

    void set_can_detach(bool can_detach) { can_detach_ = can_detach; }

   private:
    friend class ControllableDetachDelegate;
    friend class RefCountedThreadSafe<Controls>;
    ~Controls() = default;

    WaitableEvent work_running_;
    WaitableEvent work_processed_;
    WaitableEvent detach_requested_;
    WaitableEvent detached_;
    WaitableEvent can_detach_block_;
    WaitableEvent destroyed_;

    bool expect_get_work_ = true;
    bool can_detach_ = false;
    bool work_requested_ = false;

    DISALLOW_COPY_AND_ASSIGN(Controls);
  };

  ControllableDetachDelegate(TaskTracker* task_tracker)
      : task_tracker_(task_tracker), controls_(new Controls()) {}

  ~ControllableDetachDelegate() override { controls_->destroyed_.Signal(); }

  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker)
      override {
    EXPECT_TRUE(controls_->expect_get_work_);

    // Sends one item of work to signal |work_processed_|. On subsequent calls,
    // sends nullptr to indicate there's no more work to be done.
    if (controls_->work_requested_)
      return nullptr;

    controls_->work_requested_ = true;
    scoped_refptr<Sequence> sequence(new Sequence);
    std::unique_ptr<Task> task(new Task(
        FROM_HERE,
        BindOnce(
            [](WaitableEvent* work_processed, WaitableEvent* work_running) {
              work_processed->Signal();
              work_running->Wait();
            },
            Unretained(&controls_->work_processed_),
            Unretained(&controls_->work_running_)),
        {WithBaseSyncPrimitives(), TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN},
        TimeDelta()));
    EXPECT_TRUE(task_tracker_->WillPostTask(task.get()));
    sequence->PushTask(std::move(task));
    return sequence;
  }

  void DidRunTask() override {}

  bool CanDetach(SchedulerWorker* worker) override {
    // Saving |can_detach_| now so that callers waiting on |detach_requested_|
    // have the thread go to sleep and then allow detachment.
    bool can_detach = controls_->can_detach_;
    controls_->detach_requested_.Signal();
    controls_->can_detach_block_.Wait();
    return can_detach;
  }

  void OnDetach() override {
    EXPECT_TRUE(controls_->can_detach_);
    EXPECT_TRUE(controls_->detach_requested_.IsSignaled());
    controls_->detached_.Signal();
  }

  // ControllableDetachDelegate:
  scoped_refptr<Controls> controls() { return controls_; }

 private:
  scoped_refptr<Sequence> work_sequence_;
  TaskTracker* const task_tracker_;
  scoped_refptr<Controls> controls_;

  DISALLOW_COPY_AND_ASSIGN(ControllableDetachDelegate);
};

class MockedControllableDetachDelegate : public ControllableDetachDelegate {
 public:
  MockedControllableDetachDelegate(TaskTracker* task_tracker)
      : ControllableDetachDelegate(task_tracker){};
  ~MockedControllableDetachDelegate() = default;

  // SchedulerWorker::Delegate:
  MOCK_METHOD1(OnMainEntry, void(SchedulerWorker* worker));

 private:
  DISALLOW_COPY_AND_ASSIGN(MockedControllableDetachDelegate);
};

}  // namespace

TEST(TaskSchedulerWorkerTest, WorkerDetaches) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  MockedControllableDetachDelegate* delegate =
      new StrictMock<MockedControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();
  controls->set_can_detach(true);
  EXPECT_CALL(*delegate, OnMainEntry(_));
  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, WrapUnique(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();
  controls->WaitForWorkToRun();
  Mock::VerifyAndClear(delegate);
  controls->WaitForDetachRequest();
  controls->WaitForDetach();
  ASSERT_FALSE(worker->ThreadAliveForTesting());
}

TEST(TaskSchedulerWorkerTest, WorkerCleanupBeforeDetach) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the delegate
  // may destroy on a different thread. Mocks aren't designed with that in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  controls->set_can_detach(true);
  controls->MakeCanDetachBlock();

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();

  controls->WaitForDetachRequest();
  worker->Cleanup();
  worker = nullptr;
  controls->UnblockCanDetach();
  controls->WaitForDelegateDestroy();
}

TEST(TaskSchedulerWorkerTest, WorkerCleanupAfterDetach) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the delegate
  // may destroy on a different thread. Mocks aren't designed with that in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  controls->set_can_detach(true);

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();

  controls->WaitForDetach();
  worker->Cleanup();
  worker = nullptr;
  controls->WaitForDelegateDestroy();
}

TEST(TaskSchedulerWorkerTest, WorkerCleanupDuringWork) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the delegate
  // may destroy on a different thread. Mocks aren't designed with that in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  controls->HaveWorkBlock();

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();

  controls->WaitForWorkToRun();
  worker->Cleanup();
  worker = nullptr;
  controls->UnblockWork();
  controls->WaitForDelegateDestroy();
}

TEST(TaskSchedulerWorkerTest, WorkerCleanupDuringWait) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the delegate
  // may destroy on a different thread. Mocks aren't designed with that in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();

  controls->WaitForDetachRequest();
  worker->Cleanup();
  worker = nullptr;
  controls->WaitForDelegateDestroy();
}

TEST(TaskSchedulerWorkerTest, WorkerCleanupDuringShutdown) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the delegate
  // may destroy on a different thread. Mocks aren't designed with that in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  controls->HaveWorkBlock();

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();

  controls->WaitForWorkToRun();
  task_tracker.Shutdown();
  worker->Cleanup();
  worker = nullptr;
  controls->UnblockWork();
  controls->WaitForDelegateDestroy();
}

// Verify that Start() is a no-op after Cleanup().
TEST(TaskSchedulerWorkerTest, CleanupBeforeStart) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the delegate
  // may destroy on a different thread. Mocks aren't designed with that in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();
  controls->set_expect_get_work(false);

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));

  worker->Cleanup();

  worker->Start();
  worker->WakeUp();

  EXPECT_FALSE(worker->ThreadAliveForTesting());
}

namespace {

class CallJoinFromDifferentThread : public SimpleThread {
 public:
  CallJoinFromDifferentThread(SchedulerWorker* worker_to_join)
      : SimpleThread("SchedulerWorkerJoinThread"),
        worker_to_join_(worker_to_join),
        run_started_event_(WaitableEvent::ResetPolicy::MANUAL,
                           WaitableEvent::InitialState::NOT_SIGNALED) {}

  ~CallJoinFromDifferentThread() override = default;

  void Run() override {
    run_started_event_.Signal();
    worker_to_join_->JoinForTesting();
  }

  void WaitForRunToStart() { run_started_event_.Wait(); }

 private:
  SchedulerWorker* const worker_to_join_;
  WaitableEvent run_started_event_;
  DISALLOW_COPY_AND_ASSIGN(CallJoinFromDifferentThread);
};

}  // namespace

TEST(TaskSchedulerWorkerTest, WorkerCleanupDuringJoin) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  // No mock here as that's reasonably covered by other tests and the
  // delegate may destroy on a different thread. Mocks aren't designed with that
  // in mind.
  std::unique_ptr<ControllableDetachDelegate> delegate =
      MakeUnique<ControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  controls->HaveWorkBlock();

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();

  controls->WaitForWorkToRun();
  CallJoinFromDifferentThread join_from_different_thread(worker.get());
  join_from_different_thread.Start();
  join_from_different_thread.WaitForRunToStart();
  // Sleep here to give the other thread a chance to call JoinForTesting().
  // Receiving a signal that Run() was called doesn't mean JoinForTesting() was
  // necessarily called, and we can't signal after JoinForTesting() as
  // JoinForTesting() blocks until we call UnblockWork().
  PlatformThread::Sleep(TestTimeouts::tiny_timeout());
  worker->Cleanup();
  worker = nullptr;
  controls->UnblockWork();
  controls->WaitForDelegateDestroy();
  join_from_different_thread.Join();
}

TEST(TaskSchedulerWorkerTest, WorkerDetachesAndWakes) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  MockedControllableDetachDelegate* delegate =
      new StrictMock<MockedControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();

  controls->set_can_detach(true);
  EXPECT_CALL(*delegate, OnMainEntry(_));
  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, WrapUnique(delegate), &task_tracker));
  worker->Start();
  worker->WakeUp();
  controls->WaitForWorkToRun();
  Mock::VerifyAndClear(delegate);
  controls->WaitForDetachRequest();
  controls->WaitForDetach();
  ASSERT_FALSE(worker->ThreadAliveForTesting());

  controls->ResetState();
  controls->set_can_detach(false);
  // Expect OnMainEntry() to be called when SchedulerWorker recreates its
  // thread.
  EXPECT_CALL(*delegate, OnMainEntry(worker.get()));
  worker->WakeUp();
  controls->WaitForWorkToRun();
  Mock::VerifyAndClear(delegate);
  controls->WaitForDetachRequest();
  controls->WaitForDetach();
  ASSERT_TRUE(worker->ThreadAliveForTesting());
  worker->JoinForTesting();
}

TEST(TaskSchedulerWorkerTest, StartDetached) {
  TaskTracker task_tracker;
  // Will be owned by SchedulerWorker.
  MockedControllableDetachDelegate* delegate =
      new StrictMock<MockedControllableDetachDelegate>(&task_tracker);
  scoped_refptr<ControllableDetachDelegate::Controls> controls =
      delegate->controls();
  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, WrapUnique(delegate), &task_tracker,
      SchedulerBackwardCompatibility::DISABLED,
      SchedulerWorker::InitialState::DETACHED));
  worker->Start();
  ASSERT_FALSE(worker->ThreadAliveForTesting());
  EXPECT_CALL(*delegate, OnMainEntry(worker.get()));
  worker->WakeUp();
  controls->WaitForWorkToRun();
  Mock::VerifyAndClear(delegate);
  controls->WaitForDetachRequest();
  ASSERT_TRUE(worker->ThreadAliveForTesting());
  worker->JoinForTesting();
}

namespace {

class ExpectThreadPriorityDelegate : public SchedulerWorkerDefaultDelegate {
 public:
  ExpectThreadPriorityDelegate()
      : priority_verified_in_get_work_event_(
            WaitableEvent::ResetPolicy::AUTOMATIC,
            WaitableEvent::InitialState::NOT_SIGNALED),
        expected_thread_priority_(ThreadPriority::BACKGROUND) {}

  void SetExpectedThreadPriority(ThreadPriority expected_thread_priority) {
    expected_thread_priority_ = expected_thread_priority;
  }

  void WaitForPriorityVerifiedInGetWork() {
    priority_verified_in_get_work_event_.Wait();
  }

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker) override { VerifyThreadPriority(); }
  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    VerifyThreadPriority();
    priority_verified_in_get_work_event_.Signal();
    return nullptr;
  }

 private:
  void VerifyThreadPriority() {
    AutoSchedulerLock auto_lock(expected_thread_priority_lock_);
    EXPECT_EQ(expected_thread_priority_,
              PlatformThread::GetCurrentThreadPriority());
  }

  // Signaled after GetWork() has verified the priority of the worker thread.
  WaitableEvent priority_verified_in_get_work_event_;

  // Synchronizes access to |expected_thread_priority_|.
  SchedulerLock expected_thread_priority_lock_;

  // Expected thread priority for the next call to OnMainEntry() or GetWork().
  ThreadPriority expected_thread_priority_;

  DISALLOW_COPY_AND_ASSIGN(ExpectThreadPriorityDelegate);
};

}  // namespace

TEST(TaskSchedulerWorkerTest, BumpPriorityOfAliveThreadDuringShutdown) {
  TaskTracker task_tracker;

  std::unique_ptr<ExpectThreadPriorityDelegate> delegate(
      new ExpectThreadPriorityDelegate);
  ExpectThreadPriorityDelegate* delegate_raw = delegate.get();
  delegate_raw->SetExpectedThreadPriority(
      PlatformThread::CanIncreaseCurrentThreadPriority()
          ? ThreadPriority::BACKGROUND
          : ThreadPriority::NORMAL);

  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::BACKGROUND, std::move(delegate), &task_tracker));
  worker->Start();

  // Verify that the initial thread priority is BACKGROUND (or NORMAL if thread
  // priority can't be increased).
  worker->WakeUp();
  delegate_raw->WaitForPriorityVerifiedInGetWork();

  // Verify that the thread priority is bumped to NORMAL during shutdown.
  delegate_raw->SetExpectedThreadPriority(ThreadPriority::NORMAL);
  task_tracker.SetHasShutdownStartedForTesting();
  worker->WakeUp();
  delegate_raw->WaitForPriorityVerifiedInGetWork();

  worker->JoinForTesting();
}

TEST(TaskSchedulerWorkerTest, BumpPriorityOfDetachedThreadDuringShutdown) {
  TaskTracker task_tracker;

  std::unique_ptr<ExpectThreadPriorityDelegate> delegate(
      new ExpectThreadPriorityDelegate);
  ExpectThreadPriorityDelegate* delegate_raw = delegate.get();
  delegate_raw->SetExpectedThreadPriority(ThreadPriority::NORMAL);

  // Create a DETACHED thread.
  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::BACKGROUND, std::move(delegate), &task_tracker,
      SchedulerBackwardCompatibility::DISABLED,
      SchedulerWorker::InitialState::DETACHED));
  worker->Start();

  // Pretend that shutdown has started.
  task_tracker.SetHasShutdownStartedForTesting();

  // Wake up the thread and verify that its priority is NORMAL when
  // OnMainEntry() and GetWork() are called.
  worker->WakeUp();
  delegate_raw->WaitForPriorityVerifiedInGetWork();

  worker->JoinForTesting();
}

#if defined(OS_WIN)

namespace {

class CoInitializeDelegate : public SchedulerWorkerDefaultDelegate {
 public:
  CoInitializeDelegate()
      : get_work_returned_(WaitableEvent::ResetPolicy::MANUAL,
                           WaitableEvent::InitialState::NOT_SIGNALED) {}

  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    EXPECT_FALSE(get_work_returned_.IsSignaled());
    EXPECT_EQ(E_UNEXPECTED, coinitialize_hresult_);

    coinitialize_hresult_ = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(coinitialize_hresult_))
      CoUninitialize();

    get_work_returned_.Signal();
    return nullptr;
  }

  void WaitUntilGetWorkReturned() { get_work_returned_.Wait(); }

  HRESULT coinitialize_hresult() const { return coinitialize_hresult_; }

 private:
  WaitableEvent get_work_returned_;
  HRESULT coinitialize_hresult_ = E_UNEXPECTED;

  DISALLOW_COPY_AND_ASSIGN(CoInitializeDelegate);
};

}  // namespace

TEST(TaskSchedulerWorkerTest, BackwardCompatibilityEnabled) {
  TaskTracker task_tracker;
  auto delegate = MakeUnique<CoInitializeDelegate>();
  CoInitializeDelegate* const delegate_raw = delegate.get();

  // Create a worker with backward compatibility ENABLED. Wake it up and wait
  // until GetWork() returns.
  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker,
      SchedulerBackwardCompatibility::INIT_COM_STA));
  worker->Start();
  worker->WakeUp();
  delegate_raw->WaitUntilGetWorkReturned();

  // The call to CoInitializeEx() should have returned S_FALSE to indicate that
  // the COM library was already initialized on the thread.
  EXPECT_EQ(S_FALSE, delegate_raw->coinitialize_hresult());

  worker->JoinForTesting();
}

TEST(TaskSchedulerWorkerTest, BackwardCompatibilityDisabled) {
  TaskTracker task_tracker;
  auto delegate = MakeUnique<CoInitializeDelegate>();
  CoInitializeDelegate* const delegate_raw = delegate.get();

  // Create a worker with backward compatibility DISABLED. Wake it up and wait
  // until GetWork() returns.
  auto worker = make_scoped_refptr(new SchedulerWorker(
      ThreadPriority::NORMAL, std::move(delegate), &task_tracker,
      SchedulerBackwardCompatibility::DISABLED));
  worker->Start();
  worker->WakeUp();
  delegate_raw->WaitUntilGetWorkReturned();

  // The call to CoInitializeEx() should have returned S_OK to indicate that the
  // COM library wasn't already initialized on the thread.
  EXPECT_EQ(S_OK, delegate_raw->coinitialize_hresult());

  worker->JoinForTesting();
}

#endif  // defined(OS_WIN)

}  // namespace internal
}  // namespace base
