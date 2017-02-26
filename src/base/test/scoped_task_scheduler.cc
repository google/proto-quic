// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_task_scheduler.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/histogram_base.h"
#include "base/run_loop.h"
#include "base/sequence_token.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/task_runner.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/threading/thread_task_runner_handle.h"

namespace base {
namespace test {

namespace {

enum class ExecutionMode { PARALLEL, SEQUENCED, SINGLE_THREADED };

class TestTaskScheduler : public TaskScheduler {
 public:
  // |external_message_loop| is an externally provided MessageLoop on which to
  // run tasks. A MessageLoop will be created by TestTaskScheduler if
  // |external_message_loop| is nullptr.
  explicit TestTaskScheduler(MessageLoop* external_message_loop);
  ~TestTaskScheduler() override;

  // TaskScheduler:
  void PostDelayedTaskWithTraits(const tracked_objects::Location& from_here,
                                 const TaskTraits& traits,
                                 const Closure& task,
                                 TimeDelta delay) override;
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SequencedTaskRunner> CreateSequencedTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  scoped_refptr<SingleThreadTaskRunner> CreateSingleThreadTaskRunnerWithTraits(
      const TaskTraits& traits) override;
  std::vector<const HistogramBase*> GetHistograms() const override;
  int GetMaxConcurrentTasksWithTraitsDeprecated(
      const TaskTraits& traits) const override;
  void Shutdown() override;
  void FlushForTesting() override;
  void JoinForTesting() override;

  // Posts |task| to this TaskScheduler with |sequence_token|. Returns true on
  // success.
  bool PostTask(std::unique_ptr<internal::Task> task,
                const SequenceToken& sequence_token);

  // Runs |task| with |sequence_token| using this TaskScheduler's TaskTracker.
  void RunTask(std::unique_ptr<internal::Task> task,
               const SequenceToken& sequence_token);

  // Returns true if this TaskScheduler runs its tasks on the current thread.
  bool RunsTasksOnCurrentThread() const;

 private:
  // Returns the TaskRunner to which this TaskScheduler forwards tasks. It may
  // be |message_loop_->task_runner()| or a reference to it saved on entry to
  // RunTask().
  scoped_refptr<SingleThreadTaskRunner> MessageLoopTaskRunner() const {
    if (saved_task_runner_)
      return saved_task_runner_;
    DCHECK(message_loop_->task_runner());
    return message_loop_->task_runner();
  }

  // |message_loop_owned_| will be non-null if this TestTaskScheduler owns the
  // MessageLoop (wasn't provided an external one at construction).
  // |message_loop_| will always be set and is used by this TestTaskScheduler to
  // run tasks.
  std::unique_ptr<MessageLoop> message_loop_owned_;
  MessageLoop* message_loop_;

  // A reference to |message_loop_->task_runner()| saved on entry to RunTask().
  // This is required because RunTask() overrides
  // |message_loop_->task_runner()|.
  //
  // Note: |message_loop_->task_runner()| is accessed directly outside of
  // RunTask() to guarantee that ScopedTaskScheduler always uses the latest
  // TaskRunner set by external code.
  scoped_refptr<SingleThreadTaskRunner> saved_task_runner_;

  // Handles shutdown behaviors and sets up the environment to run a task.
  internal::TaskTracker task_tracker_;

  DISALLOW_COPY_AND_ASSIGN(TestTaskScheduler);
};

class TestTaskSchedulerTaskRunner : public SingleThreadTaskRunner {
 public:
  TestTaskSchedulerTaskRunner(TestTaskScheduler* task_scheduler,
                              ExecutionMode execution_mode,
                              TaskTraits traits);

  // SingleThreadTaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       const Closure& closure,
                       TimeDelta delay) override;
  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  const Closure& closure,
                                  TimeDelta delay) override;
  bool RunsTasksOnCurrentThread() const override;

 private:
  ~TestTaskSchedulerTaskRunner() override;

  TestTaskScheduler* const task_scheduler_;
  const ExecutionMode execution_mode_;
  const SequenceToken sequence_token_;
  const TaskTraits traits_;

  DISALLOW_COPY_AND_ASSIGN(TestTaskSchedulerTaskRunner);
};

TestTaskScheduler::TestTaskScheduler(MessageLoop* external_message_loop)
    : message_loop_owned_(external_message_loop ? nullptr
                                                : MakeUnique<MessageLoop>()),
      message_loop_(message_loop_owned_ ? message_loop_owned_.get()
                                        : external_message_loop) {}

TestTaskScheduler::~TestTaskScheduler() {
  // Shutdown if it hasn't already been done explicitly.
  if (!task_tracker_.HasShutdownStarted())
    Shutdown();
}

void TestTaskScheduler::PostDelayedTaskWithTraits(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    const Closure& task,
    TimeDelta delay) {
  CreateTaskRunnerWithTraits(traits)->PostDelayedTask(from_here, task, delay);
}

scoped_refptr<TaskRunner> TestTaskScheduler::CreateTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return make_scoped_refptr(
      new TestTaskSchedulerTaskRunner(this, ExecutionMode::PARALLEL, traits));
}

scoped_refptr<SequencedTaskRunner>
TestTaskScheduler::CreateSequencedTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return make_scoped_refptr(
      new TestTaskSchedulerTaskRunner(this, ExecutionMode::SEQUENCED, traits));
}

scoped_refptr<SingleThreadTaskRunner>
TestTaskScheduler::CreateSingleThreadTaskRunnerWithTraits(
    const TaskTraits& traits) {
  return make_scoped_refptr(new TestTaskSchedulerTaskRunner(
      this, ExecutionMode::SINGLE_THREADED, traits));
}

std::vector<const HistogramBase*> TestTaskScheduler::GetHistograms() const {
  NOTREACHED();
  return std::vector<const HistogramBase*>();
}

int TestTaskScheduler::GetMaxConcurrentTasksWithTraitsDeprecated(
    const TaskTraits& traits) const {
  return 1;
}

void TestTaskScheduler::Shutdown() {
  // Prevent SKIP_ON_SHUTDOWN and CONTINUE_ON_SHUTDOWN tasks from running from
  // now on.
  task_tracker_.SetHasShutdownStartedForTesting();

  // Run pending BLOCK_SHUTDOWN tasks.
  RunLoop().RunUntilIdle();
}

void TestTaskScheduler::FlushForTesting() {
  NOTREACHED();
}

void TestTaskScheduler::JoinForTesting() {
  // TestTaskScheduler doesn't create threads so this does nothing.
}

bool TestTaskScheduler::PostTask(std::unique_ptr<internal::Task> task,
                                 const SequenceToken& sequence_token) {
  DCHECK(task);
  if (!task_tracker_.WillPostTask(task.get()))
    return false;
  internal::Task* const task_ptr = task.get();
  return MessageLoopTaskRunner()->PostDelayedTask(
      task_ptr->posted_from, Bind(&TestTaskScheduler::RunTask, Unretained(this),
                                  Passed(&task), sequence_token),
      task_ptr->delay);
}

void TestTaskScheduler::RunTask(std::unique_ptr<internal::Task> task,
                                const SequenceToken& sequence_token) {
  DCHECK(!saved_task_runner_);
  saved_task_runner_ = MessageLoop::current()->task_runner();

  // Clear the MessageLoop TaskRunner to allow TaskTracker to register its own
  // Thread/SequencedTaskRunnerHandle as appropriate.
  MessageLoop::current()->ClearTaskRunnerForTesting();

  // Run the task.
  task_tracker_.RunTask(std::move(task), sequence_token.IsValid()
                                             ? sequence_token
                                             : SequenceToken::Create());

  // Make sure that any task runner that was registered was also cleaned up.
  DCHECK(!MessageLoop::current()->task_runner());

  // Restore the MessageLoop TaskRunner.
  MessageLoop::current()->SetTaskRunner(saved_task_runner_);
  saved_task_runner_ = nullptr;
}

bool TestTaskScheduler::RunsTasksOnCurrentThread() const {
  return MessageLoopTaskRunner()->RunsTasksOnCurrentThread();
}

TestTaskSchedulerTaskRunner::TestTaskSchedulerTaskRunner(
    TestTaskScheduler* task_scheduler,
    ExecutionMode execution_mode,
    TaskTraits traits)
    : task_scheduler_(task_scheduler),
      execution_mode_(execution_mode),
      sequence_token_(execution_mode == ExecutionMode::PARALLEL
                          ? SequenceToken()
                          : SequenceToken::Create()),
      traits_(traits) {}

bool TestTaskSchedulerTaskRunner::PostDelayedTask(
    const tracked_objects::Location& from_here,
    const Closure& closure,
    TimeDelta delay) {
  auto task = MakeUnique<internal::Task>(from_here, closure, traits_, delay);
  if (execution_mode_ == ExecutionMode::SEQUENCED)
    task->sequenced_task_runner_ref = make_scoped_refptr(this);
  else if (execution_mode_ == ExecutionMode::SINGLE_THREADED)
    task->single_thread_task_runner_ref = make_scoped_refptr(this);
  return task_scheduler_->PostTask(std::move(task), sequence_token_);
}

bool TestTaskSchedulerTaskRunner::PostNonNestableDelayedTask(
    const tracked_objects::Location& from_here,
    const Closure& closure,
    TimeDelta delay) {
  // Tasks are never nested within the task scheduler.
  return PostDelayedTask(from_here, closure, delay);
}

bool TestTaskSchedulerTaskRunner::RunsTasksOnCurrentThread() const {
  if (execution_mode_ == ExecutionMode::PARALLEL)
    return task_scheduler_->RunsTasksOnCurrentThread();
  return sequence_token_ == SequenceToken::GetForCurrentThread();
}

TestTaskSchedulerTaskRunner::~TestTaskSchedulerTaskRunner() = default;

}  // namespace

ScopedTaskScheduler::ScopedTaskScheduler() : ScopedTaskScheduler(nullptr) {}

ScopedTaskScheduler::ScopedTaskScheduler(MessageLoop* message_loop) {
  DCHECK(!TaskScheduler::GetInstance());
  TaskScheduler::SetInstance(MakeUnique<TestTaskScheduler>(message_loop));
  task_scheduler_ = TaskScheduler::GetInstance();
}

ScopedTaskScheduler::~ScopedTaskScheduler() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_EQ(task_scheduler_, TaskScheduler::GetInstance());

  // Per contract, call JoinForTesting() before deleting the TaskScheduler.
  TaskScheduler::GetInstance()->JoinForTesting();

  TaskScheduler::SetInstance(nullptr);
}

}  // namespace test
}  // namespace base
