// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/test_mock_time_task_runner.h"

#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/clock.h"
#include "base/time/tick_clock.h"

namespace base {

namespace {

// MockTickClock --------------------------------------------------------------

// TickClock that always returns the then-current mock time ticks of
// |task_runner| as the current time ticks.
class MockTickClock : public TickClock {
 public:
  explicit MockTickClock(
      scoped_refptr<const TestMockTimeTaskRunner> task_runner);

  // TickClock:
  TimeTicks NowTicks() override;

 private:
  scoped_refptr<const TestMockTimeTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(MockTickClock);
};

MockTickClock::MockTickClock(
    scoped_refptr<const TestMockTimeTaskRunner> task_runner)
    : task_runner_(task_runner) {
}

TimeTicks MockTickClock::NowTicks() {
  return task_runner_->NowTicks();
}

// MockClock ------------------------------------------------------------------

// Clock that always returns the then-current mock time of |task_runner| as the
// current time.
class MockClock : public Clock {
 public:
  explicit MockClock(scoped_refptr<const TestMockTimeTaskRunner> task_runner);

  // Clock:
  Time Now() override;

 private:
  scoped_refptr<const TestMockTimeTaskRunner> task_runner_;

  DISALLOW_COPY_AND_ASSIGN(MockClock);
};

MockClock::MockClock(scoped_refptr<const TestMockTimeTaskRunner> task_runner)
    : task_runner_(task_runner) {
}

Time MockClock::Now() {
  return task_runner_->Now();
}

// A SingleThreadTaskRunner which forwards everything to its |target_|. This is
// useful to break ownership chains when it is known that |target_| will outlive
// the NonOwningProxyTaskRunner it's injected into. In particular,
// TestMockTimeTaskRunner is forced to be ref-counted by virtue of being a
// SingleThreadTaskRunner. As such it is impossible for it to have a
// ThreadTaskRunnerHandle member that points back to itself as the
// ThreadTaskRunnerHandle which it owns would hold a ref back to it. To break
// this dependency cycle, the ThreadTaskRunnerHandle is instead handed a
// NonOwningProxyTaskRunner which allows the TestMockTimeTaskRunner to not hand
// a ref to its ThreadTaskRunnerHandle while promising in return that it will
// outlive that ThreadTaskRunnerHandle instance.
class NonOwningProxyTaskRunner : public SingleThreadTaskRunner {
 public:
  explicit NonOwningProxyTaskRunner(SingleThreadTaskRunner* target)
      : target_(target) {
    DCHECK(target_);
  }

  // SingleThreadTaskRunner:
  bool RunsTasksInCurrentSequence() const override {
    return target_->RunsTasksInCurrentSequence();
  }
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       OnceClosure task,
                       TimeDelta delay) override {
    return target_->PostDelayedTask(from_here, std::move(task), delay);
  }
  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  OnceClosure task,
                                  TimeDelta delay) override {
    return target_->PostNonNestableDelayedTask(from_here, std::move(task),
                                               delay);
  }

 private:
  friend class RefCountedThreadSafe<NonOwningProxyTaskRunner>;
  ~NonOwningProxyTaskRunner() override = default;

  SingleThreadTaskRunner* const target_;

  DISALLOW_COPY_AND_ASSIGN(NonOwningProxyTaskRunner);
};

}  // namespace

// TestMockTimeTaskRunner::TestOrderedPendingTask -----------------------------

// Subclass of TestPendingTask which has a strictly monotonically increasing ID
// for every task, so that tasks posted with the same 'time to run' can be run
// in the order of being posted.
struct TestMockTimeTaskRunner::TestOrderedPendingTask
    : public base::TestPendingTask {
  TestOrderedPendingTask();
  TestOrderedPendingTask(const tracked_objects::Location& location,
                         OnceClosure task,
                         TimeTicks post_time,
                         TimeDelta delay,
                         size_t ordinal,
                         TestNestability nestability);
  TestOrderedPendingTask(TestOrderedPendingTask&&);
  ~TestOrderedPendingTask();

  TestOrderedPendingTask& operator=(TestOrderedPendingTask&&);

  size_t ordinal;

 private:
  DISALLOW_COPY_AND_ASSIGN(TestOrderedPendingTask);
};

TestMockTimeTaskRunner::TestOrderedPendingTask::TestOrderedPendingTask()
    : ordinal(0) {
}

TestMockTimeTaskRunner::TestOrderedPendingTask::TestOrderedPendingTask(
    TestOrderedPendingTask&&) = default;

TestMockTimeTaskRunner::TestOrderedPendingTask::TestOrderedPendingTask(
    const tracked_objects::Location& location,
    OnceClosure task,
    TimeTicks post_time,
    TimeDelta delay,
    size_t ordinal,
    TestNestability nestability)
    : base::TestPendingTask(location,
                            std::move(task),
                            post_time,
                            delay,
                            nestability),
      ordinal(ordinal) {}

TestMockTimeTaskRunner::TestOrderedPendingTask::~TestOrderedPendingTask() {
}

TestMockTimeTaskRunner::TestOrderedPendingTask&
TestMockTimeTaskRunner::TestOrderedPendingTask::operator=(
    TestOrderedPendingTask&&) = default;

// TestMockTimeTaskRunner -----------------------------------------------------

// TODO(gab): This should also set the SequenceToken for the current thread.
// Ref. TestMockTimeTaskRunner::RunsTasksInCurrentSequence().
TestMockTimeTaskRunner::ScopedContext::ScopedContext(
    scoped_refptr<TestMockTimeTaskRunner> scope)
    : on_destroy_(ThreadTaskRunnerHandle::OverrideForTesting(scope)) {
  scope->RunUntilIdle();
}

TestMockTimeTaskRunner::ScopedContext::~ScopedContext() = default;

bool TestMockTimeTaskRunner::TemporalOrder::operator()(
    const TestOrderedPendingTask& first_task,
    const TestOrderedPendingTask& second_task) const {
  if (first_task.GetTimeToRun() == second_task.GetTimeToRun())
    return first_task.ordinal > second_task.ordinal;
  return first_task.GetTimeToRun() > second_task.GetTimeToRun();
}

TestMockTimeTaskRunner::TestMockTimeTaskRunner(Type type)
    : TestMockTimeTaskRunner(Time::UnixEpoch(), TimeTicks(), type) {}

TestMockTimeTaskRunner::TestMockTimeTaskRunner(Time start_time,
                                               TimeTicks start_ticks,
                                               Type type)
    : now_(start_time), now_ticks_(start_ticks), tasks_lock_cv_(&tasks_lock_) {
  if (type == Type::kBoundToThread) {
    run_loop_client_ = RunLoop::RegisterDelegateForCurrentThread(this);
    thread_task_runner_handle_ = std::make_unique<ThreadTaskRunnerHandle>(
        MakeRefCounted<NonOwningProxyTaskRunner>(this));
  }
}

TestMockTimeTaskRunner::~TestMockTimeTaskRunner() {
}

void TestMockTimeTaskRunner::FastForwardBy(TimeDelta delta) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_GE(delta, TimeDelta());

  const TimeTicks original_now_ticks = now_ticks_;
  ProcessAllTasksNoLaterThan(delta);
  ForwardClocksUntilTickTime(original_now_ticks + delta);
}

void TestMockTimeTaskRunner::RunUntilIdle() {
  DCHECK(thread_checker_.CalledOnValidThread());
  ProcessAllTasksNoLaterThan(TimeDelta());
}

void TestMockTimeTaskRunner::FastForwardUntilNoTasksRemain() {
  DCHECK(thread_checker_.CalledOnValidThread());
  ProcessAllTasksNoLaterThan(TimeDelta::Max());
}

void TestMockTimeTaskRunner::ClearPendingTasks() {
  DCHECK(thread_checker_.CalledOnValidThread());
  AutoLock scoped_lock(tasks_lock_);
  while (!tasks_.empty())
    tasks_.pop();
}

Time TestMockTimeTaskRunner::Now() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return now_;
}

TimeTicks TestMockTimeTaskRunner::NowTicks() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return now_ticks_;
}

std::unique_ptr<Clock> TestMockTimeTaskRunner::GetMockClock() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return std::make_unique<MockClock>(this);
}

std::unique_ptr<TickClock> TestMockTimeTaskRunner::GetMockTickClock() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return std::make_unique<MockTickClock>(this);
}

std::deque<TestPendingTask> TestMockTimeTaskRunner::TakePendingTasks() {
  AutoLock scoped_lock(tasks_lock_);
  std::deque<TestPendingTask> tasks;
  while (!tasks_.empty()) {
    // It's safe to remove const and consume |task| here, since |task| is not
    // used for ordering the item.
    tasks.push_back(
        std::move(const_cast<TestOrderedPendingTask&>(tasks_.top())));
    tasks_.pop();
  }
  return tasks;
}

bool TestMockTimeTaskRunner::HasPendingTask() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return !tasks_.empty();
}

size_t TestMockTimeTaskRunner::GetPendingTaskCount() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return tasks_.size();
}

TimeDelta TestMockTimeTaskRunner::NextPendingTaskDelay() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return tasks_.empty() ? TimeDelta::Max()
                        : tasks_.top().GetTimeToRun() - now_ticks_;
}

// TODO(gab): Combine |thread_checker_| with a SequenceToken to differentiate
// between tasks running in the scope of this TestMockTimeTaskRunner and other
// task runners sharing this thread. http://crbug.com/631186
bool TestMockTimeTaskRunner::RunsTasksInCurrentSequence() const {
  return thread_checker_.CalledOnValidThread();
}

bool TestMockTimeTaskRunner::PostDelayedTask(
    const tracked_objects::Location& from_here,
    OnceClosure task,
    TimeDelta delay) {
  AutoLock scoped_lock(tasks_lock_);
  tasks_.push(TestOrderedPendingTask(from_here, std::move(task), now_ticks_,
                                     delay, next_task_ordinal_++,
                                     TestPendingTask::NESTABLE));
  return true;
}

bool TestMockTimeTaskRunner::PostNonNestableDelayedTask(
    const tracked_objects::Location& from_here,
    OnceClosure task,
    TimeDelta delay) {
  return PostDelayedTask(from_here, std::move(task), delay);
}

void TestMockTimeTaskRunner::OnBeforeSelectingTask() {
  // Empty default implementation.
}

void TestMockTimeTaskRunner::OnAfterTimePassed() {
  // Empty default implementation.
}

void TestMockTimeTaskRunner::OnAfterTaskRun() {
  // Empty default implementation.
}

void TestMockTimeTaskRunner::ProcessAllTasksNoLaterThan(TimeDelta max_delta) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_GE(max_delta, TimeDelta());

  // Multiple test task runners can share the same thread for determinism in
  // unit tests. Make sure this TestMockTimeTaskRunner's tasks run in its scope.
  ScopedClosureRunner undo_override;
  if (!ThreadTaskRunnerHandle::IsSet() ||
      ThreadTaskRunnerHandle::Get() != this) {
    undo_override = ThreadTaskRunnerHandle::OverrideForTesting(this);
  }

  const TimeTicks original_now_ticks = now_ticks_;
  while (!quit_run_loop_) {
    OnBeforeSelectingTask();
    TestPendingTask task_info;
    if (!DequeueNextTask(original_now_ticks, max_delta, &task_info))
      break;
    // If tasks were posted with a negative delay, task_info.GetTimeToRun() will
    // be less than |now_ticks_|. ForwardClocksUntilTickTime() takes care of not
    // moving the clock backwards in this case.
    ForwardClocksUntilTickTime(task_info.GetTimeToRun());
    std::move(task_info.task).Run();
    OnAfterTaskRun();
  }
}

void TestMockTimeTaskRunner::ForwardClocksUntilTickTime(TimeTicks later_ticks) {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (later_ticks <= now_ticks_)
    return;

  now_ += later_ticks - now_ticks_;
  now_ticks_ = later_ticks;
  OnAfterTimePassed();
}

bool TestMockTimeTaskRunner::DequeueNextTask(const TimeTicks& reference,
                                             const TimeDelta& max_delta,
                                             TestPendingTask* next_task) {
  DCHECK(thread_checker_.CalledOnValidThread());
  AutoLock scoped_lock(tasks_lock_);
  if (!tasks_.empty() &&
      (tasks_.top().GetTimeToRun() - reference) <= max_delta) {
    // It's safe to remove const and consume |task| here, since |task| is not
    // used for ordering the item.
    *next_task = std::move(const_cast<TestOrderedPendingTask&>(tasks_.top()));
    tasks_.pop();
    return true;
  }
  return false;
}

void TestMockTimeTaskRunner::Run() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Since TestMockTimeTaskRunner doesn't process system messages: there's no
  // hope for anything but a chrome task to call Quit(). If this RunLoop can't
  // process chrome tasks (i.e. disallowed by default in nested RunLoops), it's
  // thereby guaranteed to hang...
  DCHECK(run_loop_client_->ProcessingTasksAllowed())
      << "This is a nested RunLoop instance and needs to be of "
         "Type::NESTABLE_TASKS_ALLOWED.";

  while (!quit_run_loop_) {
    RunUntilIdle();
    if (quit_run_loop_ || run_loop_client_->ShouldQuitWhenIdle())
      break;

    // Peek into |tasks_| to perform one of two things:
    //   A) If there are no remaining tasks, wait until one is posted and
    //      restart from the top.
    //   B) If there is a remaining delayed task. Fast-forward to reach the next
    //      round of tasks.
    TimeDelta auto_fast_forward_by;
    {
      AutoLock scoped_lock(tasks_lock_);
      if (tasks_.empty()) {
        while (tasks_.empty())
          tasks_lock_cv_.Wait();
        continue;
      }
      auto_fast_forward_by = tasks_.top().GetTimeToRun() - now_ticks_;
    }
    FastForwardBy(auto_fast_forward_by);
  }
  quit_run_loop_ = false;
}

void TestMockTimeTaskRunner::Quit() {
  DCHECK(thread_checker_.CalledOnValidThread());
  quit_run_loop_ = true;
}

void TestMockTimeTaskRunner::EnsureWorkScheduled() {
  // Nothing to do: TestMockTimeTaskRunner::Run() will always process tasks and
  // doesn't need an extra kick on nested runs.
}

}  // namespace base
