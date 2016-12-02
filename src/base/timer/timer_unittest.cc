// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/timer/timer.h"

#include <stddef.h>

#include <memory>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "base/test/sequenced_worker_pool_owner.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

namespace {

// The message loops on which each timer should be tested.
const MessageLoop::Type testing_message_loops[] = {
    MessageLoop::TYPE_DEFAULT, MessageLoop::TYPE_IO,
#if !defined(OS_IOS)  // iOS does not allow direct running of the UI loop.
    MessageLoop::TYPE_UI,
#endif
};

const int kNumTestingMessageLoops = arraysize(testing_message_loops);

class Receiver {
 public:
  Receiver() : count_(0) {}
  void OnCalled() { count_++; }
  bool WasCalled() { return count_ > 0; }
  int TimesCalled() { return count_; }

 private:
  int count_;
};

class OneShotTimerTester {
 public:
  // |did_run|, if provided, will be signaled when Run() fires.
  explicit OneShotTimerTester(
      WaitableEvent* did_run = nullptr,
      const TimeDelta& delay = TimeDelta::FromMilliseconds(10))
      : quit_closure_(run_loop_.QuitClosure()),
        did_run_(did_run),
        delay_(delay) {}

  virtual ~OneShotTimerTester() = default;

  void SetTaskRunner(scoped_refptr<SingleThreadTaskRunner> task_runner) {
    timer_->SetTaskRunner(std::move(task_runner));

    // Run() will be invoked on |task_runner| but |run_loop_|'s QuitClosure
    // needs to run on this thread (where the MessageLoop lives).
    quit_closure_ =
        Bind(IgnoreResult(&SingleThreadTaskRunner::PostTask),
             ThreadTaskRunnerHandle::Get(), FROM_HERE, run_loop_.QuitClosure());
  }

  void Start() {
    started_time_ = TimeTicks::Now();
    timer_->Start(FROM_HERE, delay_, this, &OneShotTimerTester::Run);
  }

  // Blocks until Run() executes and confirms that Run() didn't fire before
  // |delay_| expired.
  void WaitAndConfirmTimerFiredAfterDelay() {
    run_loop_.Run();

    EXPECT_NE(TimeTicks(), started_time_);
    EXPECT_GE(TimeTicks::Now() - started_time_, delay_);
  }

  bool IsRunning() { return timer_->IsRunning(); }

 protected:
  // Overridable method to do things on Run() before signaling events/closures
  // managed by this helper.
  virtual void OnRun() {}

  std::unique_ptr<OneShotTimer> timer_ = MakeUnique<OneShotTimer>();

 private:
  void Run() {
    OnRun();
    if (did_run_) {
      EXPECT_FALSE(did_run_->IsSignaled());
      did_run_->Signal();
    }
    quit_closure_.Run();
  }

  RunLoop run_loop_;
  Closure quit_closure_;
  WaitableEvent* const did_run_;

  const TimeDelta delay_;
  TimeTicks started_time_;

  DISALLOW_COPY_AND_ASSIGN(OneShotTimerTester);
};

class OneShotSelfDeletingTimerTester : public OneShotTimerTester {
 protected:
  void OnRun() override { timer_.reset(); }
};

constexpr int kNumRepeats = 10;

class RepeatingTimerTester {
 public:
  explicit RepeatingTimerTester(WaitableEvent* did_run, const TimeDelta& delay)
      : counter_(kNumRepeats),
        quit_closure_(run_loop_.QuitClosure()),
        did_run_(did_run),
        delay_(delay) {}

  void Start() {
    started_time_ = TimeTicks::Now();
    timer_.Start(FROM_HERE, delay_, this, &RepeatingTimerTester::Run);
  }

  void WaitAndConfirmTimerFiredRepeatedlyAfterDelay() {
    run_loop_.Run();

    EXPECT_NE(TimeTicks(), started_time_);
    EXPECT_GE(TimeTicks::Now() - started_time_, kNumRepeats * delay_);
  }

 private:
  void Run() {
    if (--counter_ == 0) {
      if (did_run_) {
        EXPECT_FALSE(did_run_->IsSignaled());
        did_run_->Signal();
      }
      timer_.Stop();
      quit_closure_.Run();
    }
  }

  RepeatingTimer timer_;
  int counter_;

  RunLoop run_loop_;
  Closure quit_closure_;
  WaitableEvent* const did_run_;

  const TimeDelta delay_;
  TimeTicks started_time_;

  DISALLOW_COPY_AND_ASSIGN(RepeatingTimerTester);
};

// Basic test with same setup as RunTest_OneShotTimers_Cancel below to confirm
// that |did_run_a| would be signaled in that test if it wasn't for the
// deletion.
void RunTest_OneShotTimers(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  WaitableEvent did_run_a(WaitableEvent::ResetPolicy::MANUAL,
                          WaitableEvent::InitialState::NOT_SIGNALED);
  OneShotTimerTester a(&did_run_a);
  a.Start();

  OneShotTimerTester b;
  b.Start();

  b.WaitAndConfirmTimerFiredAfterDelay();

  EXPECT_TRUE(did_run_a.IsSignaled());
}

void RunTest_OneShotTimers_Cancel(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  WaitableEvent did_run_a(WaitableEvent::ResetPolicy::MANUAL,
                          WaitableEvent::InitialState::NOT_SIGNALED);
  OneShotTimerTester* a = new OneShotTimerTester(&did_run_a);

  // This should run before the timer expires.
  SequencedTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, a);

  // Now start the timer.
  a->Start();

  OneShotTimerTester b;
  b.Start();

  b.WaitAndConfirmTimerFiredAfterDelay();

  EXPECT_FALSE(did_run_a.IsSignaled());
}

void RunTest_OneShotSelfDeletingTimer(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  OneShotSelfDeletingTimerTester f;
  f.Start();
  f.WaitAndConfirmTimerFiredAfterDelay();
}

void RunTest_RepeatingTimer(MessageLoop::Type message_loop_type,
                            const TimeDelta& delay) {
  MessageLoop loop(message_loop_type);

  RepeatingTimerTester f(nullptr, delay);
  f.Start();
  f.WaitAndConfirmTimerFiredRepeatedlyAfterDelay();
}

void RunTest_RepeatingTimer_Cancel(MessageLoop::Type message_loop_type,
                                   const TimeDelta& delay) {
  MessageLoop loop(message_loop_type);

  WaitableEvent did_run_a(WaitableEvent::ResetPolicy::MANUAL,
                          WaitableEvent::InitialState::NOT_SIGNALED);
  RepeatingTimerTester* a = new RepeatingTimerTester(&did_run_a, delay);

  // This should run before the timer expires.
  SequencedTaskRunnerHandle::Get()->DeleteSoon(FROM_HERE, a);

  // Now start the timer.
  a->Start();

  RepeatingTimerTester b(nullptr, delay);
  b.Start();

  b.WaitAndConfirmTimerFiredRepeatedlyAfterDelay();

  // |a| should not have fired despite |b| starting after it on the same
  // sequence and being complete by now.
  EXPECT_FALSE(did_run_a.IsSignaled());
}

class DelayTimerTarget {
 public:
  bool signaled() const { return signaled_; }

  void Signal() {
    ASSERT_FALSE(signaled_);
    signaled_ = true;
  }

 private:
  bool signaled_ = false;
};

void RunTest_DelayTimer_NoCall(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  // If Delay is never called, the timer shouldn't go off.
  DelayTimerTarget target;
  DelayTimer timer(FROM_HERE, TimeDelta::FromMilliseconds(1), &target,
                   &DelayTimerTarget::Signal);

  OneShotTimerTester tester;
  tester.Start();
  tester.WaitAndConfirmTimerFiredAfterDelay();

  ASSERT_FALSE(target.signaled());
}

void RunTest_DelayTimer_OneCall(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  DelayTimerTarget target;
  DelayTimer timer(FROM_HERE, TimeDelta::FromMilliseconds(1), &target,
                   &DelayTimerTarget::Signal);
  timer.Reset();

  OneShotTimerTester tester(nullptr, TimeDelta::FromMilliseconds(100));
  tester.Start();
  tester.WaitAndConfirmTimerFiredAfterDelay();

  ASSERT_TRUE(target.signaled());
}

struct ResetHelper {
  ResetHelper(DelayTimer* timer, DelayTimerTarget* target)
      : timer_(timer), target_(target) {}

  void Reset() {
    ASSERT_FALSE(target_->signaled());
    timer_->Reset();
  }

 private:
  DelayTimer* const timer_;
  DelayTimerTarget* const target_;
};

void RunTest_DelayTimer_Reset(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  // If Delay is never called, the timer shouldn't go off.
  DelayTimerTarget target;
  DelayTimer timer(FROM_HERE, TimeDelta::FromMilliseconds(50), &target,
                   &DelayTimerTarget::Signal);
  timer.Reset();

  ResetHelper reset_helper(&timer, &target);

  OneShotTimer timers[20];
  for (size_t i = 0; i < arraysize(timers); ++i) {
    timers[i].Start(FROM_HERE, TimeDelta::FromMilliseconds(i * 10),
                    &reset_helper, &ResetHelper::Reset);
  }

  OneShotTimerTester tester(nullptr, TimeDelta::FromMilliseconds(300));
  tester.Start();
  tester.WaitAndConfirmTimerFiredAfterDelay();

  ASSERT_TRUE(target.signaled());
}

class DelayTimerFatalTarget {
 public:
  void Signal() {
    ASSERT_TRUE(false);
  }
};

void RunTest_DelayTimer_Deleted(MessageLoop::Type message_loop_type) {
  MessageLoop loop(message_loop_type);

  DelayTimerFatalTarget target;

  {
    DelayTimer timer(FROM_HERE, TimeDelta::FromMilliseconds(50), &target,
                     &DelayTimerFatalTarget::Signal);
    timer.Reset();
  }

  // When the timer is deleted, the DelayTimerFatalTarget should never be
  // called.
  PlatformThread::Sleep(TimeDelta::FromMilliseconds(100));
}

}  // namespace

//-----------------------------------------------------------------------------
// Each test is run against each type of MessageLoop.  That way we are sure
// that timers work properly in all configurations.

TEST(TimerTest, OneShotTimers) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_OneShotTimers(testing_message_loops[i]);
  }
}

TEST(TimerTest, OneShotTimers_Cancel) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_OneShotTimers_Cancel(testing_message_loops[i]);
  }
}

// If underline timer does not handle properly, we will crash or fail
// in full page heap environment.
TEST(TimerTest, OneShotSelfDeletingTimer) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_OneShotSelfDeletingTimer(testing_message_loops[i]);
  }
}

TEST(TimerTest, OneShotTimer_CustomTaskRunner) {
  // A MessageLoop is required for the timer events on the other thread to
  // communicate back to the Timer under test.
  MessageLoop loop;

  Thread other_thread("OneShotTimer_CustomTaskRunner");
  other_thread.Start();

  WaitableEvent did_run(WaitableEvent::ResetPolicy::MANUAL,
                        WaitableEvent::InitialState::NOT_SIGNALED);
  OneShotTimerTester f(&did_run);
  f.SetTaskRunner(other_thread.task_runner());
  f.Start();
  EXPECT_TRUE(f.IsRunning());

  f.WaitAndConfirmTimerFiredAfterDelay();
  EXPECT_TRUE(did_run.IsSignaled());

  // |f| should already have communicated back to this |loop| before invoking
  // Run() and as such this thread should already be aware that |f| is no longer
  // running.
  EXPECT_TRUE(loop.IsIdleForTesting());
  EXPECT_FALSE(f.IsRunning());
}

TEST(TimerTest, OneShotTimerWithTickClock) {
  scoped_refptr<TestMockTimeTaskRunner> task_runner(
      new TestMockTimeTaskRunner(Time::Now(), TimeTicks::Now()));
  std::unique_ptr<TickClock> tick_clock(task_runner->GetMockTickClock());
  MessageLoop message_loop;
  message_loop.SetTaskRunner(task_runner);
  Receiver receiver;
  OneShotTimer timer(tick_clock.get());
  timer.Start(FROM_HERE, TimeDelta::FromSeconds(1),
              Bind(&Receiver::OnCalled, Unretained(&receiver)));
  task_runner->FastForwardBy(TimeDelta::FromSeconds(1));
  EXPECT_TRUE(receiver.WasCalled());
}

TEST(TimerTest, RepeatingTimer) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_RepeatingTimer(testing_message_loops[i],
                           TimeDelta::FromMilliseconds(10));
  }
}

TEST(TimerTest, RepeatingTimer_Cancel) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_RepeatingTimer_Cancel(testing_message_loops[i],
                                  TimeDelta::FromMilliseconds(10));
  }
}

TEST(TimerTest, RepeatingTimerZeroDelay) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_RepeatingTimer(testing_message_loops[i],
                           TimeDelta::FromMilliseconds(0));
  }
}

TEST(TimerTest, RepeatingTimerZeroDelay_Cancel) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_RepeatingTimer_Cancel(testing_message_loops[i],
                                  TimeDelta::FromMilliseconds(0));
  }
}

TEST(TimerTest, RepeatingTimerWithTickClock) {
  scoped_refptr<TestMockTimeTaskRunner> task_runner(
      new TestMockTimeTaskRunner(Time::Now(), TimeTicks::Now()));
  std::unique_ptr<TickClock> tick_clock(task_runner->GetMockTickClock());
  MessageLoop message_loop;
  message_loop.SetTaskRunner(task_runner);
  Receiver receiver;
  const int expected_times_called = 10;
  RepeatingTimer timer(tick_clock.get());
  timer.Start(FROM_HERE, TimeDelta::FromSeconds(1),
              Bind(&Receiver::OnCalled, Unretained(&receiver)));
  task_runner->FastForwardBy(TimeDelta::FromSeconds(expected_times_called));
  timer.Stop();
  EXPECT_EQ(expected_times_called, receiver.TimesCalled());
}

TEST(TimerTest, DelayTimer_NoCall) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_DelayTimer_NoCall(testing_message_loops[i]);
  }
}

TEST(TimerTest, DelayTimer_OneCall) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_DelayTimer_OneCall(testing_message_loops[i]);
  }
}

// It's flaky on the buildbot, http://crbug.com/25038.
TEST(TimerTest, DISABLED_DelayTimer_Reset) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_DelayTimer_Reset(testing_message_loops[i]);
  }
}

TEST(TimerTest, DelayTimer_Deleted) {
  for (int i = 0; i < kNumTestingMessageLoops; i++) {
    RunTest_DelayTimer_Deleted(testing_message_loops[i]);
  }
}

TEST(TimerTest, DelayTimerWithTickClock) {
  scoped_refptr<TestMockTimeTaskRunner> task_runner(
      new TestMockTimeTaskRunner(Time::Now(), TimeTicks::Now()));
  std::unique_ptr<TickClock> tick_clock(task_runner->GetMockTickClock());
  MessageLoop message_loop;
  message_loop.SetTaskRunner(task_runner);
  Receiver receiver;
  DelayTimer timer(FROM_HERE, TimeDelta::FromSeconds(1), &receiver,
                   &Receiver::OnCalled, tick_clock.get());
  task_runner->FastForwardBy(TimeDelta::FromMilliseconds(999));
  EXPECT_FALSE(receiver.WasCalled());
  timer.Reset();
  task_runner->FastForwardBy(TimeDelta::FromMilliseconds(999));
  EXPECT_FALSE(receiver.WasCalled());
  timer.Reset();
  task_runner->FastForwardBy(TimeDelta::FromSeconds(1));
  EXPECT_TRUE(receiver.WasCalled());
}

TEST(TimerTest, MessageLoopShutdown) {
  // This test is designed to verify that shutdown of the
  // message loop does not cause crashes if there were pending
  // timers not yet fired.  It may only trigger exceptions
  // if debug heap checking is enabled.
  WaitableEvent did_run(WaitableEvent::ResetPolicy::MANUAL,
                        WaitableEvent::InitialState::NOT_SIGNALED);
  {
    OneShotTimerTester a(&did_run);
    OneShotTimerTester b(&did_run);
    OneShotTimerTester c(&did_run);
    OneShotTimerTester d(&did_run);
    {
      MessageLoop loop;
      a.Start();
      b.Start();
    }  // MessageLoop destructs by falling out of scope.
  }  // OneShotTimers destruct.  SHOULD NOT CRASH, of course.

  EXPECT_FALSE(did_run.IsSignaled());
}

void TimerTestCallback() {
}

TEST(TimerTest, NonRepeatIsRunning) {
  {
    MessageLoop loop;
    Timer timer(false, false);
    EXPECT_FALSE(timer.IsRunning());
    timer.Start(FROM_HERE, TimeDelta::FromDays(1), Bind(&TimerTestCallback));
    EXPECT_TRUE(timer.IsRunning());
    timer.Stop();
    EXPECT_FALSE(timer.IsRunning());
    EXPECT_TRUE(timer.user_task().is_null());
  }

  {
    Timer timer(true, false);
    MessageLoop loop;
    EXPECT_FALSE(timer.IsRunning());
    timer.Start(FROM_HERE, TimeDelta::FromDays(1), Bind(&TimerTestCallback));
    EXPECT_TRUE(timer.IsRunning());
    timer.Stop();
    EXPECT_FALSE(timer.IsRunning());
    ASSERT_FALSE(timer.user_task().is_null());
    timer.Reset();
    EXPECT_TRUE(timer.IsRunning());
  }
}

TEST(TimerTest, NonRepeatMessageLoopDeath) {
  Timer timer(false, false);
  {
    MessageLoop loop;
    EXPECT_FALSE(timer.IsRunning());
    timer.Start(FROM_HERE, TimeDelta::FromDays(1), Bind(&TimerTestCallback));
    EXPECT_TRUE(timer.IsRunning());
  }
  EXPECT_FALSE(timer.IsRunning());
  EXPECT_TRUE(timer.user_task().is_null());
}

TEST(TimerTest, RetainRepeatIsRunning) {
  MessageLoop loop;
  Timer timer(FROM_HERE, TimeDelta::FromDays(1), Bind(&TimerTestCallback),
              true);
  EXPECT_FALSE(timer.IsRunning());
  timer.Reset();
  EXPECT_TRUE(timer.IsRunning());
  timer.Stop();
  EXPECT_FALSE(timer.IsRunning());
  timer.Reset();
  EXPECT_TRUE(timer.IsRunning());
}

TEST(TimerTest, RetainNonRepeatIsRunning) {
  MessageLoop loop;
  Timer timer(FROM_HERE, TimeDelta::FromDays(1), Bind(&TimerTestCallback),
              false);
  EXPECT_FALSE(timer.IsRunning());
  timer.Reset();
  EXPECT_TRUE(timer.IsRunning());
  timer.Stop();
  EXPECT_FALSE(timer.IsRunning());
  timer.Reset();
  EXPECT_TRUE(timer.IsRunning());
}

namespace {

bool g_callback_happened1 = false;
bool g_callback_happened2 = false;

void ClearAllCallbackHappened() {
  g_callback_happened1 = false;
  g_callback_happened2 = false;
}

void SetCallbackHappened1() {
  g_callback_happened1 = true;
  MessageLoop::current()->QuitWhenIdle();
}

void SetCallbackHappened2() {
  g_callback_happened2 = true;
  MessageLoop::current()->QuitWhenIdle();
}

}  // namespace

TEST(TimerTest, ContinuationStopStart) {
  {
    ClearAllCallbackHappened();
    MessageLoop loop;
    Timer timer(false, false);
    timer.Start(FROM_HERE, TimeDelta::FromMilliseconds(10),
                Bind(&SetCallbackHappened1));
    timer.Stop();
    timer.Start(FROM_HERE, TimeDelta::FromMilliseconds(40),
                Bind(&SetCallbackHappened2));
    RunLoop().Run();
    EXPECT_FALSE(g_callback_happened1);
    EXPECT_TRUE(g_callback_happened2);
  }
}

TEST(TimerTest, ContinuationReset) {
  {
    ClearAllCallbackHappened();
    MessageLoop loop;
    Timer timer(false, false);
    timer.Start(FROM_HERE, TimeDelta::FromMilliseconds(10),
                Bind(&SetCallbackHappened1));
    timer.Reset();
    // Since Reset happened before task ran, the user_task must not be cleared:
    ASSERT_FALSE(timer.user_task().is_null());
    RunLoop().Run();
    EXPECT_TRUE(g_callback_happened1);
  }
}

}  // namespace base
