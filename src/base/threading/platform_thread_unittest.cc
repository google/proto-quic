// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/platform_thread.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

#if defined(OS_POSIX)
#include "base/threading/platform_thread_internal_posix.h"
#elif defined(OS_WIN)
#include <windows.h>
#endif

namespace base {

// Trivial tests that thread runs and doesn't crash on create, join, or detach -

namespace {

class TrivialThread : public PlatformThread::Delegate {
 public:
  TrivialThread() : run_event_(WaitableEvent::ResetPolicy::MANUAL,
                               WaitableEvent::InitialState::NOT_SIGNALED) {}

  void ThreadMain() override { run_event_.Signal(); }

  WaitableEvent& run_event() { return run_event_; }

 private:
  WaitableEvent run_event_;

  DISALLOW_COPY_AND_ASSIGN(TrivialThread);
};

}  // namespace

TEST(PlatformThreadTest, TrivialJoin) {
  TrivialThread thread;
  PlatformThreadHandle handle;

  ASSERT_FALSE(thread.run_event().IsSignaled());
  ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));
  PlatformThread::Join(handle);
  ASSERT_TRUE(thread.run_event().IsSignaled());
}

TEST(PlatformThreadTest, TrivialJoinTimesTen) {
  TrivialThread thread[10];
  PlatformThreadHandle handle[arraysize(thread)];

  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_FALSE(thread[n].run_event().IsSignaled());
  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_TRUE(PlatformThread::Create(0, &thread[n], &handle[n]));
  for (size_t n = 0; n < arraysize(thread); n++)
    PlatformThread::Join(handle[n]);
  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_TRUE(thread[n].run_event().IsSignaled());
}

// The following detach tests are by nature racy. The run_event approximates the
// end and termination of the thread, but threads could persist shortly after
// the test completes.
TEST(PlatformThreadTest, TrivialDetach) {
  TrivialThread thread;
  PlatformThreadHandle handle;

  ASSERT_FALSE(thread.run_event().IsSignaled());
  ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));
  PlatformThread::Detach(handle);
  thread.run_event().Wait();
}

TEST(PlatformThreadTest, TrivialDetachTimesTen) {
  TrivialThread thread[10];
  PlatformThreadHandle handle[arraysize(thread)];

  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_FALSE(thread[n].run_event().IsSignaled());
  for (size_t n = 0; n < arraysize(thread); n++) {
    ASSERT_TRUE(PlatformThread::Create(0, &thread[n], &handle[n]));
    PlatformThread::Detach(handle[n]);
  }
  for (size_t n = 0; n < arraysize(thread); n++)
    thread[n].run_event().Wait();
}

// Tests of basic thread functions ---------------------------------------------

namespace {

class FunctionTestThread : public PlatformThread::Delegate {
 public:
  FunctionTestThread()
      : thread_id_(kInvalidThreadId),
        termination_ready_(WaitableEvent::ResetPolicy::MANUAL,
                           WaitableEvent::InitialState::NOT_SIGNALED),
        terminate_thread_(WaitableEvent::ResetPolicy::MANUAL,
                          WaitableEvent::InitialState::NOT_SIGNALED),
        done_(false) {}
  ~FunctionTestThread() override {
    EXPECT_TRUE(terminate_thread_.IsSignaled())
        << "Need to mark thread for termination and join the underlying thread "
        << "before destroying a FunctionTestThread as it owns the "
        << "WaitableEvent blocking the underlying thread's main.";
  }

  // Grabs |thread_id_|, runs an optional test on that thread, signals
  // |termination_ready_|, and then waits for |terminate_thread_| to be
  // signaled before exiting.
  void ThreadMain() override {
    thread_id_ = PlatformThread::CurrentId();
    EXPECT_NE(thread_id_, kInvalidThreadId);

    // Make sure that the thread ID is the same across calls.
    EXPECT_EQ(thread_id_, PlatformThread::CurrentId());

    // Run extra tests.
    RunTest();

    termination_ready_.Signal();
    terminate_thread_.Wait();

    done_ = true;
  }

  PlatformThreadId thread_id() const {
    EXPECT_TRUE(termination_ready_.IsSignaled()) << "Thread ID still unknown";
    return thread_id_;
  }

  bool IsRunning() const {
    return termination_ready_.IsSignaled() && !done_;
  }

  // Blocks until this thread is started and ready to be terminated.
  void WaitForTerminationReady() { termination_ready_.Wait(); }

  // Marks this thread for termination (callers must then join this thread to be
  // guaranteed of termination).
  void MarkForTermination() { terminate_thread_.Signal(); }

 private:
  // Runs an optional test on the newly created thread.
  virtual void RunTest() {}

  PlatformThreadId thread_id_;

  mutable WaitableEvent termination_ready_;
  WaitableEvent terminate_thread_;
  bool done_;

  DISALLOW_COPY_AND_ASSIGN(FunctionTestThread);
};

}  // namespace

TEST(PlatformThreadTest, Function) {
  PlatformThreadId main_thread_id = PlatformThread::CurrentId();

  FunctionTestThread thread;
  PlatformThreadHandle handle;

  ASSERT_FALSE(thread.IsRunning());
  ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));
  thread.WaitForTerminationReady();
  ASSERT_TRUE(thread.IsRunning());
  EXPECT_NE(thread.thread_id(), main_thread_id);

  thread.MarkForTermination();
  PlatformThread::Join(handle);
  ASSERT_FALSE(thread.IsRunning());

  // Make sure that the thread ID is the same across calls.
  EXPECT_EQ(main_thread_id, PlatformThread::CurrentId());
}

TEST(PlatformThreadTest, FunctionTimesTen) {
  PlatformThreadId main_thread_id = PlatformThread::CurrentId();

  FunctionTestThread thread[10];
  PlatformThreadHandle handle[arraysize(thread)];

  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_FALSE(thread[n].IsRunning());

  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_TRUE(PlatformThread::Create(0, &thread[n], &handle[n]));
  for (size_t n = 0; n < arraysize(thread); n++)
    thread[n].WaitForTerminationReady();

  for (size_t n = 0; n < arraysize(thread); n++) {
    ASSERT_TRUE(thread[n].IsRunning());
    EXPECT_NE(thread[n].thread_id(), main_thread_id);

    // Make sure no two threads get the same ID.
    for (size_t i = 0; i < n; ++i) {
      EXPECT_NE(thread[i].thread_id(), thread[n].thread_id());
    }
  }

  for (size_t n = 0; n < arraysize(thread); n++)
    thread[n].MarkForTermination();
  for (size_t n = 0; n < arraysize(thread); n++)
    PlatformThread::Join(handle[n]);
  for (size_t n = 0; n < arraysize(thread); n++)
    ASSERT_FALSE(thread[n].IsRunning());

  // Make sure that the thread ID is the same across calls.
  EXPECT_EQ(main_thread_id, PlatformThread::CurrentId());
}

namespace {

const ThreadPriority kThreadPriorityTestValues[] = {
// The order should be higher to lower to cover as much cases as possible on
// Linux trybots running without CAP_SYS_NICE permission.
#if !defined(OS_ANDROID)
    // PlatformThread::GetCurrentThreadPriority() on Android does not support
    // REALTIME_AUDIO case. See http://crbug.com/505474.
    ThreadPriority::REALTIME_AUDIO,
#endif
    ThreadPriority::DISPLAY,
    // This redundant BACKGROUND priority is to test backgrounding from other
    // priorities, and unbackgrounding.
    ThreadPriority::BACKGROUND,
    ThreadPriority::NORMAL,
    ThreadPriority::BACKGROUND};

class ThreadPriorityTestThread : public FunctionTestThread {
 public:
  explicit ThreadPriorityTestThread(ThreadPriority priority)
      : priority_(priority) {}
  ~ThreadPriorityTestThread() override = default;

 private:
  void RunTest() override {
    // Confirm that the current thread's priority is as expected.
    EXPECT_EQ(ThreadPriority::NORMAL,
              PlatformThread::GetCurrentThreadPriority());

    // Alter and verify the current thread's priority.
    PlatformThread::SetCurrentThreadPriority(priority_);
    EXPECT_EQ(priority_, PlatformThread::GetCurrentThreadPriority());
  }

  const ThreadPriority priority_;

  DISALLOW_COPY_AND_ASSIGN(ThreadPriorityTestThread);
};

}  // namespace

// Test changing a created thread's priority (which has different semantics on
// some platforms).
TEST(PlatformThreadTest, ThreadPriorityCurrentThread) {
  const bool increase_priority_allowed =
      PlatformThread::CanIncreaseCurrentThreadPriority();
  if (increase_priority_allowed) {
    // Bump the priority in order to verify that new threads are started with
    // normal priority.
    PlatformThread::SetCurrentThreadPriority(ThreadPriority::DISPLAY);
  }

  // Toggle each supported priority on the thread and confirm it affects it.
  for (size_t i = 0; i < arraysize(kThreadPriorityTestValues); ++i) {
    if (!increase_priority_allowed &&
        kThreadPriorityTestValues[i] >
            PlatformThread::GetCurrentThreadPriority()) {
      continue;
    }

    ThreadPriorityTestThread thread(kThreadPriorityTestValues[i]);
    PlatformThreadHandle handle;

    ASSERT_FALSE(thread.IsRunning());
    ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));
    thread.WaitForTerminationReady();
    ASSERT_TRUE(thread.IsRunning());

    thread.MarkForTermination();
    PlatformThread::Join(handle);
    ASSERT_FALSE(thread.IsRunning());
  }
}

// Test for a function defined in platform_thread_internal_posix.cc. On OSX and
// iOS, platform_thread_internal_posix.cc is not compiled, so these platforms
// are excluded here, too.
#if defined(OS_POSIX) && !defined(OS_MACOSX) && !defined(OS_IOS)
TEST(PlatformThreadTest, GetNiceValueToThreadPriority) {
  using internal::NiceValueToThreadPriority;
  using internal::kThreadPriorityToNiceValueMap;

  EXPECT_EQ(ThreadPriority::BACKGROUND,
            kThreadPriorityToNiceValueMap[0].priority);
  EXPECT_EQ(ThreadPriority::NORMAL,
            kThreadPriorityToNiceValueMap[1].priority);
  EXPECT_EQ(ThreadPriority::DISPLAY,
            kThreadPriorityToNiceValueMap[2].priority);
  EXPECT_EQ(ThreadPriority::REALTIME_AUDIO,
            kThreadPriorityToNiceValueMap[3].priority);

  static const int kBackgroundNiceValue =
      kThreadPriorityToNiceValueMap[0].nice_value;
  static const int kNormalNiceValue =
      kThreadPriorityToNiceValueMap[1].nice_value;
  static const int kDisplayNiceValue =
      kThreadPriorityToNiceValueMap[2].nice_value;
  static const int kRealtimeAudioNiceValue =
      kThreadPriorityToNiceValueMap[3].nice_value;

  // The tests below assume the nice values specified in the map are within
  // the range below (both ends exclusive).
  static const int kHighestNiceValue = 19;
  static const int kLowestNiceValue = -20;

  EXPECT_GT(kHighestNiceValue, kBackgroundNiceValue);
  EXPECT_GT(kBackgroundNiceValue, kNormalNiceValue);
  EXPECT_GT(kNormalNiceValue, kDisplayNiceValue);
  EXPECT_GT(kDisplayNiceValue, kRealtimeAudioNiceValue);
  EXPECT_GT(kRealtimeAudioNiceValue, kLowestNiceValue);

  EXPECT_EQ(ThreadPriority::BACKGROUND,
            NiceValueToThreadPriority(kHighestNiceValue));
  EXPECT_EQ(ThreadPriority::BACKGROUND,
            NiceValueToThreadPriority(kBackgroundNiceValue + 1));
  EXPECT_EQ(ThreadPriority::BACKGROUND,
            NiceValueToThreadPriority(kBackgroundNiceValue));
  EXPECT_EQ(ThreadPriority::BACKGROUND,
            NiceValueToThreadPriority(kNormalNiceValue + 1));
  EXPECT_EQ(ThreadPriority::NORMAL,
            NiceValueToThreadPriority(kNormalNiceValue));
  EXPECT_EQ(ThreadPriority::NORMAL,
            NiceValueToThreadPriority(kDisplayNiceValue + 1));
  EXPECT_EQ(ThreadPriority::DISPLAY,
            NiceValueToThreadPriority(kDisplayNiceValue));
  EXPECT_EQ(ThreadPriority::DISPLAY,
            NiceValueToThreadPriority(kRealtimeAudioNiceValue + 1));
  EXPECT_EQ(ThreadPriority::REALTIME_AUDIO,
            NiceValueToThreadPriority(kRealtimeAudioNiceValue));
  EXPECT_EQ(ThreadPriority::REALTIME_AUDIO,
            NiceValueToThreadPriority(kLowestNiceValue));
}
#endif

}  // namespace base
