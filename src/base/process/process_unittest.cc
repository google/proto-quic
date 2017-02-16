// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/process/process.h"

#include <utility>

#include "base/at_exit.h"
#include "base/process/kill.h"
#include "base/test/multiprocess_test.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_local.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/multiprocess_func_list.h"

namespace {

#if defined(OS_WIN)
const int kExpectedStillRunningExitCode = 0x102;
#else
const int kExpectedStillRunningExitCode = 0;
#endif

#if defined(OS_MACOSX)
// Fake port provider that returns the calling process's
// task port, ignoring its argument.
class FakePortProvider : public base::PortProvider {
  mach_port_t TaskForPid(base::ProcessHandle process) const override {
    return mach_task_self();
  }
};
#endif

}  // namespace

namespace base {

class ProcessTest : public MultiProcessTest {
};

TEST_F(ProcessTest, Create) {
  Process process(SpawnChild("SimpleChildProcess"));
  ASSERT_TRUE(process.IsValid());
  ASSERT_FALSE(process.is_current());
  process.Close();
  ASSERT_FALSE(process.IsValid());
}

TEST_F(ProcessTest, CreateCurrent) {
  Process process = Process::Current();
  ASSERT_TRUE(process.IsValid());
  ASSERT_TRUE(process.is_current());
  process.Close();
  ASSERT_FALSE(process.IsValid());
}

TEST_F(ProcessTest, Move) {
  Process process1(SpawnChild("SimpleChildProcess"));
  EXPECT_TRUE(process1.IsValid());

  Process process2;
  EXPECT_FALSE(process2.IsValid());

  process2 = std::move(process1);
  EXPECT_TRUE(process2.IsValid());
  EXPECT_FALSE(process1.IsValid());
  EXPECT_FALSE(process2.is_current());

  Process process3 = Process::Current();
  process2 = std::move(process3);
  EXPECT_TRUE(process2.is_current());
  EXPECT_TRUE(process2.IsValid());
  EXPECT_FALSE(process3.IsValid());
}

TEST_F(ProcessTest, Duplicate) {
  Process process1(SpawnChild("SimpleChildProcess"));
  ASSERT_TRUE(process1.IsValid());

  Process process2 = process1.Duplicate();
  ASSERT_TRUE(process1.IsValid());
  ASSERT_TRUE(process2.IsValid());
  EXPECT_EQ(process1.Pid(), process2.Pid());
  EXPECT_FALSE(process1.is_current());
  EXPECT_FALSE(process2.is_current());

  process1.Close();
  ASSERT_TRUE(process2.IsValid());
}

TEST_F(ProcessTest, DuplicateCurrent) {
  Process process1 = Process::Current();
  ASSERT_TRUE(process1.IsValid());

  Process process2 = process1.Duplicate();
  ASSERT_TRUE(process1.IsValid());
  ASSERT_TRUE(process2.IsValid());
  EXPECT_EQ(process1.Pid(), process2.Pid());
  EXPECT_TRUE(process1.is_current());
  EXPECT_TRUE(process2.is_current());

  process1.Close();
  ASSERT_TRUE(process2.IsValid());
}

TEST_F(ProcessTest, DeprecatedGetProcessFromHandle) {
  Process process1(SpawnChild("SimpleChildProcess"));
  ASSERT_TRUE(process1.IsValid());

  Process process2 = Process::DeprecatedGetProcessFromHandle(process1.Handle());
  ASSERT_TRUE(process1.IsValid());
  ASSERT_TRUE(process2.IsValid());
  EXPECT_EQ(process1.Pid(), process2.Pid());
  EXPECT_FALSE(process1.is_current());
  EXPECT_FALSE(process2.is_current());

  process1.Close();
  ASSERT_TRUE(process2.IsValid());
}

MULTIPROCESS_TEST_MAIN(SleepyChildProcess) {
  PlatformThread::Sleep(TestTimeouts::action_max_timeout());
  return 0;
}

TEST_F(ProcessTest, Terminate) {
  Process process(SpawnChild("SleepyChildProcess"));
  ASSERT_TRUE(process.IsValid());

  const int kDummyExitCode = 42;
  int exit_code = kDummyExitCode;
  EXPECT_EQ(TERMINATION_STATUS_STILL_RUNNING,
            GetTerminationStatus(process.Handle(), &exit_code));
  EXPECT_EQ(kExpectedStillRunningExitCode, exit_code);

  exit_code = kDummyExitCode;
  int kExpectedExitCode = 250;
  process.Terminate(kExpectedExitCode, false);
  process.WaitForExitWithTimeout(TestTimeouts::action_max_timeout(),
                                 &exit_code);

  EXPECT_NE(TERMINATION_STATUS_STILL_RUNNING,
            GetTerminationStatus(process.Handle(), &exit_code));
#if !defined(OS_POSIX)
  // The POSIX implementation actually ignores the exit_code.
  EXPECT_EQ(kExpectedExitCode, exit_code);
#endif
}

void AtExitHandler(void*) {
  // At-exit handler should not be called at
  // Process::TerminateCurrentProcessImmediately.
  DCHECK(false);
}

class ThreadLocalObject {
  ~ThreadLocalObject() {
    // Thread-local storage should not be destructed at
    // Process::TerminateCurrentProcessImmediately.
    DCHECK(false);
  }
};

MULTIPROCESS_TEST_MAIN(TerminateCurrentProcessImmediatelyWithCode0) {
  base::ThreadLocalPointer<ThreadLocalObject> object;
  base::AtExitManager::RegisterCallback(&AtExitHandler, NULL);
  Process::TerminateCurrentProcessImmediately(0);
  NOTREACHED();
  return 42;
}

TEST_F(ProcessTest, TerminateCurrentProcessImmediatelyWithZeroExitCode) {
  Process process(SpawnChild("TerminateCurrentProcessImmediatelyWithCode0"));
  ASSERT_TRUE(process.IsValid());
  int exit_code = 42;
  ASSERT_TRUE(process.WaitForExitWithTimeout(TestTimeouts::action_max_timeout(),
                                             &exit_code));
  EXPECT_EQ(0, exit_code);
}

MULTIPROCESS_TEST_MAIN(TerminateCurrentProcessImmediatelyWithCode250) {
  Process::TerminateCurrentProcessImmediately(250);
  NOTREACHED();
  return 42;
}

TEST_F(ProcessTest, TerminateCurrentProcessImmediatelyWithNonZeroExitCode) {
  Process process(SpawnChild("TerminateCurrentProcessImmediatelyWithCode250"));
  ASSERT_TRUE(process.IsValid());
  int exit_code = 42;
  ASSERT_TRUE(process.WaitForExitWithTimeout(TestTimeouts::action_max_timeout(),
                                             &exit_code));
  EXPECT_EQ(250, exit_code);
}

MULTIPROCESS_TEST_MAIN(FastSleepyChildProcess) {
  PlatformThread::Sleep(TestTimeouts::tiny_timeout() * 10);
  return 0;
}

TEST_F(ProcessTest, WaitForExit) {
  Process process(SpawnChild("FastSleepyChildProcess"));
  ASSERT_TRUE(process.IsValid());

  const int kDummyExitCode = 42;
  int exit_code = kDummyExitCode;
  EXPECT_TRUE(process.WaitForExit(&exit_code));
  EXPECT_EQ(0, exit_code);
}

TEST_F(ProcessTest, WaitForExitWithTimeout) {
  Process process(SpawnChild("SleepyChildProcess"));
  ASSERT_TRUE(process.IsValid());

  const int kDummyExitCode = 42;
  int exit_code = kDummyExitCode;
  TimeDelta timeout = TestTimeouts::tiny_timeout();
  EXPECT_FALSE(process.WaitForExitWithTimeout(timeout, &exit_code));
  EXPECT_EQ(kDummyExitCode, exit_code);

  process.Terminate(kDummyExitCode, false);
}

// Ensure that the priority of a process is restored correctly after
// backgrounding and restoring.
// Note: a platform may not be willing or able to lower the priority of
// a process. The calls to SetProcessBackground should be noops then.
TEST_F(ProcessTest, SetProcessBackgrounded) {
  if (!Process::CanBackgroundProcesses())
    return;
  Process process(SpawnChild("SimpleChildProcess"));
  int old_priority = process.GetPriority();
#if defined(OS_WIN)
  EXPECT_TRUE(process.SetProcessBackgrounded(true));
  EXPECT_TRUE(process.IsProcessBackgrounded());
  EXPECT_TRUE(process.SetProcessBackgrounded(false));
  EXPECT_FALSE(process.IsProcessBackgrounded());
#elif defined(OS_MACOSX)
  // On the Mac, backgrounding a process requires a port to that process.
  // In the browser it's available through the MachBroker class, which is not
  // part of base. Additionally, there is an indefinite amount of time between
  // spawning a process and receiving its port. Because this test just checks
  // the ability to background/foreground a process, we can use the current
  // process's port instead.
  FakePortProvider provider;
  EXPECT_TRUE(process.SetProcessBackgrounded(&provider, true));
  EXPECT_TRUE(process.IsProcessBackgrounded(&provider));
  EXPECT_TRUE(process.SetProcessBackgrounded(&provider, false));
  EXPECT_FALSE(process.IsProcessBackgrounded(&provider));

#else
  process.SetProcessBackgrounded(true);
  process.SetProcessBackgrounded(false);
#endif
  int new_priority = process.GetPriority();
  EXPECT_EQ(old_priority, new_priority);
}

// Same as SetProcessBackgrounded but to this very process. It uses
// a different code path at least for Windows.
TEST_F(ProcessTest, SetProcessBackgroundedSelf) {
  if (!Process::CanBackgroundProcesses())
    return;
  Process process = Process::Current();
  int old_priority = process.GetPriority();
#if defined(OS_WIN)
  EXPECT_TRUE(process.SetProcessBackgrounded(true));
  EXPECT_TRUE(process.IsProcessBackgrounded());
  EXPECT_TRUE(process.SetProcessBackgrounded(false));
  EXPECT_FALSE(process.IsProcessBackgrounded());
#elif defined(OS_MACOSX)
  FakePortProvider provider;
  EXPECT_TRUE(process.SetProcessBackgrounded(&provider, true));
  EXPECT_TRUE(process.IsProcessBackgrounded(&provider));
  EXPECT_TRUE(process.SetProcessBackgrounded(&provider, false));
  EXPECT_FALSE(process.IsProcessBackgrounded(&provider));
#else
  process.SetProcessBackgrounded(true);
  process.SetProcessBackgrounded(false);
#endif
  int new_priority = process.GetPriority();
  EXPECT_EQ(old_priority, new_priority);
}

#if defined(OS_CHROMEOS)

// Tests that the function IsProcessBackgroundedCGroup() can parse the contents
// of the /proc/<pid>/cgroup file successfully.
TEST_F(ProcessTest, TestIsProcessBackgroundedCGroup) {
  const char kNotBackgrounded[] = "5:cpuacct,cpu,cpuset:/daemons\n";
  const char kBackgrounded[] =
      "2:freezer:/chrome_renderers/to_be_frozen\n"
      "1:cpu:/chrome_renderers/background\n";

  EXPECT_FALSE(IsProcessBackgroundedCGroup(kNotBackgrounded));
  EXPECT_TRUE(IsProcessBackgroundedCGroup(kBackgrounded));
}

#endif  // defined(OS_CHROMEOS)

}  // namespace base
