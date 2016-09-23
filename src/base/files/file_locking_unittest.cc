// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/command_line.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/macros.h"
#include "base/test/multiprocess_test.h"
#include "base/test/test_timeouts.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/multiprocess_func_list.h"

using base::File;
using base::FilePath;

namespace {

// Flag for the parent to share a temp dir to the child.
const char kTempDirFlag[] = "temp-dir";

// Flags to control how the subprocess unlocks the file.
const char kFileUnlock[] = "file-unlock";
const char kCloseUnlock[] = "close-unlock";
const char kExitUnlock[] = "exit-unlock";

// File to lock in temp dir.
const char kLockFile[] = "lockfile";

// Constants for various requests and responses, used as |signal_file| parameter
// to signal/wait helpers.
const char kSignalLockFileLocked[] = "locked.signal";
const char kSignalLockFileClose[] = "close.signal";
const char kSignalLockFileClosed[] = "closed.signal";
const char kSignalLockFileUnlock[] = "unlock.signal";
const char kSignalLockFileUnlocked[] = "unlocked.signal";
const char kSignalExit[] = "exit.signal";

// Signal an event by creating a file which didn't previously exist.
bool SignalEvent(const FilePath& signal_dir, const char* signal_file) {
  File file(signal_dir.AppendASCII(signal_file),
            File::FLAG_CREATE | File::FLAG_WRITE);
  return file.IsValid();
}

// Check whether an event was signaled.
bool CheckEvent(const FilePath& signal_dir, const char* signal_file) {
  File file(signal_dir.AppendASCII(signal_file),
            File::FLAG_OPEN | File::FLAG_READ);
  return file.IsValid();
}

// Busy-wait for an event to be signaled, returning false for timeout.
bool WaitForEventWithTimeout(const FilePath& signal_dir,
                             const char* signal_file,
                             const base::TimeDelta& timeout) {
  const base::Time finish_by = base::Time::Now() + timeout;
  while (!CheckEvent(signal_dir, signal_file)) {
    if (base::Time::Now() > finish_by)
      return false;
    base::PlatformThread::Sleep(base::TimeDelta::FromMilliseconds(10));
  }
  return true;
}

// Wait forever for the event to be signaled (should never return false).
bool WaitForEvent(const FilePath& signal_dir, const char* signal_file) {
  return WaitForEventWithTimeout(signal_dir, signal_file,
                                 base::TimeDelta::Max());
}

// Keep these in sync so StartChild*() can refer to correct test main.
#define ChildMain ChildLockUnlock
#define ChildMainString "ChildLockUnlock"

// Subprocess to test getting a file lock then releasing it.  |kTempDirFlag|
// must pass in an existing temporary directory for the lockfile and signal
// files.  One of the following flags must be passed to determine how to unlock
// the lock file:
// - |kFileUnlock| calls Unlock() to unlock.
// - |kCloseUnlock| calls Close() while the lock is held.
// - |kExitUnlock| exits while the lock is held.
MULTIPROCESS_TEST_MAIN(ChildMain) {
  base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
  const FilePath temp_path = command_line->GetSwitchValuePath(kTempDirFlag);
  CHECK(base::DirectoryExists(temp_path));

  // Immediately lock the file.
  File file(temp_path.AppendASCII(kLockFile),
            File::FLAG_OPEN | File::FLAG_READ | File::FLAG_WRITE);
  CHECK(file.IsValid());
  CHECK_EQ(File::FILE_OK, file.Lock());
  CHECK(SignalEvent(temp_path, kSignalLockFileLocked));

  if (command_line->HasSwitch(kFileUnlock)) {
    // Wait for signal to unlock, then unlock the file.
    CHECK(WaitForEvent(temp_path, kSignalLockFileUnlock));
    CHECK_EQ(File::FILE_OK, file.Unlock());
    CHECK(SignalEvent(temp_path, kSignalLockFileUnlocked));
  } else if (command_line->HasSwitch(kCloseUnlock)) {
    // Wait for the signal to close, then close the file.
    CHECK(WaitForEvent(temp_path, kSignalLockFileClose));
    file.Close();
    CHECK(!file.IsValid());
    CHECK(SignalEvent(temp_path, kSignalLockFileClosed));
  } else {
    CHECK(command_line->HasSwitch(kExitUnlock));
  }

  // Wait for signal to exit, so that unlock or close can be distinguished from
  // exit.
  CHECK(WaitForEvent(temp_path, kSignalExit));
  return 0;
}

}  // namespace

class FileLockingTest : public testing::Test {
 public:
  FileLockingTest() {}

 protected:
  void SetUp() override {
    testing::Test::SetUp();

    // Setup the temp dir and the lock file.
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    lock_file_.Initialize(
        temp_dir_.GetPath().AppendASCII(kLockFile),
        File::FLAG_CREATE | File::FLAG_READ | File::FLAG_WRITE);
    ASSERT_TRUE(lock_file_.IsValid());
  }

  bool SignalEvent(const char* signal_file) {
    return ::SignalEvent(temp_dir_.GetPath(), signal_file);
  }

  bool WaitForEventOrTimeout(const char* signal_file) {
    return ::WaitForEventWithTimeout(temp_dir_.GetPath(), signal_file,
                                     TestTimeouts::action_timeout());
  }

  // Start a child process set to use the specified unlock action, and wait for
  // it to lock the file.
  void StartChildAndSignalLock(const char* unlock_action) {
    // Create a temporary dir and spin up a ChildLockExit subprocess against it.
    const FilePath temp_path = temp_dir_.GetPath();
    base::CommandLine child_command_line(
        base::GetMultiProcessTestChildBaseCommandLine());
    child_command_line.AppendSwitchPath(kTempDirFlag, temp_path);
    child_command_line.AppendSwitch(unlock_action);
    lock_child_ =
        base::SpawnMultiProcessTestChild(ChildMainString, child_command_line,
                                         base::LaunchOptions());
    ASSERT_TRUE(lock_child_.IsValid());

    // Wait for the child to lock the file.
    ASSERT_TRUE(WaitForEventOrTimeout(kSignalLockFileLocked));
  }

  // Signal the child to exit cleanly.
  void ExitChildCleanly() {
    ASSERT_TRUE(SignalEvent(kSignalExit));
    int rv = -1;
    ASSERT_TRUE(lock_child_.WaitForExitWithTimeout(
        TestTimeouts::action_timeout(), &rv));
    ASSERT_EQ(0, rv);
  }

  base::ScopedTempDir temp_dir_;
  base::File lock_file_;
  base::Process lock_child_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FileLockingTest);
};

// Test that locks are released by Unlock().
TEST_F(FileLockingTest, LockAndUnlock) {
  StartChildAndSignalLock(kFileUnlock);

  ASSERT_NE(File::FILE_OK, lock_file_.Lock());
  ASSERT_TRUE(SignalEvent(kSignalLockFileUnlock));
  ASSERT_TRUE(WaitForEventOrTimeout(kSignalLockFileUnlocked));
  ASSERT_EQ(File::FILE_OK, lock_file_.Lock());
  ASSERT_EQ(File::FILE_OK, lock_file_.Unlock());

  ExitChildCleanly();
}

// Test that locks are released on Close().
TEST_F(FileLockingTest, UnlockOnClose) {
  StartChildAndSignalLock(kCloseUnlock);

  ASSERT_NE(File::FILE_OK, lock_file_.Lock());
  ASSERT_TRUE(SignalEvent(kSignalLockFileClose));
  ASSERT_TRUE(WaitForEventOrTimeout(kSignalLockFileClosed));
  ASSERT_EQ(File::FILE_OK, lock_file_.Lock());
  ASSERT_EQ(File::FILE_OK, lock_file_.Unlock());

  ExitChildCleanly();
}

// Test that locks are released on exit.
TEST_F(FileLockingTest, UnlockOnExit) {
  StartChildAndSignalLock(kExitUnlock);

  ASSERT_NE(File::FILE_OK, lock_file_.Lock());
  ExitChildCleanly();
  ASSERT_EQ(File::FILE_OK, lock_file_.Lock());
  ASSERT_EQ(File::FILE_OK, lock_file_.Unlock());
}

// Test that killing the process releases the lock.  This should cover crashing.
TEST_F(FileLockingTest, UnlockOnTerminate) {
  // The child will wait for an exit which never arrives.
  StartChildAndSignalLock(kExitUnlock);

  ASSERT_NE(File::FILE_OK, lock_file_.Lock());
  ASSERT_TRUE(lock_child_.Terminate(0, true));
  ASSERT_EQ(File::FILE_OK, lock_file_.Lock());
  ASSERT_EQ(File::FILE_OK, lock_file_.Unlock());
}
