// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/cygprofile/cygprofile.h"

#include <stdint.h>
#include <sys/time.h>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/synchronization/waitable_event.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace cygprofile {
namespace {

void FlushEntries(std::vector<LogEntry>* destination,
                  std::vector<LogEntry>* entries) {
  CHECK_EQ(0U, destination->size());
  // Move the provided |entries| vector to the provided |destination| so that
  // the unit test that triggered the flush can check it.
  destination->swap(*entries);
}

// Flush callback that should not be invoked.
void CheckFlushDoesNotHappen(std::vector<LogEntry>* entries) {
  NOTREACHED();
}

uint64_t GetUsecSecTimeFromTimeSpec(struct timespec timespec) {
  return timespec.tv_sec * 1000 * 1000 + timespec.tv_nsec / 1000;
}

TEST(CygprofileTest, ThreadLogBasic) {
  ThreadLog thread_log(base::Bind(&CheckFlushDoesNotHappen));

  thread_log.AddEntry(reinterpret_cast<void*>(0x2));
  thread_log.AddEntry(reinterpret_cast<void*>(0x1));

  std::vector<LogEntry> entries;
  thread_log.TakeEntries(&entries);

  ASSERT_EQ(2U, entries.size());
  // The entries should appear in their insertion order.
  const LogEntry& first_entry = entries[0];
  ASSERT_EQ(reinterpret_cast<uintptr_t>(first_entry.address), 2U);
  ASSERT_EQ(getpid(), first_entry.pid);
  ASSERT_LT(0, first_entry.tid);

  const LogEntry& second_entry = entries[1];
  ASSERT_EQ(1U, reinterpret_cast<uintptr_t>(second_entry.address));
  ASSERT_EQ(first_entry.pid, second_entry.pid);
  ASSERT_EQ(first_entry.tid, second_entry.tid);

  ASSERT_GE(GetUsecSecTimeFromTimeSpec(second_entry.time),
            GetUsecSecTimeFromTimeSpec(first_entry.time));
}

TEST(CygprofileTest, ManagerBasic) {
  base::WaitableEvent wait_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  base::WaitableEvent notify_event(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);

  ThreadLogsManager manager(
      base::Bind(&base::WaitableEvent::Wait, base::Unretained(&wait_event)),
      base::Bind(&base::WaitableEvent::Signal,
                 base::Unretained(&notify_event)));

  std::vector<LogEntry> entries;
  std::unique_ptr<ThreadLog> thread_log(
      new ThreadLog(base::Bind(&FlushEntries, base::Unretained(&entries))));

  thread_log->AddEntry(reinterpret_cast<void*>(0x2));
  thread_log->AddEntry(reinterpret_cast<void*>(0x3));

  // This should make the manager spawn its internal flush thread which will
  // wait for a notification before it starts doing some work.
  manager.AddLog(std::move(thread_log));

  EXPECT_EQ(0U, entries.size());
  // This will wake up the internal thread.
  wait_event.Signal();
  // Now it's our turn to wait until it performed the flush.
  notify_event.Wait();

  // The flush should have moved the data to the local vector of entries.
  EXPECT_EQ(2U, entries.size());
  ASSERT_EQ(2U, reinterpret_cast<uintptr_t>(entries[0].address));
  ASSERT_EQ(3U, reinterpret_cast<uintptr_t>(entries[1].address));
}

}  // namespace
}  // namespace cygprofile

// Custom runner implementation since base's one requires JNI on Android.
int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
