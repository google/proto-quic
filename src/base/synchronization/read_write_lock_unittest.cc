// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/read_write_lock.h"

#include <stdlib.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/synchronization/waitable_event.h"
#include "base/threading/platform_thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace subtle {

// Basic test to make sure that *Acquire()/*Release() don't crash.

class BasicReadWriteLockTestThread : public PlatformThread::Delegate {
 public:
  explicit BasicReadWriteLockTestThread(ReadWriteLock* lock)
      : lock_(lock), acquired_(0) {}

  void ThreadMain() override {
    for (int i = 0; i < 10; i++) {
      AutoReadLock locker(*lock_);
      acquired_++;
    }
    for (int i = 0; i < 10; i++) {
      AutoWriteLock locker(*lock_);
      acquired_++;
      PlatformThread::Sleep(TimeDelta::FromMilliseconds(rand() % 20));
    }
  }

  int acquired() const { return acquired_; }

 private:
  ReadWriteLock* lock_;
  int acquired_;

  DISALLOW_COPY_AND_ASSIGN(BasicReadWriteLockTestThread);
};

TEST(ReadWriteLockTest, Basic) {
  ReadWriteLock lock;
  BasicReadWriteLockTestThread thread(&lock);
  PlatformThreadHandle handle;

  ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));

  int acquired = 0;
  for (int i = 0; i < 5; i++) {
    AutoReadLock locker(lock);
    acquired++;
  }
  for (int i = 0; i < 10; i++) {
    AutoWriteLock locker(lock);
    acquired++;
    PlatformThread::Sleep(TimeDelta::FromMilliseconds(rand() % 20));
  }
  for (int i = 0; i < 5; i++) {
    AutoReadLock locker(lock);
    acquired++;
  }

  PlatformThread::Join(handle);

  EXPECT_EQ(20, acquired);
  EXPECT_GE(20, thread.acquired());
}

// Tests that reader locks allow multiple simultaneous reader acquisitions.

class ReaderReadWriteLockTestThread : public PlatformThread::Delegate {
 public:
  ReaderReadWriteLockTestThread(ReadWriteLock* lock) : lock_(lock) {}

  void ThreadMain() override {
    AutoReadLock locker(*lock_);
    did_acquire_ = true;
  }

  bool did_acquire() const { return did_acquire_; }

 private:
  ReadWriteLock* lock_;
  bool did_acquire_ = false;

  DISALLOW_COPY_AND_ASSIGN(ReaderReadWriteLockTestThread);
};

TEST(ReadWriteLockTest, ReaderTwoThreads) {
  ReadWriteLock lock;

  AutoReadLock auto_lock(lock);

  ReaderReadWriteLockTestThread thread(&lock);
  PlatformThreadHandle handle;

  ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));
  PlatformThread::Join(handle);
  EXPECT_TRUE(thread.did_acquire());
}

// Tests that writer locks exclude reader locks.

class ReadAndWriteReadWriteLockTestThread : public PlatformThread::Delegate {
 public:
  ReadAndWriteReadWriteLockTestThread(ReadWriteLock* lock, int* value)
      : lock_(lock),
        value_(value),
        event_(WaitableEvent::ResetPolicy::MANUAL,
               WaitableEvent::InitialState::NOT_SIGNALED) {}

  void ThreadMain() override {
    AutoWriteLock locker(*lock_);
    (*value_)++;
    event_.Signal();
  }

  void Wait() {
    event_.Wait();
  }

 private:
  ReadWriteLock* lock_;
  int* value_;
  WaitableEvent event_;

  DISALLOW_COPY_AND_ASSIGN(ReadAndWriteReadWriteLockTestThread);
};

TEST(ReadWriteLockTest, ReadAndWriteThreads) {
  ReadWriteLock lock;
  int value = 0;

  ReadAndWriteReadWriteLockTestThread thread(&lock, &value);
  PlatformThreadHandle handle;
  {
    AutoReadLock read_locker(lock);
    ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));

    PlatformThread::Sleep(TimeDelta::FromMilliseconds(10));

    // |value| should be unchanged since we hold a reader lock.
    EXPECT_EQ(0, value);
  }

  thread.Wait();
  // After releasing our reader lock, the thread can acquire a write lock and
  // change |value|.
  EXPECT_EQ(1, value);
  PlatformThread::Join(handle);
}

// Tests that writer locks actually exclude.

class WriterReadWriteLockTestThread : public PlatformThread::Delegate {
 public:
  WriterReadWriteLockTestThread(ReadWriteLock* lock, int* value)
      : lock_(lock), value_(value) {}

  // Static helper which can also be called from the main thread.
  static void DoStuff(ReadWriteLock* lock, int* value) {
    for (int i = 0; i < 40; i++) {
      AutoWriteLock locker(*lock);
      int v = *value;
      PlatformThread::Sleep(TimeDelta::FromMilliseconds(rand() % 10));
      *value = v + 1;
    }
  }

  void ThreadMain() override { DoStuff(lock_, value_); }

 private:
  ReadWriteLock* lock_;
  int* value_;

  DISALLOW_COPY_AND_ASSIGN(WriterReadWriteLockTestThread);
};

TEST(ReadWriteLockTest, MutexTwoThreads) {
  ReadWriteLock lock;
  int value = 0;

  WriterReadWriteLockTestThread thread(&lock, &value);
  PlatformThreadHandle handle;

  ASSERT_TRUE(PlatformThread::Create(0, &thread, &handle));

  WriterReadWriteLockTestThread::DoStuff(&lock, &value);

  PlatformThread::Join(handle);

  EXPECT_EQ(2 * 40, value);
}

TEST(ReadWriteLockTest, MutexFourThreads) {
  ReadWriteLock lock;
  int value = 0;

  WriterReadWriteLockTestThread thread1(&lock, &value);
  WriterReadWriteLockTestThread thread2(&lock, &value);
  WriterReadWriteLockTestThread thread3(&lock, &value);
  PlatformThreadHandle handle1;
  PlatformThreadHandle handle2;
  PlatformThreadHandle handle3;

  ASSERT_TRUE(PlatformThread::Create(0, &thread1, &handle1));
  ASSERT_TRUE(PlatformThread::Create(0, &thread2, &handle2));
  ASSERT_TRUE(PlatformThread::Create(0, &thread3, &handle3));

  WriterReadWriteLockTestThread::DoStuff(&lock, &value);

  PlatformThread::Join(handle1);
  PlatformThread::Join(handle2);
  PlatformThread::Join(handle3);

  EXPECT_EQ(4 * 40, value);
}

}  // namespace subtle
}  // namespace base
