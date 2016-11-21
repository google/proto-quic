// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/activity_analyzer.h"

#include <atomic>
#include <memory>

#include "base/bind.h"
#include "base/debug/activity_tracker.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/files/memory_mapped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/memory/ptr_util.h"
#include "base/pending_task.h"
#include "base/process/process.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/spin_wait.h"
#include "base/threading/platform_thread.h"
#include "base/threading/simple_thread.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace debug {

namespace {

class TestActivityTracker : public ThreadActivityTracker {
 public:
  TestActivityTracker(std::unique_ptr<char[]> memory, size_t mem_size)
      : ThreadActivityTracker(memset(memory.get(), 0, mem_size), mem_size),
        mem_segment_(std::move(memory)) {}

  ~TestActivityTracker() override {}

 private:
  std::unique_ptr<char[]> mem_segment_;
};

}  // namespace


class ActivityAnalyzerTest : public testing::Test {
 public:
  const int kMemorySize = 1 << 20;  // 1MiB
  const int kStackSize  = 1 << 10;  // 1KiB

  ActivityAnalyzerTest() {}

  ~ActivityAnalyzerTest() override {
    GlobalActivityTracker* global_tracker = GlobalActivityTracker::Get();
    if (global_tracker) {
      global_tracker->ReleaseTrackerForCurrentThreadForTesting();
      delete global_tracker;
    }
  }

  std::unique_ptr<ThreadActivityTracker> CreateActivityTracker() {
    std::unique_ptr<char[]> memory(new char[kStackSize]);
    return MakeUnique<TestActivityTracker>(std::move(memory), kStackSize);
  }

  static void DoNothing() {}
};

TEST_F(ActivityAnalyzerTest, ThreadAnalyzerConstruction) {
  std::unique_ptr<ThreadActivityTracker> tracker = CreateActivityTracker();
  {
    ThreadActivityAnalyzer analyzer(*tracker);
    EXPECT_TRUE(analyzer.IsValid());
    EXPECT_EQ(PlatformThread::GetName(), analyzer.GetThreadName());
  }

  // TODO(bcwhite): More tests once Analyzer does more.
}


// GlobalActivityAnalyzer tests below.

class SimpleActivityThread : public SimpleThread {
 public:
  SimpleActivityThread(const std::string& name,
                       const void* source,
                       Activity::Type activity,
                       const ActivityData& data)
      : SimpleThread(name, Options()),
        source_(source),
        activity_(activity),
        data_(data),
        ready_(false),
        exit_(false),
        exit_condition_(&lock_) {}

  ~SimpleActivityThread() override {}

  void Run() override {
    ThreadActivityTracker::ActivityId id =
        GlobalActivityTracker::Get()
            ->GetOrCreateTrackerForCurrentThread()
            ->PushActivity(source_, activity_, data_);

    {
      AutoLock auto_lock(lock_);
      ready_.store(true, std::memory_order_release);
      while (!exit_.load(std::memory_order_relaxed))
        exit_condition_.Wait();
    }

    GlobalActivityTracker::Get()->GetTrackerForCurrentThread()->PopActivity(id);
  }

  void Exit() {
    AutoLock auto_lock(lock_);
    exit_.store(true, std::memory_order_relaxed);
    exit_condition_.Signal();
  }

  void WaitReady() {
    SPIN_FOR_1_SECOND_OR_UNTIL_TRUE(ready_.load(std::memory_order_acquire));
  }

 private:
  const void* source_;
  Activity::Type activity_;
  ActivityData data_;

  std::atomic<bool> ready_;
  std::atomic<bool> exit_;
  Lock lock_;
  ConditionVariable exit_condition_;

  DISALLOW_COPY_AND_ASSIGN(SimpleActivityThread);
};

TEST_F(ActivityAnalyzerTest, GlobalAnalyzerConstruction) {
  GlobalActivityTracker::CreateWithLocalMemory(kMemorySize, 0, "", 3);

  PersistentMemoryAllocator* allocator =
      GlobalActivityTracker::Get()->allocator();
  GlobalActivityAnalyzer analyzer(MakeUnique<PersistentMemoryAllocator>(
      const_cast<void*>(allocator->data()), allocator->size(), 0, 0, "", true));

  // The only thread at thois point is the test thread.
  ThreadActivityAnalyzer* ta1 = analyzer.GetFirstAnalyzer();
  ASSERT_TRUE(ta1);
  EXPECT_FALSE(analyzer.GetNextAnalyzer());
  ThreadActivityAnalyzer::ThreadKey tk1 = ta1->GetThreadKey();
  EXPECT_EQ(ta1, analyzer.GetAnalyzerForThread(tk1));

  // Create a second thread that will do something.
  SimpleActivityThread t2("t2", nullptr, Activity::ACT_TASK,
                          ActivityData::ForTask(11));
  t2.Start();
  t2.WaitReady();

  // Now there should be two.
  EXPECT_TRUE(analyzer.GetFirstAnalyzer());
  EXPECT_TRUE(analyzer.GetNextAnalyzer());
  EXPECT_FALSE(analyzer.GetNextAnalyzer());

  // Let thread exit.
  t2.Exit();
  t2.Join();

  // Now there should be only one again. Calling GetFirstAnalyzer invalidates
  // any previously returned analyzer pointers.
  ThreadActivityAnalyzer* ta2 = analyzer.GetFirstAnalyzer();
  ASSERT_TRUE(ta2);
  EXPECT_FALSE(analyzer.GetNextAnalyzer());
  ThreadActivityAnalyzer::ThreadKey tk2 = ta2->GetThreadKey();
  EXPECT_EQ(ta2, analyzer.GetAnalyzerForThread(tk2));
  EXPECT_EQ(tk1, tk2);
}

}  // namespace debug
}  // namespace base
