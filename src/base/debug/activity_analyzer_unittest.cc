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
#include "base/stl_util.h"
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

TEST_F(ActivityAnalyzerTest, UserDataSnapshotTest) {
  GlobalActivityTracker::CreateWithLocalMemory(kMemorySize, 0, "", 3);
  ThreadActivityAnalyzer::Snapshot snapshot;

  const char string1a[] = "string1a";
  const char string1b[] = "string1b";
  const char string2a[] = "string2a";
  const char string2b[] = "string2b";

  PersistentMemoryAllocator* allocator =
      GlobalActivityTracker::Get()->allocator();
  GlobalActivityAnalyzer global_analyzer(MakeUnique<PersistentMemoryAllocator>(
      const_cast<void*>(allocator->data()), allocator->size(), 0, 0, "", true));

  ThreadActivityTracker* tracker =
      GlobalActivityTracker::Get()->GetOrCreateTrackerForCurrentThread();

  {
    ScopedActivity activity1(1, 11, 111);
    ActivityUserData& user_data1 = activity1.user_data();
    user_data1.Set("raw1", "foo1", 4);
    user_data1.SetString("string1", "bar1");
    user_data1.SetChar("char1", '1');
    user_data1.SetInt("int1", -1111);
    user_data1.SetUint("uint1", 1111);
    user_data1.SetBool("bool1", true);
    user_data1.SetReference("ref1", string1a, sizeof(string1a));
    user_data1.SetStringReference("sref1", string1b);

    {
      ScopedActivity activity2(2, 22, 222);
      ActivityUserData& user_data2 = activity2.user_data();
      user_data2.Set("raw2", "foo2", 4);
      user_data2.SetString("string2", "bar2");
      user_data2.SetChar("char2", '2');
      user_data2.SetInt("int2", -2222);
      user_data2.SetUint("uint2", 2222);
      user_data2.SetBool("bool2", false);
      user_data2.SetReference("ref2", string2a, sizeof(string2a));
      user_data2.SetStringReference("sref2", string2b);

      ASSERT_TRUE(tracker->CreateSnapshot(&snapshot));
      ASSERT_EQ(2U, snapshot.activity_stack.size());

      ThreadActivityAnalyzer analyzer(*tracker);
      analyzer.AddGlobalInformation(&global_analyzer);
      const ThreadActivityAnalyzer::Snapshot& snapshot =
          analyzer.activity_snapshot();
      ASSERT_EQ(2U, snapshot.user_data_stack.size());
      const ActivityUserData::Snapshot& user_data =
          snapshot.user_data_stack.at(1);
      EXPECT_EQ(8U, user_data.size());
      ASSERT_TRUE(ContainsKey(user_data, "raw2"));
      EXPECT_EQ("foo2", user_data.at("raw2").Get().as_string());
      ASSERT_TRUE(ContainsKey(user_data, "string2"));
      EXPECT_EQ("bar2", user_data.at("string2").GetString().as_string());
      ASSERT_TRUE(ContainsKey(user_data, "char2"));
      EXPECT_EQ('2', user_data.at("char2").GetChar());
      ASSERT_TRUE(ContainsKey(user_data, "int2"));
      EXPECT_EQ(-2222, user_data.at("int2").GetInt());
      ASSERT_TRUE(ContainsKey(user_data, "uint2"));
      EXPECT_EQ(2222U, user_data.at("uint2").GetUint());
      ASSERT_TRUE(ContainsKey(user_data, "bool2"));
      EXPECT_FALSE(user_data.at("bool2").GetBool());
      ASSERT_TRUE(ContainsKey(user_data, "ref2"));
      EXPECT_EQ(string2a, user_data.at("ref2").GetReference().data());
      EXPECT_EQ(sizeof(string2a), user_data.at("ref2").GetReference().size());
      ASSERT_TRUE(ContainsKey(user_data, "sref2"));
      EXPECT_EQ(string2b, user_data.at("sref2").GetStringReference().data());
      EXPECT_EQ(strlen(string2b),
                user_data.at("sref2").GetStringReference().size());
    }

    ASSERT_TRUE(tracker->CreateSnapshot(&snapshot));
    ASSERT_EQ(1U, snapshot.activity_stack.size());

    ThreadActivityAnalyzer analyzer(*tracker);
    analyzer.AddGlobalInformation(&global_analyzer);
    const ThreadActivityAnalyzer::Snapshot& snapshot =
        analyzer.activity_snapshot();
    ASSERT_EQ(1U, snapshot.user_data_stack.size());
    const ActivityUserData::Snapshot& user_data =
        snapshot.user_data_stack.at(0);
    EXPECT_EQ(8U, user_data.size());
    EXPECT_EQ("foo1", user_data.at("raw1").Get().as_string());
    EXPECT_EQ("bar1", user_data.at("string1").GetString().as_string());
    EXPECT_EQ('1', user_data.at("char1").GetChar());
    EXPECT_EQ(-1111, user_data.at("int1").GetInt());
    EXPECT_EQ(1111U, user_data.at("uint1").GetUint());
    EXPECT_TRUE(user_data.at("bool1").GetBool());
    EXPECT_EQ(string1a, user_data.at("ref1").GetReference().data());
    EXPECT_EQ(sizeof(string1a), user_data.at("ref1").GetReference().size());
    EXPECT_EQ(string1b, user_data.at("sref1").GetStringReference().data());
    EXPECT_EQ(strlen(string1b),
              user_data.at("sref1").GetStringReference().size());
  }

  ASSERT_TRUE(tracker->CreateSnapshot(&snapshot));
  ASSERT_EQ(0U, snapshot.activity_stack.size());
}

TEST_F(ActivityAnalyzerTest, GlobalUserDataTest) {
  GlobalActivityTracker::CreateWithLocalMemory(kMemorySize, 0, "", 3);

  const char string1[] = "foo";
  const char string2[] = "bar";

  PersistentMemoryAllocator* allocator =
      GlobalActivityTracker::Get()->allocator();
  GlobalActivityAnalyzer global_analyzer(MakeUnique<PersistentMemoryAllocator>(
      const_cast<void*>(allocator->data()), allocator->size(), 0, 0, "", true));

  ActivityUserData& global_data = GlobalActivityTracker::Get()->global_data();
  global_data.Set("raw", "foo", 3);
  global_data.SetString("string", "bar");
  global_data.SetChar("char", '9');
  global_data.SetInt("int", -9999);
  global_data.SetUint("uint", 9999);
  global_data.SetBool("bool", true);
  global_data.SetReference("ref", string1, sizeof(string1));
  global_data.SetStringReference("sref", string2);

  ActivityUserData::Snapshot snapshot =
      global_analyzer.GetGlobalUserDataSnapshot();
  ASSERT_TRUE(ContainsKey(snapshot, "raw"));
  EXPECT_EQ("foo", snapshot.at("raw").Get().as_string());
  ASSERT_TRUE(ContainsKey(snapshot, "string"));
  EXPECT_EQ("bar", snapshot.at("string").GetString().as_string());
  ASSERT_TRUE(ContainsKey(snapshot, "char"));
  EXPECT_EQ('9', snapshot.at("char").GetChar());
  ASSERT_TRUE(ContainsKey(snapshot, "int"));
  EXPECT_EQ(-9999, snapshot.at("int").GetInt());
  ASSERT_TRUE(ContainsKey(snapshot, "uint"));
  EXPECT_EQ(9999U, snapshot.at("uint").GetUint());
  ASSERT_TRUE(ContainsKey(snapshot, "bool"));
  EXPECT_TRUE(snapshot.at("bool").GetBool());
  ASSERT_TRUE(ContainsKey(snapshot, "ref"));
  EXPECT_EQ(string1, snapshot.at("ref").GetReference().data());
  EXPECT_EQ(sizeof(string1), snapshot.at("ref").GetReference().size());
  ASSERT_TRUE(ContainsKey(snapshot, "sref"));
  EXPECT_EQ(string2, snapshot.at("sref").GetStringReference().data());
  EXPECT_EQ(strlen(string2), snapshot.at("sref").GetStringReference().size());
}

TEST_F(ActivityAnalyzerTest, GlobalModulesTest) {
  GlobalActivityTracker::CreateWithLocalMemory(kMemorySize, 0, "", 3);

  PersistentMemoryAllocator* allocator =
      GlobalActivityTracker::Get()->allocator();
  GlobalActivityAnalyzer global_analyzer(MakeUnique<PersistentMemoryAllocator>(
      const_cast<void*>(allocator->data()), allocator->size(), 0, 0, "", true));

  GlobalActivityTracker::ModuleInfo info1;
  info1.is_loaded = true;
  info1.address = 0x12345678;
  info1.load_time = 1111;
  info1.size = 0xABCDEF;
  info1.timestamp = 111;
  info1.age = 11;
  info1.identifier[0] = 1;
  info1.file = "anything";
  info1.debug_file = "elsewhere";

  GlobalActivityTracker::Get()->RecordModuleInfo(info1);
  std::vector<GlobalActivityTracker::ModuleInfo> modules1;
  modules1 = global_analyzer.GetModules();
  ASSERT_EQ(1U, modules1.size());
  GlobalActivityTracker::ModuleInfo& stored1a = modules1[0];
  EXPECT_EQ(info1.is_loaded, stored1a.is_loaded);
  EXPECT_EQ(info1.address, stored1a.address);
  EXPECT_NE(info1.load_time, stored1a.load_time);
  EXPECT_EQ(info1.size, stored1a.size);
  EXPECT_EQ(info1.timestamp, stored1a.timestamp);
  EXPECT_EQ(info1.age, stored1a.age);
  EXPECT_EQ(info1.identifier[0], stored1a.identifier[0]);
  EXPECT_EQ(info1.file, stored1a.file);
  EXPECT_EQ(info1.debug_file, stored1a.debug_file);

  info1.is_loaded = false;
  GlobalActivityTracker::Get()->RecordModuleInfo(info1);
  modules1 = global_analyzer.GetModules();
  ASSERT_EQ(1U, modules1.size());
  GlobalActivityTracker::ModuleInfo& stored1b = modules1[0];
  EXPECT_EQ(info1.is_loaded, stored1b.is_loaded);
  EXPECT_EQ(info1.address, stored1b.address);
  EXPECT_NE(info1.load_time, stored1b.load_time);
  EXPECT_EQ(info1.size, stored1b.size);
  EXPECT_EQ(info1.timestamp, stored1b.timestamp);
  EXPECT_EQ(info1.age, stored1b.age);
  EXPECT_EQ(info1.identifier[0], stored1b.identifier[0]);
  EXPECT_EQ(info1.file, stored1b.file);
  EXPECT_EQ(info1.debug_file, stored1b.debug_file);

  GlobalActivityTracker::ModuleInfo info2;
  info2.is_loaded = true;
  info2.address = 0x87654321;
  info2.load_time = 2222;
  info2.size = 0xFEDCBA;
  info2.timestamp = 222;
  info2.age = 22;
  info2.identifier[0] = 2;
  info2.file = "nothing";
  info2.debug_file = "farewell";

  GlobalActivityTracker::Get()->RecordModuleInfo(info2);
  std::vector<GlobalActivityTracker::ModuleInfo> modules2;
  modules2 = global_analyzer.GetModules();
  ASSERT_EQ(2U, modules2.size());
  GlobalActivityTracker::ModuleInfo& stored2 = modules2[1];
  EXPECT_EQ(info2.is_loaded, stored2.is_loaded);
  EXPECT_EQ(info2.address, stored2.address);
  EXPECT_NE(info2.load_time, stored2.load_time);
  EXPECT_EQ(info2.size, stored2.size);
  EXPECT_EQ(info2.timestamp, stored2.timestamp);
  EXPECT_EQ(info2.age, stored2.age);
  EXPECT_EQ(info2.identifier[0], stored2.identifier[0]);
  EXPECT_EQ(info2.file, stored2.file);
  EXPECT_EQ(info2.debug_file, stored2.debug_file);
}

TEST_F(ActivityAnalyzerTest, GlobalLogMessages) {
  GlobalActivityTracker::CreateWithLocalMemory(kMemorySize, 0, "", 3);

  PersistentMemoryAllocator* allocator =
      GlobalActivityTracker::Get()->allocator();
  GlobalActivityAnalyzer analyzer(MakeUnique<PersistentMemoryAllocator>(
      const_cast<void*>(allocator->data()), allocator->size(), 0, 0, "", true));

  GlobalActivityTracker::Get()->RecordLogMessage("hello world");
  GlobalActivityTracker::Get()->RecordLogMessage("foo bar");

  std::vector<std::string> messages = analyzer.GetLogMessages();
  ASSERT_EQ(2U, messages.size());
  EXPECT_EQ("hello world", messages[0]);
  EXPECT_EQ("foo bar", messages[1]);
}

}  // namespace debug
}  // namespace base
