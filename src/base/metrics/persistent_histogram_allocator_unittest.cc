// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/persistent_histogram_allocator.h"

#include "base/files/scoped_temp_dir.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/bucket_ranges.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/persistent_memory_allocator.h"
#include "base/metrics/statistics_recorder.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

class PersistentHistogramAllocatorTest : public testing::Test {
 protected:
  const int32_t kAllocatorMemorySize = 64 << 10;  // 64 KiB

  PersistentHistogramAllocatorTest()
      : statistics_recorder_(StatisticsRecorder::CreateTemporaryForTesting()) {
    CreatePersistentHistogramAllocator();
  }
  ~PersistentHistogramAllocatorTest() override {
    DestroyPersistentHistogramAllocator();
  }

  void CreatePersistentHistogramAllocator() {
    allocator_memory_.reset(new char[kAllocatorMemorySize]);

    GlobalHistogramAllocator::ReleaseForTesting();
    memset(allocator_memory_.get(), 0, kAllocatorMemorySize);
    GlobalHistogramAllocator::GetCreateHistogramResultHistogram();
    GlobalHistogramAllocator::CreateWithPersistentMemory(
        allocator_memory_.get(), kAllocatorMemorySize, 0, 0,
        "PersistentHistogramAllocatorTest");
    allocator_ = GlobalHistogramAllocator::Get()->memory_allocator();
  }

  void DestroyPersistentHistogramAllocator() {
    allocator_ = nullptr;
    GlobalHistogramAllocator::ReleaseForTesting();
  }

  std::unique_ptr<StatisticsRecorder> statistics_recorder_;
  std::unique_ptr<char[]> allocator_memory_;
  PersistentMemoryAllocator* allocator_ = nullptr;

 private:
  DISALLOW_COPY_AND_ASSIGN(PersistentHistogramAllocatorTest);
};

TEST_F(PersistentHistogramAllocatorTest, CreateAndIterateTest) {
  PersistentMemoryAllocator::MemoryInfo meminfo0;
  allocator_->GetMemoryInfo(&meminfo0);

  // Try basic construction
  HistogramBase* histogram = Histogram::FactoryGet(
      "TestHistogram", 1, 1000, 10, HistogramBase::kIsPersistent);
  EXPECT_TRUE(histogram);
  histogram->CheckName("TestHistogram");
  PersistentMemoryAllocator::MemoryInfo meminfo1;
  allocator_->GetMemoryInfo(&meminfo1);
  EXPECT_GT(meminfo0.free, meminfo1.free);

  HistogramBase* linear_histogram = LinearHistogram::FactoryGet(
      "TestLinearHistogram", 1, 1000, 10, HistogramBase::kIsPersistent);
  EXPECT_TRUE(linear_histogram);
  linear_histogram->CheckName("TestLinearHistogram");
  PersistentMemoryAllocator::MemoryInfo meminfo2;
  allocator_->GetMemoryInfo(&meminfo2);
  EXPECT_GT(meminfo1.free, meminfo2.free);

  HistogramBase* boolean_histogram = BooleanHistogram::FactoryGet(
      "TestBooleanHistogram", HistogramBase::kIsPersistent);
  EXPECT_TRUE(boolean_histogram);
  boolean_histogram->CheckName("TestBooleanHistogram");
  PersistentMemoryAllocator::MemoryInfo meminfo3;
  allocator_->GetMemoryInfo(&meminfo3);
  EXPECT_GT(meminfo2.free, meminfo3.free);

  std::vector<int> custom_ranges;
  custom_ranges.push_back(1);
  custom_ranges.push_back(5);
  HistogramBase* custom_histogram = CustomHistogram::FactoryGet(
      "TestCustomHistogram", custom_ranges, HistogramBase::kIsPersistent);
  EXPECT_TRUE(custom_histogram);
  custom_histogram->CheckName("TestCustomHistogram");
  PersistentMemoryAllocator::MemoryInfo meminfo4;
  allocator_->GetMemoryInfo(&meminfo4);
  EXPECT_GT(meminfo3.free, meminfo4.free);

  PersistentMemoryAllocator::Iterator iter(allocator_);
  uint32_t type;
  EXPECT_NE(0U, iter.GetNext(&type));  // Histogram
  EXPECT_NE(0U, iter.GetNext(&type));  // LinearHistogram
  EXPECT_NE(0U, iter.GetNext(&type));  // BooleanHistogram
  EXPECT_NE(0U, iter.GetNext(&type));  // CustomHistogram
  EXPECT_EQ(0U, iter.GetNext(&type));

  // Create a second allocator and have it access the memory of the first.
  std::unique_ptr<HistogramBase> recovered;
  PersistentHistogramAllocator recovery(MakeUnique<PersistentMemoryAllocator>(
      allocator_memory_.get(), kAllocatorMemorySize, 0, 0, "", false));
  PersistentHistogramAllocator::Iterator histogram_iter(&recovery);

  recovered = histogram_iter.GetNext();
  ASSERT_TRUE(recovered);
  recovered->CheckName("TestHistogram");

  recovered = histogram_iter.GetNext();
  ASSERT_TRUE(recovered);
  recovered->CheckName("TestLinearHistogram");

  recovered = histogram_iter.GetNext();
  ASSERT_TRUE(recovered);
  recovered->CheckName("TestBooleanHistogram");

  recovered = histogram_iter.GetNext();
  ASSERT_TRUE(recovered);
  recovered->CheckName("TestCustomHistogram");

  recovered = histogram_iter.GetNext();
  EXPECT_FALSE(recovered);
}

TEST_F(PersistentHistogramAllocatorTest, CreateWithFileTest) {
  const char temp_name[] = "CreateWithFileTest";
  ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  FilePath temp_file = temp_dir.GetPath().AppendASCII(temp_name);
  const size_t temp_size = 64 << 10;  // 64 KiB

  // Test creation of a new file.
  GlobalHistogramAllocator::ReleaseForTesting();
  GlobalHistogramAllocator::CreateWithFile(temp_file, temp_size, 0, temp_name);
  EXPECT_EQ(std::string(temp_name),
            GlobalHistogramAllocator::Get()->memory_allocator()->Name());

  // Test re-open of a possibly-existing file.
  GlobalHistogramAllocator::ReleaseForTesting();
  GlobalHistogramAllocator::CreateWithFile(temp_file, temp_size, 0, "");
  EXPECT_EQ(std::string(temp_name),
            GlobalHistogramAllocator::Get()->memory_allocator()->Name());

  // Test re-open of an known-existing file.
  GlobalHistogramAllocator::ReleaseForTesting();
  GlobalHistogramAllocator::CreateWithFile(temp_file, 0, 0, "");
  EXPECT_EQ(std::string(temp_name),
            GlobalHistogramAllocator::Get()->memory_allocator()->Name());

  // Final release so file and temp-dir can be removed.
  GlobalHistogramAllocator::ReleaseForTesting();
}

TEST_F(PersistentHistogramAllocatorTest, StatisticsRecorderTest) {
  size_t starting_sr_count = StatisticsRecorder::GetHistogramCount();

  // Create a local StatisticsRecorder in which the newly created histogram
  // will be recorded.
  std::unique_ptr<StatisticsRecorder> local_sr =
      StatisticsRecorder::CreateTemporaryForTesting();
  EXPECT_EQ(0U, StatisticsRecorder::GetHistogramCount());

  HistogramBase* histogram = LinearHistogram::FactoryGet(
      "TestHistogram", 1, 10, 10, HistogramBase::kIsPersistent);
  EXPECT_TRUE(histogram);
  EXPECT_EQ(1U, StatisticsRecorder::GetHistogramCount());
  histogram->Add(3);
  histogram->Add(1);
  histogram->Add(4);
  histogram->Add(1);
  histogram->Add(6);

  // Destroy the local SR and ensure that we're back to the initial state.
  local_sr.reset();
  EXPECT_EQ(starting_sr_count, StatisticsRecorder::GetHistogramCount());

  // Create a second allocator and have it access the memory of the first.
  std::unique_ptr<HistogramBase> recovered;
  PersistentHistogramAllocator recovery(MakeUnique<PersistentMemoryAllocator>(
      allocator_memory_.get(), kAllocatorMemorySize, 0, 0, "", false));
  PersistentHistogramAllocator::Iterator histogram_iter(&recovery);

  recovered = histogram_iter.GetNext();
  ASSERT_TRUE(recovered);

  // Merge the recovered histogram to the SR. It will always be a new object.
  recovery.MergeHistogramDeltaToStatisticsRecorder(recovered.get());
  EXPECT_EQ(starting_sr_count + 1, StatisticsRecorder::GetHistogramCount());
  HistogramBase* found =
      StatisticsRecorder::FindHistogram(recovered->histogram_name());
  ASSERT_TRUE(found);
  EXPECT_NE(recovered.get(), found);

  // Ensure that the data got merged, too.
  std::unique_ptr<HistogramSamples> snapshot = found->SnapshotSamples();
  EXPECT_EQ(recovered->SnapshotSamples()->TotalCount(), snapshot->TotalCount());
  EXPECT_EQ(1, snapshot->GetCount(3));
  EXPECT_EQ(2, snapshot->GetCount(1));
  EXPECT_EQ(1, snapshot->GetCount(4));
  EXPECT_EQ(1, snapshot->GetCount(6));
}

}  // namespace base
