// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test of classes in the tracked_objects.h classes.

#include "base/tracked_objects.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/macros.h"
#include "base/process/process_handle.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"

// Various tests use the address of the line number as a fake unique PC for
// Locations that need to be equivalent.
const int kLineNumber = 1776;
const char kFile[] = "FixedUnitTestFileName";
const char kWorkerThreadName[] = "WorkerThread-*";
const char kMainThreadName[] = "SomeMainThreadName";
const char kStillAlive[] = "Still_Alive";

const int32_t kAllocOps = 23;
const int32_t kFreeOps = 27;
const int32_t kAllocatedBytes = 59934;
const int32_t kFreedBytes = 2 * kAllocatedBytes;
const int32_t kAllocOverheadBytes = kAllocOps * 8;
const int32_t kMaxAllocatedBytes = kAllocatedBytes / 2;

namespace tracked_objects {

class TrackedObjectsTest : public testing::Test {
 protected:
  TrackedObjectsTest() {
    // On entry, leak any database structures in case they are still in use by
    // prior threads.
    ThreadData::ShutdownSingleThreadedCleanup(true);

    test_time_ = 0;
    ThreadData::now_function_for_testing_ = &TrackedObjectsTest::GetTestTime;
  }

  ~TrackedObjectsTest() override {
    // We should not need to leak any structures we create, since we are
    // single threaded, and carefully accounting for items.
    ThreadData::ShutdownSingleThreadedCleanup(false);
  }

  // Reset the profiler state.
  void Reset() {
    ThreadData::ShutdownSingleThreadedCleanup(false);
    test_time_ = 0;
  }

  // Simulate a birth on the thread named |thread_name|, at the given
  // |location|.
  void TallyABirth(const base::Location& location,
                   const std::string& thread_name) {
    // If the |thread_name| is empty, we don't initialize system with a thread
    // name, so we're viewed as a worker thread.
    if (!thread_name.empty())
      ThreadData::InitializeThreadContext(kMainThreadName);

    // Do not delete |birth|.  We don't own it.
    Births* birth = ThreadData::TallyABirthIfActive(location);

    if (ThreadData::status() == ThreadData::DEACTIVATED)
      EXPECT_EQ(reinterpret_cast<Births*>(NULL), birth);
    else
      EXPECT_NE(reinterpret_cast<Births*>(NULL), birth);
  }

  // Helper function to verify the most common test expectations.
  void ExpectSimpleProcessData(const ProcessDataSnapshot& process_data,
                               const std::string& function_name,
                               const std::string& birth_thread,
                               const std::string& death_thread,
                               int count,
                               int run_duration,
                               int queue_duration) {
    ASSERT_EQ(1u, process_data.phased_snapshots.size());
    auto it = process_data.phased_snapshots.find(0);
    ASSERT_TRUE(it != process_data.phased_snapshots.end());
    const ProcessDataPhaseSnapshot& process_data_phase = it->second;

    ASSERT_EQ(1u, process_data_phase.tasks.size());

    EXPECT_EQ(kFile, process_data_phase.tasks[0].birth.location.file_name);
    EXPECT_EQ(function_name,
              process_data_phase.tasks[0].birth.location.function_name);
    EXPECT_EQ(kLineNumber,
              process_data_phase.tasks[0].birth.location.line_number);

    EXPECT_EQ(birth_thread,
              process_data_phase.tasks[0].birth.sanitized_thread_name);

    EXPECT_EQ(count, process_data_phase.tasks[0].death_data.count);
    EXPECT_EQ(count * run_duration,
              process_data_phase.tasks[0].death_data.run_duration_sum);
    EXPECT_EQ(run_duration,
              process_data_phase.tasks[0].death_data.run_duration_max);
    EXPECT_EQ(run_duration,
              process_data_phase.tasks[0].death_data.run_duration_sample);
    EXPECT_EQ(count * queue_duration,
              process_data_phase.tasks[0].death_data.queue_duration_sum);
    EXPECT_EQ(queue_duration,
              process_data_phase.tasks[0].death_data.queue_duration_max);
    EXPECT_EQ(queue_duration,
              process_data_phase.tasks[0].death_data.queue_duration_sample);

    EXPECT_EQ(death_thread,
              process_data_phase.tasks[0].death_sanitized_thread_name);

    EXPECT_EQ(base::GetCurrentProcId(), process_data.process_id);
  }

  // Sets time that will be returned by ThreadData::Now().
  static void SetTestTime(unsigned int test_time) { test_time_ = test_time; }

  int GetNumThreadData() {
    int num_thread_data = 0;
    ThreadData* current = ThreadData::first();
    while (current) {
      ++num_thread_data;
      current = current->next();
    }
    return num_thread_data;
  }

 private:
  // Returns test time in milliseconds.
  static unsigned int GetTestTime() { return test_time_; }

  // Test time in milliseconds.
  static unsigned int test_time_;
};

// static
unsigned int TrackedObjectsTest::test_time_;

TEST_F(TrackedObjectsTest, TaskStopwatchNoStartStop) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  // Check that creating and destroying a stopwatch without starting it doesn't
  // crash.
  TaskStopwatch stopwatch;
}

TEST_F(TrackedObjectsTest, MinimalStartupShutdown) {
  // Minimal test doesn't even create any tasks.
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  EXPECT_FALSE(ThreadData::first());  // No activity even on this thread.
  ThreadData* data = ThreadData::Get();
  EXPECT_TRUE(ThreadData::first());  // Now class was constructed.
  ASSERT_TRUE(data);
  EXPECT_FALSE(data->next());
  EXPECT_EQ(data, ThreadData::Get());
  ThreadData::BirthMap birth_map;
  ThreadData::DeathsSnapshot deaths;
  data->SnapshotMaps(0, &birth_map, &deaths);
  EXPECT_EQ(0u, birth_map.size());
  EXPECT_EQ(0u, deaths.size());

  // Clean up with no leaking.
  Reset();

  // Do it again, just to be sure we reset state completely.
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);
  EXPECT_FALSE(ThreadData::first());  // No activity even on this thread.
  data = ThreadData::Get();
  EXPECT_TRUE(ThreadData::first());  // Now class was constructed.
  ASSERT_TRUE(data);
  EXPECT_FALSE(data->next());
  EXPECT_EQ(data, ThreadData::Get());
  birth_map.clear();
  deaths.clear();
  data->SnapshotMaps(0, &birth_map, &deaths);
  EXPECT_EQ(0u, birth_map.size());
  EXPECT_EQ(0u, deaths.size());
}

TEST_F(TrackedObjectsTest, DeathDataTestRecordDurations) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  std::unique_ptr<DeathData> data(new DeathData());
  ASSERT_NE(data, nullptr);
  EXPECT_EQ(data->run_duration_sum(), 0);
  EXPECT_EQ(data->run_duration_max(), 0);
  EXPECT_EQ(data->run_duration_sample(), 0);
  EXPECT_EQ(data->queue_duration_sum(), 0);
  EXPECT_EQ(data->queue_duration_max(), 0);
  EXPECT_EQ(data->queue_duration_sample(), 0);
  EXPECT_EQ(data->count(), 0);
  EXPECT_EQ(nullptr, data->last_phase_snapshot());

  base::TimeDelta run_duration = base::TimeDelta::FromMilliseconds(42);
  base::TimeDelta queue_duration = base::TimeDelta::FromMilliseconds(8);

  const int kUnrandomInt = 0;  // Fake random int that ensure we sample data.
  data->RecordDurations(queue_duration, run_duration, kUnrandomInt);
  EXPECT_EQ(data->run_duration_sum(), run_duration.InMilliseconds());
  EXPECT_EQ(data->run_duration_max(), run_duration.InMilliseconds());
  EXPECT_EQ(data->run_duration_sample(), run_duration.InMilliseconds());
  EXPECT_EQ(data->queue_duration_sum(), queue_duration.InMilliseconds());
  EXPECT_EQ(data->queue_duration_max(), queue_duration.InMilliseconds());
  EXPECT_EQ(data->queue_duration_sample(), queue_duration.InMilliseconds());
  EXPECT_EQ(data->count(), 1);
  EXPECT_EQ(nullptr, data->last_phase_snapshot());

  data->RecordDurations(queue_duration, run_duration, kUnrandomInt);
  EXPECT_EQ(data->run_duration_sum(),
            (run_duration + run_duration).InMilliseconds());
  EXPECT_EQ(data->run_duration_max(), run_duration.InMilliseconds());
  EXPECT_EQ(data->run_duration_sample(), run_duration.InMilliseconds());
  EXPECT_EQ(data->queue_duration_sum(),
            (queue_duration + queue_duration).InMilliseconds());
  EXPECT_EQ(data->queue_duration_max(), queue_duration.InMilliseconds());
  EXPECT_EQ(data->queue_duration_sample(), queue_duration.InMilliseconds());
  EXPECT_EQ(data->count(), 2);
  EXPECT_EQ(nullptr, data->last_phase_snapshot());
}

TEST_F(TrackedObjectsTest, DeathDataTestRecordAllocations) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  std::unique_ptr<DeathData> data(new DeathData());
  ASSERT_NE(data, nullptr);

  EXPECT_EQ(data->alloc_ops(), 0);
  EXPECT_EQ(data->free_ops(), 0);
  EXPECT_EQ(data->allocated_bytes(), 0);
  EXPECT_EQ(data->freed_bytes(), 0);
  EXPECT_EQ(data->alloc_overhead_bytes(), 0);
  EXPECT_EQ(data->max_allocated_bytes(), 0);

  EXPECT_EQ(nullptr, data->last_phase_snapshot());

  data->RecordAllocations(kAllocOps, kFreeOps, kAllocatedBytes, kFreedBytes,
                          kAllocOverheadBytes, kMaxAllocatedBytes);
  EXPECT_EQ(data->alloc_ops(), kAllocOps);
  EXPECT_EQ(data->free_ops(), kFreeOps);
  EXPECT_EQ(data->allocated_bytes(), kAllocatedBytes);
  EXPECT_EQ(data->freed_bytes(), kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(), kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), kMaxAllocatedBytes);

  // Record another batch, with a smaller max.
  const int32_t kSmallerMaxAllocatedBytes = kMaxAllocatedBytes / 2;
  data->RecordAllocations(kAllocOps, kFreeOps, kAllocatedBytes, kFreedBytes,
                          kAllocOverheadBytes, kSmallerMaxAllocatedBytes);
  EXPECT_EQ(data->alloc_ops(), 2 * kAllocOps);
  EXPECT_EQ(data->free_ops(), 2 * kFreeOps);
  EXPECT_EQ(data->allocated_bytes(), 2 * kAllocatedBytes);
  EXPECT_EQ(data->freed_bytes(), 2 * kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(), 2 * kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), kMaxAllocatedBytes);

  // Now with a larger max.
  const int32_t kLargerMaxAllocatedBytes = kMaxAllocatedBytes * 2;
  data->RecordAllocations(kAllocOps, kFreeOps, kAllocatedBytes, kFreedBytes,
                          kAllocOverheadBytes, kLargerMaxAllocatedBytes);
  EXPECT_EQ(data->alloc_ops(), 3 * kAllocOps);
  EXPECT_EQ(data->free_ops(), 3 * kFreeOps);
  EXPECT_EQ(data->allocated_bytes(), 3 * kAllocatedBytes);
  EXPECT_EQ(data->freed_bytes(), 3 * kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(), 3 * kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), kLargerMaxAllocatedBytes);

  // Saturate everything but aggregate byte counts.
  // In the 32 bit implementation, this tests the case where the low-order
  // word goes negative.
  data->RecordAllocations(INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX);
  EXPECT_EQ(data->alloc_ops(), INT_MAX);
  EXPECT_EQ(data->free_ops(), INT_MAX);
  // The cumulative byte counts are 64 bit wide, and won't saturate easily.
  EXPECT_EQ(data->allocated_bytes(),
            static_cast<int64_t>(INT_MAX) +
                static_cast<int64_t>(3 * kAllocatedBytes));
  EXPECT_EQ(data->freed_bytes(),
            static_cast<int64_t>(INT_MAX) + 3 * kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(),
            static_cast<int64_t>(INT_MAX) + 3 * kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), INT_MAX);

  // The byte counts will be pushed past the 32 bit value range.
  data->RecordAllocations(INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX, INT_MAX);
  EXPECT_EQ(data->alloc_ops(), INT_MAX);
  EXPECT_EQ(data->free_ops(), INT_MAX);
  // The cumulative byte counts are 64 bit wide, and won't saturate easily.
  EXPECT_EQ(data->allocated_bytes(),
            2 * static_cast<int64_t>(INT_MAX) +
                static_cast<int64_t>(3 * kAllocatedBytes));
  EXPECT_EQ(data->freed_bytes(),
            2 * static_cast<int64_t>(INT_MAX) + 3 * kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(),
            2 * static_cast<int64_t>(INT_MAX) + 3 * kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), INT_MAX);
}

TEST_F(TrackedObjectsTest, DeathDataTest2Phases) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  std::unique_ptr<DeathData> data(new DeathData());
  ASSERT_NE(data, nullptr);

  const base::TimeDelta run_duration = base::TimeDelta::FromMilliseconds(42);
  const base::TimeDelta queue_duration = base::TimeDelta::FromMilliseconds(8);

  const int kUnrandomInt = 0;  // Fake random int that ensure we sample data.
  data->RecordDurations(queue_duration, run_duration, kUnrandomInt);
  data->RecordDurations(queue_duration, run_duration, kUnrandomInt);

  data->RecordAllocations(kAllocOps, kFreeOps, kAllocatedBytes, kFreedBytes,
                          kAllocOverheadBytes, kMaxAllocatedBytes);

  data->OnProfilingPhaseCompleted(123);
  EXPECT_EQ(data->run_duration_sum(),
            (run_duration + run_duration).InMilliseconds());
  EXPECT_EQ(data->run_duration_max(), 0);
  EXPECT_EQ(data->run_duration_sample(), run_duration.InMilliseconds());
  EXPECT_EQ(data->queue_duration_sum(),
            (queue_duration + queue_duration).InMilliseconds());
  EXPECT_EQ(data->queue_duration_max(), 0);
  EXPECT_EQ(data->queue_duration_sample(), queue_duration.InMilliseconds());
  EXPECT_EQ(data->count(), 2);

  EXPECT_EQ(data->alloc_ops(), kAllocOps);
  EXPECT_EQ(data->free_ops(), kFreeOps);
  EXPECT_EQ(data->allocated_bytes(), kAllocatedBytes);
  EXPECT_EQ(data->freed_bytes(), kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(), kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), kMaxAllocatedBytes);

  ASSERT_NE(nullptr, data->last_phase_snapshot());
  EXPECT_EQ(123, data->last_phase_snapshot()->profiling_phase);
  EXPECT_EQ(2, data->last_phase_snapshot()->death_data.count);
  EXPECT_EQ(2 * run_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.run_duration_sum);
  EXPECT_EQ(run_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.run_duration_max);
  EXPECT_EQ(run_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.run_duration_sample);
  EXPECT_EQ(2 * queue_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.queue_duration_sum);
  EXPECT_EQ(queue_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.queue_duration_max);
  EXPECT_EQ(queue_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.queue_duration_sample);

  EXPECT_EQ(kAllocOps, data->last_phase_snapshot()->death_data.alloc_ops);
  EXPECT_EQ(kFreeOps, data->last_phase_snapshot()->death_data.free_ops);
  EXPECT_EQ(kAllocatedBytes,
            data->last_phase_snapshot()->death_data.allocated_bytes);
  EXPECT_EQ(kFreedBytes, data->last_phase_snapshot()->death_data.freed_bytes);
  EXPECT_EQ(kAllocOverheadBytes,
            data->last_phase_snapshot()->death_data.alloc_overhead_bytes);
  EXPECT_EQ(kMaxAllocatedBytes,
            data->last_phase_snapshot()->death_data.max_allocated_bytes);

  EXPECT_EQ(nullptr, data->last_phase_snapshot()->prev);

  const base::TimeDelta run_duration1 = base::TimeDelta::FromMilliseconds(21);
  const base::TimeDelta queue_duration1 = base::TimeDelta::FromMilliseconds(4);

  data->RecordDurations(queue_duration1, run_duration1, kUnrandomInt);
  data->RecordAllocations(kAllocOps, kFreeOps, kAllocatedBytes, kFreedBytes,
                          kAllocOverheadBytes, kMaxAllocatedBytes);

  EXPECT_EQ(data->run_duration_sum(),
            (run_duration + run_duration + run_duration1).InMilliseconds());
  EXPECT_EQ(data->run_duration_max(), run_duration1.InMilliseconds());
  EXPECT_EQ(data->run_duration_sample(), run_duration1.InMilliseconds());
  EXPECT_EQ(
      data->queue_duration_sum(),
      (queue_duration + queue_duration + queue_duration1).InMilliseconds());
  EXPECT_EQ(data->queue_duration_max(), queue_duration1.InMilliseconds());
  EXPECT_EQ(data->queue_duration_sample(), queue_duration1.InMilliseconds());
  EXPECT_EQ(data->count(), 3);

  EXPECT_EQ(data->alloc_ops(), 2 * kAllocOps);
  EXPECT_EQ(data->free_ops(), 2 * kFreeOps);
  EXPECT_EQ(data->allocated_bytes(), 2 * kAllocatedBytes);
  EXPECT_EQ(data->freed_bytes(), 2 * kFreedBytes);
  EXPECT_EQ(data->alloc_overhead_bytes(), 2 * kAllocOverheadBytes);
  EXPECT_EQ(data->max_allocated_bytes(), kMaxAllocatedBytes);

  ASSERT_NE(nullptr, data->last_phase_snapshot());
  EXPECT_EQ(123, data->last_phase_snapshot()->profiling_phase);
  EXPECT_EQ(2, data->last_phase_snapshot()->death_data.count);
  EXPECT_EQ(2 * run_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.run_duration_sum);
  EXPECT_EQ(run_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.run_duration_max);
  EXPECT_EQ(run_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.run_duration_sample);
  EXPECT_EQ(2 * queue_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.queue_duration_sum);
  EXPECT_EQ(queue_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.queue_duration_max);
  EXPECT_EQ(queue_duration.InMilliseconds(),
            data->last_phase_snapshot()->death_data.queue_duration_sample);

  EXPECT_EQ(kAllocOps, data->last_phase_snapshot()->death_data.alloc_ops);
  EXPECT_EQ(kFreeOps, data->last_phase_snapshot()->death_data.free_ops);
  EXPECT_EQ(kAllocatedBytes,
            data->last_phase_snapshot()->death_data.allocated_bytes);
  EXPECT_EQ(kFreedBytes, data->last_phase_snapshot()->death_data.freed_bytes);
  EXPECT_EQ(kAllocOverheadBytes,
            data->last_phase_snapshot()->death_data.alloc_overhead_bytes);
  EXPECT_EQ(kMaxAllocatedBytes,
            data->last_phase_snapshot()->death_data.max_allocated_bytes);

  EXPECT_EQ(nullptr, data->last_phase_snapshot()->prev);
}

TEST_F(TrackedObjectsTest, Delta) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  DeathDataSnapshot snapshot;
  snapshot.count = 10;
  snapshot.run_duration_sum = 100;
  snapshot.run_duration_max = 50;
  snapshot.run_duration_sample = 25;
  snapshot.queue_duration_sum = 200;
  snapshot.queue_duration_max = 101;
  snapshot.queue_duration_sample = 26;

  snapshot.alloc_ops = 95;
  snapshot.free_ops = 90;
  snapshot.allocated_bytes = 10240;
  snapshot.freed_bytes = 4096;
  snapshot.alloc_overhead_bytes = 950;
  snapshot.max_allocated_bytes = 10240;

  DeathDataSnapshot older_snapshot;
  older_snapshot.count = 2;
  older_snapshot.run_duration_sum = 95;
  older_snapshot.run_duration_max = 48;
  older_snapshot.run_duration_sample = 22;
  older_snapshot.queue_duration_sum = 190;
  older_snapshot.queue_duration_max = 99;
  older_snapshot.queue_duration_sample = 21;

  older_snapshot.alloc_ops = 45;
  older_snapshot.free_ops = 40;
  older_snapshot.allocated_bytes = 4096;
  older_snapshot.freed_bytes = 2048;
  older_snapshot.alloc_overhead_bytes = 450;
  older_snapshot.max_allocated_bytes = 10200;

  const DeathDataSnapshot& delta = snapshot.Delta(older_snapshot);
  EXPECT_EQ(8, delta.count);
  EXPECT_EQ(5, delta.run_duration_sum);
  EXPECT_EQ(50, delta.run_duration_max);
  EXPECT_EQ(25, delta.run_duration_sample);
  EXPECT_EQ(10, delta.queue_duration_sum);
  EXPECT_EQ(101, delta.queue_duration_max);
  EXPECT_EQ(26, delta.queue_duration_sample);

  EXPECT_EQ(50, delta.alloc_ops);
  EXPECT_EQ(50, delta.free_ops);
  EXPECT_EQ(6144, delta.allocated_bytes);
  EXPECT_EQ(2048, delta.freed_bytes);
  EXPECT_EQ(500, delta.alloc_overhead_bytes);
  EXPECT_EQ(10240, delta.max_allocated_bytes);
}

TEST_F(TrackedObjectsTest, DeactivatedBirthOnlyToSnapshotWorkerThread) {
  // Start in the deactivated state.
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::DEACTIVATED);

  const char kFunction[] = "DeactivatedBirthOnlyToSnapshotWorkerThread";
  base::Location location(kFunction, kFile, kLineNumber, &kLineNumber);
  TallyABirth(location, std::string());

  ProcessDataSnapshot process_data;
  ThreadData::Snapshot(0, &process_data);

  ASSERT_EQ(1u, process_data.phased_snapshots.size());

  auto it = process_data.phased_snapshots.find(0);
  ASSERT_TRUE(it != process_data.phased_snapshots.end());
  const ProcessDataPhaseSnapshot& process_data_phase = it->second;

  ASSERT_EQ(0u, process_data_phase.tasks.size());

  EXPECT_EQ(base::GetCurrentProcId(), process_data.process_id);
}

TEST_F(TrackedObjectsTest, DeactivatedBirthOnlyToSnapshotMainThread) {
  // Start in the deactivated state.
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::DEACTIVATED);

  const char kFunction[] = "DeactivatedBirthOnlyToSnapshotMainThread";
  base::Location location(kFunction, kFile, kLineNumber, &kLineNumber);
  TallyABirth(location, kMainThreadName);

  ProcessDataSnapshot process_data;
  ThreadData::Snapshot(0, &process_data);

  ASSERT_EQ(1u, process_data.phased_snapshots.size());

  auto it = process_data.phased_snapshots.find(0);
  ASSERT_TRUE(it != process_data.phased_snapshots.end());
  const ProcessDataPhaseSnapshot& process_data_phase = it->second;

  ASSERT_EQ(0u, process_data_phase.tasks.size());

  EXPECT_EQ(base::GetCurrentProcId(), process_data.process_id);
}

TEST_F(TrackedObjectsTest, BirthOnlyToSnapshotWorkerThread) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  const char kFunction[] = "BirthOnlyToSnapshotWorkerThread";
  base::Location location(kFunction, kFile, kLineNumber, &kLineNumber);
  TallyABirth(location, std::string());

  ProcessDataSnapshot process_data;
  ThreadData::Snapshot(0, &process_data);
  ExpectSimpleProcessData(process_data, kFunction, kWorkerThreadName,
                          kStillAlive, 1, 0, 0);
}

TEST_F(TrackedObjectsTest, BirthOnlyToSnapshotMainThread) {
  ThreadData::InitializeAndSetTrackingStatus(ThreadData::PROFILING_ACTIVE);

  const char kFunction[] = "BirthOnlyToSnapshotMainThread";
  base::Location location(kFunction, kFile, kLineNumber, &kLineNumber);
  TallyABirth(location, kMainThreadName);

  ProcessDataSnapshot process_data;
  ThreadData::Snapshot(0, &process_data);
  ExpectSimpleProcessData(process_data, kFunction, kMainThreadName, kStillAlive,
                          1, 0, 0);
}

}  // namespace tracked_objects
