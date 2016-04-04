// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include <iterator>

#include "base/memory/ref_counted.h"
#include "base/pending_task.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"
#include "base/trace_event/trace_event.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

// Define all strings once, because the pseudo stack requires pointer equality,
// and string interning is unreliable.
const char kCupcake[] = "Cupcake";
const char kDonut[] = "Donut";
const char kEclair[] = "Eclair";
const char kFroyo[] = "Froyo";
const char kGingerbread[] = "Gingerbread";

// Asserts that the fixed-size array |expected_backtrace| matches the backtrace
// in |AllocationContextTracker::GetContextSnapshot|.
template <size_t N>
void AssertBacktraceEquals(const StackFrame(&expected_backtrace)[N]) {
  AllocationContext ctx =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();

  auto actual = std::begin(ctx.backtrace.frames);
  auto actual_bottom = std::end(ctx.backtrace.frames);
  auto expected = std::begin(expected_backtrace);
  auto expected_bottom = std::end(expected_backtrace);

  // Note that this requires the pointers to be equal, this is not doing a deep
  // string comparison.
  for (; actual != actual_bottom && expected != expected_bottom;
       actual++, expected++)
    ASSERT_EQ(*expected, *actual);

  // Ensure that the height of the stacks is the same.
  ASSERT_EQ(actual, actual_bottom);
  ASSERT_EQ(expected, expected_bottom);
}

void AssertBacktraceEmpty() {
  AllocationContext ctx =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();

  for (StackFrame frame : ctx.backtrace.frames)
    ASSERT_EQ(nullptr, frame);
}

class AllocationContextTrackerTest : public testing::Test {
 public:
  void SetUp() override {
    TraceConfig config("");
    TraceLog::GetInstance()->SetEnabled(config, TraceLog::RECORDING_MODE);
    AllocationContextTracker::SetCaptureEnabled(true);
  }

  void TearDown() override {
    AllocationContextTracker::SetCaptureEnabled(false);
    TraceLog::GetInstance()->SetDisabled();
  }
};

// Check that |TRACE_EVENT| macros push and pop to the pseudo stack correctly.
// Also check that |GetContextSnapshot| fills the backtrace with null pointers
// when the pseudo stack height is less than the capacity.
TEST_F(AllocationContextTrackerTest, PseudoStackScopedTrace) {
  StackFrame c = kCupcake;
  StackFrame d = kDonut;
  StackFrame e = kEclair;
  StackFrame f = kFroyo;

  AssertBacktraceEmpty();

  {
    TRACE_EVENT0("Testing", kCupcake);
    StackFrame frame_c[] = {c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    AssertBacktraceEquals(frame_c);

    {
      TRACE_EVENT0("Testing", kDonut);
      StackFrame frame_cd[] = {c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      AssertBacktraceEquals(frame_cd);
    }

    AssertBacktraceEquals(frame_c);

    {
      TRACE_EVENT0("Testing", kEclair);
      StackFrame frame_ce[] = {c, e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      AssertBacktraceEquals(frame_ce);
    }

    AssertBacktraceEquals(frame_c);
  }

  AssertBacktraceEmpty();

  {
    TRACE_EVENT0("Testing", kFroyo);
    StackFrame frame_f[] = {f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    AssertBacktraceEquals(frame_f);
  }

  AssertBacktraceEmpty();
}

// Same as |PseudoStackScopedTrace|, but now test the |TRACE_EVENT_BEGIN| and
// |TRACE_EVENT_END| macros.
TEST_F(AllocationContextTrackerTest, PseudoStackBeginEndTrace) {
  StackFrame c = kCupcake;
  StackFrame d = kDonut;
  StackFrame e = kEclair;
  StackFrame f = kFroyo;

  StackFrame frame_c[] = {c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  StackFrame frame_cd[] = {c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  StackFrame frame_ce[] = {c, e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  StackFrame frame_f[] = {f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  AssertBacktraceEmpty();

  TRACE_EVENT_BEGIN0("Testing", kCupcake);
  AssertBacktraceEquals(frame_c);

  TRACE_EVENT_BEGIN0("Testing", kDonut);
  AssertBacktraceEquals(frame_cd);
  TRACE_EVENT_END0("Testing", kDonut);

  AssertBacktraceEquals(frame_c);

  TRACE_EVENT_BEGIN0("Testing", kEclair);
  AssertBacktraceEquals(frame_ce);
  TRACE_EVENT_END0("Testing", kEclair);

  AssertBacktraceEquals(frame_c);
  TRACE_EVENT_END0("Testing", kCupcake);

  AssertBacktraceEmpty();

  TRACE_EVENT_BEGIN0("Testing", kFroyo);
  AssertBacktraceEquals(frame_f);
  TRACE_EVENT_END0("Testing", kFroyo);

  AssertBacktraceEmpty();
}

TEST_F(AllocationContextTrackerTest, PseudoStackMixedTrace) {
  StackFrame c = kCupcake;
  StackFrame d = kDonut;
  StackFrame e = kEclair;
  StackFrame f = kFroyo;

  StackFrame frame_c[] = {c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  StackFrame frame_cd[] = {c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  StackFrame frame_e[] = {e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  StackFrame frame_ef[] = {e, f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  AssertBacktraceEmpty();

  TRACE_EVENT_BEGIN0("Testing", kCupcake);
  AssertBacktraceEquals(frame_c);

  {
    TRACE_EVENT0("Testing", kDonut);
    AssertBacktraceEquals(frame_cd);
  }

  AssertBacktraceEquals(frame_c);
  TRACE_EVENT_END0("Testing", kCupcake);
  AssertBacktraceEmpty();

  {
    TRACE_EVENT0("Testing", kEclair);
    AssertBacktraceEquals(frame_e);

    TRACE_EVENT_BEGIN0("Testing", kFroyo);
    AssertBacktraceEquals(frame_ef);
    TRACE_EVENT_END0("Testing", kFroyo);
    AssertBacktraceEquals(frame_e);
  }

  AssertBacktraceEmpty();
}

TEST_F(AllocationContextTrackerTest, BacktraceTakesTop) {
  // Push 12 events onto the pseudo stack.
  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kCupcake);

  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kCupcake);

  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kDonut);
  TRACE_EVENT0("Testing", kEclair);
  TRACE_EVENT0("Testing", kFroyo);

  {
    TRACE_EVENT0("Testing", kGingerbread);
    AllocationContext ctx =
        AllocationContextTracker::GetInstanceForCurrentThread()
            ->GetContextSnapshot();

    // The pseudo stack relies on pointer equality, not deep string comparisons.
    ASSERT_EQ(kCupcake, ctx.backtrace.frames[0]);
    ASSERT_EQ(kFroyo, ctx.backtrace.frames[11]);
  }

  {
    AllocationContext ctx =
        AllocationContextTracker::GetInstanceForCurrentThread()
            ->GetContextSnapshot();
    ASSERT_EQ(kCupcake, ctx.backtrace.frames[0]);
    ASSERT_EQ(kFroyo, ctx.backtrace.frames[11]);
  }
}

TEST_F(AllocationContextTrackerTest, SetCurrentThreadName) {
  TRACE_EVENT0("Testing", kCupcake);

  // Test if the thread name is inserted into backtrace.
  const char kThread1[] = "thread1";
  AllocationContextTracker::SetCurrentThreadName(kThread1);
  AllocationContext ctx1 =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();
  ASSERT_EQ(kThread1, ctx1.backtrace.frames[0]);
  ASSERT_EQ(kCupcake, ctx1.backtrace.frames[1]);

  // Test if the thread name is reset.
  const char kThread2[] = "thread2";
  AllocationContextTracker::SetCurrentThreadName(kThread2);
  AllocationContext ctx2 =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();
  ASSERT_EQ(kThread2, ctx2.backtrace.frames[0]);
  ASSERT_EQ(kCupcake, ctx2.backtrace.frames[1]);
}

TEST_F(AllocationContextTrackerTest, TrackTaskContext) {
  const char kContext1[] = "context1";
  const char kContext2[] = "context2";
  {
    // The context from the scoped task event should be used as type name.
    TRACE_EVENT_API_SCOPED_TASK_EXECUTION_EVENT event1(kContext1);
    AllocationContext ctx1 =
        AllocationContextTracker::GetInstanceForCurrentThread()
            ->GetContextSnapshot();
    ASSERT_EQ(kContext1, ctx1.type_name);

    // In case of nested events, the last event's context should be used.
    TRACE_EVENT_API_SCOPED_TASK_EXECUTION_EVENT event2(kContext2);
    AllocationContext ctx2 =
        AllocationContextTracker::GetInstanceForCurrentThread()
            ->GetContextSnapshot();
    ASSERT_EQ(kContext2, ctx2.type_name);
  }

  // Type should be nullptr without task event.
  AllocationContext ctx =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();
  ASSERT_FALSE(ctx.type_name);
}

}  // namespace trace_event
}  // namespace base
