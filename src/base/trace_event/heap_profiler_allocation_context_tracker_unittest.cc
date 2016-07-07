// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include <iterator>

#include "base/memory/ref_counted.h"
#include "base/pending_task.h"
#include "base/trace_event/heap_profiler.h"
#include "base/trace_event/heap_profiler_allocation_context.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"
#include "base/trace_event/trace_event.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

// Define all strings once, because the pseudo stack requires pointer equality,
// and string interning is unreliable.
const char kThreadName[] = "TestThread";
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

  auto* actual = std::begin(ctx.backtrace.frames);
  auto* actual_bottom = actual + ctx.backtrace.frame_count;
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

void AssertBacktraceContainsOnlyThreadName() {
  StackFrame t = StackFrame::FromThreadName(kThreadName);
  AllocationContext ctx =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();

  ASSERT_EQ(1u, ctx.backtrace.frame_count);
  ASSERT_EQ(t, ctx.backtrace.frames[0]);
}

class AllocationContextTrackerTest : public testing::Test {
 public:
  void SetUp() override {
    TraceConfig config("");
    TraceLog::GetInstance()->SetEnabled(config, TraceLog::RECORDING_MODE);
    AllocationContextTracker::SetCaptureMode(
        AllocationContextTracker::CaptureMode::PSEUDO_STACK);
    AllocationContextTracker::SetCurrentThreadName(kThreadName);
  }

  void TearDown() override {
    AllocationContextTracker::SetCaptureMode(
        AllocationContextTracker::CaptureMode::DISABLED);
    TraceLog::GetInstance()->SetDisabled();
  }
};

// Check that |TRACE_EVENT| macros push and pop to the pseudo stack correctly.
TEST_F(AllocationContextTrackerTest, PseudoStackScopedTrace) {
  StackFrame t = StackFrame::FromThreadName(kThreadName);
  StackFrame c = StackFrame::FromTraceEventName(kCupcake);
  StackFrame d = StackFrame::FromTraceEventName(kDonut);
  StackFrame e = StackFrame::FromTraceEventName(kEclair);
  StackFrame f = StackFrame::FromTraceEventName(kFroyo);

  AssertBacktraceContainsOnlyThreadName();

  {
    TRACE_EVENT0("Testing", kCupcake);
    StackFrame frame_c[] = {t, c};
    AssertBacktraceEquals(frame_c);

    {
      TRACE_EVENT0("Testing", kDonut);
      StackFrame frame_cd[] = {t, c, d};
      AssertBacktraceEquals(frame_cd);
    }

    AssertBacktraceEquals(frame_c);

    {
      TRACE_EVENT0("Testing", kEclair);
      StackFrame frame_ce[] = {t, c, e};
      AssertBacktraceEquals(frame_ce);
    }

    AssertBacktraceEquals(frame_c);
  }

  AssertBacktraceContainsOnlyThreadName();

  {
    TRACE_EVENT0("Testing", kFroyo);
    StackFrame frame_f[] = {t, f};
    AssertBacktraceEquals(frame_f);
  }

  AssertBacktraceContainsOnlyThreadName();
}

// Same as |PseudoStackScopedTrace|, but now test the |TRACE_EVENT_BEGIN| and
// |TRACE_EVENT_END| macros.
TEST_F(AllocationContextTrackerTest, PseudoStackBeginEndTrace) {
  StackFrame t = StackFrame::FromThreadName(kThreadName);
  StackFrame c = StackFrame::FromTraceEventName(kCupcake);
  StackFrame d = StackFrame::FromTraceEventName(kDonut);
  StackFrame e = StackFrame::FromTraceEventName(kEclair);
  StackFrame f = StackFrame::FromTraceEventName(kFroyo);

  StackFrame frame_c[] = {t, c};
  StackFrame frame_cd[] = {t, c, d};
  StackFrame frame_ce[] = {t, c, e};
  StackFrame frame_f[] = {t, f};

  AssertBacktraceContainsOnlyThreadName();

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

  AssertBacktraceContainsOnlyThreadName();

  TRACE_EVENT_BEGIN0("Testing", kFroyo);
  AssertBacktraceEquals(frame_f);
  TRACE_EVENT_END0("Testing", kFroyo);

  AssertBacktraceContainsOnlyThreadName();
}

TEST_F(AllocationContextTrackerTest, PseudoStackMixedTrace) {
  StackFrame t = StackFrame::FromThreadName(kThreadName);
  StackFrame c = StackFrame::FromTraceEventName(kCupcake);
  StackFrame d = StackFrame::FromTraceEventName(kDonut);
  StackFrame e = StackFrame::FromTraceEventName(kEclair);
  StackFrame f = StackFrame::FromTraceEventName(kFroyo);

  StackFrame frame_c[] = {t, c};
  StackFrame frame_cd[] = {t, c, d};
  StackFrame frame_e[] = {t, e};
  StackFrame frame_ef[] = {t, e, f};

  AssertBacktraceContainsOnlyThreadName();

  TRACE_EVENT_BEGIN0("Testing", kCupcake);
  AssertBacktraceEquals(frame_c);

  {
    TRACE_EVENT0("Testing", kDonut);
    AssertBacktraceEquals(frame_cd);
  }

  AssertBacktraceEquals(frame_c);
  TRACE_EVENT_END0("Testing", kCupcake);
  AssertBacktraceContainsOnlyThreadName();

  {
    TRACE_EVENT0("Testing", kEclair);
    AssertBacktraceEquals(frame_e);

    TRACE_EVENT_BEGIN0("Testing", kFroyo);
    AssertBacktraceEquals(frame_ef);
    TRACE_EVENT_END0("Testing", kFroyo);
    AssertBacktraceEquals(frame_e);
  }

  AssertBacktraceContainsOnlyThreadName();
}

TEST_F(AllocationContextTrackerTest, BacktraceTakesTop) {
  StackFrame t = StackFrame::FromThreadName(kThreadName);
  StackFrame c = StackFrame::FromTraceEventName(kCupcake);
  StackFrame f = StackFrame::FromTraceEventName(kFroyo);

  // Push 11 events onto the pseudo stack.
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
    ASSERT_EQ(t, ctx.backtrace.frames[0]);
    ASSERT_EQ(c, ctx.backtrace.frames[1]);
    ASSERT_EQ(f, ctx.backtrace.frames[11]);
  }

  {
    AllocationContext ctx =
        AllocationContextTracker::GetInstanceForCurrentThread()
            ->GetContextSnapshot();
    ASSERT_EQ(t, ctx.backtrace.frames[0]);
    ASSERT_EQ(c, ctx.backtrace.frames[1]);
    ASSERT_EQ(f, ctx.backtrace.frames[11]);
  }
}

TEST_F(AllocationContextTrackerTest, TrackTaskContext) {
  const char kContext1[] = "context1";
  const char kContext2[] = "context2";
  {
    // The context from the scoped task event should be used as type name.
    TRACE_HEAP_PROFILER_API_SCOPED_TASK_EXECUTION event1(kContext1);
    AllocationContext ctx1 =
        AllocationContextTracker::GetInstanceForCurrentThread()
            ->GetContextSnapshot();
    ASSERT_EQ(kContext1, ctx1.type_name);

    // In case of nested events, the last event's context should be used.
    TRACE_HEAP_PROFILER_API_SCOPED_TASK_EXECUTION event2(kContext2);
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

TEST_F(AllocationContextTrackerTest, IgnoreAllocationTest) {
  TRACE_EVENT0("Testing", kCupcake);
  TRACE_EVENT0("Testing", kDonut);
  HEAP_PROFILER_SCOPED_IGNORE;
  AllocationContext ctx =
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->GetContextSnapshot();
  const StringPiece kTracingOverhead("tracing_overhead");
  ASSERT_EQ(kTracingOverhead,
            static_cast<const char*>(ctx.backtrace.frames[0].value));
  ASSERT_EQ(1u, ctx.backtrace.frame_count);
}

}  // namespace trace_event
}  // namespace base
