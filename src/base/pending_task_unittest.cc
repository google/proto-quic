// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/pending_task.h"

#include <vector>

#include "base/bind.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

class PendingTaskTest : public ::testing::Test {
 public:
  PendingTaskTest() = default;

  ~PendingTaskTest() override = default;

 protected:
  using ExpectedTrace = std::vector<const void*>;

  static void VerifyTraceAndPost(
      const scoped_refptr<TaskRunner>& task_runner,
      const tracked_objects::Location& posted_from,
      const tracked_objects::Location& next_from_here,
      const std::vector<const void*>& expected_trace,
      Closure task) {
    SCOPED_TRACE(StringPrintf("Callback Depth: %zu", expected_trace.size()));

    // Beyond depth + 1, the trace is nonsensical because there haven't been
    // enough nested tasks called.
    const PendingTask* current_pending_task =
        MessageLoop::current()->current_pending_task_;
    size_t window = std::min(current_pending_task->task_backtrace.size(),
                             expected_trace.size());

    EXPECT_EQ(posted_from,
              MessageLoop::current()->current_pending_task_->posted_from);
    for (size_t i = 0; i < window; i++) {
      SCOPED_TRACE(StringPrintf("Trace frame: %zu", i));
      EXPECT_EQ(expected_trace[i], current_pending_task->task_backtrace[i]);
    }
    task_runner->PostTask(next_from_here, std::move(task));
  }

  static void RunTwo(Closure c1, Closure c2) {
    c1.Run();
    c2.Run();
  }
};

// Ensure the task backtrace populates correctly.
TEST_F(PendingTaskTest, SingleThreadedSimple) {
  MessageLoop loop;
  const tracked_objects::Location& location0 = FROM_HERE;
  const tracked_objects::Location& location1 = FROM_HERE;
  const tracked_objects::Location& location2 = FROM_HERE;
  const tracked_objects::Location& location3 = FROM_HERE;
  const tracked_objects::Location& location4 = FROM_HERE;
  const tracked_objects::Location& location5 = FROM_HERE;

  Closure task5 = Bind(
      &PendingTaskTest::VerifyTraceAndPost, loop.task_runner(), location4,
      location5,
      ExpectedTrace({location3.program_counter(), location2.program_counter(),
                     location1.program_counter(), location0.program_counter()}),
      Bind(&DoNothing));
  Closure task4 = Bind(
      &PendingTaskTest::VerifyTraceAndPost, loop.task_runner(), location3,
      location4,
      ExpectedTrace({location2.program_counter(), location1.program_counter(),
                     location0.program_counter(), nullptr}),
      task5);
  Closure task3 = Bind(
      &PendingTaskTest::VerifyTraceAndPost, loop.task_runner(), location2,
      location3, ExpectedTrace({location1.program_counter(),
                                location0.program_counter(), nullptr, nullptr}),
      task4);
  Closure task2 =
      Bind(&PendingTaskTest::VerifyTraceAndPost, loop.task_runner(), location1,
           location2, ExpectedTrace({location0.program_counter()}), task3);
  Closure task1 = Bind(&PendingTaskTest::VerifyTraceAndPost, loop.task_runner(),
                       location0, location1, ExpectedTrace({}), task2);

  loop.task_runner()->PostTask(location0, task1);

  RunLoop().RunUntilIdle();
}

// Post a task onto another thread. Ensure on the other thread, it has the
// right stack trace.
TEST_F(PendingTaskTest, MultipleThreads) {
  MessageLoop loop;  // Implicitly "thread a."
  Thread thread_b("pt_test_b");
  Thread thread_c("pt_test_c");
  thread_b.StartAndWaitForTesting();
  thread_c.StartAndWaitForTesting();

  const tracked_objects::Location& location_a0 = FROM_HERE;
  const tracked_objects::Location& location_a1 = FROM_HERE;
  const tracked_objects::Location& location_a2 = FROM_HERE;
  const tracked_objects::Location& location_a3 = FROM_HERE;

  const tracked_objects::Location& location_b0 = FROM_HERE;
  const tracked_objects::Location& location_b1 = FROM_HERE;

  const tracked_objects::Location& location_c0 = FROM_HERE;

  // On thread c, post a task back to thread a that verifies its trace
  // and terminates after one more self-post.
  Closure task_a2 =
      Bind(&PendingTaskTest::VerifyTraceAndPost, loop.task_runner(),
           location_a2, location_a3,
           ExpectedTrace(
               {location_c0.program_counter(), location_b0.program_counter(),
                location_a1.program_counter(), location_a0.program_counter()}),
           Bind(&DoNothing));
  Closure task_c0 = Bind(&PendingTaskTest::VerifyTraceAndPost,
                         loop.task_runner(), location_c0, location_a2,
                         ExpectedTrace({location_b0.program_counter(),
                                        location_a1.program_counter(),
                                        location_a0.program_counter()}),
                         task_a2);

  // On thread b run two tasks that conceptually come from the same location
  // (managed via RunTwo().) One will post back to thread b and another will
  // post to thread c to test spawning multiple tasks on different message
  // loops. The task posted to thread c will not get location b1 whereas the
  // one posted back to thread b will.
  Closure task_b0_fork =
      Bind(&PendingTaskTest::VerifyTraceAndPost,
           thread_c.message_loop()->task_runner(), location_b0, location_c0,
           ExpectedTrace({location_a1.program_counter(),
                          location_a0.program_counter(), nullptr}),
           task_c0);
  Closure task_b0_local =
      Bind(&PendingTaskTest::VerifyTraceAndPost,
           thread_b.message_loop()->task_runner(), location_b0, location_b1,
           ExpectedTrace({location_a1.program_counter(),
                          location_a0.program_counter(), nullptr}),
           Bind(&DoNothing));

  // Push one frame onto the stack in thread a then pass to thread b.
  Closure task_a1 =
      Bind(&PendingTaskTest::VerifyTraceAndPost,
           thread_b.message_loop()->task_runner(), location_a1, location_b0,
           ExpectedTrace({location_a0.program_counter(), nullptr}),
           Bind(&PendingTaskTest::RunTwo, task_b0_local, task_b0_fork));
  Closure task_a0 =
      Bind(&PendingTaskTest::VerifyTraceAndPost, loop.task_runner(),
           location_a0, location_a1, ExpectedTrace({nullptr}), task_a1);

  loop.task_runner()->PostTask(location_a0, task_a0);

  RunLoop().RunUntilIdle();

  thread_b.FlushForTesting();
  thread_b.Stop();

  thread_c.FlushForTesting();
  thread_c.Stop();
}

}  // namespace base
