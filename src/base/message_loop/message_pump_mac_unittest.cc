// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/message_loop/message_pump_mac.h"

#include "base/mac/scoped_cftyperef.h"
#include "base/macros.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

class TestMessagePumpCFRunLoopBase {
 public:
  bool TestCanInvalidateTimers() {
    return MessagePumpCFRunLoopBase::CanInvalidateCFRunLoopTimers();
  }
  static void SetTimerValid(CFRunLoopTimerRef timer, bool valid) {
    MessagePumpCFRunLoopBase::ChromeCFRunLoopTimerSetValid(timer, valid);
  }

  static void PerformTimerCallback(CFRunLoopTimerRef timer, void* info) {
    TestMessagePumpCFRunLoopBase* self =
        static_cast<TestMessagePumpCFRunLoopBase*>(info);
    self->timer_callback_called_ = true;

    if (self->invalidate_timer_in_callback_) {
      SetTimerValid(timer, false);
    }
  }

  bool invalidate_timer_in_callback_;

  bool timer_callback_called_;
};

TEST(MessagePumpMacTest, TestCanInvalidateTimers) {
  TestMessagePumpCFRunLoopBase message_pump_test;

  // Catch whether or not the use of private API ever starts failing.
  EXPECT_TRUE(message_pump_test.TestCanInvalidateTimers());
}

TEST(MessagePumpMacTest, TestInvalidatedTimerReuse) {
  TestMessagePumpCFRunLoopBase message_pump_test;

  CFRunLoopTimerContext timer_context = CFRunLoopTimerContext();
  timer_context.info = &message_pump_test;
  const CFTimeInterval kCFTimeIntervalMax =
      std::numeric_limits<CFTimeInterval>::max();
  ScopedCFTypeRef<CFRunLoopTimerRef> test_timer(CFRunLoopTimerCreate(
      NULL,                // allocator
      kCFTimeIntervalMax,  // fire time
      kCFTimeIntervalMax,  // interval
      0,                   // flags
      0,                   // priority
      TestMessagePumpCFRunLoopBase::PerformTimerCallback, &timer_context));
  CFRunLoopAddTimer(CFRunLoopGetCurrent(), test_timer,
                    kMessageLoopExclusiveRunLoopMode);

  // Sanity check.
  EXPECT_TRUE(CFRunLoopTimerIsValid(test_timer));

  // Confirm that the timer fires as expected, and that it's not a one-time-use
  // timer (those timers are invalidated after they fire).
  CFAbsoluteTime next_fire_time = CFAbsoluteTimeGetCurrent() + 0.01;
  CFRunLoopTimerSetNextFireDate(test_timer, next_fire_time);
  message_pump_test.timer_callback_called_ = false;
  message_pump_test.invalidate_timer_in_callback_ = false;
  CFRunLoopRunInMode(kMessageLoopExclusiveRunLoopMode, 0.02, true);
  EXPECT_TRUE(message_pump_test.timer_callback_called_);
  EXPECT_TRUE(CFRunLoopTimerIsValid(test_timer));

  // As a repeating timer, the timer should have a new fire date set in the
  // future.
  EXPECT_GT(CFRunLoopTimerGetNextFireDate(test_timer), next_fire_time);

  // Try firing the timer, and invalidating it within its callback.
  next_fire_time = CFAbsoluteTimeGetCurrent() + 0.01;
  CFRunLoopTimerSetNextFireDate(test_timer, next_fire_time);
  message_pump_test.timer_callback_called_ = false;
  message_pump_test.invalidate_timer_in_callback_ = true;
  CFRunLoopRunInMode(kMessageLoopExclusiveRunLoopMode, 0.02, true);
  EXPECT_TRUE(message_pump_test.timer_callback_called_);
  EXPECT_FALSE(CFRunLoopTimerIsValid(test_timer));

  // The CFRunLoop believes the timer is invalid, so it should not have a
  // fire date.
  EXPECT_EQ(0, CFRunLoopTimerGetNextFireDate(test_timer));

  // Now mark the timer as valid and confirm that it still fires correctly.
  TestMessagePumpCFRunLoopBase::SetTimerValid(test_timer, true);
  EXPECT_TRUE(CFRunLoopTimerIsValid(test_timer));
  next_fire_time = CFAbsoluteTimeGetCurrent() + 0.01;
  CFRunLoopTimerSetNextFireDate(test_timer, next_fire_time);
  message_pump_test.timer_callback_called_ = false;
  message_pump_test.invalidate_timer_in_callback_ = false;
  CFRunLoopRunInMode(kMessageLoopExclusiveRunLoopMode, 0.02, true);
  EXPECT_TRUE(message_pump_test.timer_callback_called_);
  EXPECT_TRUE(CFRunLoopTimerIsValid(test_timer));

  // Confirm that the run loop again gave it a new fire date in the future.
  EXPECT_GT(CFRunLoopTimerGetNextFireDate(test_timer), next_fire_time);

  CFRunLoopRemoveTimer(CFRunLoopGetCurrent(), test_timer,
                       kMessageLoopExclusiveRunLoopMode);
}
}  // namespace base
