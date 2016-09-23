// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_IOS_WAIT_UTIL_H_
#define BASE_TEST_IOS_WAIT_UTIL_H_

#include "base/ios/block_types.h"
#include "base/time/time.h"

namespace base {

class MessageLoop;

namespace test {
namespace ios {

// Runs |action| if non-nil. Then, until either |condition| is true or |timeout|
// expires, repetitively runs the current NSRunLoop and the current MessageLoop
// (if |run_message_loop| is true). |condition| may be nil if there is no
// condition to wait for; the NSRunLoop and current MessageLoop will be run run
// until |timeout| expires. DCHECKs if |condition| is non-nil and |timeout|
// expires before |condition| becomes true. If |timeout| is zero, a reasonable
// default is used. Returns the time spent in the function.
TimeDelta TimeUntilCondition(ProceduralBlock action,
                             ConditionBlock condition,
                             bool run_message_loop,
                             TimeDelta timeout);

// Same as TimeUntilCondition, but doesn't run an action.
void WaitUntilCondition(ConditionBlock condition,
                        bool run_message_loop,
                        TimeDelta timeout);
void WaitUntilCondition(ConditionBlock condition);

// Lets the run loop of the current thread process other messages
// within the given maximum delay. This method may return before max_delay
// elapsed.
void SpinRunLoopWithMaxDelay(TimeDelta max_delay);

// Lets the run loop of the current thread process other messages
// within the given minimum delay. This method returns after |min_delay|
// elapsed.
void SpinRunLoopWithMinDelay(TimeDelta min_delay);

// Deprecated.
// TODO(fdoray): Remove this once call have been removed from ios_internal.
TimeDelta TimeUntilCondition(ProceduralBlock action,
                             ConditionBlock condition,
                             MessageLoop* message_loop,
                             TimeDelta timeout);

// Deprecated.
// TODO(fdoray): Remove this once call have been removed from ios_internal.
void WaitUntilCondition(ConditionBlock condition,
                        MessageLoop* message_loop,
                        TimeDelta timeout);

}  // namespace ios
}  // namespace test
}  // namespace base

#endif  // BASE_TEST_IOS_WAIT_UTIL_H_
