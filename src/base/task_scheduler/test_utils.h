// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TEST_UTILS_H_
#define BASE_TASK_SCHEDULER_TEST_UTILS_H_

namespace base {
namespace internal {
namespace test {

// An enumeration of possible task scheduler TaskRunner types. Used to
// parametrize relevant task_scheduler tests.
enum class ExecutionMode { PARALLEL, SEQUENCED, SINGLE_THREADED };

}  // namespace test
}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_TEST_UTILS_H_
