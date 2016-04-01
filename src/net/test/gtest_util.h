// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Testing utilities that extend gtest.

#ifndef NET_TEST_GTEST_UTIL_H_
#define NET_TEST_GTEST_UTIL_H_

#include "base/test/mock_log.h"
#include "net/test/scoped_disable_exit_on_dfatal.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

// Internal implementation for the EXPECT_DFATAL and ASSERT_DFATAL
// macros.  Do not use this directly.
#define GTEST_DFATAL_(statement, matcher, fail)                        \
  GTEST_AMBIGUOUS_ELSE_BLOCKER_                                        \
  if (true) {                                                          \
    ::base::test::MockLog gtest_log;                                   \
    ::net::test::ScopedDisableExitOnDFatal gtest_disable_exit;         \
    using ::testing::_;                                                \
    EXPECT_CALL(gtest_log, Log(_, _, _, _, _))                         \
        .WillRepeatedly(::testing::Return(false));                     \
    EXPECT_CALL(gtest_log, Log(logging::LOG_DFATAL, _, _, _, matcher)) \
        .Times(::testing::AtLeast(1))                                  \
        .WillOnce(::testing::Return(false));                           \
    gtest_log.StartCapturingLogs();                                    \
    { statement; }                                                     \
    gtest_log.StopCapturingLogs();                                     \
    if (!testing::Mock::VerifyAndClear(&gtest_log)) {                  \
      goto GTEST_CONCAT_TOKEN_(gtest_label_dfatal_, __LINE__);         \
    }                                                                  \
  } else                                                               \
  GTEST_CONCAT_TOKEN_(gtest_label_dfatal_, __LINE__) : fail("")

// The EXPECT_DFATAL and ASSERT_DFATAL macros are lightweight
// alternatives to EXPECT_DEBUG_DEATH and ASSERT_DEBUG_DEATH. They
// are appropriate for testing that your code logs a message at the
// DFATAL level.
//
// Unlike EXPECT_DEBUG_DEATH and ASSERT_DEBUG_DEATH, these macros
// execute the given statement in the current process, not a forked
// one.  This works because we disable exiting the program for
// LOG(DFATAL).  This makes the tests run more quickly.
//
// The _WITH() variants allow one to specify any matcher for the
// DFATAL log message, whereas the other variants assume a regex.

#define EXPECT_DFATAL_WITH(statement, matcher) \
  GTEST_DFATAL_(statement, matcher, GTEST_NONFATAL_FAILURE_)

#define ASSERT_DFATAL_WITH(statement, matcher) \
  GTEST_DFATAL_(statement, matcher, GTEST_FATAL_FAILURE_)

#define EXPECT_DFATAL(statement, regex) \
  EXPECT_DFATAL_WITH(statement, ::testing::ContainsRegex(regex))

#define ASSERT_DFATAL(statement, regex) \
  ASSERT_DFATAL_WITH(statement, ::testing::ContainsRegex(regex))

// The EXPECT_DEBUG_DFATAL and ASSERT_DEBUG_DFATAL macros are similar to
// EXPECT_DFATAL and ASSERT_DFATAL. Use them in conjunction with DLOG(DFATAL)
// or similar macros that produce no-op in opt build and DFATAL in dbg build.

#ifndef NDEBUG

#define EXPECT_DEBUG_DFATAL(statement, regex) \
  EXPECT_DFATAL(statement, regex)
#define ASSERT_DEBUG_DFATAL(statement, regex) \
  ASSERT_DFATAL(statement, regex)

#else  // NDEBUG

#define EXPECT_DEBUG_DFATAL(statement, regex) \
  GTEST_AMBIGUOUS_ELSE_BLOCKER_               \
  if (true) {                                 \
    (void)(regex);                            \
    statement;                                \
  } else                                      \
    GTEST_NONFATAL_FAILURE_("")
#define ASSERT_DEBUG_DFATAL(statement, regex) \
  GTEST_AMBIGUOUS_ELSE_BLOCKER_               \
  if (true) {                                 \
    (void)(regex);                            \
    statement;                                \
  } else                                      \
    GTEST_NONFATAL_FAILURE_("")

#endif  // NDEBUG

}  // namespace test
}  // namespace net

#endif  // NET_TEST_GTEST_UTIL_H_
