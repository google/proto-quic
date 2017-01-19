// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Testing utilities that extend gtest.

#ifndef NET_TEST_GTEST_UTIL_H_
#define NET_TEST_GTEST_UTIL_H_

#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/test/mock_log.h"
#include "net/base/net_errors.h"
#include "net/test/scoped_disable_exit_on_dfatal.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

// A GMock matcher that checks whether the argument is the expected net::Error.
// On failure, the expected and actual net::Error names will be printed.
// Usage: EXPECT_THAT(foo(), IsError(net::ERR_INVALID_ARGUMENT));
MATCHER_P(IsError,
          expected,
          std::string(negation ? "not " : "") + net::ErrorToString(expected)) {
  if (arg <= 0)
    *result_listener << net::ErrorToString(arg);
  return arg == expected;
}

// Shorthand for IsError(net::OK).
// Usage: EXPECT_THAT(foo(), IsOk());
MATCHER(IsOk,
        std::string(negation ? "not " : "") + net::ErrorToString(net::OK)) {
  if (arg <= 0)
    *result_listener << net::ErrorToString(arg);
  return arg == net::OK;
}

// A gMock matcher for base::StringPiece arguments.
// gMock's built-in HasSubstrMatcher does not work,
// because base::StringPiece cannot be implicitly converted to std::string.
class StringPieceHasSubstrMatcher {
 public:
  explicit StringPieceHasSubstrMatcher(const std::string& substring)
      : substring_(substring) {}

  bool MatchAndExplain(base::StringPiece s,
                       ::testing::MatchResultListener* listener) const {
    return s.as_string().find(substring_) != std::string::npos;
  }

  // Describe what this matcher matches.
  void DescribeTo(std::ostream* os) const {
    *os << "has substring " << substring_;
  }

  void DescribeNegationTo(std::ostream* os) const {
    *os << "has no substring " << substring_;
  }

 private:
  const std::string substring_;

  DISALLOW_ASSIGN(StringPieceHasSubstrMatcher);
};

// Internal implementation for the EXPECT_DFATAL and ASSERT_DFATAL
// macros.  Do not use this directly.
#define GTEST_DFATAL_(statement, severity, matcher, fail)                    \
  do {                                                                       \
    ::base::test::MockLog gtest_log;                                         \
    ::net::test::ScopedDisableExitOnDFatal gtest_disable_exit;               \
    using ::testing::_;                                                      \
    EXPECT_CALL(gtest_log, Log(_, _, _, _, _))                               \
        .WillRepeatedly(::testing::Return(false));                           \
    EXPECT_CALL(gtest_log, Log(::logging::LOG_##severity, _, _, _, matcher)) \
        .Times(::testing::AtLeast(1))                                        \
        .WillOnce(::testing::Return(false));                                 \
    gtest_log.StartCapturingLogs();                                          \
    { statement; }                                                           \
    gtest_log.StopCapturingLogs();                                           \
    if (!testing::Mock::VerifyAndClear(&gtest_log))                          \
      fail("");                                                              \
  } while (false)

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
  GTEST_DFATAL_(statement, DFATAL, matcher, GTEST_NONFATAL_FAILURE_)

#define ASSERT_DFATAL_WITH(statement, matcher) \
  GTEST_DFATAL_(statement, DFATAL, matcher, GTEST_FATAL_FAILURE_)

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
  do {                                        \
    (void)(regex);                            \
    statement;                                \
  } while (false)
#define ASSERT_DEBUG_DFATAL(statement, regex) \
  do {                                        \
    (void)(regex);                            \
    statement;                                \
  } while (false)

#endif  // NDEBUG

// The EXPECT_DCHECK and ASSERT_DCHECK macros are similar to EXPECT_DFATAL and
// ASSERT_DFATAL. Use them in conjunction with DCHECK that produces no-op in opt
// build and LOG_DCHECK (FATAL) if DCHECK_IS_ON().

#if DCHECK_IS_ON()

#define EXPECT_DCHECK(statement, regex)                             \
  GTEST_DFATAL_(statement, DCHECK, ::testing::ContainsRegex(regex), \
                GTEST_NONFATAL_FAILURE_)
#define ASSERT_DCHECK(statement, regex)                             \
  GTEST_DFATAL_(statement, DCHECK, ::testing::ContainsRegex(regex), \
                GTEST_FATAL_FAILURE_)

#else  // DCHECK_IS_ON()

#define EXPECT_DCHECK(statement, regex) \
  do {                                  \
    (void)(regex);                      \
    statement;                          \
  } while (false)
#define ASSERT_DCHECK(statement, regex) \
  do {                                  \
    (void)(regex);                      \
    statement;                          \
  } while (false)

#endif  // DCHECK_IS_ON()

}  // namespace test
}  // namespace net

#endif  // NET_TEST_GTEST_UTIL_H_
