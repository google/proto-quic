// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_GTEST_UTIL_H_
#define BASE_TEST_GTEST_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"

// EXPECT/ASSERT_DCHECK_DEATH is intended to replace EXPECT/ASSERT_DEBUG_DEATH
// when the death is expected to be caused by a DCHECK. Contrary to
// EXPECT/ASSERT_DEBUG_DEATH however, it doesn't execute the statement in non-
// dcheck builds as DCHECKs are intended to catch things that should never
// happen and as such executing the statement results in undefined behavior
// (|statement| is compiled in unsupported configurations nonetheless).
// Death tests misbehave on Android.
#if DCHECK_IS_ON() && defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

// EXPECT/ASSERT_DCHECK_DEATH tests verify that a DCHECK is hit ("Check failed"
// is part of the error message), but intentionally do not expose the gtest
// death test's full |regex| parameter to avoid users having to verify the exact
// syntax of the error message produced by the DCHECK.
#define EXPECT_DCHECK_DEATH(statement) EXPECT_DEATH(statement, "Check failed")
#define ASSERT_DCHECK_DEATH(statement) ASSERT_DEATH(statement, "Check failed")

#else
// DCHECK_IS_ON() && defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

// Macro copied from gtest-death-test-internal.h as it's (1) internal for now
// and (2) only defined if !GTEST_HAS_DEATH_TEST which is only a subset of the
// conditions in which it's needed here.
// TODO(gab): Expose macro in upstream gtest repo for consumers like us that
// want more specific death tests and remove this hack.
# define GTEST_UNSUPPORTED_DEATH_TEST(statement, regex, terminator) \
    GTEST_AMBIGUOUS_ELSE_BLOCKER_ \
    if (::testing::internal::AlwaysTrue()) { \
      GTEST_LOG_(WARNING) \
          << "Death tests are not supported on this platform.\n" \
          << "Statement '" #statement "' cannot be verified."; \
    } else if (::testing::internal::AlwaysFalse()) { \
      ::testing::internal::RE::PartialMatch(".*", (regex)); \
      GTEST_SUPPRESS_UNREACHABLE_CODE_WARNING_BELOW_(statement); \
      terminator; \
    } else \
      ::testing::Message()

#define EXPECT_DCHECK_DEATH(statement) \
    GTEST_UNSUPPORTED_DEATH_TEST(statement, "Check failed", )
#define ASSERT_DCHECK_DEATH(statement) \
    GTEST_UNSUPPORTED_DEATH_TEST(statement, "Check failed", return)

#endif
// DCHECK_IS_ON() && defined(GTEST_HAS_DEATH_TEST) && !defined(OS_ANDROID)

namespace base {

class FilePath;

struct TestIdentifier {
  TestIdentifier();
  TestIdentifier(const TestIdentifier& other);

  std::string test_case_name;
  std::string test_name;
  std::string file;
  int line;
};

// Constructs a full test name given a test case name and a test name,
// e.g. for test case "A" and test name "B" returns "A.B".
std::string FormatFullTestName(const std::string& test_case_name,
                               const std::string& test_name);

// Returns the full test name with the "DISABLED_" prefix stripped out.
// e.g. for the full test names "A.DISABLED_B", "DISABLED_A.B", and
// "DISABLED_A.DISABLED_B", returns "A.B".
std::string TestNameWithoutDisabledPrefix(const std::string& full_test_name);

// Returns a vector of gtest-based tests compiled into
// current executable.
std::vector<TestIdentifier> GetCompiledInTests();

// Writes the list of gtest-based tests compiled into
// current executable as a JSON file. Returns true on success.
bool WriteCompiledInTestsToFile(const FilePath& path) WARN_UNUSED_RESULT;

// Reads the list of gtest-based tests from |path| into |output|.
// Returns true on success.
bool ReadTestNamesFromFile(
    const FilePath& path,
    std::vector<TestIdentifier>* output) WARN_UNUSED_RESULT;

}  // namespace base

#endif  // BASE_TEST_GTEST_UTIL_H_
