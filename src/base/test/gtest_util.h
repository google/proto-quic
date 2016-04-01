// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEST_GTEST_UTIL_H_
#define BASE_TEST_GTEST_UTIL_H_

#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"

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
