// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzzer launcher script tests.

#include <string>
#include <vector>

#include "base/command_line.h"
#include "base/path_service.h"
#include "base/process/launch.h"
#include "base/strings/string_split.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"


TEST(FuzzerConfigTest, DictOnly) {
  // Test of automatically generated .options file for fuzzer with dict option.
  base::FilePath exe_path;
  PathService::Get(base::FILE_EXE, &exe_path);
  std::string launcher_path =
    exe_path.DirName().Append("check_fuzzer_config.py").value();

  std::string output;
  base::CommandLine cmd({{launcher_path, "test_dict_only.options"}});
  bool success = base::GetAppOutputAndError(cmd, &output);
  EXPECT_TRUE(success);
  std::vector<std::string> fuzzer_args = base::SplitString(
      output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  EXPECT_EQ(1UL, fuzzer_args.size());

  EXPECT_EQ(fuzzer_args[0], "dict=test_dict_only.dict");
}


TEST(FuzzerConfigTest, ConfigOnly) {
  // Test of .options file for fuzzer with libfuzzer_options and without dict.
  base::FilePath exe_path;
  PathService::Get(base::FILE_EXE, &exe_path);
  std::string launcher_path =
    exe_path.DirName().Append("check_fuzzer_config.py").value();

  std::string output;
  base::CommandLine cmd({{launcher_path, "test_config_only.options"}});
  bool success = base::GetAppOutputAndError(cmd, &output);
  EXPECT_TRUE(success);
  std::vector<std::string> fuzzer_args = base::SplitString(
      output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  EXPECT_EQ(2UL, fuzzer_args.size());

  EXPECT_EQ(fuzzer_args[0], "some_test_option=test_value");
  EXPECT_EQ(fuzzer_args[1], "max_len=1024");
}


TEST(FuzzerConfigTest, ConfigAndDict) {
  // Test of .options file for fuzzer with options file and dictionary.
  base::FilePath exe_path;
  PathService::Get(base::FILE_EXE, &exe_path);
  std::string launcher_path =
    exe_path.DirName().Append("check_fuzzer_config.py").value();

  std::string output;
  base::CommandLine cmd({{launcher_path, "test_config_and_dict.options"}});
  bool success = base::GetAppOutputAndError(cmd, &output);
  EXPECT_TRUE(success);
  std::vector<std::string> fuzzer_args = base::SplitString(
      output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  EXPECT_EQ(4UL, fuzzer_args.size());

  EXPECT_EQ(fuzzer_args[0], "dict=test_config_and_dict.dict");
  EXPECT_EQ(fuzzer_args[1], "max_len=random(1337, 31337)");
  EXPECT_EQ(fuzzer_args[2], "timeout=666");
  EXPECT_EQ(fuzzer_args[3], "use_traces=1");
}


TEST(FuzzerConfigTest, DictSubdir) {
  // Test of auto-generated .options file for fuzzer with dict in sub-directory.
  base::FilePath exe_path;
  PathService::Get(base::FILE_EXE, &exe_path);
  std::string launcher_path =
    exe_path.DirName().Append("check_fuzzer_config.py").value();

  std::string output;
  base::CommandLine cmd({{launcher_path, "test_dict_from_subdir.options"}});
  bool success = base::GetAppOutputAndError(cmd, &output);
  EXPECT_TRUE(success);
  std::vector<std::string> fuzzer_args = base::SplitString(
      output, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  EXPECT_EQ(1UL, fuzzer_args.size());

  EXPECT_EQ(fuzzer_args[0], "dict=test_dict_from_subdir.dict");
}
