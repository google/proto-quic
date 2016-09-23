// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>

#include "testing/gtest/include/gtest/gtest.h"
#include "tools/gn/ninja_build_writer.h"
#include "tools/gn/pool.h"
#include "tools/gn/scheduler.h"
#include "tools/gn/target.h"
#include "tools/gn/test_with_scope.h"

TEST(NinjaBuildWriter, TwoTargets) {
  Scheduler scheduler;
  TestWithScope setup;
  Err err;

  Target target_foo(setup.settings(), Label(SourceDir("//foo/"), "bar"));
  target_foo.set_output_type(Target::ACTION);
  target_foo.action_values().set_script(SourceFile("//foo/script.py"));
  target_foo.action_values().outputs() = SubstitutionList::MakeForTest(
      "//out/Debug/out1.out", "//out/Debug/out2.out");
  target_foo.SetToolchain(setup.toolchain());
  ASSERT_TRUE(target_foo.OnResolved(&err));

  Target target_bar(setup.settings(), Label(SourceDir("//bar/"), "bar"));
  target_bar.set_output_type(Target::ACTION);
  target_bar.action_values().set_script(SourceFile("//bar/script.py"));
  target_bar.action_values().outputs() = SubstitutionList::MakeForTest(
      "//out/Debug/out3.out", "//out/Debug/out4.out");
  target_bar.SetToolchain(setup.toolchain());
  ASSERT_TRUE(target_bar.OnResolved(&err));

  // Make a secondary toolchain that references a pool.
  Label other_toolchain_label(SourceDir("//other/"), "toolchain");
  Pool other_pool(setup.settings(),
                    Label(SourceDir("//other/"), "pool",
                          other_toolchain_label.dir(),
                          other_toolchain_label.name()));
  other_pool.set_depth(42);
  Toolchain other_toolchain(setup.settings(), other_toolchain_label);
  TestWithScope::SetupToolchain(&other_toolchain);
  other_toolchain.GetTool(Toolchain::TYPE_LINK)->set_pool(
      LabelPtrPair<Pool>(&other_pool));

  // Settings to go with the other toolchain.
  Settings other_settings(setup.build_settings(), "toolchain/");
  other_settings.set_toolchain_label(other_toolchain_label);

  std::map<const Settings*, const Toolchain*> used_toolchains;
  used_toolchains[setup.settings()] = setup.toolchain();
  used_toolchains[&other_settings] = &other_toolchain;

  std::vector<const Target*> targets = { &target_foo, &target_bar };

  std::ostringstream ninja_out;
  std::ostringstream depfile_out;

  NinjaBuildWriter writer(setup.build_settings(), used_toolchains,
                          setup.toolchain(), targets, ninja_out, depfile_out);
  ASSERT_TRUE(writer.Run(&err));

  const char expected_rule_gn[] = "rule gn\n";
  const char expected_build_ninja[] =
      "build build.ninja: gn\n"
      "  generator = 1\n"
      "  depfile = build.ninja.d\n";
  const char expected_other_pool[] =
      "pool other_toolchain_other_pool\n"
      "  depth = 42\n";
  const char expected_toolchain[] =
      "subninja toolchain.ninja\n";
  const char expected_targets[] =
      "build bar: phony obj/bar/bar.stamp\n"
      "build foo$:bar: phony obj/foo/bar.stamp\n"
      "build bar$:bar: phony obj/bar/bar.stamp\n";
  const char expected_root_target[] =
      "build all: phony $\n"
      "    obj/foo/bar.stamp $\n"
      "    obj/bar/bar.stamp\n";
  const char expected_default[] =
      "default all\n";
  std::string out_str = ninja_out.str();
#define EXPECT_SNIPPET(expected) \
    EXPECT_NE(std::string::npos, out_str.find(expected)) << \
        "Expected to find: " << expected << std::endl << \
        "Within: " << out_str
  EXPECT_SNIPPET(expected_rule_gn);
  EXPECT_SNIPPET(expected_build_ninja);
  EXPECT_SNIPPET(expected_other_pool);
  EXPECT_SNIPPET(expected_toolchain);
  EXPECT_SNIPPET(expected_targets);
  EXPECT_SNIPPET(expected_root_target);
  EXPECT_SNIPPET(expected_default);
#undef EXPECT_SNIPPET
}

TEST(NinjaBuildWriter, DuplicateOutputs) {
  Scheduler scheduler;
  TestWithScope setup;
  Err err;

  Target target_foo(setup.settings(), Label(SourceDir("//foo/"), "bar"));
  target_foo.set_output_type(Target::ACTION);
  target_foo.action_values().set_script(SourceFile("//foo/script.py"));
  target_foo.action_values().outputs() = SubstitutionList::MakeForTest(
      "//out/Debug/out1.out", "//out/Debug/out2.out");
  target_foo.SetToolchain(setup.toolchain());
  ASSERT_TRUE(target_foo.OnResolved(&err));

  Target target_bar(setup.settings(), Label(SourceDir("//bar/"), "bar"));
  target_bar.set_output_type(Target::ACTION);
  target_bar.action_values().set_script(SourceFile("//bar/script.py"));
  target_bar.action_values().outputs() = SubstitutionList::MakeForTest(
      "//out/Debug/out3.out", "//out/Debug/out2.out");
  target_bar.SetToolchain(setup.toolchain());
  ASSERT_TRUE(target_bar.OnResolved(&err));

  std::map<const Settings*, const Toolchain*> used_toolchains;
  used_toolchains[setup.settings()] = setup.toolchain();
  std::vector<const Target*> targets = { &target_foo, &target_bar };
  std::ostringstream ninja_out;
  std::ostringstream depfile_out;
  NinjaBuildWriter writer(setup.build_settings(), used_toolchains,
                          setup.toolchain(), targets, ninja_out, depfile_out);
  ASSERT_FALSE(writer.Run(&err));

  const char expected_help_test[] =
      "Two or more targets generate the same output:\n"
      "  out2.out\n"
      "\n"
      "This is can often be fixed by changing one of the target names, or by \n"
      "setting an output_name on one of them.\n"
      "\n"
      "Collisions:\n"
      "  //foo:bar\n"
      "  //bar:bar\n";

  EXPECT_EQ(expected_help_test, err.help_text());
}
