// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "tools/gn/scheduler.h"
#include "tools/gn/test_with_scope.h"

// Tests that actions can't have output substitutions.
TEST(ActionTargetGenerator, ActionOutputSubstitutions) {
  Scheduler scheduler;
  TestWithScope setup;
  Scope::ItemVector items_;
  setup.scope()->set_item_collector(&items_);

  // First test one with no substitutions, this should be valid.
  TestParseInput input_good(
      "action(\"foo\") {\n"
      "  script = \"//foo.py\"\n"
      "  sources = [ \"//bar.txt\" ]\n"
      "  outputs = [ \"//out/Debug/one.txt\" ]\n"
      "}");
  ASSERT_FALSE(input_good.has_error());

  // This should run fine.
  Err err;
  input_good.parsed()->Execute(setup.scope(), &err);
  ASSERT_FALSE(err.has_error()) << err.message();

  // Same thing with a pattern in the output should fail.
  TestParseInput input_bad(
      "action(\"foo\") {\n"
      "  script = \"//foo.py\"\n"
      "  sources = [ \"//bar.txt\" ]\n"
      "  outputs = [ \"//out/Debug/{{source_name_part}}.txt\" ]\n"
      "}");
  ASSERT_FALSE(input_bad.has_error());

  // This should run fine.
  input_bad.parsed()->Execute(setup.scope(), &err);
  ASSERT_TRUE(err.has_error());
}
