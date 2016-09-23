// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "tools/gn/test_with_scope.h"

TEST(FunctionForeach, CollisionOnLoopVar) {
  TestWithScope setup;
  TestParseInput input(
      "a = 5\n"
      "i = 6\n"
      "foreach(i, [1, 2, 3]) {\n"  // Use same loop var name previously defined.
      "  print(\"$a $i\")\n"
      "  a = a + 1\n"  // Test for side effects inside loop.
      "}\n"
      "print(\"$a $i\")");  // Make sure that i goes back to original value.
  ASSERT_FALSE(input.has_error());

  Err err;
  input.parsed()->Execute(setup.scope(), &err);
  ASSERT_FALSE(err.has_error()) << err.message();

  EXPECT_EQ("5 1\n6 2\n7 3\n8 6\n", setup.print_output());
}

TEST(FunctionForeach, UniqueLoopVar) {
  TestWithScope setup;
  TestParseInput input_good(
      "foreach(i, [1, 2, 3]) {\n"
      "  print(i)\n"
      "}\n");
  ASSERT_FALSE(input_good.has_error());

  Err err;
  input_good.parsed()->Execute(setup.scope(), &err);
  ASSERT_FALSE(err.has_error()) << err.message();

  EXPECT_EQ("1\n2\n3\n", setup.print_output());
  setup.print_output().clear();

  // Same thing but try to use the loop var after loop is done. It should be
  // undefined and throw an error.
  TestParseInput input_bad(
      "foreach(i, [1, 2, 3]) {\n"
      "  print(i)\n"
      "}\n"
      "print(i)");
  ASSERT_FALSE(input_bad.has_error());  // Should parse OK.

  input_bad.parsed()->Execute(setup.scope(), &err);
  ASSERT_TRUE(err.has_error());  // Shouldn't actually run.
}

// Checks that the identifier used as the list is marked as "used".
TEST(FunctionForeach, MarksIdentAsUsed) {
  TestWithScope setup;
  TestParseInput input_good(
      "a = [1, 2]\n"
      "foreach(i, a) {\n"
      "  print(i)\n"
      "}\n");
  ASSERT_FALSE(input_good.has_error());

  Err err;
  input_good.parsed()->Execute(setup.scope(), &err);
  ASSERT_FALSE(err.has_error()) << err.message();

  EXPECT_EQ("1\n2\n", setup.print_output());
  setup.print_output().clear();

  // Check for unused vars.
  EXPECT_TRUE(setup.scope()->CheckForUnusedVars(&err));
  EXPECT_FALSE(err.has_error());
}
