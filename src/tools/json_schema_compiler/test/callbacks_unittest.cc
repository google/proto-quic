// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/callbacks.h"

#include <memory>
#include <utility>

#include "testing/gtest/include/gtest/gtest.h"

using namespace test::api::callbacks;

TEST(JsonSchemaCompilerCallbacksTest, ReturnsObjectResultCreate) {
  ReturnsObject::Results::SomeObject some_object;
  some_object.state = ENUMERATION_FOO;
  std::unique_ptr<base::ListValue> results =
      ReturnsObject::Results::Create(some_object);

  std::unique_ptr<base::DictionaryValue> expected_dict(
      new base::DictionaryValue());
  expected_dict->SetString("state", "foo");
  base::ListValue expected;
  expected.Append(std::move(expected_dict));
  EXPECT_TRUE(results->Equals(&expected));
}

TEST(JsonSchemaCompilerCallbacksTest, ReturnsMultipleResultCreate) {
  ReturnsMultiple::Results::SomeObject some_object;
  some_object.state = ENUMERATION_FOO;
  std::unique_ptr<base::ListValue> results =
      ReturnsMultiple::Results::Create(5, some_object);

  std::unique_ptr<base::DictionaryValue> expected_dict(
      new base::DictionaryValue());
  expected_dict->SetString("state", "foo");
  base::ListValue expected;
  expected.AppendInteger(5);
  expected.Append(std::move(expected_dict));
  EXPECT_TRUE(results->Equals(&expected));
}
