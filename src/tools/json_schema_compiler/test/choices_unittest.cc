// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/choices.h"

#include <stddef.h>

#include <utility>

#include "base/strings/string_piece.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "tools/json_schema_compiler/test/test_util.h"

namespace {

using namespace test::api::choices;
using json_schema_compiler::test_util::Dictionary;
using json_schema_compiler::test_util::List;
using json_schema_compiler::test_util::ReadJson;
using json_schema_compiler::test_util::Vector;

TEST(JsonSchemaCompilerChoicesTest, TakesIntegersParamsCreate) {
  {
    std::unique_ptr<TakesIntegers::Params> params(
        TakesIntegers::Params::Create(*List(new base::Value(true))));
    EXPECT_FALSE(params);
  }
  {
    std::unique_ptr<TakesIntegers::Params> params(
        TakesIntegers::Params::Create(*List(new base::Value(6))));
    ASSERT_TRUE(params);
    EXPECT_FALSE(params->nums.as_integers);
    EXPECT_EQ(6, *params->nums.as_integer);
  }
  {
    std::unique_ptr<TakesIntegers::Params> params(TakesIntegers::Params::Create(
        *List(List(new base::Value(2), new base::Value(6), new base::Value(8))
                  .release())));
    ASSERT_TRUE(params);
    ASSERT_TRUE(params->nums.as_integers);
    EXPECT_EQ(Vector(2, 6, 8), *params->nums.as_integers);
  }
}

TEST(JsonSchemaCompilerChoicesTest, ObjectWithChoicesParamsCreate) {
  {
    std::unique_ptr<ObjectWithChoices::Params> params(
        ObjectWithChoices::Params::Create(
            *List(Dictionary("strings", new base::Value("asdf")).release())));
    ASSERT_TRUE(params);
    EXPECT_FALSE(params->string_info.strings.as_strings);
    EXPECT_EQ("asdf", *params->string_info.strings.as_string);
    EXPECT_FALSE(params->string_info.integers);
  }
  {
    std::unique_ptr<ObjectWithChoices::Params> params(
        ObjectWithChoices::Params::Create(
            *List(Dictionary("strings", new base::Value("asdf"), "integers",
                             new base::Value(6))
                      .release())));
    ASSERT_TRUE(params);
    EXPECT_FALSE(params->string_info.strings.as_strings);
    EXPECT_EQ("asdf", *params->string_info.strings.as_string);
    ASSERT_TRUE(params->string_info.integers);
    EXPECT_FALSE(params->string_info.integers->as_integers);
    EXPECT_EQ(6, *params->string_info.integers->as_integer);
  }
}

// TODO(kalman): Clean up the rest of these tests to use the
// Vector/List/Dictionary helpers.

TEST(JsonSchemaCompilerChoicesTest, ObjectWithChoicesParamsCreateFail) {
  {
    std::unique_ptr<base::DictionaryValue> object_param(
        new base::DictionaryValue());
    object_param->SetWithoutPathExpansion("strings", new base::Value(5));
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(std::move(object_param));
    std::unique_ptr<ObjectWithChoices::Params> params(
        ObjectWithChoices::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
  {
    std::unique_ptr<base::DictionaryValue> object_param(
        new base::DictionaryValue());
    object_param->SetWithoutPathExpansion("strings", new base::Value("asdf"));
    object_param->SetWithoutPathExpansion("integers", new base::Value("asdf"));
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(std::move(object_param));
    std::unique_ptr<ObjectWithChoices::Params> params(
        ObjectWithChoices::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
  {
    std::unique_ptr<base::DictionaryValue> object_param(
        new base::DictionaryValue());
    object_param->SetWithoutPathExpansion("integers", new base::Value(6));
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(std::move(object_param));
    std::unique_ptr<ObjectWithChoices::Params> params(
        ObjectWithChoices::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
}

TEST(JsonSchemaCompilerChoicesTest, PopulateChoiceType) {
  std::vector<std::string> strings = Vector(std::string("list"),
                                            std::string("of"),
                                            std::string("strings"));

  base::ListValue* strings_value = new base::ListValue();
  for (size_t i = 0; i < strings.size(); ++i)
    strings_value->AppendString(strings[i]);

  base::DictionaryValue value;
  value.SetInteger("integers", 4);
  value.Set("strings", strings_value);

  ChoiceType out;
  ASSERT_TRUE(ChoiceType::Populate(value, &out));
  ASSERT_TRUE(out.integers.as_integer.get());
  EXPECT_FALSE(out.integers.as_integers.get());
  EXPECT_EQ(4, *out.integers.as_integer);

  EXPECT_FALSE(out.strings->as_string.get());
  ASSERT_TRUE(out.strings->as_strings.get());
  EXPECT_EQ(strings, *out.strings->as_strings);
}

TEST(JsonSchemaCompilerChoicesTest, ChoiceTypeToValue) {
  base::ListValue* strings_value = new base::ListValue();
  strings_value->AppendString("list");
  strings_value->AppendString("of");
  strings_value->AppendString("strings");

  base::DictionaryValue value;
  value.SetInteger("integers", 5);
  value.Set("strings", strings_value);

  ChoiceType out;
  ASSERT_TRUE(ChoiceType::Populate(value, &out));

  EXPECT_TRUE(value.Equals(out.ToValue().get()));
}

TEST(JsonSchemaCompilerChoicesTest, ReturnChoices) {
  {
    ReturnChoices::Results::Result results;
    results.as_integers.reset(new std::vector<int>(Vector(1, 2)));

    std::unique_ptr<base::Value> results_value = results.ToValue();
    ASSERT_TRUE(results_value);

    base::ListValue expected;
    expected.AppendInteger(1);
    expected.AppendInteger(2);

    EXPECT_TRUE(expected.Equals(results_value.get()));
  }
  {
    ReturnChoices::Results::Result results;
    results.as_integer.reset(new int(5));

    std::unique_ptr<base::Value> results_value = results.ToValue();
    ASSERT_TRUE(results_value);

    base::Value expected(5);

    EXPECT_TRUE(expected.Equals(results_value.get()));
  }
}

TEST(JsonSchemaCompilerChoicesTest, NestedChoices) {
  // These test both ToValue and FromValue for every legitimate configuration of
  // NestedChoices.
  {
    // The plain integer choice.
    std::unique_ptr<base::Value> value = ReadJson("42");
    std::unique_ptr<NestedChoice> obj = NestedChoice::FromValue(*value);

    ASSERT_TRUE(obj);
    ASSERT_TRUE(obj->as_integer);
    EXPECT_FALSE(obj->as_choice1);
    EXPECT_FALSE(obj->as_choice2);
    EXPECT_EQ(42, *obj->as_integer);

    EXPECT_TRUE(base::Value::Equals(value.get(), obj->ToValue().get()));
  }

  {
    // The string choice within the first choice.
    std::unique_ptr<base::Value> value = ReadJson("\"foo\"");
    std::unique_ptr<NestedChoice> obj = NestedChoice::FromValue(*value);

    ASSERT_TRUE(obj);
    EXPECT_FALSE(obj->as_integer);
    ASSERT_TRUE(obj->as_choice1);
    EXPECT_FALSE(obj->as_choice2);
    ASSERT_TRUE(obj->as_choice1->as_string);
    EXPECT_FALSE(obj->as_choice1->as_boolean);
    EXPECT_EQ("foo", *obj->as_choice1->as_string);

    EXPECT_TRUE(base::Value::Equals(value.get(), obj->ToValue().get()));
  }

  {
    // The boolean choice within the first choice.
    std::unique_ptr<base::Value> value = ReadJson("true");
    std::unique_ptr<NestedChoice> obj = NestedChoice::FromValue(*value);

    ASSERT_TRUE(obj);
    EXPECT_FALSE(obj->as_integer);
    ASSERT_TRUE(obj->as_choice1);
    EXPECT_FALSE(obj->as_choice2);
    EXPECT_FALSE(obj->as_choice1->as_string);
    ASSERT_TRUE(obj->as_choice1->as_boolean);
    EXPECT_TRUE(*obj->as_choice1->as_boolean);

    EXPECT_TRUE(base::Value::Equals(value.get(), obj->ToValue().get()));
  }

  {
    // The double choice within the second choice.
    std::unique_ptr<base::Value> value = ReadJson("42.0");
    std::unique_ptr<NestedChoice> obj = NestedChoice::FromValue(*value);

    ASSERT_TRUE(obj);
    EXPECT_FALSE(obj->as_integer);
    EXPECT_FALSE(obj->as_choice1);
    ASSERT_TRUE(obj->as_choice2);
    ASSERT_TRUE(obj->as_choice2->as_double);
    EXPECT_FALSE(obj->as_choice2->as_choice_type);
    EXPECT_FALSE(obj->as_choice2->as_choice_types);
    EXPECT_EQ(42.0, *obj->as_choice2->as_double);

    EXPECT_TRUE(base::Value::Equals(value.get(), obj->ToValue().get()));
  }

  {
    // The ChoiceType choice within the second choice.
    std::unique_ptr<base::Value> value =
        ReadJson("{\"integers\": [1, 2], \"strings\": \"foo\"}");
    std::unique_ptr<NestedChoice> obj = NestedChoice::FromValue(*value);

    ASSERT_TRUE(obj);
    EXPECT_FALSE(obj->as_integer);
    EXPECT_FALSE(obj->as_choice1);
    ASSERT_TRUE(obj->as_choice2);
    EXPECT_FALSE(obj->as_choice2->as_double);
    ASSERT_TRUE(obj->as_choice2->as_choice_type);
    EXPECT_FALSE(obj->as_choice2->as_choice_types);
    {
      ChoiceType* choice_type = obj->as_choice2->as_choice_type.get();
      ASSERT_TRUE(choice_type->integers.as_integers);
      EXPECT_FALSE(choice_type->integers.as_integer);
      EXPECT_EQ(Vector(1, 2), *choice_type->integers.as_integers);
      ASSERT_TRUE(choice_type->strings);
      EXPECT_FALSE(choice_type->strings->as_strings);
      ASSERT_TRUE(choice_type->strings->as_string);
      EXPECT_EQ("foo", *choice_type->strings->as_string);
    }

    EXPECT_TRUE(base::Value::Equals(value.get(), obj->ToValue().get()));
  }

  {
    // The array of ChoiceTypes within the second choice.
    std::unique_ptr<base::Value> value = ReadJson(
        "["
        "  {\"integers\": [1, 2], \"strings\": \"foo\"},"
        "  {\"integers\": 3, \"strings\": [\"bar\", \"baz\"]}"
        "]");
    std::unique_ptr<NestedChoice> obj = NestedChoice::FromValue(*value);

    ASSERT_TRUE(obj);
    EXPECT_FALSE(obj->as_integer);
    EXPECT_FALSE(obj->as_choice1);
    ASSERT_TRUE(obj->as_choice2);
    EXPECT_FALSE(obj->as_choice2->as_double);
    EXPECT_FALSE(obj->as_choice2->as_choice_type);
    ASSERT_TRUE(obj->as_choice2->as_choice_types);
    {
      std::vector<ChoiceType>* choice_types =
          obj->as_choice2->as_choice_types.get();
      // Bleh too much effort to test everything.
      ASSERT_EQ(2u, choice_types->size());
    }

    EXPECT_TRUE(base::Value::Equals(value.get(), obj->ToValue().get()));
  }
}

}  // namespace
