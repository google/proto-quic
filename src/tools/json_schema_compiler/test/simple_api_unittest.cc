// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/simple_api.h"

#include "testing/gtest/include/gtest/gtest.h"

using namespace test::api::simple_api;

namespace {

static std::unique_ptr<base::DictionaryValue> CreateTestTypeDictionary() {
  std::unique_ptr<base::DictionaryValue> value(new base::DictionaryValue());
  value->SetWithoutPathExpansion("number", new base::FundamentalValue(1.1));
  value->SetWithoutPathExpansion("integer", new base::FundamentalValue(4));
  value->SetWithoutPathExpansion("string", new base::StringValue("bling"));
  value->SetWithoutPathExpansion("boolean", new base::FundamentalValue(true));
  return value;
}

}  // namespace

TEST(JsonSchemaCompilerSimpleTest, IncrementIntegerResultCreate) {
  std::unique_ptr<base::ListValue> results =
      IncrementInteger::Results::Create(5);
  base::ListValue expected;
  expected.AppendInteger(5);
  EXPECT_TRUE(results->Equals(&expected));
}

TEST(JsonSchemaCompilerSimpleTest, IncrementIntegerParamsCreate) {
  std::unique_ptr<base::ListValue> params_value(new base::ListValue());
  params_value->AppendInteger(6);
  std::unique_ptr<IncrementInteger::Params> params(
      IncrementInteger::Params::Create(*params_value));
  EXPECT_TRUE(params.get());
  EXPECT_EQ(6, params->num);
}

TEST(JsonSchemaCompilerSimpleTest, NumberOfParams) {
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->AppendString("text");
    params_value->AppendString("text");
    std::unique_ptr<OptionalString::Params> params(
        OptionalString::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    std::unique_ptr<IncrementInteger::Params> params(
        IncrementInteger::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
}

TEST(JsonSchemaCompilerSimpleTest, OptionalStringParamsCreate) {
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    std::unique_ptr<OptionalString::Params> params(
        OptionalString::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_FALSE(params->str.get());
  }
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->AppendString("asdf");
    std::unique_ptr<OptionalString::Params> params(
        OptionalString::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_TRUE(params->str.get());
    EXPECT_EQ("asdf", *params->str);
  }
}

TEST(JsonSchemaCompilerSimpleTest, OptionalParamsTakingNull) {
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(base::Value::CreateNullValue());
    std::unique_ptr<OptionalString::Params> params(
        OptionalString::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_FALSE(params->str.get());
  }
}

TEST(JsonSchemaCompilerSimpleTest, OptionalStringParamsWrongType) {
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->AppendInteger(5);
    std::unique_ptr<OptionalString::Params> params(
        OptionalString::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
}

TEST(JsonSchemaCompilerSimpleTest, OptionalBeforeRequired) {
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(base::Value::CreateNullValue());
    params_value->AppendString("asdf");
    std::unique_ptr<OptionalBeforeRequired::Params> params(
        OptionalBeforeRequired::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_FALSE(params->first.get());
    EXPECT_EQ("asdf", params->second);
  }
}

TEST(JsonSchemaCompilerSimpleTest, NoParamsResultCreate) {
  std::unique_ptr<base::ListValue> results = OptionalString::Results::Create();
  base::ListValue expected;
  EXPECT_TRUE(results->Equals(&expected));
}

TEST(JsonSchemaCompilerSimpleTest, TestTypePopulate) {
  {
    std::unique_ptr<TestType> test_type(new TestType());
    std::unique_ptr<base::DictionaryValue> value = CreateTestTypeDictionary();
    EXPECT_TRUE(TestType::Populate(*value, test_type.get()));
    EXPECT_EQ("bling", test_type->string);
    EXPECT_EQ(1.1, test_type->number);
    EXPECT_EQ(4, test_type->integer);
    EXPECT_EQ(true, test_type->boolean);
    EXPECT_TRUE(value->Equals(test_type->ToValue().get()));
  }
  {
    std::unique_ptr<TestType> test_type(new TestType());
    std::unique_ptr<base::DictionaryValue> value = CreateTestTypeDictionary();
    value->Remove("number", NULL);
    EXPECT_FALSE(TestType::Populate(*value, test_type.get()));
  }
}

TEST(JsonSchemaCompilerSimpleTest, GetTestType) {
  {
    std::unique_ptr<base::DictionaryValue> value = CreateTestTypeDictionary();
    std::unique_ptr<TestType> test_type(new TestType());
    EXPECT_TRUE(TestType::Populate(*value, test_type.get()));
    std::unique_ptr<base::ListValue> results =
        GetTestType::Results::Create(*test_type);

    base::DictionaryValue* result = NULL;
    results->GetDictionary(0, &result);
    EXPECT_TRUE(result->Equals(value.get()));
  }
}

TEST(JsonSchemaCompilerSimpleTest, OnIntegerFiredCreate) {
  {
    std::unique_ptr<base::ListValue> results(OnIntegerFired::Create(5));
    base::ListValue expected;
    expected.AppendInteger(5);
    EXPECT_TRUE(results->Equals(&expected));
  }
}

TEST(JsonSchemaCompilerSimpleTest, OnStringFiredCreate) {
  {
    std::unique_ptr<base::ListValue> results(OnStringFired::Create("yo dawg"));
    base::ListValue expected;
    expected.AppendString("yo dawg");
    EXPECT_TRUE(results->Equals(&expected));
  }
}

TEST(JsonSchemaCompilerSimpleTest, OnTestTypeFiredCreate) {
  {
    TestType some_test_type;
    std::unique_ptr<base::DictionaryValue> expected =
        CreateTestTypeDictionary();
    ASSERT_TRUE(expected->GetDouble("number", &some_test_type.number));
    ASSERT_TRUE(expected->GetString("string", &some_test_type.string));
    ASSERT_TRUE(expected->GetInteger("integer", &some_test_type.integer));
    ASSERT_TRUE(expected->GetBoolean("boolean", &some_test_type.boolean));

    std::unique_ptr<base::ListValue> results(
        OnTestTypeFired::Create(some_test_type));
    base::DictionaryValue* result = NULL;
    results->GetDictionary(0, &result);
    EXPECT_TRUE(result->Equals(expected.get()));
  }
}
