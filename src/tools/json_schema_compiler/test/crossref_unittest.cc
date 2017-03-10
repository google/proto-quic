// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/crossref.h"

#include <memory>
#include <utility>

#include "testing/gtest/include/gtest/gtest.h"
#include "tools/json_schema_compiler/test/simple_api.h"

using namespace test::api;

namespace {

std::unique_ptr<base::DictionaryValue> CreateTestTypeValue() {
  std::unique_ptr<base::DictionaryValue> value(new base::DictionaryValue());
  value->Set("number", new base::Value(1.1));
  value->Set("integer", new base::Value(4));
  value->Set("string", new base::Value("bling"));
  value->Set("boolean", new base::Value(true));
  return value;
}

}  // namespace

TEST(JsonSchemaCompilerCrossrefTest, CrossrefTypePopulateAndToValue) {
  base::DictionaryValue crossref_orig;
  crossref_orig.Set("testType", CreateTestTypeValue().release());
  crossref_orig.Set("testEnumRequired", new base::Value("one"));
  crossref_orig.Set("testEnumOptional", new base::Value("two"));

  // Test Populate of the value --> compiled type.
  crossref::CrossrefType crossref_type;
  ASSERT_TRUE(crossref::CrossrefType::Populate(crossref_orig, &crossref_type));
  EXPECT_EQ(1.1, crossref_type.test_type.number);
  EXPECT_EQ(4, crossref_type.test_type.integer);
  EXPECT_EQ("bling", crossref_type.test_type.string);
  EXPECT_EQ(true, crossref_type.test_type.boolean);
  EXPECT_EQ(simple_api::TEST_ENUM_ONE, crossref_type.test_enum_required);
  EXPECT_EQ(simple_api::TEST_ENUM_TWO, crossref_type.test_enum_optional);
  EXPECT_EQ(simple_api::TEST_ENUM_NONE, crossref_type.test_enum_optional_extra);

  // Test ToValue of the compiled type --> value.
  std::unique_ptr<base::DictionaryValue> crossref_value =
      crossref_type.ToValue();
  ASSERT_TRUE(crossref_value);
  EXPECT_TRUE(crossref_orig.Equals(crossref_value.get()));
}

TEST(JsonSchemaCompilerCrossrefTest, TestTypeOptionalParamCreate) {
  std::unique_ptr<base::ListValue> params_value(new base::ListValue());
  params_value->Append(CreateTestTypeValue());
  std::unique_ptr<crossref::TestTypeOptionalParam::Params> params(
      crossref::TestTypeOptionalParam::Params::Create(*params_value));
  EXPECT_TRUE(params.get());
  EXPECT_TRUE(params->test_type.get());
  EXPECT_TRUE(
      CreateTestTypeValue()->Equals(params->test_type->ToValue().get()));
}

TEST(JsonSchemaCompilerCrossrefTest, TestTypeOptionalParamFail) {
  std::unique_ptr<base::ListValue> params_value(new base::ListValue());
  std::unique_ptr<base::DictionaryValue> test_type_value =
      CreateTestTypeValue();
  test_type_value->RemoveWithoutPathExpansion("number", NULL);
  params_value->Append(std::move(test_type_value));
  std::unique_ptr<crossref::TestTypeOptionalParam::Params> params(
      crossref::TestTypeOptionalParam::Params::Create(*params_value));
  EXPECT_FALSE(params.get());
}

TEST(JsonSchemaCompilerCrossrefTest, GetTestType) {
  std::unique_ptr<base::DictionaryValue> value = CreateTestTypeValue();
  std::unique_ptr<simple_api::TestType> test_type(new simple_api::TestType());
  EXPECT_TRUE(simple_api::TestType::Populate(*value, test_type.get()));

  std::unique_ptr<base::ListValue> results =
      crossref::GetTestType::Results::Create(*test_type);
  base::DictionaryValue* result_dict = NULL;
  results->GetDictionary(0, &result_dict);
  EXPECT_TRUE(value->Equals(result_dict));
}

TEST(JsonSchemaCompilerCrossrefTest, TestTypeInObjectParamsCreate) {
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    std::unique_ptr<base::DictionaryValue> param_object_value(
        new base::DictionaryValue());
    param_object_value->Set("testType", CreateTestTypeValue().release());
    param_object_value->Set("boolean", new base::Value(true));
    params_value->Append(std::move(param_object_value));
    std::unique_ptr<crossref::TestTypeInObject::Params> params(
        crossref::TestTypeInObject::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_TRUE(params->param_object.test_type.get());
    EXPECT_TRUE(params->param_object.boolean);
    EXPECT_TRUE(CreateTestTypeValue()->Equals(
        params->param_object.test_type->ToValue().get()));
  }
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    std::unique_ptr<base::DictionaryValue> param_object_value(
        new base::DictionaryValue());
    param_object_value->Set("boolean", new base::Value(true));
    params_value->Append(std::move(param_object_value));
    std::unique_ptr<crossref::TestTypeInObject::Params> params(
        crossref::TestTypeInObject::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_FALSE(params->param_object.test_type.get());
    EXPECT_TRUE(params->param_object.boolean);
  }
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    std::unique_ptr<base::DictionaryValue> param_object_value(
        new base::DictionaryValue());
    param_object_value->Set("testType", new base::Value("invalid"));
    param_object_value->Set("boolean", new base::Value(true));
    params_value->Append(std::move(param_object_value));
    std::unique_ptr<crossref::TestTypeInObject::Params> params(
        crossref::TestTypeInObject::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
  {
    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    std::unique_ptr<base::DictionaryValue> param_object_value(
        new base::DictionaryValue());
    param_object_value->Set("testType", CreateTestTypeValue().release());
    params_value->Append(std::move(param_object_value));
    std::unique_ptr<crossref::TestTypeInObject::Params> params(
        crossref::TestTypeInObject::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
}
