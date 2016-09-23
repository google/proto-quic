// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/objects.h"

#include <stddef.h>

#include <utility>

#include "base/json/json_writer.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "tools/json_schema_compiler/test/objects_movable.h"
#include "tools/json_schema_compiler/test/objects_movable_json.h"

using namespace test::api::objects;
using namespace test::api::objects_movable;
using namespace test::api::objects_movable_json;

TEST(JsonSchemaCompilerObjectsTest, ObjectParamParamsCreate) {
  {
    std::unique_ptr<base::ListValue> strings(new base::ListValue());
    strings->AppendString("one");
    strings->AppendString("two");
    std::unique_ptr<base::DictionaryValue> info_value(
        new base::DictionaryValue());
    info_value->Set("strings", strings.release());
    info_value->Set("integer", new base::FundamentalValue(5));
    info_value->Set("boolean", new base::FundamentalValue(true));

    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(std::move(info_value));
    std::unique_ptr<ObjectParam::Params> params(
        ObjectParam::Params::Create(*params_value));
    EXPECT_TRUE(params.get());
    EXPECT_EQ((size_t) 2, params->info.strings.size());
    EXPECT_EQ("one", params->info.strings[0]);
    EXPECT_EQ("two", params->info.strings[1]);
    EXPECT_EQ(5, params->info.integer);
    EXPECT_TRUE(params->info.boolean);
  }
  {
    std::unique_ptr<base::ListValue> strings(new base::ListValue());
    strings->AppendString("one");
    strings->AppendString("two");
    std::unique_ptr<base::DictionaryValue> info_value(
        new base::DictionaryValue());
    info_value->Set("strings", strings.release());
    info_value->Set("integer", new base::FundamentalValue(5));

    std::unique_ptr<base::ListValue> params_value(new base::ListValue());
    params_value->Append(std::move(info_value));
    std::unique_ptr<ObjectParam::Params> params(
        ObjectParam::Params::Create(*params_value));
    EXPECT_FALSE(params.get());
  }
}

TEST(JsonSchemaCompilerObjectsTest, ReturnsObjectResultCreate) {
  ReturnsObject::Results::Info info;
  info.state = FIRST_STATE_FOO;
  std::unique_ptr<base::ListValue> results =
      ReturnsObject::Results::Create(info);

  base::DictionaryValue expected;
  expected.SetString("state", "foo");
  base::DictionaryValue* result = NULL;
  ASSERT_TRUE(results->GetDictionary(0, &result));
  ASSERT_TRUE(result->Equals(&expected));
}

TEST(JsonSchemaCompilerObjectsTest, OnObjectFiredCreate) {
  OnObjectFired::SomeObject object;
  object.state = FIRST_STATE_BAR;
  std::unique_ptr<base::ListValue> results(OnObjectFired::Create(object));

  base::DictionaryValue expected;
  expected.SetString("state", "bar");
  base::DictionaryValue* result = NULL;
  ASSERT_TRUE(results->GetDictionary(0, &result));
  ASSERT_TRUE(result->Equals(&expected));
}
TEST(JsonSchemaCompilerMovableObjectsTest, MovableObjectsTest) {
  std::vector<MovablePod> pods;
  {
    MovablePod pod;
    pod.foo = FOO_BAR;
    pod.str = "str1";
    pod.num = 42;
    pod.b = true;
    pods.push_back(std::move(pod));
  }
  {
    MovablePod pod;
    pod.foo = FOO_BAZ;
    pod.str = "str2";
    pod.num = 45;
    pod.b = false;
    pods.push_back(std::move(pod));
  }
  MovableParent parent;
  parent.pods = std::move(pods);
  parent.strs.push_back("pstr");
  parent.blob.additional_properties.SetString("key", "val");
  parent.choice.as_string.reset(new std::string("string"));

  MovableParent parent2(std::move(parent));
  ASSERT_EQ(2u, parent2.pods.size());
  EXPECT_EQ(FOO_BAR, parent2.pods[0].foo);
  EXPECT_EQ("str1", parent2.pods[0].str);
  EXPECT_EQ(42, parent2.pods[0].num);
  EXPECT_TRUE(parent2.pods[0].b);
  EXPECT_EQ(FOO_BAZ, parent2.pods[1].foo);
  EXPECT_EQ("str2", parent2.pods[1].str);
  EXPECT_EQ(45, parent2.pods[1].num);
  EXPECT_FALSE(parent2.pods[1].b);
  ASSERT_EQ(1u, parent2.strs.size());
  EXPECT_EQ("pstr", parent2.strs[0]);
  EXPECT_FALSE(parent2.choice.as_movable_pod.get());
  ASSERT_TRUE(parent2.choice.as_string.get());
  EXPECT_EQ("string", *parent2.choice.as_string);
  std::string blob_string;
  EXPECT_TRUE(
      parent2.blob.additional_properties.GetString("key", &blob_string));
  EXPECT_EQ("val", blob_string);

  {
    MovableParent parent_with_pod_choice;
    MovablePod pod;
    pod.foo = FOO_BAZ;
    pod.str = "str";
    pod.num = 10;
    pod.b = false;
    parent_with_pod_choice.choice.as_movable_pod.reset(
        new MovablePod(std::move(pod)));
    parent2 = std::move(parent_with_pod_choice);
  }
  EXPECT_TRUE(parent2.pods.empty());
  EXPECT_TRUE(parent2.strs.empty());
  EXPECT_TRUE(parent2.blob.additional_properties.empty());
  EXPECT_FALSE(parent2.choice.as_string.get());
  ASSERT_TRUE(parent2.choice.as_movable_pod.get());
  EXPECT_EQ(FOO_BAZ, parent2.choice.as_movable_pod->foo);
  EXPECT_EQ("str", parent2.choice.as_movable_pod->str);
  EXPECT_EQ(10, parent2.choice.as_movable_pod->num);
  EXPECT_FALSE(parent2.choice.as_movable_pod->b);

  MovableWithAdditional with_additional;
  with_additional.str = "str";
  std::vector<std::string> vals1;
  vals1.push_back("vals1a");
  vals1.push_back("vals1b");
  with_additional.additional_properties["key1"] = vals1;
  std::vector<std::string> vals2;
  vals2.push_back("vals2a");
  vals2.push_back("vals2b");
  with_additional.additional_properties["key2"] = vals2;

  MovableWithAdditional with_additional2(std::move(with_additional));
  EXPECT_EQ("str", with_additional2.str);
  EXPECT_EQ(2u, with_additional2.additional_properties.size());
  EXPECT_EQ(vals1, with_additional2.additional_properties["key1"]);
  EXPECT_EQ(vals2, with_additional2.additional_properties["key2"]);
}
