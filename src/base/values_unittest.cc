// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/values.h"

#include <stddef.h>

#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "base/containers/adapters.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string16.h"
#include "base/strings/utf_string_conversions.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {

TEST(ValuesTest, TestNothrow) {
  static_assert(std::is_nothrow_move_constructible<Value>::value,
                "IsNothrowMoveConstructible");
  static_assert(std::is_nothrow_default_constructible<Value>::value,
                "IsNothrowDefaultConstructible");
  static_assert(std::is_nothrow_constructible<Value, std::string&&>::value,
                "IsNothrowMoveConstructibleFromString");
  static_assert(
      std::is_nothrow_constructible<Value, Value::BlobStorage&&>::value,
      "IsNothrowMoveConstructibleFromBlob");
  static_assert(
      std::is_nothrow_constructible<Value, Value::ListStorage&&>::value,
      "IsNothrowMoveConstructibleFromList");
  static_assert(std::is_nothrow_move_assignable<Value>::value,
                "IsNothrowMoveAssignable");
  static_assert(
      std::is_nothrow_constructible<ListValue, Value::ListStorage&&>::value,
      "ListIsNothrowMoveConstructibleFromList");
}

// Group of tests for the value constructors.
TEST(ValuesTest, ConstructBool) {
  Value true_value(true);
  EXPECT_EQ(Value::Type::BOOLEAN, true_value.type());
  EXPECT_TRUE(true_value.GetBool());

  Value false_value(false);
  EXPECT_EQ(Value::Type::BOOLEAN, false_value.type());
  EXPECT_FALSE(false_value.GetBool());
}

TEST(ValuesTest, ConstructInt) {
  Value value(-37);
  EXPECT_EQ(Value::Type::INTEGER, value.type());
  EXPECT_EQ(-37, value.GetInt());
}

TEST(ValuesTest, ConstructDouble) {
  Value value(-4.655);
  EXPECT_EQ(Value::Type::DOUBLE, value.type());
  EXPECT_EQ(-4.655, value.GetDouble());
}

TEST(ValuesTest, ConstructStringFromConstCharPtr) {
  const char* str = "foobar";
  Value value(str);
  EXPECT_EQ(Value::Type::STRING, value.type());
  EXPECT_EQ("foobar", value.GetString());
}

TEST(ValuesTest, ConstructStringFromStdStringConstRef) {
  std::string str = "foobar";
  Value value(str);
  EXPECT_EQ(Value::Type::STRING, value.type());
  EXPECT_EQ("foobar", value.GetString());
}

TEST(ValuesTest, ConstructStringFromStdStringRefRef) {
  std::string str = "foobar";
  Value value(std::move(str));
  EXPECT_EQ(Value::Type::STRING, value.type());
  EXPECT_EQ("foobar", value.GetString());
}

TEST(ValuesTest, ConstructStringFromConstChar16Ptr) {
  string16 str = ASCIIToUTF16("foobar");
  Value value(str.c_str());
  EXPECT_EQ(Value::Type::STRING, value.type());
  EXPECT_EQ("foobar", value.GetString());
}

TEST(ValuesTest, ConstructStringFromString16) {
  string16 str = ASCIIToUTF16("foobar");
  Value value(str);
  EXPECT_EQ(Value::Type::STRING, value.type());
  EXPECT_EQ("foobar", value.GetString());
}

TEST(ValuesTest, ConstructStringFromStringPiece) {
  StringPiece str = "foobar";
  Value value(str);
  EXPECT_EQ(Value::Type::STRING, value.type());
  EXPECT_EQ("foobar", value.GetString());
}

TEST(ValuesTest, ConstructBinary) {
  Value value(Value::BlobStorage({0xF, 0x0, 0x0, 0xB, 0xA, 0x2}));
  EXPECT_EQ(Value::Type::BINARY, value.type());
  EXPECT_EQ(Value::BlobStorage({0xF, 0x0, 0x0, 0xB, 0xA, 0x2}),
            value.GetBlob());
}

TEST(ValuesTest, ConstructDict) {
  DictionaryValue value;
  EXPECT_EQ(Value::Type::DICTIONARY, value.type());
}

TEST(ValuesTest, ConstructList) {
  ListValue value;
  EXPECT_EQ(Value::Type::LIST, value.type());
}

TEST(ValuesTest, ConstructListFromStorage) {
  Value::ListStorage storage;
  storage.emplace_back("foo");

  {
    ListValue value(storage);
    EXPECT_EQ(Value::Type::LIST, value.type());
    EXPECT_EQ(1u, value.GetList().size());
    EXPECT_EQ(Value::Type::STRING, value.GetList()[0].type());
    EXPECT_EQ("foo", value.GetList()[0].GetString());
  }

  storage.back() = base::Value("bar");
  {
    ListValue value(std::move(storage));
    EXPECT_EQ(Value::Type::LIST, value.type());
    EXPECT_EQ(1u, value.GetList().size());
    EXPECT_EQ(Value::Type::STRING, value.GetList()[0].type());
    EXPECT_EQ("bar", value.GetList()[0].GetString());
  }
}

// Group of tests for the copy constructors and copy-assigmnent. For equality
// checks comparisons of the interesting fields are done instead of relying on
// Equals being correct.
TEST(ValuesTest, CopyBool) {
  Value true_value(true);
  Value copied_true_value(true_value);
  EXPECT_EQ(true_value.type(), copied_true_value.type());
  EXPECT_EQ(true_value.GetBool(), copied_true_value.GetBool());

  Value false_value(false);
  Value copied_false_value(false_value);
  EXPECT_EQ(false_value.type(), copied_false_value.type());
  EXPECT_EQ(false_value.GetBool(), copied_false_value.GetBool());

  Value blank;

  blank = true_value;
  EXPECT_EQ(true_value.type(), blank.type());
  EXPECT_EQ(true_value.GetBool(), blank.GetBool());

  blank = false_value;
  EXPECT_EQ(false_value.type(), blank.type());
  EXPECT_EQ(false_value.GetBool(), blank.GetBool());
}

TEST(ValuesTest, CopyInt) {
  Value value(74);
  Value copied_value(value);
  EXPECT_EQ(value.type(), copied_value.type());
  EXPECT_EQ(value.GetInt(), copied_value.GetInt());

  Value blank;

  blank = value;
  EXPECT_EQ(value.type(), blank.type());
  EXPECT_EQ(value.GetInt(), blank.GetInt());
}

TEST(ValuesTest, CopyDouble) {
  Value value(74.896);
  Value copied_value(value);
  EXPECT_EQ(value.type(), copied_value.type());
  EXPECT_EQ(value.GetDouble(), copied_value.GetDouble());

  Value blank;

  blank = value;
  EXPECT_EQ(value.type(), blank.type());
  EXPECT_EQ(value.GetDouble(), blank.GetDouble());
}

TEST(ValuesTest, CopyString) {
  Value value("foobar");
  Value copied_value(value);
  EXPECT_EQ(value.type(), copied_value.type());
  EXPECT_EQ(value.GetString(), copied_value.GetString());

  Value blank;

  blank = value;
  EXPECT_EQ(value.type(), blank.type());
  EXPECT_EQ(value.GetString(), blank.GetString());
}

TEST(ValuesTest, CopyBinary) {
  Value value(Value::BlobStorage({0xF, 0x0, 0x0, 0xB, 0xA, 0x2}));
  Value copied_value(value);
  EXPECT_EQ(value.type(), copied_value.type());
  EXPECT_EQ(value.GetBlob(), copied_value.GetBlob());

  Value blank;

  blank = value;
  EXPECT_EQ(value.type(), blank.type());
  EXPECT_EQ(value.GetBlob(), blank.GetBlob());
}

TEST(ValuesTest, CopyDictionary) {
  Value::DictStorage storage;
  storage.emplace("Int", MakeUnique<Value>(123));
  Value value(std::move(storage));

  Value copied_value(value);
  EXPECT_EQ(value, copied_value);

  Value blank;
  blank = value;
  EXPECT_EQ(value, blank);
}

TEST(ValuesTest, CopyList) {
  Value value(Value::ListStorage{Value(123)});

  Value copied_value(value);
  EXPECT_EQ(value, copied_value);

  Value blank;
  blank = value;
  EXPECT_EQ(value, blank);
}

// Group of tests for the move constructors and move-assigmnent.
TEST(ValuesTest, MoveBool) {
  Value true_value(true);
  Value moved_true_value(std::move(true_value));
  EXPECT_EQ(Value::Type::BOOLEAN, moved_true_value.type());
  EXPECT_TRUE(moved_true_value.GetBool());

  Value false_value(false);
  Value moved_false_value(std::move(false_value));
  EXPECT_EQ(Value::Type::BOOLEAN, moved_false_value.type());
  EXPECT_FALSE(moved_false_value.GetBool());

  Value blank;

  blank = Value(true);
  EXPECT_EQ(Value::Type::BOOLEAN, blank.type());
  EXPECT_TRUE(blank.GetBool());

  blank = Value(false);
  EXPECT_EQ(Value::Type::BOOLEAN, blank.type());
  EXPECT_FALSE(blank.GetBool());
}

TEST(ValuesTest, MoveInt) {
  Value value(74);
  Value moved_value(std::move(value));
  EXPECT_EQ(Value::Type::INTEGER, moved_value.type());
  EXPECT_EQ(74, moved_value.GetInt());

  Value blank;

  blank = Value(47);
  EXPECT_EQ(Value::Type::INTEGER, blank.type());
  EXPECT_EQ(47, blank.GetInt());
}

TEST(ValuesTest, MoveDouble) {
  Value value(74.896);
  Value moved_value(std::move(value));
  EXPECT_EQ(Value::Type::DOUBLE, moved_value.type());
  EXPECT_EQ(74.896, moved_value.GetDouble());

  Value blank;

  blank = Value(654.38);
  EXPECT_EQ(Value::Type::DOUBLE, blank.type());
  EXPECT_EQ(654.38, blank.GetDouble());
}

TEST(ValuesTest, MoveString) {
  Value value("foobar");
  Value moved_value(std::move(value));
  EXPECT_EQ(Value::Type::STRING, moved_value.type());
  EXPECT_EQ("foobar", moved_value.GetString());

  Value blank;

  blank = Value("foobar");
  EXPECT_EQ(Value::Type::STRING, blank.type());
  EXPECT_EQ("foobar", blank.GetString());
}

TEST(ValuesTest, MoveBinary) {
  const Value::BlobStorage buffer = {0xF, 0x0, 0x0, 0xB, 0xA, 0x2};
  Value value(buffer);
  Value moved_value(std::move(value));
  EXPECT_EQ(Value::Type::BINARY, moved_value.type());
  EXPECT_EQ(buffer, moved_value.GetBlob());

  Value blank;

  blank = Value(buffer);
  EXPECT_EQ(Value::Type::BINARY, blank.type());
  EXPECT_EQ(buffer, blank.GetBlob());
}

TEST(ValuesTest, MoveConstructDictionary) {
  Value::DictStorage storage;
  storage.emplace("Int", MakeUnique<Value>(123));

  Value value(std::move(storage));
  Value moved_value(std::move(value));
  EXPECT_EQ(Value::Type::DICTIONARY, moved_value.type());
  EXPECT_EQ(123, moved_value.FindKey("Int")->second.GetInt());
}

TEST(ValuesTest, MoveAssignDictionary) {
  Value::DictStorage storage;
  storage.emplace("Int", MakeUnique<Value>(123));

  Value blank;
  blank = Value(std::move(storage));
  EXPECT_EQ(Value::Type::DICTIONARY, blank.type());
  EXPECT_EQ(123, blank.FindKey("Int")->second.GetInt());
}

TEST(ValuesTest, MoveList) {
  const Value::ListStorage list = {Value(123)};
  Value value(list);
  Value moved_value(std::move(value));
  EXPECT_EQ(Value::Type::LIST, moved_value.type());
  EXPECT_EQ(123, moved_value.GetList().back().GetInt());

  Value blank;

  blank = Value(list);
  EXPECT_EQ(Value::Type::LIST, blank.type());
  EXPECT_EQ(123, blank.GetList().back().GetInt());
}

TEST(ValuesTest, FindKey) {
  Value::DictStorage storage;
  storage.emplace("foo", MakeUnique<Value>("bar"));
  Value dict(std::move(storage));
  EXPECT_NE(dict.FindKey("foo"), dict.DictEnd());
  EXPECT_EQ(dict.FindKey("baz"), dict.DictEnd());
}

TEST(ValuesTest, FindKeyChangeValue) {
  Value::DictStorage storage;
  storage.emplace("foo", MakeUnique<Value>("bar"));
  Value dict(std::move(storage));
  auto it = dict.FindKey("foo");
  EXPECT_NE(it, dict.DictEnd());
  const std::string& key = it->first;
  EXPECT_EQ("foo", key);
  EXPECT_EQ("bar", it->second.GetString());

  it->second = Value(123);
  EXPECT_EQ(123, dict.FindKey("foo")->second.GetInt());
}

TEST(ValuesTest, FindKeyConst) {
  Value::DictStorage storage;
  storage.emplace("foo", MakeUnique<Value>("bar"));
  const Value dict(std::move(storage));
  EXPECT_NE(dict.FindKey("foo"), dict.DictEnd());
  EXPECT_EQ(dict.FindKey("baz"), dict.DictEnd());
}

TEST(ValuesTest, FindKeyOfType) {
  Value::DictStorage storage;
  storage.emplace("null", MakeUnique<Value>(Value::Type::NONE));
  storage.emplace("bool", MakeUnique<Value>(Value::Type::BOOLEAN));
  storage.emplace("int", MakeUnique<Value>(Value::Type::INTEGER));
  storage.emplace("double", MakeUnique<Value>(Value::Type::DOUBLE));
  storage.emplace("string", MakeUnique<Value>(Value::Type::STRING));
  storage.emplace("blob", MakeUnique<Value>(Value::Type::BINARY));
  storage.emplace("list", MakeUnique<Value>(Value::Type::LIST));
  storage.emplace("dict", MakeUnique<Value>(Value::Type::DICTIONARY));

  Value dict(std::move(storage));
  EXPECT_NE(dict.FindKeyOfType("null", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::NONE), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("bool", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("int", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::DICTIONARY), dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("double", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("string", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::STRING), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("blob", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::BINARY), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("list", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::LIST), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("dict", Value::Type::DICTIONARY),
            dict.DictEnd());
}

TEST(ValuesTest, FindKeyOfTypeConst) {
  Value::DictStorage storage;
  storage.emplace("null", MakeUnique<Value>(Value::Type::NONE));
  storage.emplace("bool", MakeUnique<Value>(Value::Type::BOOLEAN));
  storage.emplace("int", MakeUnique<Value>(Value::Type::INTEGER));
  storage.emplace("double", MakeUnique<Value>(Value::Type::DOUBLE));
  storage.emplace("string", MakeUnique<Value>(Value::Type::STRING));
  storage.emplace("blob", MakeUnique<Value>(Value::Type::BINARY));
  storage.emplace("list", MakeUnique<Value>(Value::Type::LIST));
  storage.emplace("dict", MakeUnique<Value>(Value::Type::DICTIONARY));

  const Value dict(std::move(storage));
  EXPECT_NE(dict.FindKeyOfType("null", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("null", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::NONE), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("bool", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("bool", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("int", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("int", Value::Type::DICTIONARY), dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("double", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("double", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("string", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("string", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::STRING), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("blob", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("blob", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::BINARY), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("list", Value::Type::LIST), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("list", Value::Type::DICTIONARY),
            dict.DictEnd());

  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::NONE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::BOOLEAN), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::INTEGER), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::DOUBLE), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::STRING), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::BINARY), dict.DictEnd());
  EXPECT_EQ(dict.FindKeyOfType("dict", Value::Type::LIST), dict.DictEnd());
  EXPECT_NE(dict.FindKeyOfType("dict", Value::Type::DICTIONARY),
            dict.DictEnd());
}

TEST(ValuesTest, SetKey) {
  Value::DictStorage storage;
  storage.emplace("null", MakeUnique<Value>(Value::Type::NONE));
  storage.emplace("bool", MakeUnique<Value>(Value::Type::BOOLEAN));
  storage.emplace("int", MakeUnique<Value>(Value::Type::INTEGER));
  storage.emplace("double", MakeUnique<Value>(Value::Type::DOUBLE));
  storage.emplace("string", MakeUnique<Value>(Value::Type::STRING));
  storage.emplace("blob", MakeUnique<Value>(Value::Type::BINARY));
  storage.emplace("list", MakeUnique<Value>(Value::Type::LIST));
  storage.emplace("dict", MakeUnique<Value>(Value::Type::DICTIONARY));

  Value dict(Value::Type::DICTIONARY);
  dict.SetKey("null", Value(Value::Type::NONE));
  dict.SetKey("bool", Value(Value::Type::BOOLEAN));
  dict.SetKey("int", Value(Value::Type::INTEGER));
  dict.SetKey("double", Value(Value::Type::DOUBLE));
  dict.SetKey("string", Value(Value::Type::STRING));
  dict.SetKey("blob", Value(Value::Type::BINARY));
  dict.SetKey("list", Value(Value::Type::LIST));
  dict.SetKey("dict", Value(Value::Type::DICTIONARY));

  EXPECT_EQ(Value(std::move(storage)), dict);
}

TEST(ValuesTest, DictEnd) {
  Value dict(Value::Type::DICTIONARY);
  EXPECT_EQ(dict.DictItems().end(), dict.DictEnd());
}

TEST(ValuesTest, DictEndConst) {
  const Value dict(Value::Type::DICTIONARY);
  EXPECT_EQ(dict.DictItems().end(), dict.DictEnd());
}

TEST(ValuesTest, Basic) {
  // Test basic dictionary getting/setting
  DictionaryValue settings;
  std::string homepage = "http://google.com";
  ASSERT_FALSE(settings.GetString("global.homepage", &homepage));
  ASSERT_EQ(std::string("http://google.com"), homepage);

  ASSERT_FALSE(settings.Get("global", NULL));
  settings.SetBoolean("global", true);
  ASSERT_TRUE(settings.Get("global", NULL));
  settings.SetString("global.homepage", "http://scurvy.com");
  ASSERT_TRUE(settings.Get("global", NULL));
  homepage = "http://google.com";
  ASSERT_TRUE(settings.GetString("global.homepage", &homepage));
  ASSERT_EQ(std::string("http://scurvy.com"), homepage);

  // Test storing a dictionary in a list.
  ListValue* toolbar_bookmarks;
  ASSERT_FALSE(
    settings.GetList("global.toolbar.bookmarks", &toolbar_bookmarks));

  std::unique_ptr<ListValue> new_toolbar_bookmarks(new ListValue);
  settings.Set("global.toolbar.bookmarks", std::move(new_toolbar_bookmarks));
  ASSERT_TRUE(settings.GetList("global.toolbar.bookmarks", &toolbar_bookmarks));

  std::unique_ptr<DictionaryValue> new_bookmark(new DictionaryValue);
  new_bookmark->SetString("name", "Froogle");
  new_bookmark->SetString("url", "http://froogle.com");
  toolbar_bookmarks->Append(std::move(new_bookmark));

  ListValue* bookmark_list;
  ASSERT_TRUE(settings.GetList("global.toolbar.bookmarks", &bookmark_list));
  DictionaryValue* bookmark;
  ASSERT_EQ(1U, bookmark_list->GetSize());
  ASSERT_TRUE(bookmark_list->GetDictionary(0, &bookmark));
  std::string bookmark_name = "Unnamed";
  ASSERT_TRUE(bookmark->GetString("name", &bookmark_name));
  ASSERT_EQ(std::string("Froogle"), bookmark_name);
  std::string bookmark_url;
  ASSERT_TRUE(bookmark->GetString("url", &bookmark_url));
  ASSERT_EQ(std::string("http://froogle.com"), bookmark_url);
}

TEST(ValuesTest, List) {
  std::unique_ptr<ListValue> mixed_list(new ListValue());
  mixed_list->Set(0, MakeUnique<Value>(true));
  mixed_list->Set(1, MakeUnique<Value>(42));
  mixed_list->Set(2, MakeUnique<Value>(88.8));
  mixed_list->Set(3, MakeUnique<Value>("foo"));
  ASSERT_EQ(4u, mixed_list->GetSize());

  Value *value = NULL;
  bool bool_value = false;
  int int_value = 0;
  double double_value = 0.0;
  std::string string_value;

  ASSERT_FALSE(mixed_list->Get(4, &value));

  ASSERT_FALSE(mixed_list->GetInteger(0, &int_value));
  ASSERT_EQ(0, int_value);
  ASSERT_FALSE(mixed_list->GetBoolean(1, &bool_value));
  ASSERT_FALSE(bool_value);
  ASSERT_FALSE(mixed_list->GetString(2, &string_value));
  ASSERT_EQ("", string_value);
  ASSERT_FALSE(mixed_list->GetInteger(2, &int_value));
  ASSERT_EQ(0, int_value);
  ASSERT_FALSE(mixed_list->GetBoolean(3, &bool_value));
  ASSERT_FALSE(bool_value);

  ASSERT_TRUE(mixed_list->GetBoolean(0, &bool_value));
  ASSERT_TRUE(bool_value);
  ASSERT_TRUE(mixed_list->GetInteger(1, &int_value));
  ASSERT_EQ(42, int_value);
  // implicit conversion from Integer to Double should be possible.
  ASSERT_TRUE(mixed_list->GetDouble(1, &double_value));
  ASSERT_EQ(42, double_value);
  ASSERT_TRUE(mixed_list->GetDouble(2, &double_value));
  ASSERT_EQ(88.8, double_value);
  ASSERT_TRUE(mixed_list->GetString(3, &string_value));
  ASSERT_EQ("foo", string_value);

  // Try searching in the mixed list.
  base::Value sought_value(42);
  base::Value not_found_value(false);

  ASSERT_NE(mixed_list->end(), mixed_list->Find(sought_value));
  ASSERT_TRUE((*mixed_list->Find(sought_value)).GetAsInteger(&int_value));
  ASSERT_EQ(42, int_value);
  ASSERT_EQ(mixed_list->end(), mixed_list->Find(not_found_value));
}

TEST(ValuesTest, BinaryValue) {
  // Default constructor creates a BinaryValue with a buffer of size 0.
  auto binary = MakeUnique<Value>(Value::Type::BINARY);
  ASSERT_TRUE(binary.get());
  ASSERT_TRUE(binary->GetBlob().empty());

  // Test the common case of a non-empty buffer
  Value::BlobStorage buffer(15);
  char* original_buffer = buffer.data();
  binary.reset(new Value(std::move(buffer)));
  ASSERT_TRUE(binary.get());
  ASSERT_TRUE(binary->GetBlob().data());
  ASSERT_EQ(original_buffer, binary->GetBlob().data());
  ASSERT_EQ(15U, binary->GetBlob().size());

  char stack_buffer[42];
  memset(stack_buffer, '!', 42);
  binary = Value::CreateWithCopiedBuffer(stack_buffer, 42);
  ASSERT_TRUE(binary.get());
  ASSERT_TRUE(binary->GetBlob().data());
  ASSERT_NE(stack_buffer, binary->GetBlob().data());
  ASSERT_EQ(42U, binary->GetBlob().size());
  ASSERT_EQ(0, memcmp(stack_buffer, binary->GetBlob().data(),
                      binary->GetBlob().size()));
}

TEST(ValuesTest, StringValue) {
  // Test overloaded StringValue constructor.
  std::unique_ptr<Value> narrow_value(new Value("narrow"));
  ASSERT_TRUE(narrow_value.get());
  ASSERT_TRUE(narrow_value->IsType(Value::Type::STRING));
  std::unique_ptr<Value> utf16_value(new Value(ASCIIToUTF16("utf16")));
  ASSERT_TRUE(utf16_value.get());
  ASSERT_TRUE(utf16_value->IsType(Value::Type::STRING));

  // Test overloaded GetAsString.
  std::string narrow = "http://google.com";
  string16 utf16 = ASCIIToUTF16("http://google.com");
  const Value* string_value = NULL;
  ASSERT_TRUE(narrow_value->GetAsString(&narrow));
  ASSERT_TRUE(narrow_value->GetAsString(&utf16));
  ASSERT_TRUE(narrow_value->GetAsString(&string_value));
  ASSERT_EQ(std::string("narrow"), narrow);
  ASSERT_EQ(ASCIIToUTF16("narrow"), utf16);
  ASSERT_EQ(string_value->GetString(), narrow);

  ASSERT_TRUE(utf16_value->GetAsString(&narrow));
  ASSERT_TRUE(utf16_value->GetAsString(&utf16));
  ASSERT_TRUE(utf16_value->GetAsString(&string_value));
  ASSERT_EQ(std::string("utf16"), narrow);
  ASSERT_EQ(ASCIIToUTF16("utf16"), utf16);
  ASSERT_EQ(string_value->GetString(), narrow);

  // Don't choke on NULL values.
  ASSERT_TRUE(narrow_value->GetAsString(static_cast<string16*>(NULL)));
  ASSERT_TRUE(narrow_value->GetAsString(static_cast<std::string*>(NULL)));
  ASSERT_TRUE(narrow_value->GetAsString(static_cast<const Value**>(NULL)));
}

TEST(ValuesTest, ListDeletion) {
  ListValue list;
  list.Append(MakeUnique<Value>());
  EXPECT_FALSE(list.empty());
  list.Clear();
  EXPECT_TRUE(list.empty());
}

TEST(ValuesTest, ListRemoval) {
  std::unique_ptr<Value> removed_item;

  {
    ListValue list;
    list.Append(MakeUnique<Value>());
    EXPECT_EQ(1U, list.GetSize());
    EXPECT_FALSE(list.Remove(std::numeric_limits<size_t>::max(),
                             &removed_item));
    EXPECT_FALSE(list.Remove(1, &removed_item));
    EXPECT_TRUE(list.Remove(0, &removed_item));
    ASSERT_TRUE(removed_item);
    EXPECT_EQ(0U, list.GetSize());
  }
  removed_item.reset();

  {
    ListValue list;
    list.Append(MakeUnique<Value>());
    EXPECT_TRUE(list.Remove(0, NULL));
    EXPECT_EQ(0U, list.GetSize());
  }

  {
    ListValue list;
    auto value = MakeUnique<Value>();
    Value original_value = *value;
    list.Append(std::move(value));
    size_t index = 0;
    list.Remove(original_value, &index);
    EXPECT_EQ(0U, index);
    EXPECT_EQ(0U, list.GetSize());
  }
}

TEST(ValuesTest, DictionaryDeletion) {
  std::string key = "test";
  DictionaryValue dict;
  dict.Set(key, MakeUnique<Value>());
  EXPECT_FALSE(dict.empty());
  dict.Clear();
  EXPECT_TRUE(dict.empty());
}

TEST(ValuesTest, DictionarySetReturnsPointer) {
  {
    DictionaryValue dict;
    Value* blank_ptr = dict.Set("foo.bar", base::MakeUnique<base::Value>());
    EXPECT_EQ(Value::Type::NONE, blank_ptr->type());
  }

  {
    DictionaryValue dict;
    Value* blank_ptr = dict.SetWithoutPathExpansion(
        "foo.bar", base::MakeUnique<base::Value>());
    EXPECT_EQ(Value::Type::NONE, blank_ptr->type());
  }

  {
    DictionaryValue dict;
    Value* bool_ptr = dict.SetBooleanWithoutPathExpansion("foo.bar", false);
    EXPECT_EQ(Value::Type::BOOLEAN, bool_ptr->type());
    EXPECT_FALSE(bool_ptr->GetBool());
  }

  {
    DictionaryValue dict;
    Value* int_ptr = dict.SetInteger("foo.bar", 42);
    EXPECT_EQ(Value::Type::INTEGER, int_ptr->type());
    EXPECT_EQ(42, int_ptr->GetInt());
  }

  {
    DictionaryValue dict;
    Value* int_ptr = dict.SetIntegerWithoutPathExpansion("foo.bar", 123);
    EXPECT_EQ(Value::Type::INTEGER, int_ptr->type());
    EXPECT_EQ(123, int_ptr->GetInt());
  }

  {
    DictionaryValue dict;
    Value* double_ptr = dict.SetDouble("foo.bar", 3.142);
    EXPECT_EQ(Value::Type::DOUBLE, double_ptr->type());
    EXPECT_EQ(3.142, double_ptr->GetDouble());
  }

  {
    DictionaryValue dict;
    Value* double_ptr = dict.SetDoubleWithoutPathExpansion("foo.bar", 2.718);
    EXPECT_EQ(Value::Type::DOUBLE, double_ptr->type());
    EXPECT_EQ(2.718, double_ptr->GetDouble());
  }

  {
    DictionaryValue dict;
    Value* string_ptr = dict.SetString("foo.bar", "foo");
    EXPECT_EQ(Value::Type::STRING, string_ptr->type());
    EXPECT_EQ("foo", string_ptr->GetString());
  }

  {
    DictionaryValue dict;
    Value* string_ptr = dict.SetStringWithoutPathExpansion("foo.bar", "bar");
    EXPECT_EQ(Value::Type::STRING, string_ptr->type());
    EXPECT_EQ("bar", string_ptr->GetString());
  }

  {
    DictionaryValue dict;
    Value* string16_ptr = dict.SetString("foo.bar", ASCIIToUTF16("baz"));
    EXPECT_EQ(Value::Type::STRING, string16_ptr->type());
    EXPECT_EQ("baz", string16_ptr->GetString());
  }

  {
    DictionaryValue dict;
    Value* string16_ptr =
        dict.SetStringWithoutPathExpansion("foo.bar", ASCIIToUTF16("qux"));
    EXPECT_EQ(Value::Type::STRING, string16_ptr->type());
    EXPECT_EQ("qux", string16_ptr->GetString());
  }

  {
    DictionaryValue dict;
    DictionaryValue* dict_ptr = dict.SetDictionary(
        "foo.bar", base::MakeUnique<base::DictionaryValue>());
    EXPECT_EQ(Value::Type::DICTIONARY, dict_ptr->type());
  }

  {
    DictionaryValue dict;
    DictionaryValue* dict_ptr = dict.SetDictionaryWithoutPathExpansion(
        "foo.bar", base::MakeUnique<base::DictionaryValue>());
    EXPECT_EQ(Value::Type::DICTIONARY, dict_ptr->type());
  }

  {
    DictionaryValue dict;
    ListValue* list_ptr =
        dict.SetList("foo.bar", base::MakeUnique<base::ListValue>());
    EXPECT_EQ(Value::Type::LIST, list_ptr->type());
  }

  {
    DictionaryValue dict;
    ListValue* list_ptr = dict.SetListWithoutPathExpansion(
        "foo.bar", base::MakeUnique<base::ListValue>());
    EXPECT_EQ(Value::Type::LIST, list_ptr->type());
  }
}

TEST(ValuesTest, DictionaryRemoval) {
  std::string key = "test";
  std::unique_ptr<Value> removed_item;

  {
    DictionaryValue dict;
    dict.Set(key, MakeUnique<Value>());
    EXPECT_TRUE(dict.HasKey(key));
    EXPECT_FALSE(dict.Remove("absent key", &removed_item));
    EXPECT_TRUE(dict.Remove(key, &removed_item));
    EXPECT_FALSE(dict.HasKey(key));
    ASSERT_TRUE(removed_item);
  }

  {
    DictionaryValue dict;
    dict.Set(key, MakeUnique<Value>());
    EXPECT_TRUE(dict.HasKey(key));
    EXPECT_TRUE(dict.Remove(key, NULL));
    EXPECT_FALSE(dict.HasKey(key));
  }
}

TEST(ValuesTest, DictionaryWithoutPathExpansion) {
  DictionaryValue dict;
  dict.Set("this.is.expanded", MakeUnique<Value>());
  dict.SetWithoutPathExpansion("this.isnt.expanded", MakeUnique<Value>());

  EXPECT_FALSE(dict.HasKey("this.is.expanded"));
  EXPECT_TRUE(dict.HasKey("this"));
  Value* value1;
  EXPECT_TRUE(dict.Get("this", &value1));
  DictionaryValue* value2;
  ASSERT_TRUE(dict.GetDictionaryWithoutPathExpansion("this", &value2));
  EXPECT_EQ(value1, value2);
  EXPECT_EQ(1U, value2->size());

  EXPECT_TRUE(dict.HasKey("this.isnt.expanded"));
  Value* value3;
  EXPECT_FALSE(dict.Get("this.isnt.expanded", &value3));
  Value* value4;
  ASSERT_TRUE(dict.GetWithoutPathExpansion("this.isnt.expanded", &value4));
  EXPECT_EQ(Value::Type::NONE, value4->GetType());
}

// Tests the deprecated version of SetWithoutPathExpansion.
// TODO(estade): remove.
TEST(ValuesTest, DictionaryWithoutPathExpansionDeprecated) {
  DictionaryValue dict;
  dict.Set("this.is.expanded", MakeUnique<Value>());
  dict.SetWithoutPathExpansion("this.isnt.expanded", MakeUnique<Value>());

  EXPECT_FALSE(dict.HasKey("this.is.expanded"));
  EXPECT_TRUE(dict.HasKey("this"));
  Value* value1;
  EXPECT_TRUE(dict.Get("this", &value1));
  DictionaryValue* value2;
  ASSERT_TRUE(dict.GetDictionaryWithoutPathExpansion("this", &value2));
  EXPECT_EQ(value1, value2);
  EXPECT_EQ(1U, value2->size());

  EXPECT_TRUE(dict.HasKey("this.isnt.expanded"));
  Value* value3;
  EXPECT_FALSE(dict.Get("this.isnt.expanded", &value3));
  Value* value4;
  ASSERT_TRUE(dict.GetWithoutPathExpansion("this.isnt.expanded", &value4));
  EXPECT_EQ(Value::Type::NONE, value4->GetType());
}

TEST(ValuesTest, DictionaryRemovePath) {
  DictionaryValue dict;
  dict.SetInteger("a.long.way.down", 1);
  dict.SetBoolean("a.long.key.path", true);

  std::unique_ptr<Value> removed_item;
  EXPECT_TRUE(dict.RemovePath("a.long.way.down", &removed_item));
  ASSERT_TRUE(removed_item);
  EXPECT_TRUE(removed_item->IsType(base::Value::Type::INTEGER));
  EXPECT_FALSE(dict.HasKey("a.long.way.down"));
  EXPECT_FALSE(dict.HasKey("a.long.way"));
  EXPECT_TRUE(dict.Get("a.long.key.path", NULL));

  removed_item.reset();
  EXPECT_FALSE(dict.RemovePath("a.long.way.down", &removed_item));
  EXPECT_FALSE(removed_item);
  EXPECT_TRUE(dict.Get("a.long.key.path", NULL));

  removed_item.reset();
  EXPECT_TRUE(dict.RemovePath("a.long.key.path", &removed_item));
  ASSERT_TRUE(removed_item);
  EXPECT_TRUE(removed_item->IsType(base::Value::Type::BOOLEAN));
  EXPECT_TRUE(dict.empty());
}

TEST(ValuesTest, DeepCopy) {
  DictionaryValue original_dict;
  Value* null_weak = original_dict.Set("null", MakeUnique<Value>());
  Value* bool_weak = original_dict.Set("bool", MakeUnique<Value>(true));
  Value* int_weak = original_dict.Set("int", MakeUnique<Value>(42));
  Value* double_weak = original_dict.Set("double", MakeUnique<Value>(3.14));
  Value* string_weak = original_dict.Set("string", MakeUnique<Value>("hello"));
  Value* string16_weak =
      original_dict.Set("string16", MakeUnique<Value>(ASCIIToUTF16("hello16")));

  Value* binary_weak = original_dict.Set(
      "binary", MakeUnique<Value>(Value::BlobStorage(42, '!')));

  Value* list_weak = original_dict.Set(
      "list", MakeUnique<Value>(Value::ListStorage({Value(0), Value(1)})));
  Value* list_element_0_weak = &list_weak->GetList()[0];
  Value* list_element_1_weak = &list_weak->GetList()[1];

  DictionaryValue* dict_weak =
      original_dict.SetDictionary("dictionary", MakeUnique<DictionaryValue>());
  dict_weak->SetString("key", "value");

  auto copy_dict = MakeUnique<DictionaryValue>(original_dict);
  ASSERT_TRUE(copy_dict.get());
  ASSERT_NE(copy_dict.get(), &original_dict);

  Value* copy_null = NULL;
  ASSERT_TRUE(copy_dict->Get("null", &copy_null));
  ASSERT_TRUE(copy_null);
  ASSERT_NE(copy_null, null_weak);
  ASSERT_TRUE(copy_null->IsType(Value::Type::NONE));

  Value* copy_bool = NULL;
  ASSERT_TRUE(copy_dict->Get("bool", &copy_bool));
  ASSERT_TRUE(copy_bool);
  ASSERT_NE(copy_bool, bool_weak);
  ASSERT_TRUE(copy_bool->IsType(Value::Type::BOOLEAN));
  bool copy_bool_value = false;
  ASSERT_TRUE(copy_bool->GetAsBoolean(&copy_bool_value));
  ASSERT_TRUE(copy_bool_value);

  Value* copy_int = NULL;
  ASSERT_TRUE(copy_dict->Get("int", &copy_int));
  ASSERT_TRUE(copy_int);
  ASSERT_NE(copy_int, int_weak);
  ASSERT_TRUE(copy_int->IsType(Value::Type::INTEGER));
  int copy_int_value = 0;
  ASSERT_TRUE(copy_int->GetAsInteger(&copy_int_value));
  ASSERT_EQ(42, copy_int_value);

  Value* copy_double = NULL;
  ASSERT_TRUE(copy_dict->Get("double", &copy_double));
  ASSERT_TRUE(copy_double);
  ASSERT_NE(copy_double, double_weak);
  ASSERT_TRUE(copy_double->IsType(Value::Type::DOUBLE));
  double copy_double_value = 0;
  ASSERT_TRUE(copy_double->GetAsDouble(&copy_double_value));
  ASSERT_EQ(3.14, copy_double_value);

  Value* copy_string = NULL;
  ASSERT_TRUE(copy_dict->Get("string", &copy_string));
  ASSERT_TRUE(copy_string);
  ASSERT_NE(copy_string, string_weak);
  ASSERT_TRUE(copy_string->IsType(Value::Type::STRING));
  std::string copy_string_value;
  string16 copy_string16_value;
  ASSERT_TRUE(copy_string->GetAsString(&copy_string_value));
  ASSERT_TRUE(copy_string->GetAsString(&copy_string16_value));
  ASSERT_EQ(std::string("hello"), copy_string_value);
  ASSERT_EQ(ASCIIToUTF16("hello"), copy_string16_value);

  Value* copy_string16 = NULL;
  ASSERT_TRUE(copy_dict->Get("string16", &copy_string16));
  ASSERT_TRUE(copy_string16);
  ASSERT_NE(copy_string16, string16_weak);
  ASSERT_TRUE(copy_string16->IsType(Value::Type::STRING));
  ASSERT_TRUE(copy_string16->GetAsString(&copy_string_value));
  ASSERT_TRUE(copy_string16->GetAsString(&copy_string16_value));
  ASSERT_EQ(std::string("hello16"), copy_string_value);
  ASSERT_EQ(ASCIIToUTF16("hello16"), copy_string16_value);

  Value* copy_binary = NULL;
  ASSERT_TRUE(copy_dict->Get("binary", &copy_binary));
  ASSERT_TRUE(copy_binary);
  ASSERT_NE(copy_binary, binary_weak);
  ASSERT_TRUE(copy_binary->IsType(Value::Type::BINARY));
  ASSERT_NE(binary_weak->GetBlob().data(), copy_binary->GetBlob().data());
  ASSERT_EQ(binary_weak->GetBlob(), copy_binary->GetBlob());

  Value* copy_value = NULL;
  ASSERT_TRUE(copy_dict->Get("list", &copy_value));
  ASSERT_TRUE(copy_value);
  ASSERT_NE(copy_value, list_weak);
  ASSERT_TRUE(copy_value->IsType(Value::Type::LIST));
  ListValue* copy_list = NULL;
  ASSERT_TRUE(copy_value->GetAsList(&copy_list));
  ASSERT_TRUE(copy_list);
  ASSERT_EQ(2U, copy_list->GetSize());

  Value* copy_list_element_0;
  ASSERT_TRUE(copy_list->Get(0, &copy_list_element_0));
  ASSERT_TRUE(copy_list_element_0);
  ASSERT_NE(copy_list_element_0, list_element_0_weak);
  int copy_list_element_0_value;
  ASSERT_TRUE(copy_list_element_0->GetAsInteger(&copy_list_element_0_value));
  ASSERT_EQ(0, copy_list_element_0_value);

  Value* copy_list_element_1;
  ASSERT_TRUE(copy_list->Get(1, &copy_list_element_1));
  ASSERT_TRUE(copy_list_element_1);
  ASSERT_NE(copy_list_element_1, list_element_1_weak);
  int copy_list_element_1_value;
  ASSERT_TRUE(copy_list_element_1->GetAsInteger(&copy_list_element_1_value));
  ASSERT_EQ(1, copy_list_element_1_value);

  copy_value = NULL;
  ASSERT_TRUE(copy_dict->Get("dictionary", &copy_value));
  ASSERT_TRUE(copy_value);
  ASSERT_NE(copy_value, dict_weak);
  ASSERT_TRUE(copy_value->IsType(Value::Type::DICTIONARY));
  DictionaryValue* copy_nested_dictionary = NULL;
  ASSERT_TRUE(copy_value->GetAsDictionary(&copy_nested_dictionary));
  ASSERT_TRUE(copy_nested_dictionary);
  EXPECT_TRUE(copy_nested_dictionary->HasKey("key"));
}

TEST(ValuesTest, Equals) {
  auto null1 = MakeUnique<Value>();
  auto null2 = MakeUnique<Value>();
  EXPECT_NE(null1.get(), null2.get());
  EXPECT_EQ(*null1, *null2);

  Value boolean(false);
  EXPECT_NE(*null1, boolean);

  DictionaryValue dv;
  dv.SetBoolean("a", false);
  dv.SetInteger("b", 2);
  dv.SetDouble("c", 2.5);
  dv.SetString("d1", "string");
  dv.SetString("d2", ASCIIToUTF16("http://google.com"));
  dv.Set("e", MakeUnique<Value>());

  auto copy = MakeUnique<DictionaryValue>(dv);
  EXPECT_EQ(dv, *copy);

  std::unique_ptr<ListValue> list(new ListValue);
  list->Append(MakeUnique<Value>());
  list->Append(WrapUnique(new DictionaryValue));
  auto list_copy = MakeUnique<Value>(*list);

  ListValue* list_weak = dv.SetList("f", std::move(list));
  EXPECT_NE(dv, *copy);
  copy->Set("f", std::move(list_copy));
  EXPECT_EQ(dv, *copy);

  list_weak->Append(MakeUnique<Value>(true));
  EXPECT_NE(dv, *copy);

  // Check if Equals detects differences in only the keys.
  copy = MakeUnique<DictionaryValue>(dv);
  EXPECT_EQ(dv, *copy);
  copy->Remove("a", NULL);
  copy->SetBoolean("aa", false);
  EXPECT_NE(dv, *copy);
}

TEST(ValuesTest, Comparisons) {
  // Test None Values.
  Value null1;
  Value null2;
  EXPECT_EQ(null1, null2);
  EXPECT_FALSE(null1 != null2);
  EXPECT_FALSE(null1 < null2);
  EXPECT_FALSE(null1 > null2);
  EXPECT_LE(null1, null2);
  EXPECT_GE(null1, null2);

  // Test Bool Values.
  Value bool1(false);
  Value bool2(true);
  EXPECT_FALSE(bool1 == bool2);
  EXPECT_NE(bool1, bool2);
  EXPECT_LT(bool1, bool2);
  EXPECT_FALSE(bool1 > bool2);
  EXPECT_LE(bool1, bool2);
  EXPECT_FALSE(bool1 >= bool2);

  // Test Int Values.
  Value int1(1);
  Value int2(2);
  EXPECT_FALSE(int1 == int2);
  EXPECT_NE(int1, int2);
  EXPECT_LT(int1, int2);
  EXPECT_FALSE(int1 > int2);
  EXPECT_LE(int1, int2);
  EXPECT_FALSE(int1 >= int2);

  // Test Double Values.
  Value double1(1.0);
  Value double2(2.0);
  EXPECT_FALSE(double1 == double2);
  EXPECT_NE(double1, double2);
  EXPECT_LT(double1, double2);
  EXPECT_FALSE(double1 > double2);
  EXPECT_LE(double1, double2);
  EXPECT_FALSE(double1 >= double2);

  // Test String Values.
  Value string1("1");
  Value string2("2");
  EXPECT_FALSE(string1 == string2);
  EXPECT_NE(string1, string2);
  EXPECT_LT(string1, string2);
  EXPECT_FALSE(string1 > string2);
  EXPECT_LE(string1, string2);
  EXPECT_FALSE(string1 >= string2);

  // Test Binary Values.
  Value binary1(Value::BlobStorage{0x01});
  Value binary2(Value::BlobStorage{0x02});
  EXPECT_FALSE(binary1 == binary2);
  EXPECT_NE(binary1, binary2);
  EXPECT_LT(binary1, binary2);
  EXPECT_FALSE(binary1 > binary2);
  EXPECT_LE(binary1, binary2);
  EXPECT_FALSE(binary1 >= binary2);

  // Test Empty List Values.
  ListValue null_list1;
  ListValue null_list2;
  EXPECT_EQ(null_list1, null_list2);
  EXPECT_FALSE(null_list1 != null_list2);
  EXPECT_FALSE(null_list1 < null_list2);
  EXPECT_FALSE(null_list1 > null_list2);
  EXPECT_LE(null_list1, null_list2);
  EXPECT_GE(null_list1, null_list2);

  // Test Non Empty List Values.
  ListValue int_list1;
  ListValue int_list2;
  int_list1.AppendInteger(1);
  int_list2.AppendInteger(2);
  EXPECT_FALSE(int_list1 == int_list2);
  EXPECT_NE(int_list1, int_list2);
  EXPECT_LT(int_list1, int_list2);
  EXPECT_FALSE(int_list1 > int_list2);
  EXPECT_LE(int_list1, int_list2);
  EXPECT_FALSE(int_list1 >= int_list2);

  // Test Empty Dict Values.
  DictionaryValue null_dict1;
  DictionaryValue null_dict2;
  EXPECT_EQ(null_dict1, null_dict2);
  EXPECT_FALSE(null_dict1 != null_dict2);
  EXPECT_FALSE(null_dict1 < null_dict2);
  EXPECT_FALSE(null_dict1 > null_dict2);
  EXPECT_LE(null_dict1, null_dict2);
  EXPECT_GE(null_dict1, null_dict2);

  // Test Non Empty Dict Values.
  DictionaryValue int_dict1;
  DictionaryValue int_dict2;
  int_dict1.SetInteger("key", 1);
  int_dict2.SetInteger("key", 2);
  EXPECT_FALSE(int_dict1 == int_dict2);
  EXPECT_NE(int_dict1, int_dict2);
  EXPECT_LT(int_dict1, int_dict2);
  EXPECT_FALSE(int_dict1 > int_dict2);
  EXPECT_LE(int_dict1, int_dict2);
  EXPECT_FALSE(int_dict1 >= int_dict2);

  // Test Values of different types.
  std::vector<Value> values = {null1,   bool1,   int1,      double1,
                               string1, binary1, int_dict1, int_list1};
  for (size_t i = 0; i < values.size(); ++i) {
    for (size_t j = i + 1; j < values.size(); ++j) {
      EXPECT_FALSE(values[i] == values[j]);
      EXPECT_NE(values[i], values[j]);
      EXPECT_LT(values[i], values[j]);
      EXPECT_FALSE(values[i] > values[j]);
      EXPECT_LE(values[i], values[j]);
      EXPECT_FALSE(values[i] >= values[j]);
    }
  }
}

TEST(ValuesTest, DeepCopyCovariantReturnTypes) {
  DictionaryValue original_dict;
  Value* null_weak = original_dict.Set("null", MakeUnique<Value>());
  Value* bool_weak = original_dict.Set("bool", MakeUnique<Value>(true));
  Value* int_weak = original_dict.Set("int", MakeUnique<Value>(42));
  Value* double_weak = original_dict.Set("double", MakeUnique<Value>(3.14));
  Value* string_weak = original_dict.Set("string", MakeUnique<Value>("hello"));
  Value* string16_weak =
      original_dict.Set("string16", MakeUnique<Value>(ASCIIToUTF16("hello16")));

  Value* binary_weak = original_dict.Set(
      "binary", MakeUnique<Value>(Value::BlobStorage(42, '!')));

  Value* list_weak = original_dict.Set(
      "list", MakeUnique<Value>(Value::ListStorage({Value(0), Value(1)})));

  auto copy_dict = MakeUnique<Value>(original_dict);
  auto copy_null = MakeUnique<Value>(*null_weak);
  auto copy_bool = MakeUnique<Value>(*bool_weak);
  auto copy_int = MakeUnique<Value>(*int_weak);
  auto copy_double = MakeUnique<Value>(*double_weak);
  auto copy_string = MakeUnique<Value>(*string_weak);
  auto copy_string16 = MakeUnique<Value>(*string16_weak);
  auto copy_binary = MakeUnique<Value>(*binary_weak);
  auto copy_list = MakeUnique<Value>(*list_weak);

  EXPECT_EQ(original_dict, *copy_dict);
  EXPECT_EQ(*null_weak, *copy_null);
  EXPECT_EQ(*bool_weak, *copy_bool);
  EXPECT_EQ(*int_weak, *copy_int);
  EXPECT_EQ(*double_weak, *copy_double);
  EXPECT_EQ(*string_weak, *copy_string);
  EXPECT_EQ(*string16_weak, *copy_string16);
  EXPECT_EQ(*binary_weak, *copy_binary);
  EXPECT_EQ(*list_weak, *copy_list);
}

TEST(ValuesTest, RemoveEmptyChildren) {
  auto root = base::MakeUnique<DictionaryValue>();
  // Remove empty lists and dictionaries.
  root->Set("empty_dict", MakeUnique<DictionaryValue>());
  root->Set("empty_list", MakeUnique<ListValue>());
  root->SetWithoutPathExpansion("a.b.c.d.e", MakeUnique<DictionaryValue>());
  root = root->DeepCopyWithoutEmptyChildren();
  EXPECT_TRUE(root->empty());

  // Make sure we don't prune too much.
  root->SetBoolean("bool", true);
  root->Set("empty_dict", MakeUnique<DictionaryValue>());
  root->SetString("empty_string", std::string());
  root = root->DeepCopyWithoutEmptyChildren();
  EXPECT_EQ(2U, root->size());

  // Should do nothing.
  root = root->DeepCopyWithoutEmptyChildren();
  EXPECT_EQ(2U, root->size());

  // Nested test cases.  These should all reduce back to the bool and string
  // set above.
  {
    root->Set("a.b.c.d.e", MakeUnique<DictionaryValue>());
    root = root->DeepCopyWithoutEmptyChildren();
    EXPECT_EQ(2U, root->size());
  }
  {
    auto inner = base::MakeUnique<DictionaryValue>();
    inner->Set("empty_dict", MakeUnique<DictionaryValue>());
    inner->Set("empty_list", MakeUnique<ListValue>());
    root->Set("dict_with_empty_children", std::move(inner));
    root = root->DeepCopyWithoutEmptyChildren();
    EXPECT_EQ(2U, root->size());
  }
  {
    auto inner = base::MakeUnique<ListValue>();
    inner->Append(MakeUnique<DictionaryValue>());
    inner->Append(MakeUnique<ListValue>());
    root->Set("list_with_empty_children", std::move(inner));
    root = root->DeepCopyWithoutEmptyChildren();
    EXPECT_EQ(2U, root->size());
  }

  // Nested with siblings.
  {
    auto inner = base::MakeUnique<ListValue>();
    inner->Append(MakeUnique<DictionaryValue>());
    inner->Append(MakeUnique<ListValue>());
    root->Set("list_with_empty_children", std::move(inner));
    auto inner2 = base::MakeUnique<DictionaryValue>();
    inner2->Set("empty_dict", MakeUnique<DictionaryValue>());
    inner2->Set("empty_list", MakeUnique<ListValue>());
    root->Set("dict_with_empty_children", std::move(inner2));
    root = root->DeepCopyWithoutEmptyChildren();
    EXPECT_EQ(2U, root->size());
  }

  // Make sure nested values don't get pruned.
  {
    auto inner = base::MakeUnique<ListValue>();
    auto inner2 = base::MakeUnique<ListValue>();
    inner2->Append(MakeUnique<Value>("hello"));
    inner->Append(MakeUnique<DictionaryValue>());
    inner->Append(std::move(inner2));
    root->Set("list_with_empty_children", std::move(inner));
    root = root->DeepCopyWithoutEmptyChildren();
    EXPECT_EQ(3U, root->size());

    ListValue* inner_value, *inner_value2;
    EXPECT_TRUE(root->GetList("list_with_empty_children", &inner_value));
    EXPECT_EQ(1U, inner_value->GetSize());  // Dictionary was pruned.
    EXPECT_TRUE(inner_value->GetList(0, &inner_value2));
    EXPECT_EQ(1U, inner_value2->GetSize());
  }
}

TEST(ValuesTest, MergeDictionary) {
  std::unique_ptr<DictionaryValue> base(new DictionaryValue);
  base->SetString("base_key", "base_key_value_base");
  base->SetString("collide_key", "collide_key_value_base");
  std::unique_ptr<DictionaryValue> base_sub_dict(new DictionaryValue);
  base_sub_dict->SetString("sub_base_key", "sub_base_key_value_base");
  base_sub_dict->SetString("sub_collide_key", "sub_collide_key_value_base");
  base->Set("sub_dict_key", std::move(base_sub_dict));

  std::unique_ptr<DictionaryValue> merge(new DictionaryValue);
  merge->SetString("merge_key", "merge_key_value_merge");
  merge->SetString("collide_key", "collide_key_value_merge");
  std::unique_ptr<DictionaryValue> merge_sub_dict(new DictionaryValue);
  merge_sub_dict->SetString("sub_merge_key", "sub_merge_key_value_merge");
  merge_sub_dict->SetString("sub_collide_key", "sub_collide_key_value_merge");
  merge->Set("sub_dict_key", std::move(merge_sub_dict));

  base->MergeDictionary(merge.get());

  EXPECT_EQ(4U, base->size());
  std::string base_key_value;
  EXPECT_TRUE(base->GetString("base_key", &base_key_value));
  EXPECT_EQ("base_key_value_base", base_key_value); // Base value preserved.
  std::string collide_key_value;
  EXPECT_TRUE(base->GetString("collide_key", &collide_key_value));
  EXPECT_EQ("collide_key_value_merge", collide_key_value); // Replaced.
  std::string merge_key_value;
  EXPECT_TRUE(base->GetString("merge_key", &merge_key_value));
  EXPECT_EQ("merge_key_value_merge", merge_key_value); // Merged in.

  DictionaryValue* res_sub_dict;
  EXPECT_TRUE(base->GetDictionary("sub_dict_key", &res_sub_dict));
  EXPECT_EQ(3U, res_sub_dict->size());
  std::string sub_base_key_value;
  EXPECT_TRUE(res_sub_dict->GetString("sub_base_key", &sub_base_key_value));
  EXPECT_EQ("sub_base_key_value_base", sub_base_key_value); // Preserved.
  std::string sub_collide_key_value;
  EXPECT_TRUE(res_sub_dict->GetString("sub_collide_key",
                                      &sub_collide_key_value));
  EXPECT_EQ("sub_collide_key_value_merge", sub_collide_key_value); // Replaced.
  std::string sub_merge_key_value;
  EXPECT_TRUE(res_sub_dict->GetString("sub_merge_key", &sub_merge_key_value));
  EXPECT_EQ("sub_merge_key_value_merge", sub_merge_key_value); // Merged in.
}

TEST(ValuesTest, MergeDictionaryDeepCopy) {
  std::unique_ptr<DictionaryValue> child(new DictionaryValue);
  DictionaryValue* original_child = child.get();
  child->SetString("test", "value");
  EXPECT_EQ(1U, child->size());

  std::string value;
  EXPECT_TRUE(child->GetString("test", &value));
  EXPECT_EQ("value", value);

  std::unique_ptr<DictionaryValue> base(new DictionaryValue);
  base->Set("dict", std::move(child));
  EXPECT_EQ(1U, base->size());

  DictionaryValue* ptr;
  EXPECT_TRUE(base->GetDictionary("dict", &ptr));
  EXPECT_EQ(original_child, ptr);

  std::unique_ptr<DictionaryValue> merged(new DictionaryValue);
  merged->MergeDictionary(base.get());
  EXPECT_EQ(1U, merged->size());
  EXPECT_TRUE(merged->GetDictionary("dict", &ptr));
  EXPECT_NE(original_child, ptr);
  EXPECT_TRUE(ptr->GetString("test", &value));
  EXPECT_EQ("value", value);

  original_child->SetString("test", "overwrite");
  base.reset();
  EXPECT_TRUE(ptr->GetString("test", &value));
  EXPECT_EQ("value", value);
}

TEST(ValuesTest, DictionaryIterator) {
  DictionaryValue dict;
  for (DictionaryValue::Iterator it(dict); !it.IsAtEnd(); it.Advance()) {
    ADD_FAILURE();
  }

  Value value1("value1");
  dict.Set("key1", MakeUnique<Value>(value1));
  bool seen1 = false;
  for (DictionaryValue::Iterator it(dict); !it.IsAtEnd(); it.Advance()) {
    EXPECT_FALSE(seen1);
    EXPECT_EQ("key1", it.key());
    EXPECT_EQ(value1, it.value());
    seen1 = true;
  }
  EXPECT_TRUE(seen1);

  Value value2("value2");
  dict.Set("key2", MakeUnique<Value>(value2));
  bool seen2 = seen1 = false;
  for (DictionaryValue::Iterator it(dict); !it.IsAtEnd(); it.Advance()) {
    if (it.key() == "key1") {
      EXPECT_FALSE(seen1);
      EXPECT_EQ(value1, it.value());
      seen1 = true;
    } else if (it.key() == "key2") {
      EXPECT_FALSE(seen2);
      EXPECT_EQ(value2, it.value());
      seen2 = true;
    } else {
      ADD_FAILURE();
    }
  }
  EXPECT_TRUE(seen1);
  EXPECT_TRUE(seen2);
}

TEST(ValuesTest, StdDictionaryIterator) {
  DictionaryValue dict;
  for (auto it = dict.begin(); it != dict.end(); ++it) {
    ADD_FAILURE();
  }

  Value value1("value1");
  dict.Set("key1", MakeUnique<Value>(value1));
  bool seen1 = false;
  for (const auto& it : dict) {
    EXPECT_FALSE(seen1);
    EXPECT_EQ("key1", it.first);
    EXPECT_EQ(value1, *it.second);
    seen1 = true;
  }
  EXPECT_TRUE(seen1);

  Value value2("value2");
  dict.Set("key2", MakeUnique<Value>(value2));
  bool seen2 = seen1 = false;
  for (const auto& it : dict) {
    if (it.first == "key1") {
      EXPECT_FALSE(seen1);
      EXPECT_EQ(value1, *it.second);
      seen1 = true;
    } else if (it.first == "key2") {
      EXPECT_FALSE(seen2);
      EXPECT_EQ(value2, *it.second);
      seen2 = true;
    } else {
      ADD_FAILURE();
    }
  }
  EXPECT_TRUE(seen1);
  EXPECT_TRUE(seen2);
}

// DictionaryValue/ListValue's Get*() methods should accept NULL as an out-value
// and still return true/false based on success.
TEST(ValuesTest, GetWithNullOutValue) {
  DictionaryValue main_dict;
  ListValue main_list;

  Value bool_value(false);
  Value int_value(1234);
  Value double_value(12.34567);
  Value string_value("foo");
  Value binary_value(Value::Type::BINARY);
  DictionaryValue dict_value;
  ListValue list_value;

  main_dict.Set("bool", MakeUnique<Value>(bool_value));
  main_dict.Set("int", MakeUnique<Value>(int_value));
  main_dict.Set("double", MakeUnique<Value>(double_value));
  main_dict.Set("string", MakeUnique<Value>(string_value));
  main_dict.Set("binary", MakeUnique<Value>(binary_value));
  main_dict.Set("dict", MakeUnique<Value>(dict_value));
  main_dict.Set("list", MakeUnique<Value>(list_value));

  main_list.Append(MakeUnique<Value>(bool_value));
  main_list.Append(MakeUnique<Value>(int_value));
  main_list.Append(MakeUnique<Value>(double_value));
  main_list.Append(MakeUnique<Value>(string_value));
  main_list.Append(MakeUnique<Value>(binary_value));
  main_list.Append(MakeUnique<Value>(dict_value));
  main_list.Append(MakeUnique<Value>(list_value));

  EXPECT_TRUE(main_dict.Get("bool", NULL));
  EXPECT_TRUE(main_dict.Get("int", NULL));
  EXPECT_TRUE(main_dict.Get("double", NULL));
  EXPECT_TRUE(main_dict.Get("string", NULL));
  EXPECT_TRUE(main_dict.Get("binary", NULL));
  EXPECT_TRUE(main_dict.Get("dict", NULL));
  EXPECT_TRUE(main_dict.Get("list", NULL));
  EXPECT_FALSE(main_dict.Get("DNE", NULL));

  EXPECT_TRUE(main_dict.GetBoolean("bool", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("int", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("double", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("string", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("binary", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("dict", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("list", NULL));
  EXPECT_FALSE(main_dict.GetBoolean("DNE", NULL));

  EXPECT_FALSE(main_dict.GetInteger("bool", NULL));
  EXPECT_TRUE(main_dict.GetInteger("int", NULL));
  EXPECT_FALSE(main_dict.GetInteger("double", NULL));
  EXPECT_FALSE(main_dict.GetInteger("string", NULL));
  EXPECT_FALSE(main_dict.GetInteger("binary", NULL));
  EXPECT_FALSE(main_dict.GetInteger("dict", NULL));
  EXPECT_FALSE(main_dict.GetInteger("list", NULL));
  EXPECT_FALSE(main_dict.GetInteger("DNE", NULL));

  // Both int and double values can be obtained from GetDouble.
  EXPECT_FALSE(main_dict.GetDouble("bool", NULL));
  EXPECT_TRUE(main_dict.GetDouble("int", NULL));
  EXPECT_TRUE(main_dict.GetDouble("double", NULL));
  EXPECT_FALSE(main_dict.GetDouble("string", NULL));
  EXPECT_FALSE(main_dict.GetDouble("binary", NULL));
  EXPECT_FALSE(main_dict.GetDouble("dict", NULL));
  EXPECT_FALSE(main_dict.GetDouble("list", NULL));
  EXPECT_FALSE(main_dict.GetDouble("DNE", NULL));

  EXPECT_FALSE(main_dict.GetString("bool", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("int", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("double", static_cast<std::string*>(NULL)));
  EXPECT_TRUE(main_dict.GetString("string", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("binary", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("dict", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("list", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("DNE", static_cast<std::string*>(NULL)));

  EXPECT_FALSE(main_dict.GetString("bool", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("int", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("double", static_cast<string16*>(NULL)));
  EXPECT_TRUE(main_dict.GetString("string", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("binary", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("dict", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("list", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetString("DNE", static_cast<string16*>(NULL)));

  EXPECT_FALSE(main_dict.GetBinary("bool", NULL));
  EXPECT_FALSE(main_dict.GetBinary("int", NULL));
  EXPECT_FALSE(main_dict.GetBinary("double", NULL));
  EXPECT_FALSE(main_dict.GetBinary("string", NULL));
  EXPECT_TRUE(main_dict.GetBinary("binary", NULL));
  EXPECT_FALSE(main_dict.GetBinary("dict", NULL));
  EXPECT_FALSE(main_dict.GetBinary("list", NULL));
  EXPECT_FALSE(main_dict.GetBinary("DNE", NULL));

  EXPECT_FALSE(main_dict.GetDictionary("bool", NULL));
  EXPECT_FALSE(main_dict.GetDictionary("int", NULL));
  EXPECT_FALSE(main_dict.GetDictionary("double", NULL));
  EXPECT_FALSE(main_dict.GetDictionary("string", NULL));
  EXPECT_FALSE(main_dict.GetDictionary("binary", NULL));
  EXPECT_TRUE(main_dict.GetDictionary("dict", NULL));
  EXPECT_FALSE(main_dict.GetDictionary("list", NULL));
  EXPECT_FALSE(main_dict.GetDictionary("DNE", NULL));

  EXPECT_FALSE(main_dict.GetList("bool", NULL));
  EXPECT_FALSE(main_dict.GetList("int", NULL));
  EXPECT_FALSE(main_dict.GetList("double", NULL));
  EXPECT_FALSE(main_dict.GetList("string", NULL));
  EXPECT_FALSE(main_dict.GetList("binary", NULL));
  EXPECT_FALSE(main_dict.GetList("dict", NULL));
  EXPECT_TRUE(main_dict.GetList("list", NULL));
  EXPECT_FALSE(main_dict.GetList("DNE", NULL));

  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("bool", NULL));
  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("int", NULL));
  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("double", NULL));
  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("string", NULL));
  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("binary", NULL));
  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("dict", NULL));
  EXPECT_TRUE(main_dict.GetWithoutPathExpansion("list", NULL));
  EXPECT_FALSE(main_dict.GetWithoutPathExpansion("DNE", NULL));

  EXPECT_TRUE(main_dict.GetBooleanWithoutPathExpansion("bool", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("int", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("double", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("string", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("binary", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("dict", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("list", NULL));
  EXPECT_FALSE(main_dict.GetBooleanWithoutPathExpansion("DNE", NULL));

  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("bool", NULL));
  EXPECT_TRUE(main_dict.GetIntegerWithoutPathExpansion("int", NULL));
  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("double", NULL));
  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("string", NULL));
  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("binary", NULL));
  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("dict", NULL));
  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("list", NULL));
  EXPECT_FALSE(main_dict.GetIntegerWithoutPathExpansion("DNE", NULL));

  EXPECT_FALSE(main_dict.GetDoubleWithoutPathExpansion("bool", NULL));
  EXPECT_TRUE(main_dict.GetDoubleWithoutPathExpansion("int", NULL));
  EXPECT_TRUE(main_dict.GetDoubleWithoutPathExpansion("double", NULL));
  EXPECT_FALSE(main_dict.GetDoubleWithoutPathExpansion("string", NULL));
  EXPECT_FALSE(main_dict.GetDoubleWithoutPathExpansion("binary", NULL));
  EXPECT_FALSE(main_dict.GetDoubleWithoutPathExpansion("dict", NULL));
  EXPECT_FALSE(main_dict.GetDoubleWithoutPathExpansion("list", NULL));
  EXPECT_FALSE(main_dict.GetDoubleWithoutPathExpansion("DNE", NULL));

  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "bool", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "int", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "double", static_cast<std::string*>(NULL)));
  EXPECT_TRUE(main_dict.GetStringWithoutPathExpansion(
      "string", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "binary", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "dict", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "list", static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "DNE", static_cast<std::string*>(NULL)));

  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "bool", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "int", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "double", static_cast<string16*>(NULL)));
  EXPECT_TRUE(main_dict.GetStringWithoutPathExpansion(
      "string", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "binary", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "dict", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "list", static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_dict.GetStringWithoutPathExpansion(
      "DNE", static_cast<string16*>(NULL)));

  // There is no GetBinaryWithoutPathExpansion for some reason, but if there
  // were it should be tested here...

  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("bool", NULL));
  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("int", NULL));
  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("double", NULL));
  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("string", NULL));
  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("binary", NULL));
  EXPECT_TRUE(main_dict.GetDictionaryWithoutPathExpansion("dict", NULL));
  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("list", NULL));
  EXPECT_FALSE(main_dict.GetDictionaryWithoutPathExpansion("DNE", NULL));

  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("bool", NULL));
  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("int", NULL));
  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("double", NULL));
  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("string", NULL));
  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("binary", NULL));
  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("dict", NULL));
  EXPECT_TRUE(main_dict.GetListWithoutPathExpansion("list", NULL));
  EXPECT_FALSE(main_dict.GetListWithoutPathExpansion("DNE", NULL));

  EXPECT_TRUE(main_list.Get(0, NULL));
  EXPECT_TRUE(main_list.Get(1, NULL));
  EXPECT_TRUE(main_list.Get(2, NULL));
  EXPECT_TRUE(main_list.Get(3, NULL));
  EXPECT_TRUE(main_list.Get(4, NULL));
  EXPECT_TRUE(main_list.Get(5, NULL));
  EXPECT_TRUE(main_list.Get(6, NULL));
  EXPECT_FALSE(main_list.Get(7, NULL));

  EXPECT_TRUE(main_list.GetBoolean(0, NULL));
  EXPECT_FALSE(main_list.GetBoolean(1, NULL));
  EXPECT_FALSE(main_list.GetBoolean(2, NULL));
  EXPECT_FALSE(main_list.GetBoolean(3, NULL));
  EXPECT_FALSE(main_list.GetBoolean(4, NULL));
  EXPECT_FALSE(main_list.GetBoolean(5, NULL));
  EXPECT_FALSE(main_list.GetBoolean(6, NULL));
  EXPECT_FALSE(main_list.GetBoolean(7, NULL));

  EXPECT_FALSE(main_list.GetInteger(0, NULL));
  EXPECT_TRUE(main_list.GetInteger(1, NULL));
  EXPECT_FALSE(main_list.GetInteger(2, NULL));
  EXPECT_FALSE(main_list.GetInteger(3, NULL));
  EXPECT_FALSE(main_list.GetInteger(4, NULL));
  EXPECT_FALSE(main_list.GetInteger(5, NULL));
  EXPECT_FALSE(main_list.GetInteger(6, NULL));
  EXPECT_FALSE(main_list.GetInteger(7, NULL));

  EXPECT_FALSE(main_list.GetDouble(0, NULL));
  EXPECT_TRUE(main_list.GetDouble(1, NULL));
  EXPECT_TRUE(main_list.GetDouble(2, NULL));
  EXPECT_FALSE(main_list.GetDouble(3, NULL));
  EXPECT_FALSE(main_list.GetDouble(4, NULL));
  EXPECT_FALSE(main_list.GetDouble(5, NULL));
  EXPECT_FALSE(main_list.GetDouble(6, NULL));
  EXPECT_FALSE(main_list.GetDouble(7, NULL));

  EXPECT_FALSE(main_list.GetString(0, static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_list.GetString(1, static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_list.GetString(2, static_cast<std::string*>(NULL)));
  EXPECT_TRUE(main_list.GetString(3, static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_list.GetString(4, static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_list.GetString(5, static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_list.GetString(6, static_cast<std::string*>(NULL)));
  EXPECT_FALSE(main_list.GetString(7, static_cast<std::string*>(NULL)));

  EXPECT_FALSE(main_list.GetString(0, static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_list.GetString(1, static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_list.GetString(2, static_cast<string16*>(NULL)));
  EXPECT_TRUE(main_list.GetString(3, static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_list.GetString(4, static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_list.GetString(5, static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_list.GetString(6, static_cast<string16*>(NULL)));
  EXPECT_FALSE(main_list.GetString(7, static_cast<string16*>(NULL)));

  EXPECT_FALSE(main_list.GetBinary(0, NULL));
  EXPECT_FALSE(main_list.GetBinary(1, NULL));
  EXPECT_FALSE(main_list.GetBinary(2, NULL));
  EXPECT_FALSE(main_list.GetBinary(3, NULL));
  EXPECT_TRUE(main_list.GetBinary(4, NULL));
  EXPECT_FALSE(main_list.GetBinary(5, NULL));
  EXPECT_FALSE(main_list.GetBinary(6, NULL));
  EXPECT_FALSE(main_list.GetBinary(7, NULL));

  EXPECT_FALSE(main_list.GetDictionary(0, NULL));
  EXPECT_FALSE(main_list.GetDictionary(1, NULL));
  EXPECT_FALSE(main_list.GetDictionary(2, NULL));
  EXPECT_FALSE(main_list.GetDictionary(3, NULL));
  EXPECT_FALSE(main_list.GetDictionary(4, NULL));
  EXPECT_TRUE(main_list.GetDictionary(5, NULL));
  EXPECT_FALSE(main_list.GetDictionary(6, NULL));
  EXPECT_FALSE(main_list.GetDictionary(7, NULL));

  EXPECT_FALSE(main_list.GetList(0, NULL));
  EXPECT_FALSE(main_list.GetList(1, NULL));
  EXPECT_FALSE(main_list.GetList(2, NULL));
  EXPECT_FALSE(main_list.GetList(3, NULL));
  EXPECT_FALSE(main_list.GetList(4, NULL));
  EXPECT_FALSE(main_list.GetList(5, NULL));
  EXPECT_TRUE(main_list.GetList(6, NULL));
  EXPECT_FALSE(main_list.GetList(7, NULL));
}

TEST(ValuesTest, SelfSwap) {
  base::Value test(1);
  std::swap(test, test);
  EXPECT_TRUE(test.GetInt() == 1);
}

}  // namespace base
