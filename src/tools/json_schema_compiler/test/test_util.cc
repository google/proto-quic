// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/test_util.h"

#include <string>

#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"

namespace json_schema_compiler {
namespace test_util {

std::unique_ptr<base::Value> ReadJson(const base::StringPiece& json) {
  int error_code;
  std::string error_msg;
  std::unique_ptr<base::Value> result(base::JSONReader::ReadAndReturnError(
      json, base::JSON_ALLOW_TRAILING_COMMAS, &error_code, &error_msg));
  // CHECK not ASSERT since passing invalid |json| is a test error.
  CHECK(result) << error_msg;
  return result;
}

std::unique_ptr<base::ListValue> List(base::Value* a) {
  std::unique_ptr<base::ListValue> list(new base::ListValue());
  list->Append(base::WrapUnique(a));
  return list;
}
std::unique_ptr<base::ListValue> List(base::Value* a, base::Value* b) {
  std::unique_ptr<base::ListValue> list = List(a);
  list->Append(base::WrapUnique(b));
  return list;
}
std::unique_ptr<base::ListValue> List(base::Value* a,
                                      base::Value* b,
                                      base::Value* c) {
  std::unique_ptr<base::ListValue> list = List(a, b);
  list->Append(base::WrapUnique(c));
  return list;
}

std::unique_ptr<base::DictionaryValue> Dictionary(const std::string& ak,
                                                  base::Value* av) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetWithoutPathExpansion(ak, av);
  return dict;
}
std::unique_ptr<base::DictionaryValue> Dictionary(const std::string& ak,
                                                  base::Value* av,
                                                  const std::string& bk,
                                                  base::Value* bv) {
  std::unique_ptr<base::DictionaryValue> dict = Dictionary(ak, av);
  dict->SetWithoutPathExpansion(bk, bv);
  return dict;
}
std::unique_ptr<base::DictionaryValue> Dictionary(const std::string& ak,
                                                  base::Value* av,
                                                  const std::string& bk,
                                                  base::Value* bv,
                                                  const std::string& ck,
                                                  base::Value* cv) {
  std::unique_ptr<base::DictionaryValue> dict = Dictionary(ak, av, bk, bv);
  dict->SetWithoutPathExpansion(ck, cv);
  return dict;
}

}  // namespace test_util
}  // namespace json_schema_compiler
