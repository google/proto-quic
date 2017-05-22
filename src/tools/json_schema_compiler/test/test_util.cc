// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/json_schema_compiler/test/test_util.h"

#include <string>
#include <utility>

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

std::unique_ptr<base::ListValue> List(std::unique_ptr<base::Value> a) {
  auto list = base::MakeUnique<base::ListValue>();
  list->Append(std::move(a));
  return list;
}
std::unique_ptr<base::ListValue> List(std::unique_ptr<base::Value> a,
                                      std::unique_ptr<base::Value> b) {
  auto list = base::MakeUnique<base::ListValue>();
  list->Append(std::move(a));
  list->Append(std::move(b));
  return list;
}
std::unique_ptr<base::ListValue> List(std::unique_ptr<base::Value> a,
                                      std::unique_ptr<base::Value> b,
                                      std::unique_ptr<base::Value> c) {
  auto list = base::MakeUnique<base::ListValue>();
  list->Append(std::move(a));
  list->Append(std::move(b));
  list->Append(std::move(c));
  return list;
}

std::unique_ptr<base::DictionaryValue> Dictionary(
    const std::string& ak,
    std::unique_ptr<base::Value> av) {
  auto dict = base::MakeUnique<base::DictionaryValue>();
  dict->SetWithoutPathExpansion(ak, std::move(av));
  return dict;
}
std::unique_ptr<base::DictionaryValue> Dictionary(
    const std::string& ak,
    std::unique_ptr<base::Value> av,
    const std::string& bk,
    std::unique_ptr<base::Value> bv) {
  auto dict = base::MakeUnique<base::DictionaryValue>();
  dict->SetWithoutPathExpansion(ak, std::move(av));
  dict->SetWithoutPathExpansion(bk, std::move(bv));
  return dict;
}
std::unique_ptr<base::DictionaryValue> Dictionary(
    const std::string& ak,
    std::unique_ptr<base::Value> av,
    const std::string& bk,
    std::unique_ptr<base::Value> bv,
    const std::string& ck,
    std::unique_ptr<base::Value> cv) {
  auto dict = base::MakeUnique<base::DictionaryValue>();
  dict->SetWithoutPathExpansion(ak, std::move(av));
  dict->SetWithoutPathExpansion(bk, std::move(bv));
  dict->SetWithoutPathExpansion(ck, std::move(cv));
  return dict;
}

}  // namespace test_util
}  // namespace json_schema_compiler
