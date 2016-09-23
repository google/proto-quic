// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_JSON_SCHEMA_COMPILER_TEST_TEST_UTIL_H_
#define TOOLS_JSON_SCHEMA_COMPILER_TEST_TEST_UTIL_H_

#include <memory>

#include "base/strings/string_piece.h"
#include "base/values.h"

namespace json_schema_compiler {
namespace test_util {

std::unique_ptr<base::Value> ReadJson(const base::StringPiece& json);

template <typename T>
std::vector<T> Vector(const T& a) {
  std::vector<T> arr;
  arr.push_back(a);
  return arr;
}
template <typename T>
std::vector<T> Vector(const T& a, const T& b) {
  std::vector<T> arr = Vector(a);
  arr.push_back(b);
  return arr;
}
template <typename T>
std::vector<T> Vector(const T& a, const T& b, const T& c) {
  std::vector<T> arr = Vector(a, b);
  arr.push_back(c);
  return arr;
}

// TODO(dcheng): These various helpers should all take std::unique_ptr
// arguments. See https://crbug.com/581865.
std::unique_ptr<base::ListValue> List(base::Value* a);
std::unique_ptr<base::ListValue> List(base::Value* a, base::Value* b);
std::unique_ptr<base::ListValue> List(base::Value* a,
                                      base::Value* b,
                                      base::Value* c);

std::unique_ptr<base::DictionaryValue> Dictionary(const std::string& ak,
                                                  base::Value* av);
std::unique_ptr<base::DictionaryValue> Dictionary(const std::string& ak,
                                                  base::Value* av,
                                                  const std::string& bk,
                                                  base::Value* bv);
std::unique_ptr<base::DictionaryValue> Dictionary(const std::string& ak,
                                                  base::Value* av,
                                                  const std::string& bk,
                                                  base::Value* bv,
                                                  const std::string& ck,
                                                  base::Value* cv);

}  // namespace test_util
}  // namespace json_schema_compiler

#endif  // TOOLS_JSON_SCHEMA_COMPILER_TEST_TEST_UTIL_H_
