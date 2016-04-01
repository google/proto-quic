// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/json/json_reader.h"
#include "base/memory/scoped_ptr.h"
#include "base/trace_event/heap_profiler_type_name_deduplicator.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

// Define all strings once, because the deduplicator requires pointer equality,
// and string interning is unreliable.
const char kInt[] = "int";
const char kBool[] = "bool";
const char kString[] = "string";
const char kNeedsEscape[] = "\"quotes\"";

scoped_ptr<Value> DumpAndReadBack(const TypeNameDeduplicator& deduplicator) {
  std::string json;
  deduplicator.AppendAsTraceFormat(&json);
  return JSONReader::Read(json);
}

TEST(TypeNameDeduplicatorTest, Deduplication) {
  // The type IDs should be like this:
  // 0: [unknown]
  // 1: int
  // 2: bool
  // 3: string

  scoped_ptr<TypeNameDeduplicator> dedup(new TypeNameDeduplicator);
  ASSERT_EQ(1, dedup->Insert(kInt));
  ASSERT_EQ(2, dedup->Insert(kBool));
  ASSERT_EQ(3, dedup->Insert(kString));

  // Inserting again should return the same IDs.
  ASSERT_EQ(2, dedup->Insert(kBool));
  ASSERT_EQ(1, dedup->Insert(kInt));
  ASSERT_EQ(3, dedup->Insert(kString));

  // A null pointer should yield type ID 0.
  ASSERT_EQ(0, dedup->Insert(nullptr));
}

TEST(TypeNameDeduplicatorTest, EscapeTypeName) {
  scoped_ptr<TypeNameDeduplicator> dedup(new TypeNameDeduplicator);
  ASSERT_EQ(1, dedup->Insert(kNeedsEscape));

  // Reading json should not fail, because the type name should have been
  // escaped properly.
  scoped_ptr<Value> type_names = DumpAndReadBack(*dedup);
  ASSERT_NE(nullptr, type_names);

  const DictionaryValue* dictionary;
  ASSERT_TRUE(type_names->GetAsDictionary(&dictionary));

  // When the type name was inserted, it got ID 1. The exported key "1"
  // should contain the name, with quotes.
  std::string type_name;
  ASSERT_TRUE(dictionary->GetString("1", &type_name));
  ASSERT_EQ("\"quotes\"", type_name);
}

}  // namespace trace_event
}  // namespace base
