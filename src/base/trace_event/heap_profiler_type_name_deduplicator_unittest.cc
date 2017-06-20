// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_type_name_deduplicator.h"

#include <memory>
#include <string>

#include "base/memory/ptr_util.h"
#include "base/trace_event/heap_profiler_string_deduplicator.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

namespace {

#if defined(OS_POSIX)
const char kTaskFileName[] = "../../base/trace_event/trace_log.cc";
const char kTaskPath[] = "base/trace_event";
#else
const char kTaskFileName[] = "..\\..\\base\\memory\\memory_win.cc";
const char kTaskPath[] = "base\\memory";
#endif

// Calls TypeNameDeduplicator::SerializeIncrementally() and returns ListValue
// with serialized entries.
std::unique_ptr<ListValue> SerializeEntriesIncrementally(
    TypeNameDeduplicator* dedup) {
  TracedValue traced_value;
  traced_value.BeginArray("");
  dedup->SerializeIncrementally(&traced_value);
  traced_value.EndArray();

  auto base_value = traced_value.ToBaseValue();
  DictionaryValue* dictionary;
  std::unique_ptr<Value> entries;
  if (!base_value->GetAsDictionary(&dictionary) ||
      !dictionary->Remove("", &entries)) {
    return nullptr;
  }
  return ListValue::From(std::move(entries));
}

struct TypeNameMapping {
  const int id;
  const char* const name;
};

std::unique_ptr<ListValue> SerializeMappingsAsEntries(
    StringDeduplicator* string_dedup,
    std::initializer_list<TypeNameMapping> mappings) {
  auto entries = MakeUnique<ListValue>();
  for (const auto& mapping : mappings) {
    auto entry = MakeUnique<DictionaryValue>();
    entry->SetInteger("id", mapping.id);
    entry->SetInteger("name_sid", string_dedup->Insert(mapping.name));
    entries->Append(std::move(entry));
  }
  return entries;
}

void ExpectIncrementalEntries(TypeNameDeduplicator* dedup,
                              StringDeduplicator* string_dedup,
                              std::initializer_list<TypeNameMapping> mappings) {
  auto entries = SerializeEntriesIncrementally(dedup);
  ASSERT_TRUE(entries);

  auto expected_entries = SerializeMappingsAsEntries(string_dedup, mappings);
  ASSERT_TRUE(expected_entries->Equals(entries.get()))
      << "expected_entries = " << *expected_entries << "entries = " << *entries;
}

}  // namespace

TEST(TypeNameDeduplicatorTest, ImplicitId0) {
  StringDeduplicator string_dedup;
  TypeNameDeduplicator dedup(&string_dedup);

  // NULL type name is mapped to an implicitly added ID #0.
  ExpectIncrementalEntries(&dedup, &string_dedup, {{0, "[unknown]"}});
  ASSERT_EQ(0, dedup.Insert(nullptr));

  // Even though ID #0 is serialized as "[unknown]" string, it's distinct
  // from "[unknown]" type name.
  ASSERT_EQ(1, dedup.Insert("[unknown]"));
  ExpectIncrementalEntries(&dedup, &string_dedup, {{1, "[unknown]"}});
}

TEST(TypeNameDeduplicatorTest, Deduplicate) {
  // The type IDs should be like this:
  // 0: [unknown]
  // 1: int
  // 2: bool
  // 3: string

  StringDeduplicator string_dedup;
  TypeNameDeduplicator dedup(&string_dedup);
  ASSERT_EQ(1, dedup.Insert("int"));
  ASSERT_EQ(2, dedup.Insert("bool"));
  ASSERT_EQ(3, dedup.Insert("string"));

  // Inserting again should return the same IDs.
  ASSERT_EQ(2, dedup.Insert("bool"));
  ASSERT_EQ(1, dedup.Insert("int"));
  ASSERT_EQ(3, dedup.Insert("string"));
}

TEST(TypeNameDeduplicatorTest, TestExtractFileName) {
  StringDeduplicator string_dedup;
  TypeNameDeduplicator dedup(&string_dedup);

  ASSERT_EQ(1, dedup.Insert(kTaskFileName));

  ExpectIncrementalEntries(&dedup, &string_dedup,
                           {{0, "[unknown]"}, {1, kTaskPath}});
}

TEST(TypeNameDeduplicatorTest, SerializeIncrementally) {
  StringDeduplicator string_dedup;
  TypeNameDeduplicator dedup(&string_dedup);

  ASSERT_EQ(1, dedup.Insert("int"));
  ASSERT_EQ(2, dedup.Insert("bool"));

  ExpectIncrementalEntries(&dedup, &string_dedup,
                           {{0, "[unknown]"}, {1, "int"}, {2, "bool"}});

  ASSERT_EQ(2, dedup.Insert("bool"));
  ASSERT_EQ(3, dedup.Insert("string"));

  ExpectIncrementalEntries(&dedup, &string_dedup, {{3, "string"}});

  ExpectIncrementalEntries(&dedup, &string_dedup, {});
}

}  // namespace trace_event
}  // namespace base
