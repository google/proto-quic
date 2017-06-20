// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_string_deduplicator.h"

#include <memory>
#include <string>

#include "base/memory/ptr_util.h"
#include "base/trace_event/trace_event_argument.h"
#include "base/values.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace base {
namespace trace_event {

namespace {

// Calls StringDeduplicator::SerializeIncrementally() and returns ListValue
// with serialized entries.
std::unique_ptr<ListValue> SerializeEntriesIncrementally(
    StringDeduplicator* dedup) {
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

struct StringMapping {
  const int id;
  const char* const string;
};

std::unique_ptr<ListValue> SerializeMappingsAsEntries(
    std::initializer_list<StringMapping> mappings) {
  auto entries = MakeUnique<ListValue>();
  for (const auto& mapping : mappings) {
    auto entry = MakeUnique<DictionaryValue>();
    entry->SetInteger("id", mapping.id);
    entry->SetString("string", mapping.string);
    entries->Append(std::move(entry));
  }
  return entries;
}

void ExpectIncrementalEntries(StringDeduplicator* dedup,
                              std::initializer_list<StringMapping> mappings) {
  auto entries = SerializeEntriesIncrementally(dedup);
  ASSERT_TRUE(entries);

  auto expected_entries = SerializeMappingsAsEntries(mappings);
  ASSERT_TRUE(expected_entries->Equals(entries.get()))
      << "expected_entries = " << *expected_entries << "entries = " << *entries;
}

}  // namespace

TEST(StringDeduplicatorTest, ImplicitId0) {
  StringDeduplicator dedup;

  // NULL string is mapped to an implicitly added ID #0.
  ExpectIncrementalEntries(&dedup, {{0, "[null]"}});
  ASSERT_EQ(0, dedup.Insert(nullptr));

  // Even though ID #0 is serialized as "[null]", it's distinct from
  // explicitly added "[null]" string.
  ASSERT_EQ(1, dedup.Insert("[null]"));
  ExpectIncrementalEntries(&dedup, {{1, "[null]"}});
}

TEST(StringDeduplicatorTest, Deduplicate) {
  StringDeduplicator dedup;

  ASSERT_EQ(1, dedup.Insert("foo"));
  ASSERT_EQ(2, dedup.Insert("bar"));
  ASSERT_EQ(3, dedup.Insert("baz"));

  // Inserting again should return the same IDs.
  ASSERT_EQ(2, dedup.Insert("bar"));
  ASSERT_EQ(1, dedup.Insert("foo"));
  ASSERT_EQ(3, dedup.Insert("baz"));
}

TEST(StringDeduplicatorTest, InsertCopies) {
  StringDeduplicator dedup;

  std::string string = "foo";
  ASSERT_EQ(1, dedup.Insert(string));

  // StringDeduplicatorTest::Insert() takes StringPiece, which implicitly
  // constructs from both const char* and std::string. Check that Insert()
  // actually copies string data, and doesn't simply copy StringPieces.
  string = "???";
  ASSERT_EQ(1, dedup.Insert("foo"));
}

TEST(StringDeduplicatorTest, SerializeIncrementally) {
  StringDeduplicator dedup;

  ASSERT_EQ(1, dedup.Insert("foo"));
  ASSERT_EQ(2, dedup.Insert("bar"));

  ExpectIncrementalEntries(&dedup, {{0, "[null]"}, {1, "foo"}, {2, "bar"}});

  ASSERT_EQ(2, dedup.Insert("bar"));
  ASSERT_EQ(3, dedup.Insert("baz"));

  ExpectIncrementalEntries(&dedup, {{3, "baz"}});

  ExpectIncrementalEntries(&dedup, {});
}

}  // namespace trace_event
}  // namespace base
