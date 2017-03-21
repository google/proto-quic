// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_static_table.h"

#include <set>
#include <vector>

#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/platform/api/spdy_string_piece.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace test {

namespace {

class HpackStaticTableTest : public ::testing::Test {
 protected:
  HpackStaticTableTest() : table_() {}

  HpackStaticTable table_;
};

// Check that an initialized instance has the right number of entries.
TEST_F(HpackStaticTableTest, Initialize) {
  EXPECT_FALSE(table_.IsInitialized());
  std::vector<HpackStaticEntry> static_table = HpackStaticTableVector();
  table_.Initialize(&static_table[0], static_table.size());
  EXPECT_TRUE(table_.IsInitialized());

  HpackHeaderTable::EntryTable static_entries = table_.GetStaticEntries();
  EXPECT_EQ(static_table.size(), static_entries.size());

  HpackHeaderTable::UnorderedEntrySet static_index = table_.GetStaticIndex();
  EXPECT_EQ(static_table.size(), static_index.size());

  HpackHeaderTable::NameToEntryMap static_name_index =
      table_.GetStaticNameIndex();
  std::set<SpdyStringPiece> names;
  for (auto* entry : static_index) {
    names.insert(entry->name());
  }
  EXPECT_EQ(names.size(), static_name_index.size());
}

// Test that ObtainHpackStaticTable returns the same instance every time.
TEST_F(HpackStaticTableTest, IsSingleton) {
  const HpackStaticTable* static_table_one = &ObtainHpackStaticTable();
  const HpackStaticTable* static_table_two = &ObtainHpackStaticTable();
  EXPECT_EQ(static_table_one, static_table_two);
}

}  // namespace

}  // namespace test

}  // namespace net
