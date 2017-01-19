// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_decoder_tables.h"

#include "base/logging.h"

namespace net {
namespace {

std::vector<HpackStringPair>* MakeStaticTable() {
  auto ptr = new std::vector<HpackStringPair>();
  ptr->reserve(kFirstDynamicTableIndex);
  ptr->emplace_back("", "");

#define STATIC_TABLE_ENTRY(name, value, index) \
  DCHECK_EQ(ptr->size(), index);               \
  ptr->emplace_back(name, value)

#include "net/http2/hpack/hpack_static_table_entries.inc"

#undef STATIC_TABLE_ENTRY

  return ptr;
}

const std::vector<HpackStringPair>* GetStaticTable() {
  static const std::vector<HpackStringPair>* const g_static_table =
      MakeStaticTable();
  return g_static_table;
}

}  // namespace

HpackDecoderStaticTable::HpackDecoderStaticTable(
    const std::vector<HpackStringPair>* table)
    : table_(table) {}

HpackDecoderStaticTable::HpackDecoderStaticTable() : table_(GetStaticTable()) {}

const HpackStringPair* HpackDecoderStaticTable::Lookup(size_t index) const {
  if (0 < index && index < kFirstDynamicTableIndex) {
    return &((*table_)[index]);
  }
  return nullptr;
}

HpackDecoderDynamicTable::HpackDecoderDynamicTable() {}
HpackDecoderDynamicTable::~HpackDecoderDynamicTable() {}

void HpackDecoderDynamicTable::DynamicTableSizeUpdate(size_t size_limit) {
  DVLOG(3) << "HpackDecoderDynamicTable::DynamicTableSizeUpdate " << size_limit;
  EnsureSizeNoMoreThan(size_limit);
  DCHECK_LE(current_size_, size_limit);
  size_limit_ = size_limit;
}

// TODO(jamessynge): Check somewhere before here that names received from the
// peer are valid (e.g. are lower-case, no whitespace, etc.).
bool HpackDecoderDynamicTable::Insert(const HpackString& name,
                                      const HpackString& value) {
  HpackStringPair p(name, value);
  size_t entry_size = p.size();
  DVLOG(2) << "InsertEntry of size=" << entry_size << "\n     name: " << name
           << "\n    value: " << value;
  if (entry_size > size_limit_) {
    DVLOG(2) << "InsertEntry: entry larger than table, removing "
             << table_.size() << " entries, of total size " << current_size_
             << " bytes.";
    table_.clear();
    current_size_ = 0;
    return false;  // Not inserted because too large.
  }
  size_t insert_limit = size_limit_ - entry_size;
  EnsureSizeNoMoreThan(insert_limit);
  table_.push_front(p);
  current_size_ += entry_size;
  DVLOG(2) << "InsertEntry: current_size_=" << current_size_;
  DCHECK_GE(current_size_, entry_size);
  DCHECK_LE(current_size_, size_limit_);
  return true;
}

const HpackStringPair* HpackDecoderDynamicTable::Lookup(size_t index) const {
  if (index < table_.size()) {
    return &(table_[index]);
  }
  return nullptr;
}

void HpackDecoderDynamicTable::EnsureSizeNoMoreThan(size_t limit) {
  DVLOG(2) << "EnsureSizeNoMoreThan limit=" << limit
           << ", current_size_=" << current_size_;
  // Not the most efficient choice, but any easy way to start.
  while (current_size_ > limit) {
    RemoveLastEntry();
  }
  DCHECK_LE(current_size_, limit);
}

void HpackDecoderDynamicTable::RemoveLastEntry() {
  DCHECK(!table_.empty());
  if (!table_.empty()) {
    DVLOG(2) << "RemoveLastEntry current_size_=" << current_size_
             << ", last entry size=" << table_.back().size();
    DCHECK_GE(current_size_, table_.back().size());
    current_size_ -= table_.back().size();
    table_.pop_back();
    // Empty IFF current_size_ == 0.
    DCHECK_EQ(table_.empty(), current_size_ == 0);
  }
}

HpackDecoderTables::HpackDecoderTables() {}
HpackDecoderTables::~HpackDecoderTables() {}

}  // namespace net
