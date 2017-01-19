// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_HPACK_DECODER_HPACK_DECODER_TABLES_H_
#define NET_HTTP2_HPACK_DECODER_HPACK_DECODER_TABLES_H_

// Static and dynamic tables for the HPACK decoder. See:
// http://httpwg.org/specs/rfc7541.html#indexing.tables

// Note that the Lookup methods return nullptr if the requested index was not
// found. This should be treated as a COMPRESSION error according to the HTTP/2
// spec, which is a connection level protocol error (i.e. the connection must
// be terminated). See these sections in the two RFCs:
// http://httpwg.org/specs/rfc7541.html#indexed.header.representation
// http://httpwg.org/specs/rfc7541.html#index.address.space
// http://httpwg.org/specs/rfc7540.html#HeaderBlock

#include <stddef.h>

#include <deque>
#include <vector>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/http2/hpack/hpack_string.h"
#include "net/http2/http2_constants.h"

namespace net {
namespace test {
class HpackDecoderTablesPeer;
}  // namespace test

const size_t kFirstDynamicTableIndex = 62;

// See http://httpwg.org/specs/rfc7541.html#static.table.definition for the
// contents, and http://httpwg.org/specs/rfc7541.html#index.address.space for
// info about accessing the static table.
class NET_EXPORT_PRIVATE HpackDecoderStaticTable {
 public:
  explicit HpackDecoderStaticTable(const std::vector<HpackStringPair>* table);
  // Uses a global table shared by all threads.
  HpackDecoderStaticTable();

  // If index is valid, returns a pointer to the entry, otherwise returns
  // nullptr.
  const HpackStringPair* Lookup(size_t index) const;

 private:
  friend class test::HpackDecoderTablesPeer;
  const std::vector<HpackStringPair>* const table_;
};

// HpackDecoderDynamicTable implements HPACK compression feature "indexed
// headers"; previously sent headers may be referenced later by their index
// in the dynamic table. See these sections of the RFC:
//   http://httpwg.org/specs/rfc7541.html#dynamic.table
//   http://httpwg.org/specs/rfc7541.html#dynamic.table.management
class NET_EXPORT_PRIVATE HpackDecoderDynamicTable {
 public:
  HpackDecoderDynamicTable();
  ~HpackDecoderDynamicTable();

  // Sets a new size limit, received from the peer; performs evictions if
  // necessary to ensure that the current size does not exceed the new limit.
  // The caller needs to have validated that size_limit does not
  // exceed the acknowledged value of SETTINGS_HEADER_TABLE_SIZE.
  void DynamicTableSizeUpdate(size_t size_limit);

  // Returns true if inserted, false if too large (at which point the
  // dynamic table will be empty.)
  bool Insert(const HpackString& name, const HpackString& value);

  // If index is valid, returns a pointer to the entry, otherwise returns
  // nullptr.
  const HpackStringPair* Lookup(size_t index) const;

  size_t size_limit() const { return size_limit_; }
  size_t current_size() const { return current_size_; }

 private:
  friend class test::HpackDecoderTablesPeer;

  // Drop older entries to ensure the size is not greater than limit.
  void EnsureSizeNoMoreThan(size_t limit);

  // Removes the oldest dynamic table entry.
  void RemoveLastEntry();

  // The last received DynamicTableSizeUpdate value, initialized to
  // SETTINGS_HEADER_TABLE_SIZE.
  size_t size_limit_ = Http2SettingsInfo::DefaultHeaderTableSize();

  size_t current_size_ = 0;

  std::deque<HpackStringPair> table_;

  DISALLOW_COPY_AND_ASSIGN(HpackDecoderDynamicTable);
};

class NET_EXPORT_PRIVATE HpackDecoderTables {
 public:
  HpackDecoderTables();
  ~HpackDecoderTables();

  // Sets a new size limit, received from the peer; performs evictions if
  // necessary to ensure that the current size does not exceed the new limit.
  // The caller needs to have validated that size_limit does not
  // exceed the acknowledged value of SETTINGS_HEADER_TABLE_SIZE.
  void DynamicTableSizeUpdate(size_t size_limit) {
    dynamic_table_.DynamicTableSizeUpdate(size_limit);
  }

  // Returns true if inserted, false if too large (at which point the
  // dynamic table will be empty.)
  // TODO(jamessynge): Add methods for moving the string(s) into the table,
  // or for otherwise avoiding unnecessary copies.
  bool Insert(const HpackString& name, const HpackString& value) {
    return dynamic_table_.Insert(name, value);
  }

  // If index is valid, returns a pointer to the entry, otherwise returns
  // nullptr.
  const HpackStringPair* Lookup(size_t index) const {
    if (index < kFirstDynamicTableIndex) {
      return static_table_.Lookup(index);
    } else {
      return dynamic_table_.Lookup(index - kFirstDynamicTableIndex);
    }
  }

  // The size limit that the peer (the HPACK encoder) has told the decoder it is
  // currently operating with. Defaults to SETTINGS_HEADER_TABLE_SIZE, 4096.
  size_t header_table_size_limit() const { return dynamic_table_.size_limit(); }

  // Sum of the sizes of the dynamic table entries.
  size_t current_header_table_size() const {
    return dynamic_table_.current_size();
  }

 private:
  friend class test::HpackDecoderTablesPeer;
  HpackDecoderStaticTable static_table_;
  HpackDecoderDynamicTable dynamic_table_;

  DISALLOW_COPY_AND_ASSIGN(HpackDecoderTables);
};

}  // namespace net

#endif  // NET_HTTP2_HPACK_DECODER_HPACK_DECODER_TABLES_H_
