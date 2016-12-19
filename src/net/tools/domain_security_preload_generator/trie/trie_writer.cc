// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/domain_security_preload_generator/trie/trie_writer.h"

#include <algorithm>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "net/tools/domain_security_preload_generator/trie/trie_bit_buffer.h"

namespace net {

namespace transport_security_state {

namespace {

bool CompareReversedEntries(const std::unique_ptr<ReversedEntry>& lhs,
                            const std::unique_ptr<ReversedEntry>& rhs) {
  return lhs->reversed_name < rhs->reversed_name;
}

std::string DomainConstant(base::StringPiece input) {
  std::vector<base::StringPiece> parts = base::SplitStringPiece(
      input, ".", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.empty()) {
    return std::string();
  }

  std::string gtld = parts[parts.size() - 1].as_string();
  if (parts.size() == 1) {
    return base::ToUpperASCII(gtld);
  }

  std::string domain = base::ToUpperASCII(parts[parts.size() - 2].as_string());
  base::ReplaceChars(domain, "-", "_", &domain);

  return base::ToUpperASCII(domain + "_" + gtld);
}

}  // namespace

ReversedEntry::ReversedEntry(std::vector<uint8_t> reversed_name,
                             const DomainSecurityEntry* entry)
    : reversed_name(reversed_name), entry(entry) {}

ReversedEntry::~ReversedEntry() {}

TrieWriter::TrieWriter(const HuffmanRepresentationTable& huffman_table,
                       const NameIDMap& domain_ids_map,
                       const NameIDMap& expect_ct_report_uri_map,
                       const NameIDMap& expect_staple_report_uri_map,
                       const NameIDMap& pinsets_map,
                       HuffmanFrequencyTracker* frequency_tracker)
    : huffman_table_(huffman_table),
      domain_ids_map_(domain_ids_map),
      expect_ct_report_uri_map_(expect_ct_report_uri_map),
      expect_staple_report_uri_map_(expect_staple_report_uri_map),
      pinsets_map_(pinsets_map),
      frequency_tracker_(frequency_tracker) {}

TrieWriter::~TrieWriter() {}

uint32_t TrieWriter::WriteEntries(const DomainSecurityEntries& entries) {
  ReversedEntries reversed_entries;

  for (auto const& entry : entries) {
    std::unique_ptr<ReversedEntry> reversed_entry(
        new ReversedEntry(ReverseName(entry->hostname), entry.get()));
    reversed_entries.push_back(std::move(reversed_entry));
  }

  std::stable_sort(reversed_entries.begin(), reversed_entries.end(),
                   CompareReversedEntries);

  return WriteDispatchTables(reversed_entries.begin(), reversed_entries.end());
}

uint32_t TrieWriter::WriteDispatchTables(ReversedEntries::iterator start,
                                         ReversedEntries::iterator end) {
  DCHECK(start != end) << "No entries passed to WriteDispatchTables";

  TrieBitBuffer writer;

  std::vector<uint8_t> prefix = LongestCommonPrefix(start, end);
  for (size_t i = 0; i < prefix.size(); ++i) {
    writer.WriteBit(1);
  }
  writer.WriteBit(0);

  if (prefix.size()) {
    for (size_t i = 0; i < prefix.size(); ++i) {
      writer.WriteChar(prefix.at(i), huffman_table_, frequency_tracker_);
    }
  }

  RemovePrefix(prefix.size(), start, end);
  int32_t last_position = -1;

  while (start != end) {
    uint8_t candidate = (*start)->reversed_name.at(0);
    ReversedEntries::iterator sub_entries_end = start + 1;

    for (; sub_entries_end != end; sub_entries_end++) {
      if ((*sub_entries_end)->reversed_name.at(0) != candidate) {
        break;
      }
    }

    writer.WriteChar(candidate, huffman_table_, frequency_tracker_);

    if (candidate == kTerminalValue) {
      DCHECK((sub_entries_end - start) == 1)
          << "Multiple values with the same name";
      WriteSecurityEntry((*start)->entry, &writer);
    } else {
      RemovePrefix(1, start, sub_entries_end);
      uint32_t position = WriteDispatchTables(start, sub_entries_end);
      writer.WritePosition(position, &last_position);
    }

    start = sub_entries_end;
  }

  writer.WriteChar(kEndOfTableValue, huffman_table_, frequency_tracker_);

  uint32_t position = buffer_.position();
  writer.Flush();
  writer.WriteToBitWriter(&buffer_);
  return position;
}

void TrieWriter::WriteSecurityEntry(const DomainSecurityEntry* entry,
                                    TrieBitBuffer* writer) {
  uint8_t include_subdomains = 0;
  if (entry->include_subdomains) {
    include_subdomains = 1;
  }
  writer->WriteBit(include_subdomains);

  uint8_t force_https = 0;
  if (entry->force_https) {
    force_https = 1;
  }
  writer->WriteBit(force_https);

  if (entry->pinset.size()) {
    writer->WriteBit(1);
    NameIDMap::const_iterator pin_id_it = pinsets_map_.find(entry->pinset);
    DCHECK(pin_id_it != pinsets_map_.cend()) << "invalid pinset";
    const uint8_t& pin_id = pin_id_it->second;
    DCHECK(pin_id <= 16) << "too many pinsets";
    writer->WriteBits(pin_id, 4);

    NameIDMap::const_iterator domain_id_it =
        domain_ids_map_.find(DomainConstant(entry->hostname));
    DCHECK(domain_id_it != domain_ids_map_.cend()) << "invalid domain id";
    uint32_t domain_id = domain_id_it->second;
    DCHECK(domain_id < 512) << "too many domain ids";
    writer->WriteBits(domain_id, 9);

    if (!entry->include_subdomains) {
      uint8_t include_subdomains_for_pinning = 0;
      if (entry->hpkp_include_subdomains) {
        include_subdomains_for_pinning = 1;
      }
      writer->WriteBit(include_subdomains_for_pinning);
    }
  } else {
    writer->WriteBit(0);
  }

  if (entry->expect_ct) {
    writer->WriteBit(1);
    NameIDMap::const_iterator expect_ct_report_uri_it =
        expect_ct_report_uri_map_.find(entry->expect_ct_report_uri);
    DCHECK(expect_ct_report_uri_it != expect_ct_report_uri_map_.cend())
        << "invalid expect-ct report-uri";
    const uint8_t& expect_ct_report_id = expect_ct_report_uri_it->second;

    DCHECK(expect_ct_report_id < 16) << "too many expect-ct ids";

    writer->WriteBits(expect_ct_report_id, 4);
  } else {
    writer->WriteBit(0);
  }

  if (entry->expect_staple) {
    writer->WriteBit(1);

    if (entry->expect_staple_include_subdomains) {
      writer->WriteBit(1);
    } else {
      writer->WriteBit(0);
    }

    NameIDMap::const_iterator expect_staple_report_uri_it =
        expect_staple_report_uri_map_.find(entry->expect_staple_report_uri);
    DCHECK(expect_staple_report_uri_it != expect_staple_report_uri_map_.cend())
        << "invalid expect-ct report-uri";
    const uint8_t& expect_staple_report_id =
        expect_staple_report_uri_it->second;
    DCHECK(expect_staple_report_id < 16) << "too many expect-staple ids";

    writer->WriteBits(expect_staple_report_id, 4);
  } else {
    writer->WriteBit(0);
  }
}

void TrieWriter::RemovePrefix(size_t length,
                              ReversedEntries::iterator start,
                              ReversedEntries::iterator end) {
  for (ReversedEntries::iterator it = start; it != end; ++it) {
    (*it)->reversed_name.erase((*it)->reversed_name.begin(),
                               (*it)->reversed_name.begin() + length);
  }
}

std::vector<uint8_t> TrieWriter::LongestCommonPrefix(
    ReversedEntries::iterator start,
    ReversedEntries::iterator end) const {
  if (start == end) {
    return std::vector<uint8_t>();
  }

  std::vector<uint8_t> prefix;
  for (size_t i = 0;; ++i) {
    if (i > (*start)->reversed_name.size()) {
      break;
    }

    uint8_t candidate = (*start)->reversed_name.at(i);
    if (candidate == kTerminalValue) {
      break;
    }

    bool ok = true;
    for (ReversedEntries::iterator it = start + 1; it != end; ++it) {
      if (i > (*it)->reversed_name.size() ||
          (*it)->reversed_name.at(i) != candidate) {
        ok = false;
        break;
      }
    }

    if (!ok) {
      break;
    }

    prefix.push_back(candidate);
  }

  return prefix;
}

std::vector<uint8_t> TrieWriter::ReverseName(
    const std::string& hostname) const {
  size_t hostname_size = hostname.size();
  std::vector<uint8_t> reversed_name(hostname_size + 1);

  for (size_t i = 0; i < hostname_size; ++i) {
    reversed_name[i] = hostname[hostname_size - i - 1];
  }

  reversed_name[reversed_name.size() - 1] = kTerminalValue;
  return reversed_name;
}

uint32_t TrieWriter::position() const {
  return buffer_.position();
}

void TrieWriter::Flush() {
  buffer_.Flush();
}

}  // namespace transport_security_state

}  // namespace net
