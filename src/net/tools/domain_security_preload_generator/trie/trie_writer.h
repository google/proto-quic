// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_TRIE_TRIE_WRITER_H_
#define NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_TRIE_TRIE_WRITER_H_

#include <string>
#include <vector>

#include "net/tools/domain_security_preload_generator/bit_writer.h"
#include "net/tools/domain_security_preload_generator/domain_security_entry.h"
#include "net/tools/domain_security_preload_generator/huffman/huffman_frequency_tracker.h"

namespace net {

namespace transport_security_state {

struct DomainSecurityEntry;
class TrieBitBuffer;

// Maps a name to an index. This is used to track the index of several values
// in the C++ code. The trie refers to the array index of the values. For
// example; the pinsets are outputted as a C++ array and the index for the
// pinset in that array is placed in the trie.
using NameIDMap = std::map<std::string, uint32_t>;
using NameIDPair = std::pair<std::string, uint32_t>;

class TrieWriter {
 public:
  enum : uint8_t { kTerminalValue = 0, kEndOfTableValue = 127 };

  TrieWriter(const HuffmanRepresentationTable& huffman_table,
             const NameIDMap& domain_ids_map,
             const NameIDMap& expect_ct_report_uri_map,
             const NameIDMap& expect_staple_report_uri_map,
             const NameIDMap& pinsets_map,
             HuffmanFrequencyTracker* frequency_tracker);
  ~TrieWriter();

  // Constructs a trie containing all |entries|. The output is written to
  // |buffer_|. Returns the position of the trie root.
  uint32_t WriteEntries(const DomainSecurityEntries& entries);

  // Returns the position |buffer_| is currently at. The returned value
  // represents the number of bits.
  uint32_t position() const;

  // Flushes |buffer_|.
  void Flush();

  // Returns the trie bytes. Call Flush() first to ensure the buffer is
  // complete.
  const std::vector<uint8_t>& bytes() const { return buffer_.bytes(); }

 private:
  uint32_t WriteDispatchTables(ReversedEntries::iterator start,
                               ReversedEntries::iterator end);

  // Serializes |*entry| and writes it to |*writer|.
  void WriteSecurityEntry(const DomainSecurityEntry* entry,
                          TrieBitBuffer* writer);

  // Removes the first |length| characters from all entries between |start| and
  // |end|.
  void RemovePrefix(size_t length,
                    ReversedEntries::iterator start,
                    ReversedEntries::iterator end);

  // Searches for the longest common prefix for all entries between |start| and
  // |end|.
  std::vector<uint8_t> LongestCommonPrefix(ReversedEntries::iterator start,
                                           ReversedEntries::iterator end) const;

  // Returns the reversed |hostname| as a vector of bytes. The reversed hostname
  // will be terminated by |kTerminalValue|.
  std::vector<uint8_t> ReverseName(const std::string& hostname) const;

  BitWriter buffer_;
  const HuffmanRepresentationTable& huffman_table_;
  const NameIDMap& domain_ids_map_;
  const NameIDMap& expect_ct_report_uri_map_;
  const NameIDMap& expect_staple_report_uri_map_;
  const NameIDMap& pinsets_map_;
  HuffmanFrequencyTracker* frequency_tracker_;
};

}  // namespace transport_security_state

}  // namespace net

#endif  // NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_TRIE_TRIE_WRITER_H_
