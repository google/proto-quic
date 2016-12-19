// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/domain_security_preload_generator/preloaded_state_generator.h"

#include <iostream>

#include <string>

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/tools/domain_security_preload_generator/cert_util.h"
#include "net/tools/domain_security_preload_generator/huffman/huffman_frequency_tracker.h"
#include "net/tools/domain_security_preload_generator/spki_hash.h"

namespace net {

namespace transport_security_state {

namespace {

static const char kNewLine[] = "\n";
static const char kIndent[] = "  ";

std::string FormatSPKIName(const std::string& name) {
  return "kSPKIHash_" + name;
}

std::string FormatAcceptedKeyName(const std::string& name) {
  return "k" + name + "AcceptableCerts";
}

std::string FormatRejectedKeyName(const std::string& name) {
  return "k" + name + "RejectedCerts";
}

std::string FormatReportURIName(const std::string& name) {
  return "k" + name + "ReportURI";
}

// Replaces the first occurrence of "[[" + name + "]]" in |*tpl| with
// |value|.
bool ReplaceTag(const std::string& name,
                const std::string& value,
                std::string* tpl) {
  std::string tag = "[[" + name + "]]";

  size_t start_pos = tpl->find(tag);
  if (start_pos == std::string::npos) {
    return false;
  }

  tpl->replace(start_pos, tag.length(), value);
  return true;
}

// Formats the bytes in |bytes| as an C++ array initializer and returns the
// resulting string.
std::string FormatVectorAsArray(const std::vector<uint8_t>& bytes) {
  std::string output = "{";
  output.append(kNewLine);
  output.append(kIndent);
  output.append(kIndent);

  size_t bytes_on_current_line = 0;

  for (size_t i = 0; i < bytes.size(); ++i) {
    base::StringAppendF(&output, "0x%02x,", bytes[i]);

    bytes_on_current_line++;
    if (bytes_on_current_line >= 12 && i + 1 < bytes.size()) {
      output.append(kNewLine);
      output.append(kIndent);
      output.append(kIndent);

      bytes_on_current_line = 0;
    } else if (i + 1 < bytes.size()) {
      output.append(" ");
    }
  }

  output.append(kNewLine);
  output.append("}");

  return output;
}

std::string WritePinsetList(const std::string& name,
                            const std::vector<std::string>& pins) {
  std::string output = "static const char* const " + name + "[] = {";
  output.append(kNewLine);

  for (const auto& pin_name : pins) {
    output.append(kIndent);
    output.append(kIndent);
    output.append(FormatSPKIName(pin_name));
    output.append(",");
    output.append(kNewLine);
  }

  output.append(kIndent);
  output.append(kIndent);
  output.append("NULL,");
  output.append(kNewLine);
  output.append("};");

  return output;
}

HuffmanRepresentationTable ApproximateHuffman(
    const DomainSecurityEntries& entries) {
  HuffmanFrequencyTracker tracker;
  for (const auto& entry : entries) {
    for (const auto& c : entry->hostname) {
      tracker.RecordUsage(c);
    }

    tracker.RecordUsage(TrieWriter::kTerminalValue);
    tracker.RecordUsage(TrieWriter::kEndOfTableValue);
  }

  return tracker.ToTable();
}

}  // namespace

PreloadedStateGenerator::PreloadedStateGenerator() {}

PreloadedStateGenerator::~PreloadedStateGenerator() {}

std::string PreloadedStateGenerator::Generate(
    const std::string& preload_template,
    const DomainSecurityEntries& entries,
    const DomainIDList& domain_ids,
    const Pinsets& pinsets,
    bool verbose) {
  std::string output = preload_template;

  NameIDMap domain_ids_map;
  ProcessDomainIds(domain_ids, &domain_ids_map, &output);

  ProcessSPKIHashes(pinsets, &output);

  NameIDMap expect_ct_report_uri_map;
  ProcessExpectCTURIs(entries, &expect_ct_report_uri_map, &output);

  NameIDMap expect_staple_report_uri_map;
  ProcessExpectStapleURIs(entries, &expect_staple_report_uri_map, &output);

  NameIDMap pinsets_map;
  ProcessPinsets(pinsets, &pinsets_map, &output);

  // The trie generation process is ran twice, the first time using an
  // approximate Huffman table. During this first run, the correct character
  // frequencies are collected which are then used to calculate the most space
  // efficient Huffman table for the given inputs. This table is used for the
  // second run.
  HuffmanRepresentationTable table = ApproximateHuffman(entries);
  HuffmanFrequencyTracker tracker;
  TrieWriter writer(table, domain_ids_map, expect_ct_report_uri_map,
                    expect_staple_report_uri_map, pinsets_map, &tracker);
  writer.WriteEntries(entries);
  uint32_t initial_length = writer.position();

  HuffmanRepresentationTable optimal_table = tracker.ToTable();
  TrieWriter new_writer(optimal_table, domain_ids_map, expect_ct_report_uri_map,
                        expect_staple_report_uri_map, pinsets_map, nullptr);

  uint32_t root_position = new_writer.WriteEntries(entries);
  uint32_t new_length = new_writer.position();

  std::vector<uint8_t> huffman_tree = tracker.ToVector();

  new_writer.Flush();

  ReplaceTag("HUFFMAN_TREE", FormatVectorAsArray(huffman_tree), &output);
  ReplaceTag("HSTS_TRIE", FormatVectorAsArray(new_writer.bytes()), &output);

  ReplaceTag("HSTS_TRIE_BITS", std::to_string(new_length), &output);
  ReplaceTag("HSTS_TRIE_ROOT", std::to_string(root_position), &output);

  if (verbose) {
    std::cout << "Saved " << std::to_string(initial_length - new_length)
              << " bits by using accurate Huffman counts." << std::endl;
    std::cout << "Bit length " << std::to_string(new_length) << std::endl;
    std::cout << "Root position " << std::to_string(root_position) << std::endl;
  }

  return output;
}

void PreloadedStateGenerator::ProcessDomainIds(const DomainIDList& domain_ids,
                                               NameIDMap* map,
                                               std::string* tpl) {
  std::string output = "{";
  output.append(kNewLine);

  for (size_t i = 0; i < domain_ids.size(); ++i) {
    const std::string& current = domain_ids.at(i);
    output.append(kIndent);
    output.append("DOMAIN_" + current + ",");
    output.append(kNewLine);

    map->insert(NameIDPair(current, static_cast<uint32_t>(i)));
  }

  output.append(kIndent);
  output.append("// Boundary value for UMA_HISTOGRAM_ENUMERATION.");
  output.append(kNewLine);
  output.append(kIndent);
  output.append("DOMAIN_NUM_EVENTS,");
  output.append(kNewLine);
  output.append("}");

  ReplaceTag("DOMAIN_IDS", output, tpl);
}

void PreloadedStateGenerator::ProcessSPKIHashes(const Pinsets& pinset,
                                                std::string* tpl) {
  std::string output;

  const SPKIHashMap& hashes = pinset.spki_hashes();
  for (const auto& current : hashes) {
    const std::string& name = current.first;
    const SPKIHash& hash = current.second;

    output.append("static const char " + FormatSPKIName(name) + "[] =");
    output.append(kNewLine);

    for (size_t i = 0; i < hash.size() / 16; ++i) {
      output.append(kIndent);
      output.append(kIndent);
      output.append("\"");

      for (size_t j = i * 16; j < ((i + 1) * 16); ++j) {
        base::StringAppendF(&output, "\\x%02x", hash.data()[j]);
      }

      output.append("\"");
      if (i + 1 == hash.size() / 16) {
        output.append(";");
      }
      output.append(kNewLine);
    }

    output.append(kNewLine);
  }

  base::TrimString(output, kNewLine, &output);
  ReplaceTag("SPKI_HASHES", output, tpl);
}

void PreloadedStateGenerator::ProcessExpectCTURIs(
    const DomainSecurityEntries& entries,
    NameIDMap* expect_ct_report_uri_map,
    std::string* tpl) {
  std::string output = "{";
  output.append(kNewLine);

  for (const auto& entry : entries) {
    const std::string& url = entry->expect_ct_report_uri;
    if (entry->expect_ct && url.size() &&
        expect_ct_report_uri_map->find(url) ==
            expect_ct_report_uri_map->cend()) {
      output.append(kIndent);
      output.append(kIndent);
      output.append("\"" + entry->expect_ct_report_uri + "\",");
      output.append(kNewLine);

      expect_ct_report_uri_map->insert(
          NameIDPair(entry->expect_ct_report_uri,
                     static_cast<uint32_t>(expect_ct_report_uri_map->size())));
    }
  }

  output.append("}");
  ReplaceTag("EXPECT_CT_REPORT_URIS", output, tpl);
}

void PreloadedStateGenerator::ProcessExpectStapleURIs(
    const DomainSecurityEntries& entries,
    NameIDMap* expect_staple_report_uri_map,
    std::string* tpl) {
  std::string output = "{";
  output.append(kNewLine);

  for (const auto& entry : entries) {
    const std::string& url = entry->expect_staple_report_uri;
    if (entry->expect_staple && url.size() &&
        expect_staple_report_uri_map->find(url) ==
            expect_staple_report_uri_map->cend()) {
      output.append(kIndent);
      output.append(kIndent);
      output.append("\"" + entry->expect_staple_report_uri + "\",");
      output.append(kNewLine);

      expect_staple_report_uri_map->insert(NameIDPair(
          entry->expect_staple_report_uri,
          static_cast<uint32_t>(expect_staple_report_uri_map->size())));
    }
  }

  output.append("}");
  ReplaceTag("EXPECT_STAPLE_REPORT_URIS", output, tpl);
}

void PreloadedStateGenerator::ProcessPinsets(const Pinsets& pinset,
                                             NameIDMap* pinset_map,
                                             std::string* tpl) {
  std::string certs_output;
  std::string pinsets_output = "{";
  pinsets_output.append(kNewLine);

  const PinsetMap& pinsets = pinset.pinsets();
  for (const auto& current : pinsets) {
    const std::unique_ptr<Pinset>& pinset = current.second;
    std::string uppercased_name = pinset->name();
    uppercased_name[0] = base::ToUpperASCII(uppercased_name[0]);

    const std::string& accepted_pins_names =
        FormatAcceptedKeyName(uppercased_name);
    certs_output.append(
        WritePinsetList(accepted_pins_names, pinset->static_spki_hashes()));
    certs_output.append(kNewLine);

    std::string rejected_pins_names = "kNoRejectedPublicKeys";
    if (pinset->bad_static_spki_hashes().size()) {
      rejected_pins_names = FormatRejectedKeyName(uppercased_name);
      certs_output.append(WritePinsetList(rejected_pins_names,
                                          pinset->bad_static_spki_hashes()));
      certs_output.append(kNewLine);
    }

    std::string report_uri = "kNoReportURI";
    if (pinset->report_uri().size()) {
      report_uri = FormatReportURIName(uppercased_name);
      certs_output.append("static const char " + report_uri + "[] = ");
      certs_output.append("\"");
      certs_output.append(pinset->report_uri());
      certs_output.append("\";");
      certs_output.append(kNewLine);
    }
    certs_output.append(kNewLine);

    pinsets_output.append(kIndent);
    pinsets_output.append(kIndent);
    pinsets_output.append("{" + accepted_pins_names + ", " +
                          rejected_pins_names + ", " + report_uri + "},");
    pinsets_output.append(kNewLine);

    pinset_map->insert(
        NameIDPair(pinset->name(), static_cast<uint32_t>(pinset_map->size())));
  }

  pinsets_output.append("}");

  base::TrimString(certs_output, kNewLine, &certs_output);

  ReplaceTag("ACCEPTABLE_CERTS", certs_output, tpl);
  ReplaceTag("PINSETS", pinsets_output, tpl);
}

}  // namespace transport_security_state

}  // namespace net
