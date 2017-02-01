// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/json/json_reader.h"
#include "base/path_service.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/values.h"
#include "crypto/openssl_util.h"
#include "net/tools/transport_security_state_generator/cert_util.h"
#include "net/tools/transport_security_state_generator/pinset.h"
#include "net/tools/transport_security_state_generator/pinsets.h"
#include "net/tools/transport_security_state_generator/preloaded_state_generator.h"
#include "net/tools/transport_security_state_generator/spki_hash.h"
#include "net/tools/transport_security_state_generator/transport_security_state_entry.h"
#include "third_party/boringssl/src/include/openssl/x509v3.h"

using net::transport_security_state::TransportSecurityStateEntry;
using net::transport_security_state::TransportSecurityStateEntries;
using net::transport_security_state::Pinset;
using net::transport_security_state::Pinsets;
using net::transport_security_state::PreloadedStateGenerator;
using net::transport_security_state::DomainIDList;
using net::transport_security_state::SPKIHash;

namespace {

// Print the command line help.
void PrintHelp() {
  std::cout << "transport_security_state_generator <json-file> <pins-file>"
            << " <template-file> <output-file> [-v]" << std::endl;
}

// Parses the |json| string and copies the items under the "entries" key to
// |entries|, the pinsets under the "pinsets" key to |pinsets|, and the domain
// IDs under the "domain_ids" key to |domain_ids|.
//
// More info on the format can be found in
// net/http/transport_security_state_static.json
bool ParseJSON(const std::string& json,
               TransportSecurityStateEntries* entries,
               Pinsets* pinsets,
               DomainIDList* domain_ids) {
  std::unique_ptr<base::Value> value = base::JSONReader::Read(json);
  base::DictionaryValue* dict_value = nullptr;
  if (!value.get() || !value->GetAsDictionary(&dict_value)) {
    std::cerr << "Could not parse the input JSON" << std::endl;
    return false;
  }

  const base::ListValue* preload_entries = nullptr;
  if (!dict_value->GetList("entries", &preload_entries)) {
    std::cerr << "Could not parse the entries in the input JSON" << std::endl;
    return false;
  }

  for (size_t i = 0; i < preload_entries->GetSize(); ++i) {
    const base::DictionaryValue* parsed = nullptr;
    if (!preload_entries->GetDictionary(i, &parsed)) {
      std::cerr << "Could not parse entry " << i << std::endl;
      return false;
    }

    std::unique_ptr<TransportSecurityStateEntry> entry(
        new TransportSecurityStateEntry());

    if (!parsed->GetString("name", &entry->hostname)) {
      std::cerr << "Could not extract the name for entry " << i << std::endl;
      return false;
    }

    parsed->GetBoolean("include_subdomains", &entry->include_subdomains);
    std::string mode;
    parsed->GetString("mode", &mode);
    entry->force_https = (mode == "force-https");
    parsed->GetBoolean("include_subdomains_for_pinning",
                       &entry->hpkp_include_subdomains);
    parsed->GetString("pins", &entry->pinset);
    parsed->GetBoolean("expect_ct", &entry->expect_ct);
    parsed->GetString("expect_ct_report_uri", &entry->expect_ct_report_uri);
    parsed->GetBoolean("expect_staple", &entry->expect_staple);
    parsed->GetBoolean("include_subdomains_for_expect_staple",
                       &entry->expect_staple_include_subdomains);
    parsed->GetString("expect_staple_report_uri",
                      &entry->expect_staple_report_uri);

    entries->push_back(std::move(entry));
  }

  const base::ListValue* pinsets_list = nullptr;
  if (!dict_value->GetList("pinsets", &pinsets_list)) {
    std::cerr << "Could not parse the pinsets in the input JSON" << std::endl;
    return false;
  }

  for (size_t i = 0; i < pinsets_list->GetSize(); ++i) {
    const base::DictionaryValue* parsed = nullptr;
    if (!pinsets_list->GetDictionary(i, &parsed)) {
      std::cerr << "Could not parse pinset " << i << std::endl;
      return false;
    }

    std::string name;
    if (!parsed->GetString("name", &name)) {
      std::cerr << "Could not extract the name for pinset " << i << std::endl;
      return false;
    }

    std::string report_uri;
    parsed->GetString("report_uri", &report_uri);

    std::unique_ptr<Pinset> pinset(new Pinset(name, report_uri));

    const base::ListValue* pinset_static_hashes_list = nullptr;
    if (parsed->GetList("static_spki_hashes", &pinset_static_hashes_list)) {
      for (size_t i = 0; i < pinset_static_hashes_list->GetSize(); ++i) {
        std::string hash;
        pinset_static_hashes_list->GetString(i, &hash);
        pinset->AddStaticSPKIHash(hash);
      }
    }

    const base::ListValue* pinset_bad_static_hashes_list = nullptr;
    if (parsed->GetList("bad_static_spki_hashes",
                        &pinset_bad_static_hashes_list)) {
      for (size_t i = 0; i < pinset_bad_static_hashes_list->GetSize(); ++i) {
        std::string hash;
        pinset_bad_static_hashes_list->GetString(i, &hash);
        pinset->AddBadStaticSPKIHash(hash);
      }
    }

    pinsets->RegisterPinset(std::move(pinset));
  }

  // TODO(Martijnc): Remove the domain IDs from the preload format.
  // https://crbug.com/661206.
  const base::ListValue* domain_ids_list = nullptr;
  if (!dict_value->GetList("domain_ids", &domain_ids_list)) {
    std::cerr << "Failed parsing JSON (domain_ids)" << std::endl;
    return false;
  }

  for (size_t i = 0; i < domain_ids_list->GetSize(); ++i) {
    std::string domain;
    domain_ids_list->GetString(i, &domain);
    domain_ids->push_back(domain);
  }

  return true;
}

bool IsImportantWordInCertificateName(base::StringPiece name) {
  const char* const important_words[] = {"Universal", "Global", "EV", "G1",
                                         "G2",        "G3",     "G4", "G5"};
  for (auto* important_word : important_words) {
    if (name == important_word) {
      return true;
    }
  }
  return false;
}

// Strips all characters not matched by the RegEx [A-Za-z0-9_] from |name| and
// returns the result.
std::string FilterName(base::StringPiece name) {
  std::string filtered;
  for (const char& character : name) {
    if ((character >= '0' && character <= '9') ||
        (character >= 'a' && character <= 'z') ||
        (character >= 'A' && character <= 'Z') || character == '_') {
      filtered += character;
    }
  }
  return base::ToLowerASCII(filtered);
}

// Returns true if |pin_name| is a reasonable match for the certificate name
// |name|.
bool MatchCertificateName(base::StringPiece name, base::StringPiece pin_name) {
  std::vector<base::StringPiece> words = base::SplitStringPiece(
      name, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (words.empty()) {
    std::cerr << "no words in certificate name" << std::endl;
    return false;
  }
  base::StringPiece first_word = words[0];

  if (first_word.ends_with(",")) {
    first_word = first_word.substr(0, first_word.size() - 1);
  }

  if (first_word.starts_with("*.")) {
    first_word = first_word.substr(2, first_word.size() - 2);
  }

  size_t pos = first_word.find('.');
  if (pos != std::string::npos) {
    first_word = first_word.substr(0, first_word.size() - pos);
  }

  pos = first_word.find('-');
  if (pos != std::string::npos) {
    first_word = first_word.substr(0, first_word.size() - pos);
  }

  if (first_word.empty()) {
    std::cerr << "first word of certificate name is empty" << std::endl;
    return false;
  }

  std::string filtered_word = FilterName(first_word);
  first_word = filtered_word;
  if (!base::EqualsCaseInsensitiveASCII(pin_name.substr(0, first_word.size()),
                                        first_word)) {
    std::cerr << "the first word of the certificate name ("
              << first_word.as_string()
              << ") isn't a prefix of the variable name ("
              << pin_name.as_string() << ")" << std::endl;
    return false;
  }

  for (size_t i = 0; i < words.size(); ++i) {
    const base::StringPiece& word = words[i];
    if (word == "Class" && (i + 1) < words.size()) {
      std::string class_name = word.as_string();
      words[i + 1].AppendToString(&class_name);

      size_t pos = pin_name.find(class_name);
      if (pos == std::string::npos) {
        std::cerr << "class specification doesn't appear in the variable name"
                  << std::endl;
        return false;
      }
    } else if (word.size() == 1 && word[0] >= '0' && word[0] <= '9') {
      size_t pos = pin_name.find(word);
      if (pos == std::string::npos) {
        std::cerr << "number doesn't appear in the variable name" << std::endl;
        return false;
      }
    } else if (IsImportantWordInCertificateName(word)) {
      size_t pos = pin_name.find(word);
      if (pos == std::string::npos) {
        std::cerr << word.as_string() << " doesn't appear in the variable name"
                  << std::endl;
        return false;
      }
    }
  }

  return true;
}

// Returns true iff |candidate| is not empty, the first character is in the
// range A-Z, and the remaining characters are in the ranges a-Z, 0-9, or '_'.
bool IsValidName(const std::string& candidate) {
  if (candidate.empty() || candidate[0] < 'A' || candidate[0] > 'Z') {
    return false;
  }

  bool isValid = true;
  for (const char& character : candidate) {
    isValid = (character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') || character == '_';
    if (!isValid) {
      return false;
    }
  }
  return true;
}

static const char kStartOfCert[] = "-----BEGIN CERTIFICATE";
static const char kStartOfPublicKey[] = "-----BEGIN PUBLIC KEY";
static const char kEndOfCert[] = "-----END CERTIFICATE";
static const char kEndOfPublicKey[] = "-----END PUBLIC KEY";
static const char kStartOfSHA256[] = "sha256/";

enum class CertificateParserState {
  PRE_NAME,
  POST_NAME,
  IN_CERTIFICATE,
  IN_PUBLIC_KEY
};

// Extracts SPKI information from the preloaded pins file. The SPKI's can be
// in the form of a PEM certificate, a PEM public key, or a BASE64 string.
//
// More info on the format can be found in
// net/http/transport_security_state_static.pins
bool ParseCertificatesFile(const std::string& certs_input, Pinsets* pinsets) {
  std::istringstream input_stream(certs_input);
  std::string line;
  CertificateParserState current_state = CertificateParserState::PRE_NAME;

  const base::CompareCase& compare_mode = base::CompareCase::INSENSITIVE_ASCII;
  std::string name;
  std::string buffer;
  std::string subject_name;
  bssl::UniquePtr<X509> certificate;
  SPKIHash hash;

  for (std::string line; std::getline(input_stream, line);) {
    if (line[0] == '#') {
      continue;
    }

    if (line.empty() && current_state == CertificateParserState::PRE_NAME) {
      continue;
    }

    switch (current_state) {
      case CertificateParserState::PRE_NAME:
        if (!IsValidName(line)) {
          std::cerr << "Invalid name in certificates file: " << line;
          return false;
        }
        name = line;
        current_state = CertificateParserState::POST_NAME;
        break;
      case CertificateParserState::POST_NAME:
        if (base::StartsWith(line, kStartOfSHA256, compare_mode)) {
          if (!hash.FromString(line)) {
            std::cerr << "Invalid hash value in certificate file for " << name
                      << std::endl;
            return false;
          }

          pinsets->RegisterSPKIHash(name, hash);
          current_state = CertificateParserState::PRE_NAME;
        } else if (base::StartsWith(line, kStartOfCert, compare_mode)) {
          buffer = line + '\n';
          current_state = CertificateParserState::IN_CERTIFICATE;
        } else if (base::StartsWith(line, kStartOfPublicKey, compare_mode)) {
          buffer = line + '\n';
          current_state = CertificateParserState::IN_PUBLIC_KEY;
        } else {
          std::cerr << "Invalid value in certificates file for " << name
                    << std::endl;
          return false;
        }
        break;
      case CertificateParserState::IN_CERTIFICATE:
        buffer += line + '\n';
        if (!base::StartsWith(line, kEndOfCert, compare_mode)) {
          continue;
        }

        certificate = GetX509CertificateFromPEM(buffer);
        if (!certificate) {
          std::cerr << "Could not parse certificate " << name << std::endl;
          return false;
        }

        if (!CalculateSPKIHashFromCertificate(certificate.get(), &hash)) {
          std::cerr << "Could not extract SPKI from certificate " << name
                    << std::endl;
          return false;
        }

        if (!ExtractSubjectNameFromCertificate(certificate.get(),
                                               &subject_name)) {
          std::cerr << "Could not extract name from certificate " << name
                    << std::endl;
          return false;
        }

        if (!MatchCertificateName(subject_name, name)) {
          std::cerr << name << " is not a reasonable name for " << subject_name
                    << std::endl;
          return false;
        }

        pinsets->RegisterSPKIHash(name, hash);
        current_state = CertificateParserState::PRE_NAME;
        break;
      case CertificateParserState::IN_PUBLIC_KEY:
        buffer += line + '\n';
        if (!base::StartsWith(line, kEndOfPublicKey, compare_mode)) {
          continue;
        }

        if (!CalculateSPKIHashFromKey(buffer, &hash)) {
          std::cerr << "Parsing of the public key " << name << " failed"
                    << std::endl;
          return false;
        }

        pinsets->RegisterSPKIHash(name, hash);
        current_state = CertificateParserState::PRE_NAME;
        break;
      default:
        DCHECK(false) << "Unknown parser state";
    }
  }

  return true;
}

// Checks if there are pins with the same name or the same hash.
bool CheckForDuplicatePins(const Pinsets& pinsets) {
  std::set<std::string> seen_names;
  std::map<std::string, std::string> seen_hashes;

  for (const auto& pin : pinsets.spki_hashes()) {
    if (seen_names.find(pin.first) != seen_names.cend()) {
      std::cerr << "Duplicate pin name " << pin.first << std::endl;
      return false;
    }
    seen_names.insert(pin.first);

    std::string hash =
        std::string(pin.second.data(), pin.second.data() + pin.second.size());
    std::map<std::string, std::string>::iterator it = seen_hashes.find(hash);
    if (it != seen_hashes.cend()) {
      std::cerr << "Duplicate pin hash for " << pin.first
                << ", already seen as " << it->second << std::endl;
      return false;
    }
    seen_hashes.insert(std::pair<std::string, std::string>(hash, pin.first));
  }

  return true;
}

// Checks if there are pinsets that reference non-existing pins, if two
// pinsets share the same name, or if there are unused pins.
bool CheckCertificatesInPinsets(const Pinsets& pinsets) {
  std::set<std::string> pin_names;
  for (const auto& pin : pinsets.spki_hashes()) {
    pin_names.insert(pin.first);
  }

  std::set<std::string> used_pin_names;
  std::set<std::string> pinset_names;
  for (const auto& pinset : pinsets.pinsets()) {
    if (pinset_names.find(pinset.second->name()) != pinset_names.cend()) {
      std::cerr << "Duplicate pinset name " << pinset.second->name()
                << std::endl;
      return false;
    }
    pinset_names.insert(pinset.second->name());

    const std::vector<std::string>& good_hashes =
        pinset.second->static_spki_hashes();
    const std::vector<std::string>& bad_hashes =
        pinset.second->bad_static_spki_hashes();

    std::vector<std::string> all_pin_names;
    all_pin_names.reserve(good_hashes.size() + bad_hashes.size());
    all_pin_names.insert(all_pin_names.end(), good_hashes.begin(),
                         good_hashes.end());
    all_pin_names.insert(all_pin_names.end(), bad_hashes.begin(),
                         bad_hashes.end());

    for (const auto& pin_name : all_pin_names) {
      if (pin_names.find(pin_name) == pin_names.cend()) {
        std::cerr << "Unknown pin: " << pin_name << std::endl;
        return false;
      }
      used_pin_names.insert(pin_name);
    }
  }

  for (const auto& pin_name : pin_names) {
    if (used_pin_names.find(pin_name) == used_pin_names.cend()) {
      std::cerr << "Unused pin: " << pin_name << std::endl;
      return false;
    }
  }

  return true;
}

// Checks if there are two or more entries for the same hostname.
bool CheckDuplicateEntries(const TransportSecurityStateEntries& entries) {
  std::set<std::string> seen_entries;
  for (const auto& entry : entries) {
    if (seen_entries.find(entry->hostname) != seen_entries.cend()) {
      std::cerr << "Duplicate entry for " << entry->hostname << std::endl;
      return false;
    }
    seen_entries.insert(entry->hostname);
  }
  return true;
}

// Checks for entries which have no effect.
bool CheckNoopEntries(const TransportSecurityStateEntries& entries) {
  for (const auto& entry : entries) {
    if (!entry->force_https && entry->pinset.empty() && !entry->expect_ct &&
        !entry->expect_staple) {
      if (entry->hostname == "learn.doubleclick.net") {
        // This entry is deliberately used as an exclusion.
        continue;
      }

      std::cerr
          << "Entry for " + entry->hostname +
                 " has no mode, no pins and is not expect-CT or expect-staple"
          << std::endl;
      return false;
    }
  }
  return true;
}

// Checks all entries for incorrect usage of the includeSubdomains flags.
bool CheckSubdomainsFlags(const TransportSecurityStateEntries& entries) {
  for (const auto& entry : entries) {
    if (entry->include_subdomains && entry->hpkp_include_subdomains) {
      std::cerr << "Entry for \"" << entry->hostname
                << "\" sets include_subdomains_for_pinning but also sets "
                   "include_subdomains, which implies it"
                << std::endl;
      return false;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  crypto::EnsureOpenSSLInit();

  base::CommandLine::Init(argc, argv);
  const base::CommandLine& command_line =
      *base::CommandLine::ForCurrentProcess();

#if defined(OS_WIN)
  std::vector<std::string> args;
  base::CommandLine::StringVector wide_args = command_line.GetArgs();
  for (const auto& arg : wide_args) {
    args.push_back(base::WideToUTF8(arg));
  }
#else
  base::CommandLine::StringVector args = command_line.GetArgs();
#endif
  if (args.size() < 4U) {
    PrintHelp();
    return 1;
  }

  bool verbose = command_line.HasSwitch("v");

  base::FilePath json_filepath = base::FilePath::FromUTF8Unsafe(argv[1]);
  if (!base::PathExists(json_filepath)) {
    std::cerr << "Input JSON file doesn't exist." << std::endl;
    return 1;
  }
  json_filepath = base::MakeAbsoluteFilePath(json_filepath);

  std::string json_input;
  if (!base::ReadFileToString(json_filepath, &json_input)) {
    std::cerr << "Could not read input JSON file." << std::endl;
    return 1;
  }

  base::FilePath pins_filepath = base::FilePath::FromUTF8Unsafe(argv[2]);
  if (!base::PathExists(pins_filepath)) {
    std::cerr << "Input pins file doesn't exist." << std::endl;
    return 1;
  }
  pins_filepath = base::MakeAbsoluteFilePath(pins_filepath);

  std::string certs_input;
  if (!base::ReadFileToString(pins_filepath, &certs_input)) {
    std::cerr << "Could not read input pins file." << std::endl;
    return 1;
  }

  TransportSecurityStateEntries entries;
  Pinsets pinsets;
  DomainIDList domain_ids;

  if (!ParseCertificatesFile(certs_input, &pinsets)) {
    std::cerr << "Error while parsing the pins file." << std::endl;
    return 1;
  }
  if (!ParseJSON(json_input, &entries, &pinsets, &domain_ids)) {
    std::cerr << "Error while parsing the JSON file." << std::endl;
    return 1;
  }

  if (!CheckDuplicateEntries(entries) || !CheckNoopEntries(entries) ||
      !CheckSubdomainsFlags(entries) || !CheckForDuplicatePins(pinsets) ||
      !CheckCertificatesInPinsets(pinsets)) {
    std::cerr << "Checks failed. Aborting." << std::endl;
    return 1;
  }

  base::FilePath template_path = base::FilePath::FromUTF8Unsafe(argv[3]);
  if (!base::PathExists(template_path)) {
    std::cerr << "Template file doesn't exist." << std::endl;
    return 1;
  }
  template_path = base::MakeAbsoluteFilePath(template_path);

  std::string preload_template;
  if (!base::ReadFileToString(template_path, &preload_template)) {
    std::cerr << "Could not read template file." << std::endl;
    return 1;
  }

  std::string result;
  PreloadedStateGenerator generator;
  result = generator.Generate(preload_template, entries, domain_ids, pinsets,
                              verbose);

  base::FilePath output_path;
  output_path = base::FilePath::FromUTF8Unsafe(argv[4]);

  if (base::WriteFile(output_path, result.c_str(),
                      static_cast<uint32_t>(result.size())) <= 0) {
    std::cerr << "Failed to write output." << std::endl;
    return 1;
  }

  return 0;
}
