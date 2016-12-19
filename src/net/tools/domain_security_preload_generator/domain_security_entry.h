// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_DOMAIN_SECURITY_ENTRY_H_
#define NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_DOMAIN_SECURITY_ENTRY_H_

#include <memory>
#include <string>
#include <vector>

namespace net {

namespace transport_security_state {

// DomainSecurityEntry represents a preloaded entry.
struct DomainSecurityEntry {
  DomainSecurityEntry();
  ~DomainSecurityEntry();

  std::string hostname;

  bool include_subdomains = false;
  bool force_https = false;

  bool hpkp_include_subdomains = false;
  std::string pinset;

  bool expect_ct = false;
  std::string expect_ct_report_uri;

  bool expect_staple = false;
  bool expect_staple_include_subdomains = false;
  std::string expect_staple_report_uri;
};

using DomainSecurityEntries = std::vector<std::unique_ptr<DomainSecurityEntry>>;

// TODO(Martijnc): Remove the domain IDs from the preload format.
// https://crbug.com/661206.
using DomainIDList = std::vector<std::string>;

// ReversedEntry points to a DomainSecurityEntry and contains the reversed
// hostname for that entry. This is used to construct the trie.
struct ReversedEntry {
  ReversedEntry(std::vector<uint8_t> reversed_name,
                const DomainSecurityEntry* entry);
  ~ReversedEntry();

  std::vector<uint8_t> reversed_name;
  const DomainSecurityEntry* entry;
};

using ReversedEntries = std::vector<std::unique_ptr<ReversedEntry>>;

}  // namespace transport_security_state

}  // namespace net

#endif  // NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_DOMAIN_SECURITY_ENTRY_H_
