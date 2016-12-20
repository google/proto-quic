// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_PRELOADED_STATE_GENERATOR_H_
#define NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_PRELOADED_STATE_GENERATOR_H_

#include <stdint.h>

#include <memory>
#include <string>

#include "net/tools/domain_security_preload_generator/domain_security_entry.h"
#include "net/tools/domain_security_preload_generator/pinset.h"
#include "net/tools/domain_security_preload_generator/pinsets.h"
#include "net/tools/domain_security_preload_generator/trie/trie_writer.h"

namespace net {

namespace transport_security_state {

// PreloadedStateGenerator generates C++ code that contains the preloaded
// entries in a way the Chromium code understands. The code that reads the
// output can be found in net/http/transport_security_state.cc. The output gets
// compiled into the binary.
class PreloadedStateGenerator {
 public:
  PreloadedStateGenerator();
  ~PreloadedStateGenerator();

  std::string Generate(const std::string& preload_template,
                       const DomainSecurityEntries& entries,
                       const DomainIDList& domain_ids,
                       const Pinsets& pinsets,
                       bool verbose);

 private:
  // TODO(Martijnc): Remove the domain IDs from the preload format.
  // https://crbug.com/661206.
  void ProcessDomainIds(const DomainIDList& domain_ids,
                        NameIDMap* map,
                        std::string* tpl);
  void ProcessSPKIHashes(const Pinsets& pinset, std::string* tpl);
  void ProcessExpectCTURIs(const DomainSecurityEntries& entries,
                           NameIDMap* expect_ct_report_uri_map,
                           std::string* tpl);
  void ProcessExpectStapleURIs(const DomainSecurityEntries& entries,
                               NameIDMap* expect_staple_report_uri_map,
                               std::string* tpl);
  void ProcessPinsets(const Pinsets& pinset,
                      NameIDMap* pinset_map,
                      std::string* tpl);
};

}  // namespace transport_security_state

}  // namespace net

#endif  // NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_PRELOADED_STATE_GENERATOR_H_
