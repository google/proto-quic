// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_PINSETS_H_
#define NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_PINSETS_H_

#include <map>
#include <memory>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/tools/domain_security_preload_generator/cert_util.h"
#include "net/tools/domain_security_preload_generator/pinset.h"
#include "net/tools/domain_security_preload_generator/pinsets.h"
#include "net/tools/domain_security_preload_generator/spki_hash.h"

namespace net {

namespace transport_security_state {

// Contains SPKIHashes and their names. The names are used to reference
// the hashes from Pinset's.
using SPKIHashMap = std::map<std::string, SPKIHash>;
using PinsetMap = std::map<std::string, std::unique_ptr<Pinset>>;

class Pinsets {
 public:
  Pinsets();
  ~Pinsets();

  void RegisterSPKIHash(base::StringPiece name, const SPKIHash& hash);
  void RegisterPinset(std::unique_ptr<Pinset> set);

  size_t size() const { return pinsets_.size(); }
  size_t spki_size() const { return spki_hashes_.size(); }

  const SPKIHashMap& spki_hashes() const { return spki_hashes_; }
  const PinsetMap& pinsets() const { return pinsets_; }

 private:
  // Contains all SPKI hashes found in the input pins file.
  SPKIHashMap spki_hashes_;

  // Contains all pinsets in the input JSON file.
  PinsetMap pinsets_;

  DISALLOW_COPY_AND_ASSIGN(Pinsets);
};

}  // namespace transport_security_state

}  // namespace net

#endif  // NET_TOOLS_DOMAIN_SECURITY_PRELOAD_GENERATOR_PINSETS_H_
