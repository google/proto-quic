// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/transport_security_state_generator/pinset.h"

namespace net {

namespace transport_security_state {

Pinset::Pinset(std::string name, std::string report_uri)
    : name_(name), report_uri_(report_uri) {}

Pinset::~Pinset() {}

void Pinset::AddStaticSPKIHash(const std::string& hash_name) {
  static_spki_hashes_.push_back(hash_name);
}

void Pinset::AddBadStaticSPKIHash(const std::string& hash_name) {
  bad_static_spki_hashes_.push_back(hash_name);
}

}  // namespace transport_security_state

}  // namespace net
