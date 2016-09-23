// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "net/proxy/proxy_bypass_rules.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::ProxyBypassRules rules;
  std::string input(data, data + size);
  rules.ParseFromString(input);
  rules.ParseFromStringUsingSuffixMatching(input);
  return 0;
}
