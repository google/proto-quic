// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_name_match.h"

#include "net/der/input.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  net::der::Input in(data, size);
  std::string normalized_der;
  bool success = net::NormalizeName(in, &normalized_der);
  if (success) {
    // If the input was successfully normalized, re-normalizing it should
    // produce the same output again.
    std::string renormalized_der;
    bool renormalize_success =
        net::NormalizeName(net::der::Input(&normalized_der), &renormalized_der);
    CHECK(renormalize_success);
    CHECK_EQ(normalized_der, renormalized_der);
  }
  return 0;
}
