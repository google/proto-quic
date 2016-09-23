// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "net/base/escape.h"

static const int kMaxUnescapeRule = 31;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string path(reinterpret_cast<const char*>(data), size);
  for (int i = 0; i <= kMaxUnescapeRule; i++) {
    (void)net::UnescapeURLComponent(path,
                                    static_cast<net::UnescapeRule::Type>(i));
  }
  return 0;
}
