// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/json/json_reader.h"
#include "base/values.h"

int error_code, error_line, error_column;
std::string error_message;

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1)
    return 0;

  const std::string input_string(reinterpret_cast<const char*>(data), size - 1);
  const int options = data[size - 1];
  base::JSONReader::ReadAndReturnError(input_string, options, &error_code,
                                       &error_message, &error_line,
                                       &error_column);
  return 0;
}
