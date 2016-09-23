// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "base/strings/string_number_conversions.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string input(reinterpret_cast<const char*>(data), size);
  int out_int;
  base::StringToInt(input, &out_int);
  unsigned out_uint;
  base::StringToUint(input, &out_uint);
  int64_t out_int64;
  base::StringToInt64(input, &out_int64);
  uint64_t out_uint64;
  base::StringToUint64(input, &out_uint64);
  size_t out_size;
  base::StringToSizeT(input, &out_size);
  double out_double;
  base::StringToDouble(input, &out_double);
  base::HexStringToInt(input, &out_int);
  base::HexStringToUInt(input, &out_uint);
  base::HexStringToInt64(input, &out_int64);
  base::HexStringToUInt64(input, &out_uint64);

  std::vector<uint8_t> out_bytes;
  base::HexStringToBytes(input, &out_bytes);

  base::HexEncode(data, size);
  return 0;
}
