// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/internal/verify_name_match.h"

#include "base/test/fuzzed_data_provider.h"
#include "net/der/input.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  base::FuzzedDataProvider fuzzed_data(data, size);
  size_t first_part_size = fuzzed_data.ConsumeUint16();
  base::StringPiece first_part = fuzzed_data.ConsumeBytes(first_part_size);
  base::StringPiece second_part = fuzzed_data.ConsumeRemainingBytes();

  net::der::Input in1(first_part);
  net::der::Input in2(second_part);
  bool match = net::VerifyNameMatch(in1, in2);
  bool reverse_order_match = net::VerifyNameMatch(in2, in1);
  // Result should be the same regardless of argument order.
  CHECK_EQ(match, reverse_order_match);
  return 0;
}
