// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/fuzzed_data_provider.h"

#include <algorithm>
#include <limits>

#include "base/logging.h"

namespace base {

FuzzedDataProvider::FuzzedDataProvider(const uint8_t* data, size_t size)
    : remaining_data_(reinterpret_cast<const char*>(data), size) {}

FuzzedDataProvider::~FuzzedDataProvider() {}

StringPiece FuzzedDataProvider::ConsumeBytes(size_t num_bytes) {
  num_bytes = std::min(num_bytes, remaining_data_.length());
  StringPiece result(remaining_data_.data(), num_bytes);
  remaining_data_ = remaining_data_.substr(num_bytes);
  return result;
}

StringPiece FuzzedDataProvider::ConsumeRemainingBytes() {
  return ConsumeBytes(remaining_data_.length());
}

uint32_t FuzzedDataProvider::ConsumeUint32InRange(uint32_t min, uint32_t max) {
  CHECK_LE(min, max);

  uint32_t range = max - min;
  uint32_t offset = 0;
  uint32_t result = 0;

  while (offset < 32 && (range >> offset) > 0 && !remaining_data_.empty()) {
    // Pull bytes off the end of the seed data. Experimentally, this seems to
    // allow the fuzzer to more easily explore the input space. This makes
    // sense, since it works by modifying inputs that caused new code to run,
    // and this data is often used to encode length of data read by
    // ConsumeBytes. Separating out read lengths makes it easier modify the
    // contents of the data that is actually read.
    uint8_t next_byte = remaining_data_.back();
    remaining_data_.remove_suffix(1);
    result = (result << 8) | next_byte;
    offset += 8;
  }

  // Avoid division by 0, in the case |range + 1| results in overflow.
  if (range == std::numeric_limits<uint32_t>::max())
    return result;

  return min + result % (range + 1);
}

int FuzzedDataProvider::ConsumeInt32InRange(int min, int max) {
  CHECK_LE(min, max);

  uint32_t range = max - min;
  return min + ConsumeUint32InRange(0, range);
}

bool FuzzedDataProvider::ConsumeBool() {
  return (ConsumeUint8() & 0x01) == 0x01;
}

uint8_t FuzzedDataProvider::ConsumeUint8() {
  return ConsumeUint32InRange(0, 0xFF);
}

uint16_t FuzzedDataProvider::ConsumeUint16() {
  return ConsumeUint32InRange(0, 0xFFFF);
}

}  // namespace base
