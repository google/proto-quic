// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/http2_hpack_constants.h"

#include <sstream>

namespace net {

std::string HpackEntryTypeToString(HpackEntryType v) {
  switch (v) {
    case HpackEntryType::kIndexedHeader:
      return "kIndexedHeader";
    case HpackEntryType::kDynamicTableSizeUpdate:
      return "kDynamicTableSizeUpdate";
    case HpackEntryType::kIndexedLiteralHeader:
      return "kIndexedLiteralHeader";
    case HpackEntryType::kUnindexedLiteralHeader:
      return "kUnindexedLiteralHeader";
    case HpackEntryType::kNeverIndexedLiteralHeader:
      return "kNeverIndexedLiteralHeader";
  }
  std::stringstream ss;
  ss << "UnknownHpackEntryType(" << static_cast<int>(v) << ")";
  return ss.str();
}

std::ostream& operator<<(std::ostream& out, HpackEntryType v) {
  return out << HpackEntryTypeToString(v);
}

}  // namespace net
