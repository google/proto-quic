// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/header_coalescer.h"

#include <utility>

#include "base/strings/string_util.h"
#include "net/http/http_util.h"
#include "net/spdy/platform/api/spdy_estimate_memory_usage.h"

namespace net {

const size_t kMaxHeaderListSize = 256 * 1024;

void HeaderCoalescer::OnHeader(base::StringPiece key, base::StringPiece value) {
  if (error_seen_) {
    return;
  }

  if (key.empty()) {
    DVLOG(1) << "Header name must not be empty.";
    error_seen_ = true;
    return;
  }

  base::StringPiece key_name = key;
  if (key[0] == ':') {
    if (regular_header_seen_) {
      error_seen_ = true;
      return;
    }
    key_name.remove_prefix(1);
  } else if (!regular_header_seen_) {
    regular_header_seen_ = true;
  }

  if (!HttpUtil::IsValidHeaderName(key_name)) {
    error_seen_ = true;
    return;
  }

  // 32 byte overhead according to RFC 7540 Section 6.5.2.
  header_list_size_ += key.size() + value.size() + 32;
  if (header_list_size_ > kMaxHeaderListSize) {
    error_seen_ = true;
    return;
  }

  // End of line delimiter is forbidden according to RFC 7230 Section 3.2.
  // Line folding, RFC 7230 Section 3.2.4., is a special case of this.
  if (value.find("\r\n") != base::StringPiece::npos) {
    error_seen_ = true;
    return;
  }

  auto iter = headers_.find(key);
  if (iter == headers_.end()) {
    headers_[key] = value;
  } else {
    // This header had multiple values, so it must be reconstructed.
    base::StringPiece v = iter->second;
    std::string s(v.data(), v.length());
    if (key == "cookie") {
      // Obeys section 8.1.2.5 in RFC 7540 for cookie reconstruction.
      s.append("; ");
    } else {
      base::StringPiece("\0", 1).AppendToString(&s);
    }
    value.AppendToString(&s);
    headers_[key] = s;
  }
}

SpdyHeaderBlock HeaderCoalescer::release_headers() {
  DCHECK(headers_valid_);
  headers_valid_ = false;
  return std::move(headers_);
}

size_t HeaderCoalescer::EstimateMemoryUsage() const {
  return SpdyEstimateMemoryUsage(headers_);
}

}  // namespace net
