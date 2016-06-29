// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HEADER_COALESCER_H_
#define NET_SPDY_HEADER_COALESCER_H_

#include "net/base/net_export.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_handler_interface.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

class NET_EXPORT_PRIVATE HeaderCoalescer : public SpdyHeadersHandlerInterface {
 public:
  explicit HeaderCoalescer(const SpdyMajorVersion& protocol_version)
      : protocol_version_(protocol_version) {}

  void OnHeaderBlockStart() override {}

  void OnHeader(base::StringPiece key, base::StringPiece value) override;

  void OnHeaderBlockEnd(size_t uncompressed_header_bytes) override {}

  const SpdyHeaderBlock& headers() const { return headers_; }
  bool error_seen() const { return error_seen_; }

 private:
  SpdyHeaderBlock headers_;
  size_t header_list_size_ = 0;
  bool error_seen_ = false;
  bool regular_header_seen_ = false;
  SpdyMajorVersion protocol_version_;
};

}  // namespace net

#endif  // NET_SPDY_HEADER_COALESCER_H_
