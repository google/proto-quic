// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_no_op_visitor.h"

#include <type_traits>

namespace net {
namespace test {

SpdyNoOpVisitor::SpdyNoOpVisitor() {
  static_assert(std::is_abstract<SpdyNoOpVisitor>::value == false,
                "Need to update SpdyNoOpVisitor.");
}
SpdyNoOpVisitor::~SpdyNoOpVisitor() {}

net::SpdyHeadersHandlerInterface* SpdyNoOpVisitor::OnHeaderFrameStart(
    SpdyStreamId stream_id) {
  return this;
}

bool SpdyNoOpVisitor::OnControlFrameHeaderData(SpdyStreamId stream_id,
                                               const char* header_data,
                                               size_t header_data_len) {
  return true;
}

bool SpdyNoOpVisitor::OnUnknownFrame(SpdyStreamId stream_id, int frame_type) {
  return true;
}

}  // namespace test
}  // namespace net
