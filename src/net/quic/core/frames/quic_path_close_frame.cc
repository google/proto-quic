// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/frames/quic_path_close_frame.h"

namespace net {

QuicPathCloseFrame::QuicPathCloseFrame(QuicPathId path_id) : path_id(path_id) {}

std::ostream& operator<<(std::ostream& os,
                         const QuicPathCloseFrame& path_close_frame) {
  os << "{ path_id: " << static_cast<int>(path_close_frame.path_id) << " }\n";
  return os;
}

}  // namespace net
