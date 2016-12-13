// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_FRAMES_QUIC_PATH_CLOSE_FRAME_H_
#define NET_QUIC_CORE_FRAMES_QUIC_PATH_CLOSE_FRAME_H_

#include <ostream>

#include "net/quic/core/quic_types.h"
#include "net/quic/platform/api/quic_export.h"

namespace net {

// The PATH_CLOSE frame is used to explicitly close a path. Both endpoints can
// send a PATH_CLOSE frame to initiate a path termination. A path is considered
// to be closed either a PATH_CLOSE frame is sent or received. An endpoint drops
// receive side of a closed path, and packets with retransmittable frames on a
// closed path are marked as retransmissions which will be transmitted on other
// paths.
struct QUIC_EXPORT_PRIVATE QuicPathCloseFrame {
  QuicPathCloseFrame() {}
  explicit QuicPathCloseFrame(QuicPathId path_id);

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(
      std::ostream& os,
      const QuicPathCloseFrame& p);

  QuicPathId path_id;
};

}  // namespace net

#endif  // NET_QUIC_CORE_FRAMES_QUIC_PATH_CLOSE_FRAME_H_
