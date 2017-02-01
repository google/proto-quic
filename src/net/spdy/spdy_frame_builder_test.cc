// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_frame_builder.h"

#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/platform_test.h"

namespace net {

TEST(SpdyFrameBuilderTest, GetWritableBuffer) {
  const size_t kBuilderSize = 10;
  SpdyFrameBuilder builder(kBuilderSize);
  char* writable_buffer = builder.GetWritableBuffer(kBuilderSize);
  memset(writable_buffer, ~1, kBuilderSize);
  EXPECT_TRUE(builder.Seek(kBuilderSize));
  SpdySerializedFrame frame(builder.take());
  char expected[kBuilderSize];
  memset(expected, ~1, kBuilderSize);
  EXPECT_EQ(base::StringPiece(expected, kBuilderSize),
            base::StringPiece(frame.data(), kBuilderSize));
}

}  // namespace net
