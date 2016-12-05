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

TEST(SpdyFrameBuilderTest, RewriteLength) {
  // Create an empty SETTINGS frame both via framer and manually via builder.
  // The one created via builder is initially given the incorrect length, but
  // then is corrected via RewriteLength().
  SpdyFramer framer;
  SpdySettingsIR settings_ir;
  SpdySerializedFrame expected(framer.SerializeSettings(settings_ir));
  SpdyFrameBuilder builder(expected.size() + 1);
  builder.BeginNewFrame(framer, SETTINGS, 0, 0);
  EXPECT_TRUE(builder.GetWritableBuffer(1) != NULL);
  builder.RewriteLength(framer);
  SpdySerializedFrame built(builder.take());
  EXPECT_EQ(base::StringPiece(expected.data(), expected.size()),
            base::StringPiece(built.data(), expected.size()));
}

TEST(SpdyFrameBuilderTest, OverwriteFlags) {
  // Create a HEADERS frame both via framer and manually via builder with
  // different flags set, then make them match using OverwriteFlags().
  SpdyFramer framer;
  SpdyHeadersIR headers_ir(1);
  SpdySerializedFrame expected(framer.SerializeHeaders(headers_ir));
  SpdyFrameBuilder builder(expected.size());
  builder.BeginNewFrame(framer, HEADERS, 0, 1);
  builder.OverwriteFlags(framer, HEADERS_FLAG_END_HEADERS);
  SpdySerializedFrame built(builder.take());
  EXPECT_EQ(base::StringPiece(expected.data(), expected.size()),
            base::StringPiece(built.data(), built.size()));
}
}  // namespace net
