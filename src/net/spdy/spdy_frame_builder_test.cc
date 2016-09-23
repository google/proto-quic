// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_frame_builder.h"

#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"
#include "testing/platform_test.h"

namespace net {

class SpdyFrameBuilderTest : public ::testing::TestWithParam<SpdyMajorVersion> {
 protected:
  void SetUp() override { spdy_version_ = GetParam(); }

  // Major version of SPDY protocol to be used.
  SpdyMajorVersion spdy_version_;
};

// All tests are run with SPDY/3 and HTTP/2.
INSTANTIATE_TEST_CASE_P(SpdyFrameBuilderTests,
                        SpdyFrameBuilderTest,
                        ::testing::Values(SPDY3, HTTP2));

TEST_P(SpdyFrameBuilderTest, GetWritableBuffer) {
  const size_t builder_size = 10;
  SpdyFrameBuilder builder(builder_size, spdy_version_);
  char* writable_buffer = builder.GetWritableBuffer(builder_size);
  memset(writable_buffer, ~1, builder_size);
  EXPECT_TRUE(builder.Seek(builder_size));
  SpdySerializedFrame frame(builder.take());
  char expected[builder_size];
  memset(expected, ~1, builder_size);
  EXPECT_EQ(base::StringPiece(expected, builder_size),
            base::StringPiece(frame.data(), builder_size));
}

TEST_P(SpdyFrameBuilderTest, RewriteLength) {
  // Create an empty SETTINGS frame both via framer and manually via builder.
  // The one created via builder is initially given the incorrect length, but
  // then is corrected via RewriteLength().
  SpdyFramer framer(spdy_version_);
  SpdySettingsIR settings_ir;
  SpdySerializedFrame expected(framer.SerializeSettings(settings_ir));
  SpdyFrameBuilder builder(expected.size() + 1, spdy_version_);
  if (spdy_version_ == SPDY3) {
    builder.WriteControlFrameHeader(framer, SETTINGS, 0);
    builder.WriteUInt32(0);  // Write the number of settings.
  } else {
    builder.BeginNewFrame(framer, SETTINGS, 0, 0);
  }
  EXPECT_TRUE(builder.GetWritableBuffer(1) != NULL);
  builder.RewriteLength(framer);
  SpdySerializedFrame built(builder.take());
  EXPECT_EQ(base::StringPiece(expected.data(), expected.size()),
            base::StringPiece(built.data(), expected.size()));
}

TEST_P(SpdyFrameBuilderTest, OverwriteFlags) {
  // Create a HEADERS frame both via framer and manually via builder with
  // different flags set, then make them match using OverwriteFlags().
  SpdyFramer framer(spdy_version_);
  if (spdy_version_ == SPDY3) {
    return;
  }
  SpdyHeadersIR headers_ir(1);
  SpdySerializedFrame expected(framer.SerializeHeaders(headers_ir));
  SpdyFrameBuilder builder(expected.size(), spdy_version_);
  builder.BeginNewFrame(framer, HEADERS, 0, 1);
  builder.OverwriteFlags(framer, HEADERS_FLAG_END_HEADERS);
  SpdySerializedFrame built(builder.take());
  EXPECT_EQ(base::StringPiece(expected.data(), expected.size()),
            base::StringPiece(built.data(), built.size()));
}

}  // namespace net
