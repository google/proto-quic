// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/payload_decoders/rst_stream_payload_decoder.h"

#include <stddef.h>

#include "base/logging.h"
#include "net/http2/decoder/http2_frame_decoder_listener.h"
#include "net/http2/decoder/payload_decoders/payload_decoder_base_test_util.h"
#include "net/http2/http2_constants.h"
#include "net/http2/http2_constants_test_util.h"
#include "net/http2/http2_structures_test_util.h"
#include "net/http2/test_tools/frame_parts.h"
#include "net/http2/test_tools/frame_parts_collector.h"
#include "net/http2/tools/http2_frame_builder.h"
#include "net/http2/tools/http2_random.h"
#include "net/http2/tools/random_decoder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

class RstStreamPayloadDecoderPeer {
 public:
  static constexpr Http2FrameType FrameType() {
    return Http2FrameType::RST_STREAM;
  }

  // Returns the mask of flags that affect the decoding of the payload (i.e.
  // flags that that indicate the presence of certain fields or padding).
  static constexpr uint8_t FlagsAffectingPayloadDecoding() { return 0; }

  static void Randomize(RstStreamPayloadDecoder* p, RandomBase* rng) {
    VLOG(1) << "RstStreamPayloadDecoderPeer::Randomize";
    test::Randomize(&p->rst_stream_fields_, rng);
  }
};

namespace {

struct Listener : public FramePartsCollector {
  void OnRstStream(const Http2FrameHeader& header,
                   Http2ErrorCode error_code) override {
    VLOG(1) << "OnRstStream: " << header << "; error_code=" << error_code;
    StartAndEndFrame(header)->OnRstStream(header, error_code);
  }

  void OnFrameSizeError(const Http2FrameHeader& header) override {
    VLOG(1) << "OnFrameSizeError: " << header;
    FrameError(header)->OnFrameSizeError(header);
  }
};

class RstStreamPayloadDecoderTest
    : public AbstractPayloadDecoderTest<RstStreamPayloadDecoder,
                                        RstStreamPayloadDecoderPeer,
                                        Listener> {
 protected:
  Http2RstStreamFields RandRstStreamFields() {
    Http2RstStreamFields fields;
    test::Randomize(&fields, RandomPtr());
    return fields;
  }
};

// Confirm we get an error if the payload is not the correct size to hold
// exactly one Http2RstStreamFields.
TEST_F(RstStreamPayloadDecoderTest, WrongSize) {
  auto approve_size = [](size_t size) {
    return size != Http2RstStreamFields::EncodedSize();
  };
  Http2FrameBuilder fb;
  fb.Append(RandRstStreamFields());
  fb.Append(RandRstStreamFields());
  fb.Append(RandRstStreamFields());
  EXPECT_TRUE(VerifyDetectsFrameSizeError(0, fb.buffer(), approve_size));
}

TEST_F(RstStreamPayloadDecoderTest, AllErrors) {
  for (auto error_code : AllHttp2ErrorCodes()) {
    Http2RstStreamFields fields{error_code};
    Http2FrameBuilder fb;
    fb.Append(fields);
    Http2FrameHeader header(fb.size(), Http2FrameType::RST_STREAM, RandFlags(),
                            RandStreamId());
    set_frame_header(header);
    FrameParts expected(header);
    expected.opt_rst_stream_error_code = error_code;
    EXPECT_TRUE(DecodePayloadAndValidateSeveralWays(fb.buffer(), expected));
  }
}

}  // namespace
}  // namespace test
}  // namespace net
