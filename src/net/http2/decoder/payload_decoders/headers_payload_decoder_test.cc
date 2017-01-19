// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/payload_decoders/headers_payload_decoder.h"

#include <stddef.h>

#include <string>

#include "base/logging.h"
#include "net/http2/decoder/frame_parts.h"
#include "net/http2/decoder/frame_parts_collector.h"
#include "net/http2/decoder/http2_frame_decoder_listener.h"
#include "net/http2/decoder/payload_decoders/payload_decoder_base_test_util.h"
#include "net/http2/http2_constants.h"
#include "net/http2/http2_structures_test_util.h"
#include "net/http2/tools/http2_frame_builder.h"
#include "net/http2/tools/http2_random.h"
#include "net/http2/tools/random_decoder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

using std::string;

namespace net {
namespace test {

class HeadersPayloadDecoderPeer {
 public:
  static constexpr Http2FrameType FrameType() {
    return Http2FrameType::HEADERS;
  }

  // Returns the mask of flags that affect the decoding of the payload (i.e.
  // flags that that indicate the presence of certain fields or padding).
  static constexpr uint8_t FlagsAffectingPayloadDecoding() {
    return Http2FrameFlag::FLAG_PADDED | Http2FrameFlag::FLAG_PRIORITY;
  }

  static void Randomize(HeadersPayloadDecoder* p, RandomBase* rng) {
    CorruptEnum(&p->payload_state_, rng);
    test::Randomize(&p->priority_fields_, rng);
    VLOG(1) << "HeadersPayloadDecoderPeer::Randomize priority_fields_: "
            << p->priority_fields_;
  }
};

namespace {

// Listener handles all On* methods that are expected to be called. If any other
// On* methods of Http2FrameDecoderListener is called then the test fails; this
// is achieved by way of FailingHttp2FrameDecoderListener, the base class of
// FramePartsCollector.
// These On* methods make use of StartFrame, EndFrame, etc. of the base class
// to create and access to FrameParts instance(s) that will record the details.
// After decoding, the test validation code can access the FramePart instance(s)
// via the public methods of FramePartsCollector.
struct Listener : public FramePartsCollector {
  void OnHeadersStart(const Http2FrameHeader& header) override {
    VLOG(1) << "OnHeadersStart: " << header;
    StartFrame(header)->OnHeadersStart(header);
  }

  void OnHeadersPriority(const Http2PriorityFields& priority) override {
    VLOG(1) << "OnHeadersPriority: " << priority;
    CurrentFrame()->OnHeadersPriority(priority);
  }

  void OnHpackFragment(const char* data, size_t len) override {
    VLOG(1) << "OnHpackFragment: len=" << len;
    CurrentFrame()->OnHpackFragment(data, len);
  }

  void OnHeadersEnd() override {
    VLOG(1) << "OnHeadersEnd";
    EndFrame()->OnHeadersEnd();
  }

  void OnPadLength(size_t pad_length) override {
    VLOG(1) << "OnPadLength: " << pad_length;
    CurrentFrame()->OnPadLength(pad_length);
  }

  void OnPadding(const char* padding, size_t skipped_length) override {
    VLOG(1) << "OnPadding: " << skipped_length;
    CurrentFrame()->OnPadding(padding, skipped_length);
  }

  void OnPaddingTooLong(const Http2FrameHeader& header,
                        size_t missing_length) override {
    VLOG(1) << "OnPaddingTooLong: " << header
            << "; missing_length: " << missing_length;
    FrameError(header)->OnPaddingTooLong(header, missing_length);
  }

  void OnFrameSizeError(const Http2FrameHeader& header) override {
    VLOG(1) << "OnFrameSizeError: " << header;
    FrameError(header)->OnFrameSizeError(header);
  }
};

class HeadersPayloadDecoderTest
    : public AbstractPaddablePayloadDecoderTest<HeadersPayloadDecoder,
                                                HeadersPayloadDecoderPeer,
                                                Listener> {};

INSTANTIATE_TEST_CASE_P(VariousPadLengths,
                        HeadersPayloadDecoderTest,
                        ::testing::Values(0, 1, 2, 3, 4, 254, 255, 256));

// Decode various sizes of (fake) HPACK payload, both with and without the
// PRIORITY flag set.
TEST_P(HeadersPayloadDecoderTest, VariousHpackPayloadSizes) {
  for (size_t hpack_size : {0, 1, 2, 3, 255, 256, 1024}) {
    LOG(INFO) << "###########   hpack_size = " << hpack_size << "  ###########";
    Http2PriorityFields priority(RandStreamId(), 1 + Random().Rand8(),
                                 Random().OneIn(2));

    for (bool has_priority : {false, true}) {
      Reset();
      ASSERT_EQ(IsPadded() ? 1u : 0u, frame_builder_.size());
      uint8_t flags = RandFlags();
      if (has_priority) {
        flags |= Http2FrameFlag::FLAG_PRIORITY;
        frame_builder_.Append(priority);
      }

      string hpack_payload = Random().RandString(hpack_size);
      frame_builder_.Append(hpack_payload);

      MaybeAppendTrailingPadding();
      Http2FrameHeader frame_header(frame_builder_.size(),
                                    Http2FrameType::HEADERS, flags,
                                    RandStreamId());
      set_frame_header(frame_header);
      ScrubFlagsOfHeader(&frame_header);
      FrameParts expected(frame_header, hpack_payload, total_pad_length_);
      if (has_priority) {
        expected.opt_priority = priority;
      }
      EXPECT_TRUE(DecodePayloadAndValidateSeveralWays(frame_builder_.buffer(),
                                                      expected));
    }
  }
}

// Confirm we get an error if the PRIORITY flag is set but the payload is
// not long enough, regardless of the amount of (valid) padding.
TEST_P(HeadersPayloadDecoderTest, Truncated) {
  auto approve_size = [](size_t size) {
    return size != Http2PriorityFields::EncodedSize();
  };
  Http2FrameBuilder fb;
  fb.Append(Http2PriorityFields(RandStreamId(), 1 + Random().Rand8(),
                                Random().OneIn(2)));
  EXPECT_TRUE(VerifyDetectsMultipleFrameSizeErrors(
      Http2FrameFlag::FLAG_PRIORITY, fb.buffer(), approve_size,
      total_pad_length_));
}

// Confirm we get an error if the PADDED flag is set but the payload is not
// long enough to hold even the Pad Length amount of padding.
TEST_P(HeadersPayloadDecoderTest, PaddingTooLong) {
  EXPECT_TRUE(VerifyDetectsPaddingTooLong());
}

}  // namespace
}  // namespace test
}  // namespace net
