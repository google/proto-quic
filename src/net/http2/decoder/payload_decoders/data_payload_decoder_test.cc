// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/payload_decoders/data_payload_decoder.h"

#include <stddef.h>

#include <string>

#include "base/logging.h"
#include "net/http2/decoder/http2_frame_decoder_listener.h"
#include "net/http2/decoder/payload_decoders/payload_decoder_base_test_util.h"
#include "net/http2/http2_constants.h"
#include "net/http2/http2_structures.h"
#include "net/http2/http2_structures_test_util.h"
#include "net/http2/test_tools/frame_parts.h"
#include "net/http2/test_tools/frame_parts_collector.h"
#include "net/http2/tools/failure.h"
#include "net/http2/tools/http2_frame_builder.h"
#include "net/http2/tools/http2_random.h"
#include "net/http2/tools/random_decoder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::AssertionResult;
using std::string;

namespace net {
namespace test {

// Provides friend access to an instance of the payload decoder, and also
// provides info to aid in testing.
class DataPayloadDecoderPeer {
 public:
  static constexpr Http2FrameType FrameType() { return Http2FrameType::DATA; }

  // Returns the mask of flags that affect the decoding of the payload (i.e.
  // flags that that indicate the presence of certain fields or padding).
  static constexpr uint8_t FlagsAffectingPayloadDecoding() {
    return Http2FrameFlag::FLAG_PADDED;
  }

  static void Randomize(DataPayloadDecoder* p, RandomBase* rng) {
    VLOG(1) << "DataPayloadDecoderPeer::Randomize";
    CorruptEnum(&p->payload_state_, rng);
  }
};

namespace {

struct Listener : public FramePartsCollector {
  void OnDataStart(const Http2FrameHeader& header) override {
    VLOG(1) << "OnDataStart: " << header;
    StartFrame(header)->OnDataStart(header);
  }

  void OnDataPayload(const char* data, size_t len) override {
    VLOG(1) << "OnDataPayload: len=" << len;
    CurrentFrame()->OnDataPayload(data, len);
  }

  void OnDataEnd() override {
    VLOG(1) << "OnDataEnd";
    EndFrame()->OnDataEnd();
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
            << "    missing_length: " << missing_length;
    EndFrame()->OnPaddingTooLong(header, missing_length);
  }
};

class DataPayloadDecoderTest
    : public AbstractPaddablePayloadDecoderTest<DataPayloadDecoder,
                                                DataPayloadDecoderPeer,
                                                Listener> {
 protected:
  AssertionResult CreateAndDecodeDataOfSize(size_t data_size) {
    Reset();
    uint8_t flags = RandFlags();

    string data_payload = Random().RandString(data_size);
    frame_builder_.Append(data_payload);
    MaybeAppendTrailingPadding();

    Http2FrameHeader frame_header(frame_builder_.size(), Http2FrameType::DATA,
                                  flags, RandStreamId());
    set_frame_header(frame_header);
    ScrubFlagsOfHeader(&frame_header);
    FrameParts expected(frame_header, data_payload, total_pad_length_);
    VERIFY_AND_RETURN_SUCCESS(
        DecodePayloadAndValidateSeveralWays(frame_builder_.buffer(), expected));
  }
};

INSTANTIATE_TEST_CASE_P(VariousPadLengths,
                        DataPayloadDecoderTest,
                        ::testing::Values(0, 1, 2, 3, 4, 254, 255, 256));

TEST_P(DataPayloadDecoderTest, VariousDataPayloadSizes) {
  for (size_t data_size : {0, 1, 2, 3, 255, 256, 1024}) {
    EXPECT_TRUE(CreateAndDecodeDataOfSize(data_size));
  }
}

}  // namespace
}  // namespace test
}  // namespace net
