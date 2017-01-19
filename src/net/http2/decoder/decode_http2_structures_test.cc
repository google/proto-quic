// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/decode_http2_structures.h"

// Tests decoding all of the fixed size HTTP/2 structures (i.e. those defined
// in net/http2/http2_structures.h).

// TODO(jamessynge): Combine tests of DoDecode, MaybeDecode, SlowDecode and
// Http2StructureDecoder test using gUnit's support for tests parameterized
// by type.

#include <stddef.h>
#include <string>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/http2/http2_constants.h"
#include "net/http2/http2_structures_test_util.h"
#include "net/http2/tools/http2_frame_builder.h"
#include "net/http2/tools/random_decoder_test.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::AssertionFailure;
using ::testing::AssertionResult;
using ::testing::AssertionSuccess;
using base::StringPiece;
using std::string;

namespace net {
namespace test {
namespace {

template <class S>
string SerializeStructure(const S& s) {
  Http2FrameBuilder fb;
  fb.Append(s);
  EXPECT_EQ(S::EncodedSize(), fb.size());
  return fb.buffer();
}

template <class S>
class StructureDecoderTest : public RandomDecoderTest {
 protected:
  typedef S Structure;

  StructureDecoderTest() {
    // IF the test adds more data after the encoded structure, stop as
    // soon as the structure is decoded.
    stop_decode_on_done_ = true;
  }

  // Reset the decoding to the start of the structure, and overwrite the
  // current contents of |structure_|, in to which we'll decode the buffer.
  DecodeStatus StartDecoding(DecodeBuffer* b) override {
    decode_offset_ = 0;
    Randomize(&structure_);
    return ResumeDecoding(b);
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* b) override {
    // If we're at the start...
    if (decode_offset_ == 0) {
      const uint32_t start_offset = b->Offset();
      const char* const start_cursor = b->cursor();
      // ... attempt to decode the entire structure.
      if (MaybeDecode(&structure_, b)) {
        ++fast_decode_count_;
        EXPECT_EQ(S::EncodedSize(), b->Offset() - start_offset);

        if (!HasFailure()) {
          // Success. Confirm that SlowDecode produces the same result.
          DecodeBuffer b2(start_cursor, b->Offset() - start_offset);
          S second;
          Randomize(&second);
          uint32_t second_offset = 0;
          EXPECT_TRUE(SlowDecode(&second, &b2, &second_offset));
          EXPECT_EQ(S::EncodedSize(), second_offset);
          EXPECT_EQ(structure_, second);
        }

        // Test can't easily tell if MaybeDecode or SlowDecode is used, so
        // update decode_offset_ as if SlowDecode had been used to completely
        // decode.
        decode_offset_ = S::EncodedSize();
        return DecodeStatus::kDecodeDone;
      }
    }

    // We didn't have enough in the first buffer to decode everything, so we'll
    // reach here multiple times until we've completely decoded the structure.
    if (SlowDecode(&structure_, b, &decode_offset_)) {
      ++slow_decode_count_;
      EXPECT_EQ(S::EncodedSize(), decode_offset_);
      return DecodeStatus::kDecodeDone;
    }

    // Drained the input buffer, but not yet done.
    EXPECT_TRUE(b->Empty());
    EXPECT_GT(S::EncodedSize(), decode_offset_);

    return DecodeStatus::kDecodeInProgress;
  }

  // Set the fields of |*p| to random values.
  void Randomize(S* p) { ::net::test::Randomize(p, RandomPtr()); }

  // Fully decodes the Structure at the start of data, and confirms it matches
  // *expected (if provided).
  void DecodeLeadingStructure(const S* expected, StringPiece data) {
    ASSERT_LE(S::EncodedSize(), data.size());
    DecodeBuffer original(data);

    // The validator is called after each of the several times that the input
    // DecodeBuffer is decoded, each with a different segmentation of the input.
    // Validate that structure_ matches the expected value, if provided.
    Validator validator = [expected, this](
        const DecodeBuffer& db, DecodeStatus status) -> AssertionResult {
      if (expected != nullptr && *expected != structure_) {
        return AssertionFailure()
               << "Expected structs to be equal\nExpected: " << *expected
               << "\n  Actual: " << structure_;
      }
      return AssertionSuccess();
    };

    // First validate that decoding is done and that we've advanced the cursor
    // the expected amount.
    validator = ValidateDoneAndOffset(S::EncodedSize(), validator);

    // Decode several times, with several segmentations of the input buffer.
    fast_decode_count_ = 0;
    slow_decode_count_ = 0;
    EXPECT_TRUE(DecodeAndValidateSeveralWays(
        &original, false /*return_non_zero_on_first*/, validator));

    if (!HasFailure()) {
      EXPECT_EQ(S::EncodedSize(), decode_offset_);
      EXPECT_EQ(S::EncodedSize(), original.Offset());
      EXPECT_LT(0u, fast_decode_count_);
      EXPECT_LT(0u, slow_decode_count_);
      if (expected != nullptr) {
        DVLOG(1) << "DecodeLeadingStructure expected: " << *expected;
        DVLOG(1) << "DecodeLeadingStructure   actual: " << structure_;
        EXPECT_EQ(*expected, structure_);
      }
    }
  }

  template <size_t N>
  void DecodeLeadingStructure(const char (&data)[N]) {
    DecodeLeadingStructure(nullptr, StringPiece(data, N));
  }

  // Encode the structure |in_s| into bytes, then decode the bytes
  // and validate that the decoder produced the same field values.
  void EncodeThenDecode(const S& in_s) {
    string bytes = SerializeStructure(in_s);
    EXPECT_EQ(S::EncodedSize(), bytes.size());
    DecodeLeadingStructure(&in_s, bytes);
  }

  // Generate
  void TestDecodingRandomizedStructures(size_t count) {
    for (size_t i = 0; i < count && !HasFailure(); ++i) {
      Structure input;
      Randomize(&input);
      EncodeThenDecode(input);
    }
  }

  uint32_t decode_offset_ = 0;
  S structure_;
  size_t fast_decode_count_ = 0;
  size_t slow_decode_count_ = 0;
};

class FrameHeaderDecoderTest : public StructureDecoderTest<Http2FrameHeader> {};

TEST_F(FrameHeaderDecoderTest, DecodesLiteral) {
  {
    // Realistic input.
    const char kData[] = {
        0x00, 0x00, 0x05,        // Payload length: 5
        0x01,                    // Frame type: HEADERS
        0x08,                    // Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream ID: 1
        0x04,                    // Padding length: 4
        0x00, 0x00, 0x00, 0x00,  // Padding bytes
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(5u, structure_.payload_length);
      EXPECT_EQ(Http2FrameType::HEADERS, structure_.type);
      EXPECT_EQ(Http2FrameFlag::FLAG_PADDED, structure_.flags);
      EXPECT_EQ(1u, structure_.stream_id);
    }
  }
  {
    // Unlikely input.
    const char kData[] = {
        0xffu, 0xffu, 0xffu,         // Payload length: uint24 max
        0xffu,                       // Frame type: Unknown
        0xffu,                       // Flags: Unknown/All
        0xffu, 0xffu, 0xffu, 0xffu,  // Stream ID: uint31 max, plus R-bit
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ((1u << 24) - 1, structure_.payload_length);
      EXPECT_EQ(static_cast<Http2FrameType>(255), structure_.type);
      EXPECT_EQ(255, structure_.flags);
      EXPECT_EQ(0x7FFFFFFFu, structure_.stream_id);
    }
  }
}

TEST_F(FrameHeaderDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class PriorityFieldsDecoderTest
    : public StructureDecoderTest<Http2PriorityFields> {};

TEST_F(PriorityFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x80u, 0x00, 0x00, 0x05,  // Exclusive (yes) and Dependency (5)
        0xffu,                    // Weight: 256 (after adding 1)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(5u, structure_.stream_dependency);
      EXPECT_EQ(256u, structure_.weight);
      EXPECT_EQ(true, structure_.is_exclusive);
    }
  }
  {
    const char kData[] = {
        0x7f,  0xffu,
        0xffu, 0xffu,  // Exclusive (no) and Dependency (0x7fffffff)
        0x00,          // Weight: 1 (after adding 1)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.stream_dependency);
      EXPECT_EQ(1u, structure_.weight);
      EXPECT_FALSE(structure_.is_exclusive);
    }
  }
}

TEST_F(PriorityFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class RstStreamFieldsDecoderTest
    : public StructureDecoderTest<Http2RstStreamFields> {};

TEST_F(RstStreamFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Error: PROTOCOL_ERROR
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_TRUE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(Http2ErrorCode::PROTOCOL_ERROR, structure_.error_code);
    }
  }
  {
    const char kData[] = {
        0xffu, 0xffu, 0xffu, 0xffu,  // Error: max uint32 (Unknown error code)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_FALSE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_.error_code);
    }
  }
}

TEST_F(RstStreamFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class SettingFieldsDecoderTest
    : public StructureDecoderTest<Http2SettingFields> {};

TEST_F(SettingFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x00, 0x01,              // Setting: HEADER_TABLE_SIZE
        0x00, 0x00, 0x40, 0x00,  // Value: 16K
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_TRUE(structure_.IsSupportedParameter());
      EXPECT_EQ(Http2SettingsParameter::HEADER_TABLE_SIZE,
                structure_.parameter);
      EXPECT_EQ(1u << 14, structure_.value);
    }
  }
  {
    const char kData[] = {
        0x00,  0x00,                 // Setting: Unknown (0)
        0xffu, 0xffu, 0xffu, 0xffu,  // Value: max uint32
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_FALSE(structure_.IsSupportedParameter());
      EXPECT_EQ(static_cast<Http2SettingsParameter>(0), structure_.parameter);
    }
  }
}

TEST_F(SettingFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class PushPromiseFieldsDecoderTest
    : public StructureDecoderTest<Http2PushPromiseFields> {};

TEST_F(PushPromiseFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x00, 0x01, 0x8au, 0x92u,  // Promised Stream ID: 101010
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(101010u, structure_.promised_stream_id);
    }
  }
  {
    // Promised stream id has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    const char kData[] = {
        0xffu, 0xffu, 0xffu, 0xffu,  // Promised Stream ID: max uint31 and R-bit
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.promised_stream_id);
    }
  }
}

TEST_F(PushPromiseFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class PingFieldsDecoderTest : public StructureDecoderTest<Http2PingFields> {};

TEST_F(PingFieldsDecoderTest, DecodesLiteral) {
  {
    // Each byte is different, so can detect if order changed.
    const char kData[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StringPiece(kData, 8), ToStringPiece(structure_.opaque_data));
    }
  }
  {
    // All zeros, detect problems handling NULs.
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StringPiece(kData, 8), ToStringPiece(structure_.opaque_data));
    }
  }
  {
    const char kData[] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StringPiece(kData, 8), ToStringPiece(structure_.opaque_data));
    }
  }
}

TEST_F(PingFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class GoAwayFieldsDecoderTest : public StructureDecoderTest<Http2GoAwayFields> {
};

TEST_F(GoAwayFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Last Stream ID: 0
        0x00, 0x00, 0x00, 0x00,  // Error: NO_ERROR (0)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(0u, structure_.last_stream_id);
      EXPECT_TRUE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(Http2ErrorCode::HTTP2_NO_ERROR, structure_.error_code);
    }
  }
  {
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Last Stream ID: 1
        0x00, 0x00, 0x00, 0x0d,  // Error: HTTP_1_1_REQUIRED
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(1u, structure_.last_stream_id);
      EXPECT_TRUE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(Http2ErrorCode::HTTP_1_1_REQUIRED, structure_.error_code);
    }
  }
  {
    const char kData[] = {
        0xffu, 0xffu, 0xffu, 0xffu,  // Last Stream ID: max uint31 and R-bit
        0xffu, 0xffu, 0xffu, 0xffu,  // Error: max uint32 (Unknown error code)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.last_stream_id);  // No high-bit.
      EXPECT_FALSE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_.error_code);
    }
  }
}

TEST_F(GoAwayFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class WindowUpdateFieldsDecoderTest
    : public StructureDecoderTest<Http2WindowUpdateFields> {};

TEST_F(WindowUpdateFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x00, 0x01, 0x00, 0x00,  // Window Size Increment: 2 ^ 16
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(1u << 16, structure_.window_size_increment);
    }
  }
  {
    // Increment must be non-zero, but we need to be able to decode the invalid
    // zero to detect it.
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Window Size Increment: 0
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(0u, structure_.window_size_increment);
    }
  }
  {
    // Increment has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    const char kData[] = {
        0xffu, 0xffu, 0xffu,
        0xffu,  // Window Size Increment: max uint31 and R-bit
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.window_size_increment);
    }
  }
}

TEST_F(WindowUpdateFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

//------------------------------------------------------------------------------

class AltSvcFieldsDecoderTest : public StructureDecoderTest<Http2AltSvcFields> {
};

TEST_F(AltSvcFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        0x00, 0x00,  // Origin Length: 0
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(0, structure_.origin_length);
    }
  }
  {
    const char kData[] = {
        0x00, 0x14,  // Origin Length: 20
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(20, structure_.origin_length);
    }
  }
  {
    const char kData[] = {
        0xffu, 0xffu,  // Origin Length: uint16 max
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(65535, structure_.origin_length);
    }
  }
}

TEST_F(AltSvcFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures(100);
}

}  // namespace
}  // namespace test
}  // namespace net
