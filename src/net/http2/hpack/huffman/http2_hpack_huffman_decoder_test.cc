// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/huffman/http2_hpack_huffman_decoder.h"

// Tests of HpackHuffmanDecoder and HuffmanBitBuffer.

#include <iostream>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/http2/tools/failure.h"
#include "net/http2/tools/random_decoder_test.h"
#include "net/spdy/spdy_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::AssertionResult;
using ::testing::AssertionSuccess;
using base::StringPiece;
using std::string;

namespace net {
namespace test {
namespace {

TEST(HuffmanBitBufferTest, Reset) {
  HuffmanBitBuffer bb;
  EXPECT_TRUE(bb.IsEmpty());
  EXPECT_TRUE(bb.InputProperlyTerminated());
  EXPECT_EQ(bb.count(), 0u);
  EXPECT_EQ(bb.free_count(), 64u);
  EXPECT_EQ(bb.value(), 0u);
}

TEST(HuffmanBitBufferTest, AppendBytesAligned) {
  string s;
  s.push_back('\x11');
  s.push_back('\x22');
  s.push_back('\x33');
  StringPiece sp(s);

  HuffmanBitBuffer bb;
  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_TRUE(sp.empty());
  EXPECT_FALSE(bb.IsEmpty()) << bb;
  EXPECT_FALSE(bb.InputProperlyTerminated());
  EXPECT_EQ(bb.count(), 24u) << bb;
  EXPECT_EQ(bb.free_count(), 40u) << bb;
  EXPECT_EQ(bb.value(), HuffmanAccumulator(0x112233) << 40) << bb;

  s.clear();
  s.push_back('\x44');
  sp = s;

  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_TRUE(sp.empty());
  EXPECT_EQ(bb.count(), 32u) << bb;
  EXPECT_EQ(bb.free_count(), 32u) << bb;
  EXPECT_EQ(bb.value(), HuffmanAccumulator(0x11223344) << 32) << bb;

  s.clear();
  s.push_back('\x55');
  s.push_back('\x66');
  s.push_back('\x77');
  s.push_back('\x88');
  s.push_back('\x99');
  sp = s;

  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_EQ(sp.size(), 1u);
  EXPECT_EQ('\x99', sp[0]);
  EXPECT_EQ(bb.count(), 64u) << bb;
  EXPECT_EQ(bb.free_count(), 0u) << bb;
  EXPECT_EQ(bb.value(), HuffmanAccumulator(0x1122334455667788LL)) << bb;

  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_EQ(sp.size(), 1u);
  EXPECT_EQ('\x99', sp[0]);
  EXPECT_EQ(bb.count(), 64u) << bb;
  EXPECT_EQ(bb.free_count(), 0u) << bb;
  EXPECT_EQ(bb.value(), HuffmanAccumulator(0x1122334455667788LL)) << bb;
}

TEST(HuffmanBitBufferTest, ConsumeBits) {
  string s;
  s.push_back('\x11');
  s.push_back('\x22');
  s.push_back('\x33');
  StringPiece sp(s);

  HuffmanBitBuffer bb;
  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_TRUE(sp.empty());

  bb.ConsumeBits(1);
  EXPECT_EQ(bb.count(), 23u) << bb;
  EXPECT_EQ(bb.free_count(), 41u) << bb;
  EXPECT_EQ(bb.value(), HuffmanAccumulator(0x112233) << 41) << bb;

  bb.ConsumeBits(20);
  EXPECT_EQ(bb.count(), 3u) << bb;
  EXPECT_EQ(bb.free_count(), 61u) << bb;
  EXPECT_EQ(bb.value(), HuffmanAccumulator(0x3) << 61) << bb;
}

TEST(HuffmanBitBufferTest, AppendBytesUnaligned) {
  string s;
  s.push_back('\x11');
  s.push_back('\x22');
  s.push_back('\x33');
  s.push_back('\x44');
  s.push_back('\x55');
  s.push_back('\x66');
  s.push_back('\x77');
  s.push_back('\x88');
  s.push_back('\x99');
  s.push_back('\xaa');
  s.push_back('\xbb');
  s.push_back('\xcc');
  s.push_back('\xdd');
  StringPiece sp(s);

  HuffmanBitBuffer bb;
  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_EQ(sp.size(), 5u);
  EXPECT_FALSE(bb.InputProperlyTerminated());

  bb.ConsumeBits(15);
  EXPECT_EQ(bb.count(), 49u) << bb;
  EXPECT_EQ(bb.free_count(), 15u) << bb;

  HuffmanAccumulator expected(0x1122334455667788);
  expected <<= 15;
  EXPECT_EQ(bb.value(), expected);

  sp.remove_prefix(bb.AppendBytes(sp));
  EXPECT_EQ(sp.size(), 4u);
  EXPECT_EQ(bb.count(), 57u) << bb;
  EXPECT_EQ(bb.free_count(), 7u) << bb;

  expected |= (HuffmanAccumulator(0x99) << 7);
  EXPECT_EQ(bb.value(), expected) << bb << std::hex
                                  << "\n   actual: " << bb.value()
                                  << "\n expected: " << expected;
}

enum class DecoderChoice { IF_TREE, SHORT_CODE };

class HpackHuffmanDecoderTest
    : public RandomDecoderTest,
      public ::testing::WithParamInterface<DecoderChoice> {
 protected:
  HpackHuffmanDecoderTest() {
    // The decoder may return true, and its accumulator may be empty, at
    // many boundaries while decoding, and yet the whole string hasn't
    // been decoded.
    stop_decode_on_done_ = false;
  }

  DecodeStatus StartDecoding(DecodeBuffer* b) override {
    input_bytes_seen_ = 0;
    output_buffer_.clear();
    decoder_.Reset();
    return ResumeDecoding(b);
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* b) override {
    input_bytes_seen_ += b->Remaining();
    StringPiece sp(b->cursor(), b->Remaining());
    if (DecodeFragment(sp)) {
      b->AdvanceCursor(b->Remaining());
      // Successfully decoded (or buffered) the bytes in StringPiece.
      EXPECT_LE(input_bytes_seen_, input_bytes_expected_);
      // Have we reached the end of the encoded string?
      if (input_bytes_expected_ == input_bytes_seen_) {
        if (decoder_.InputProperlyTerminated()) {
          return DecodeStatus::kDecodeDone;
        } else {
          return DecodeStatus::kDecodeError;
        }
      }
      return DecodeStatus::kDecodeInProgress;
    }
    return DecodeStatus::kDecodeError;
  }

  bool DecodeFragment(StringPiece sp) {
    switch (GetParam()) {
      case DecoderChoice::IF_TREE:
        return decoder_.DecodeWithIfTreeAndStruct(sp, &output_buffer_);
      case DecoderChoice::SHORT_CODE:
        return decoder_.DecodeShortCodesFirst(sp, &output_buffer_);
    }

    NOTREACHED();
    return false;
  }

  AssertionResult HuffmanDecodeAndValidateSeveralWays(
      StringPiece encoded,
      StringPiece expected_plain) {
    input_bytes_expected_ = encoded.size();
    NoArgValidator validator = [expected_plain, this]() -> AssertionResult {
      VERIFY_EQ(output_buffer_.size(), expected_plain.size());
      VERIFY_EQ(output_buffer_, expected_plain);
      return AssertionSuccess();
    };
    DecodeBuffer db(encoded);
    bool return_non_zero_on_first = false;
    return DecodeAndValidateSeveralWays(&db, return_non_zero_on_first,
                                        ValidateDoneAndEmpty(validator));
  }

  HpackHuffmanDecoder decoder_;
  string output_buffer_;
  size_t input_bytes_seen_;
  size_t input_bytes_expected_;
};
INSTANTIATE_TEST_CASE_P(AllDecoders,
                        HpackHuffmanDecoderTest,
                        ::testing::Values(DecoderChoice::IF_TREE,
                                          DecoderChoice::SHORT_CODE));

TEST_P(HpackHuffmanDecoderTest, SpecRequestExamples) {
  HpackHuffmanDecoder decoder;
  string test_table[] = {
      a2b_hex("f1e3c2e5f23a6ba0ab90f4ff"),
      "www.example.com",
      a2b_hex("a8eb10649cbf"),
      "no-cache",
      a2b_hex("25a849e95ba97d7f"),
      "custom-key",
      a2b_hex("25a849e95bb8e8b4bf"),
      "custom-value",
  };
  for (size_t i = 0; i != arraysize(test_table); i += 2) {
    const string& huffman_encoded(test_table[i]);
    const string& plain_string(test_table[i + 1]);
    string buffer;
    decoder.Reset();
    EXPECT_TRUE(decoder.Decode(huffman_encoded, &buffer)) << decoder;
    EXPECT_TRUE(decoder.InputProperlyTerminated()) << decoder;
    EXPECT_EQ(buffer, plain_string);
  }
}

TEST_P(HpackHuffmanDecoderTest, SpecResponseExamples) {
  HpackHuffmanDecoder decoder;
  // clang-format off
  string test_table[] = {
    a2b_hex("6402"),
    "302",
    a2b_hex("aec3771a4b"),
    "private",
    a2b_hex("d07abe941054d444a8200595040b8166"
            "e082a62d1bff"),
    "Mon, 21 Oct 2013 20:13:21 GMT",
    a2b_hex("9d29ad171863c78f0b97c8e9ae82ae43"
            "d3"),
    "https://www.example.com",
    a2b_hex("94e7821dd7f2e6c7b335dfdfcd5b3960"
            "d5af27087f3672c1ab270fb5291f9587"
            "316065c003ed4ee5b1063d5007"),
    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
  };
  // clang-format on
  for (size_t i = 0; i != arraysize(test_table); i += 2) {
    const string& huffman_encoded(test_table[i]);
    const string& plain_string(test_table[i + 1]);
    string buffer;
    decoder.Reset();
    EXPECT_TRUE(decoder.Decode(huffman_encoded, &buffer)) << decoder;
    EXPECT_TRUE(decoder.InputProperlyTerminated()) << decoder;
    EXPECT_EQ(buffer, plain_string);
  }
}

}  // namespace
}  // namespace test
}  // namespace net
