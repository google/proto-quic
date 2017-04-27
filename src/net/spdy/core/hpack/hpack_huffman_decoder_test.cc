// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/core/hpack/hpack_huffman_decoder.h"

#include <bitset>
#include <limits>

#include "base/logging.h"
#include "base/macros.h"
#include "base/rand_util.h"
#include "net/spdy/core/hpack/hpack_constants.h"
#include "net/spdy/core/hpack/hpack_huffman_table.h"
#include "net/spdy/core/hpack/hpack_input_stream.h"
#include "net/spdy/core/hpack/hpack_output_stream.h"
#include "net/spdy/core/spdy_test_utils.h"
#include "net/spdy/platform/api/spdy_string_piece.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace test {

namespace {

uint32_t RandUint32() {
  return static_cast<uint32_t>(base::RandUint64() & 0xffffffff);
}

}  // anonymous namespace

// Bits(HuffmanWord) constructs a bitset<32>, which produces nicely formatted
// binary numbers when LOG'd.
typedef std::bitset<32> Bits;

typedef HpackHuffmanDecoder::HuffmanWord HuffmanWord;
typedef HpackHuffmanDecoder::HuffmanCodeLength HuffmanCodeLength;

class HpackHuffmanDecoderPeer {
 public:
  static HuffmanCodeLength CodeLengthOfPrefix(HuffmanWord value) {
    return HpackHuffmanDecoder::CodeLengthOfPrefix(value);
  }

  static HuffmanWord DecodeToCanonical(HuffmanCodeLength code_length,
                                       HuffmanWord bits) {
    return HpackHuffmanDecoder::DecodeToCanonical(code_length, bits);
  }

  static char CanonicalToSource(HuffmanWord canonical) {
    return HpackHuffmanDecoder::CanonicalToSource(canonical);
  }
};

// Tests of the ability to decode the HPACK Huffman Code, defined in:
//     https://httpwg.github.io/specs/rfc7541.html#huffman.code
class HpackHuffmanDecoderTest : public ::testing::Test {
 protected:
  HpackHuffmanDecoderTest() : table_(ObtainHpackHuffmanTable()) {}

  // Since kHpackHuffmanCode doesn't include the canonical symbol value,
  // this helper helps us to decode directly to the source symbol, allowing
  // for EOS.
  uint16_t DecodeToSource(HuffmanCodeLength code_length, HuffmanWord bits) {
    HuffmanWord canonical =
        HpackHuffmanDecoderPeer::DecodeToCanonical(code_length, bits);
    EXPECT_LE(canonical, 256u);
    if (canonical == 256u) {
      return canonical;
    }
    return static_cast<unsigned char>(
        HpackHuffmanDecoderPeer::CanonicalToSource(canonical));
  }

  void EncodeString(SpdyStringPiece input, SpdyString* encoded) {
    HpackOutputStream output_stream;
    table_.EncodeString(input, &output_stream);
    encoded->clear();
    output_stream.TakeString(encoded);
    // Verify EncodedSize() agrees with EncodeString().
    EXPECT_EQ(encoded->size(), table_.EncodedSize(input));
  }

  SpdyString EncodeString(SpdyStringPiece input) {
    SpdyString result;
    EncodeString(input, &result);
    return result;
  }

  const HpackHuffmanTable& table_;
};

TEST_F(HpackHuffmanDecoderTest, CodeLengthOfPrefix) {
  for (const HpackHuffmanSymbol& entry : HpackHuffmanCode()) {
    // First confirm our assumption that the low order bits of entry.code
    // (those not part of the high order entry.length bits) are zero.
    uint32_t non_code_bits = 0xffffffff >> entry.length;
    EXPECT_EQ(0u, entry.code & non_code_bits);

    // entry.code has a code length of entry.length.
    EXPECT_EQ(entry.length,
              HpackHuffmanDecoderPeer::CodeLengthOfPrefix(entry.code))
        << "Full code: " << Bits(entry.code) << "\n"
        << "       ID: " << entry.id;

    // Let's try again with all the low order bits set to 1.
    uint32_t bits = entry.code | (0xffffffff >> entry.length);
    EXPECT_EQ(entry.length, HpackHuffmanDecoderPeer::CodeLengthOfPrefix(bits))
        << "Full code: " << Bits(entry.code) << "\n"
        << "     bits: " << Bits(bits) << "\n"
        << "       ID: " << entry.id;

    // Let's try again with random low order bits.
    uint32_t rand = RandUint32() & (0xffffffff >> entry.length);
    bits = entry.code | rand;
    EXPECT_EQ(entry.length, HpackHuffmanDecoderPeer::CodeLengthOfPrefix(bits))
        << "Full code: " << Bits(entry.code) << "\n"
        << "     rand: " << Bits(rand) << "\n"
        << "     bits: " << Bits(bits) << "\n"
        << "       ID: " << entry.id;

    // If fewer bits are available and low order bits are zero after left
    // shifting (should be true), CodeLengthOfPrefix should never return
    // a value that is <= the number of available bits.
    for (uint8_t available = entry.length - 1; available > 0; --available) {
      uint32_t mask = 0xffffffff;
      uint32_t avail_mask = mask << (32 - available);
      bits = entry.code & avail_mask;
      EXPECT_LT(available, HpackHuffmanDecoderPeer::CodeLengthOfPrefix(bits))
          << "Full code: " << Bits(entry.code) << "\n"
          << "availMask: " << Bits(avail_mask) << "\n"
          << "     bits: " << Bits(bits) << "\n"
          << "       ID: " << entry.id;
    }
  }
}

TEST_F(HpackHuffmanDecoderTest, DecodeToSource) {
  for (const HpackHuffmanSymbol& entry : HpackHuffmanCode()) {
    // Check that entry.code, which has all the low order bits set to 0,
    // decodes to entry.id.
    EXPECT_EQ(entry.id, DecodeToSource(entry.length, entry.code))
        << "   Length: " << entry.length << "\n"
        << "Full code: " << Bits(entry.code);

    // Let's try again with all the low order bits set to 1.
    uint32_t bits = entry.code | (0xffffffff >> entry.length);
    EXPECT_EQ(entry.id, DecodeToSource(entry.length, bits))
        << "   Length: " << entry.length << "\n"
        << "Full code: " << Bits(entry.code) << "\n"
        << "     bits: " << Bits(bits);

    // Let's try again with random low order bits.
    uint32_t rand = RandUint32() & (0xffffffff >> entry.length);
    bits = entry.code | rand;
    EXPECT_EQ(entry.id, DecodeToSource(entry.length, bits))
        << "   Length: " << entry.length << "\n"
        << "Full code: " << Bits(entry.code) << "\n"
        << "     rand: " << Bits(rand) << "\n"
        << "     bits: " << Bits(bits);
  }
}

TEST_F(HpackHuffmanDecoderTest, SpecRequestExamples) {
  SpdyString buffer;
  SpdyString test_table[] = {
      a2b_hex("f1e3c2e5f23a6ba0ab90f4ff"),
      "www.example.com",
      a2b_hex("a8eb10649cbf"),
      "no-cache",
      a2b_hex("25a849e95ba97d7f"),
      "custom-key",
      a2b_hex("25a849e95bb8e8b4bf"),
      "custom-value",
  };
  // Round-trip each test example.
  for (size_t i = 0; i != arraysize(test_table); i += 2) {
    const SpdyString& encodedFixture(test_table[i]);
    const SpdyString& decodedFixture(test_table[i + 1]);
    HpackInputStream input_stream(encodedFixture);
    EXPECT_TRUE(HpackHuffmanDecoder::DecodeString(&input_stream, &buffer));
    EXPECT_EQ(decodedFixture, buffer);
    buffer = EncodeString(decodedFixture);
    EXPECT_EQ(encodedFixture, buffer);
  }
}

TEST_F(HpackHuffmanDecoderTest, SpecResponseExamples) {
  SpdyString buffer;
  // clang-format off
  SpdyString test_table[] = {
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
  // Round-trip each test example.
  for (size_t i = 0; i != arraysize(test_table); i += 2) {
    const SpdyString& encodedFixture(test_table[i]);
    const SpdyString& decodedFixture(test_table[i + 1]);
    HpackInputStream input_stream(encodedFixture);
    EXPECT_TRUE(HpackHuffmanDecoder::DecodeString(&input_stream, &buffer));
    EXPECT_EQ(decodedFixture, buffer);
    buffer = EncodeString(decodedFixture);
    EXPECT_EQ(encodedFixture, buffer);
  }
}

TEST_F(HpackHuffmanDecoderTest, RoundTripIndividualSymbols) {
  for (size_t i = 0; i != 256; i++) {
    char c = static_cast<char>(i);
    char storage[3] = {c, c, c};
    SpdyStringPiece input(storage, arraysize(storage));
    SpdyString buffer_in = EncodeString(input);
    SpdyString buffer_out;
    HpackInputStream input_stream(buffer_in);
    EXPECT_TRUE(HpackHuffmanDecoder::DecodeString(&input_stream, &buffer_out));
    EXPECT_EQ(input, buffer_out);
  }
}

// Creates 256 input strings, each with a unique byte value i used to sandwich
// all the other higher byte values.
TEST_F(HpackHuffmanDecoderTest, RoundTripSymbolSequences) {
  SpdyString input;
  SpdyString encoded;
  SpdyString decoded;
  for (size_t i = 0; i != 256; i++) {
    input.clear();
    auto ic = static_cast<char>(i);
    input.push_back(ic);
    for (size_t j = i; j != 256; j++) {
      input.push_back(static_cast<char>(j));
      input.push_back(ic);
    }
    EncodeString(input, &encoded);
    HpackInputStream input_stream(encoded);
    EXPECT_TRUE(HpackHuffmanDecoder::DecodeString(&input_stream, &decoded));
    EXPECT_EQ(input, decoded);
  }
}

}  // namespace test
}  // namespace net
