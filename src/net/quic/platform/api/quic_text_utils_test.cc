// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/api/quic_text_utils.h"

#include <string>

#include "base/strings/string_piece.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::StringPiece;
using std::string;

namespace net {
namespace test {

TEST(QuicTextUtilsText, StartsWith) {
  EXPECT_TRUE(QuicTextUtils::StartsWith("hello world", "hello"));
  EXPECT_TRUE(QuicTextUtils::StartsWith("hello world", "hello world"));
  EXPECT_TRUE(QuicTextUtils::StartsWith("hello world", ""));
  EXPECT_FALSE(QuicTextUtils::StartsWith("hello world", "Hello"));
  EXPECT_FALSE(QuicTextUtils::StartsWith("hello world", "world"));
  EXPECT_FALSE(QuicTextUtils::StartsWith("hello world", "bar"));
}

TEST(QuicTextUtilsText, EndsWithIgnoreCase) {
  EXPECT_TRUE(QuicTextUtils::EndsWithIgnoreCase("hello world", "world"));
  EXPECT_TRUE(QuicTextUtils::EndsWithIgnoreCase("hello world", "hello world"));
  EXPECT_TRUE(QuicTextUtils::EndsWithIgnoreCase("hello world", ""));
  EXPECT_TRUE(QuicTextUtils::EndsWithIgnoreCase("hello world", "WORLD"));
  EXPECT_FALSE(QuicTextUtils::EndsWithIgnoreCase("hello world", "hello"));
}

TEST(QuicTextUtilsText, ToLower) {
  EXPECT_EQ("lower", QuicTextUtils::ToLower("LOWER"));
  EXPECT_EQ("lower", QuicTextUtils::ToLower("lower"));
  EXPECT_EQ("lower", QuicTextUtils::ToLower("lOwEr"));
  EXPECT_EQ("123", QuicTextUtils::ToLower("123"));
  EXPECT_EQ("", QuicTextUtils::ToLower(""));
}

TEST(QuicTextUtilsText, RemoveLeadingAndTrailingWhitespace) {
  string input;

  for (auto input : {"text", " text", "  text", "text ", "text  ", " text ",
                     "  text  ", "\r\n\ttext", "text\n\r\t"}) {
    StringPiece piece(input);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&piece);
    EXPECT_EQ("text", piece);
  }
}

TEST(QuicTextUtilsText, StringToUint64) {
  uint64_t val = 0;
  EXPECT_TRUE(QuicTextUtils::StringToUint64("123", &val));
  EXPECT_EQ(123u, val);
  EXPECT_TRUE(QuicTextUtils::StringToUint64("1234", &val));
  EXPECT_EQ(1234u, val);
  EXPECT_FALSE(QuicTextUtils::StringToUint64("", &val));
  EXPECT_FALSE(QuicTextUtils::StringToUint64("-123", &val));
  EXPECT_FALSE(QuicTextUtils::StringToUint64("-123.0", &val));
}

TEST(QuicTextUtilsText, Uint64ToString) {
  EXPECT_EQ("123", QuicTextUtils::Uint64ToString(123));
  EXPECT_EQ("1234", QuicTextUtils::Uint64ToString(1234));
}

TEST(QuicTextUtilsText, HexEncode) {
  EXPECT_EQ("48656c6c6f", QuicTextUtils::HexEncode("Hello", 5));
  EXPECT_EQ("48656c6c6f", QuicTextUtils::HexEncode("Hello World", 5));
  EXPECT_EQ("48656c6c6f", QuicTextUtils::HexEncode("Hello"));
}

TEST(QuicTextUtilsText, HexDecode) {
  EXPECT_EQ("Hello", QuicTextUtils::HexDecode("48656c6c6f"));
  EXPECT_EQ("", QuicTextUtils::HexDecode(""));
}

TEST(QuicTextUtilsText, HexDump) {
  // Verify output of the HexDump method is as expected.
  char packet[] = {
      0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x51, 0x55, 0x49, 0x43, 0x21,
      0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
      0x20, 0x73, 0x68, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x6c,
      0x6f, 0x6e, 0x67, 0x20, 0x65, 0x6e, 0x6f, 0x75, 0x67, 0x68, 0x20, 0x74,
      0x6f, 0x20, 0x73, 0x70, 0x61, 0x6e, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69,
      0x70, 0x6c, 0x65, 0x20, 0x6c, 0x69, 0x6e, 0x65, 0x73, 0x20, 0x6f, 0x66,
      0x20, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x2e, 0x01, 0x02, 0x03, 0x00,
  };
  EXPECT_EQ(
      QuicTextUtils::HexDump(packet),
      "0x0000:  4865 6c6c 6f2c 2051 5549 4321 2054 6869  Hello,.QUIC!.Thi\n"
      "0x0010:  7320 7374 7269 6e67 2073 686f 756c 6420  s.string.should.\n"
      "0x0020:  6265 206c 6f6e 6720 656e 6f75 6768 2074  be.long.enough.t\n"
      "0x0030:  6f20 7370 616e 206d 756c 7469 706c 6520  o.span.multiple.\n"
      "0x0040:  6c69 6e65 7320 6f66 206f 7574 7075 742e  lines.of.output.\n"
      "0x0050:  0102 03                                  ...\n");
}

TEST(QuicTextUtilsText, Base64Encode) {
  string output;
  string input = "Hello";
  QuicTextUtils::Base64Encode(reinterpret_cast<const uint8_t*>(input.data()),
                              input.length(), &output);
  EXPECT_EQ("SGVsbG8", output);

  input =
      "Hello, QUIC! This string should be long enough to span"
      "multiple lines of output\n";
  QuicTextUtils::Base64Encode(reinterpret_cast<const uint8_t*>(input.data()),
                              input.length(), &output);
  EXPECT_EQ(
      "SGVsbG8sIFFVSUMhIFRoaXMgc3RyaW5nIHNob3VsZCBiZSBsb25n"
      "IGVub3VnaCB0byBzcGFubXVsdGlwbGUgbGluZXMgb2Ygb3V0cHV0Cg",
      output);
}

TEST(QuicTextUtilsText, ContainsUpperCase) {
  EXPECT_FALSE(QuicTextUtils::ContainsUpperCase("abc"));
  EXPECT_FALSE(QuicTextUtils::ContainsUpperCase(""));
  EXPECT_FALSE(QuicTextUtils::ContainsUpperCase("123"));
  EXPECT_TRUE(QuicTextUtils::ContainsUpperCase("ABC"));
  EXPECT_TRUE(QuicTextUtils::ContainsUpperCase("aBc"));
}

TEST(QuicTextUtilsText, Split) {
  EXPECT_EQ(std::vector<StringPiece>({"a", "b", "c"}),
            QuicTextUtils::Split("a,b,c", ','));
  EXPECT_EQ(std::vector<StringPiece>({"a", "b", "c"}),
            QuicTextUtils::Split("a:b:c", ':'));
  EXPECT_EQ(std::vector<StringPiece>({"a:b:c"}),
            QuicTextUtils::Split("a:b:c", ','));
}

}  // namespace test
}  // namespace net
