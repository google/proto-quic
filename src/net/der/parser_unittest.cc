// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/numerics/safe_math.h"
#include "net/der/input.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace der {
namespace test {

TEST(ParserTest, ConsumesAllBytesOfTLV) {
  const uint8_t der[] = {0x04, 0x00};
  Parser parser((Input(der)));
  Tag tag;
  Input value;
  ASSERT_TRUE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_EQ(0x04, tag);
  ASSERT_FALSE(parser.HasMore());
}

TEST(ParserTest, CanReadRawTLV) {
  const uint8_t der[] = {0x02, 0x01, 0x01};
  Parser parser((Input(der)));
  Input tlv;
  ASSERT_TRUE(parser.ReadRawTLV(&tlv));
  ByteReader tlv_reader(tlv);
  size_t tlv_len = tlv_reader.BytesLeft();
  ASSERT_EQ(3u, tlv_len);
  Input tlv_data;
  ASSERT_TRUE(tlv_reader.ReadBytes(tlv_len, &tlv_data));
  ASSERT_FALSE(parser.HasMore());
}

TEST(ParserTest, IgnoresContentsOfInnerValues) {
  // This is a SEQUENCE which has one member. The member is another SEQUENCE
  // with an invalid encoding - its length is too long.
  const uint8_t der[] = {0x30, 0x02, 0x30, 0x7e};
  Parser parser((Input(der)));
  Tag tag;
  Input value;
  ASSERT_TRUE(parser.ReadTagAndValue(&tag, &value));
}

TEST(ParserTest, FailsIfLengthOverlapsAnotherTLV) {
  // This DER encoding has 2 top-level TLV tuples. The first is a SEQUENCE;
  // the second is an INTEGER. The SEQUENCE contains an INTEGER, but its length
  // is longer than what it has contents for.
  const uint8_t der[] = {0x30, 0x02, 0x02, 0x01, 0x02, 0x01, 0x01};
  Parser parser((Input(der)));

  Parser inner_sequence;
  ASSERT_TRUE(parser.ReadSequence(&inner_sequence));
  uint64_t int_value;
  ASSERT_TRUE(parser.ReadUint64(&int_value));
  ASSERT_EQ(1u, int_value);
  ASSERT_FALSE(parser.HasMore());

  // Try to read the INTEGER from the SEQUENCE, which should fail.
  Tag tag;
  Input value;
  ASSERT_FALSE(inner_sequence.ReadTagAndValue(&tag, &value));
}

TEST(ParserTest, CanSkipOptionalTagAtEndOfInput) {
  const uint8_t der[] = {0x02, 0x01, 0x01};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_TRUE(parser.ReadTagAndValue(&tag, &value));
  bool present;
  ASSERT_TRUE(parser.ReadOptionalTag(0x02, &value, &present));
  ASSERT_FALSE(present);
  ASSERT_FALSE(parser.HasMore());
}

TEST(ParserTest, SkipOptionalTagDoesntConsumePresentNonMatchingTLVs) {
  const uint8_t der[] = {0x02, 0x01, 0x01};
  Parser parser((Input(der)));

  bool present;
  ASSERT_TRUE(parser.SkipOptionalTag(0x04, &present));
  ASSERT_FALSE(present);
  ASSERT_TRUE(parser.SkipOptionalTag(0x02, &present));
  ASSERT_TRUE(present);
  ASSERT_FALSE(parser.HasMore());
}

TEST(ParserTest, TagNumbersAboveThirtyUnsupported) {
  // Context-specific class, tag number 31, length 0.
  const uint8_t der[] = {0x9f, 0x1f, 0x00};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_FALSE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_TRUE(parser.HasMore());
}

TEST(ParserTest, IncompleteEncodingTagOnly) {
  const uint8_t der[] = {0x01};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_FALSE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_TRUE(parser.HasMore());
}

TEST(ParserTest, IncompleteEncodingLengthTruncated) {
  // Tag: octet string; length: long form, should have 2 total octets, but
  // the last one is missing. (There's also no value.)
  const uint8_t der[] = {0x04, 0x81};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_FALSE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_TRUE(parser.HasMore());
}

TEST(ParserTest, IncompleteEncodingValueShorterThanLength) {
  // Tag: octet string; length: 2; value: first octet 'T', second octet missing.
  const uint8_t der[] = {0x04, 0x02, 0x84};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_FALSE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_TRUE(parser.HasMore());
}

TEST(ParserTest, LengthMustBeEncodedWithMinimumNumberOfOctets) {
  const uint8_t der[] = {0x01, 0x81, 0x01, 0x00};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_FALSE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_TRUE(parser.HasMore());
}

TEST(ParserTest, LengthMustNotHaveLeadingZeroes) {
  // Tag: octet string; length: 3 bytes of length encoding a value of 128
  // (it should be encoded in only 2 bytes). Value: 128 bytes of 0.
  const uint8_t der[] = {
      0x04, 0x83, 0x80, 0x81, 0x80,  // group the 0s separately
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  Parser parser((Input(der)));

  Tag tag;
  Input value;
  ASSERT_FALSE(parser.ReadTagAndValue(&tag, &value));
  ASSERT_TRUE(parser.HasMore());
}

TEST(ParserTest, ReadConstructedFailsForNonConstructedTags) {
  // Tag number is for SEQUENCE, but the constructed bit isn't set.
  const uint8_t der[] = {0x10, 0x00};
  Parser parser((Input(der)));

  Tag expected_tag = 0x10;
  Parser sequence_parser;
  ASSERT_FALSE(parser.ReadConstructed(expected_tag, &sequence_parser));

  // Check that we didn't fail above because of a tag mismatch or an improperly
  // encoded TLV.
  Input value;
  ASSERT_TRUE(parser.ReadTag(expected_tag, &value));
  ASSERT_FALSE(parser.HasMore());
}

TEST(ParserTest, CannotAdvanceAfterReadOptionalTag) {
  const uint8_t der[] = {0x02, 0x01, 0x01};
  Parser parser((Input(der)));

  Input value;
  bool present;
  ASSERT_TRUE(parser.ReadOptionalTag(0x04, &value, &present));
  ASSERT_FALSE(present);
  ASSERT_FALSE(parser.Advance());
}

// Reads a valid BIT STRING with 1 unused bit.
TEST(ParserTest, ReadBitString) {
  const uint8_t der[] = {0x03, 0x03, 0x01, 0xAA, 0xBE};
  Parser parser((Input(der)));

  BitString bit_string;
  ASSERT_TRUE(parser.ReadBitString(&bit_string));
  EXPECT_FALSE(parser.HasMore());

  EXPECT_EQ(1u, bit_string.unused_bits());
  ASSERT_EQ(2u, bit_string.bytes().Length());
  EXPECT_EQ(0xAA, bit_string.bytes().UnsafeData()[0]);
  EXPECT_EQ(0xBE, bit_string.bytes().UnsafeData()[1]);
}

// Tries reading a BIT STRING. This should fail because the tag is not for a
// BIT STRING.
TEST(ParserTest, ReadBitStringBadTag) {
  const uint8_t der[] = {0x05, 0x03, 0x01, 0xAA, 0xBE};
  Parser parser((Input(der)));

  BitString bit_string;
  EXPECT_FALSE(parser.ReadBitString(&bit_string));
}

}  // namespace test
}  // namespace der
}  // namespace net
