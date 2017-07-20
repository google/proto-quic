// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ntlm/ntlm_buffer_reader.h"

#include "base/macros.h"
#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace ntlm {

TEST(NtlmBufferReaderTest, Initialization) {
  const uint8_t buf[1] = {0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_EQ(arraysize(buf), reader.GetLength());
  ASSERT_EQ(0u, reader.GetCursor());
  ASSERT_FALSE(reader.IsEndOfBuffer());
  ASSERT_TRUE(reader.CanRead(1));
  ASSERT_FALSE(reader.CanRead(2));
  ASSERT_TRUE(reader.CanReadFrom(0, 1));
  ASSERT_TRUE(reader.CanReadFrom(SecurityBuffer(0, 1)));
  ASSERT_FALSE(reader.CanReadFrom(1, 1));
  ASSERT_FALSE(reader.CanReadFrom(SecurityBuffer(1, 1)));
  ASSERT_FALSE(reader.CanReadFrom(0, 2));
  ASSERT_FALSE(reader.CanReadFrom(SecurityBuffer(0, 2)));

  // With length=0 the offset can be out of bounds.
  ASSERT_TRUE(reader.CanReadFrom(99, 0));
  ASSERT_TRUE(reader.CanReadFrom(SecurityBuffer(99, 0)));
}

TEST(NtlmBufferReaderTest, Read16) {
  const uint8_t buf[2] = {0x22, 0x11};
  const uint16_t expected = 0x1122;

  NtlmBufferReader reader(buf, arraysize(buf));

  uint16_t actual;
  ASSERT_TRUE(reader.ReadUInt16(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadUInt16(&actual));
}

TEST(NtlmBufferReaderTest, Read32) {
  const uint8_t buf[4] = {0x44, 0x33, 0x22, 0x11};
  const uint32_t expected = 0x11223344;

  NtlmBufferReader reader(buf, arraysize(buf));

  uint32_t actual;
  ASSERT_TRUE(reader.ReadUInt32(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadUInt32(&actual));
}

TEST(NtlmBufferReaderTest, Read64) {
  const uint8_t buf[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  const uint64_t expected = 0x1122334455667788;

  NtlmBufferReader reader(buf, arraysize(buf));

  uint64_t actual;
  ASSERT_TRUE(reader.ReadUInt64(&actual));
  ASSERT_EQ(expected, actual);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadUInt64(&actual));
}

TEST(NtlmBufferReaderTest, ReadBytes) {
  const uint8_t expected[8] = {0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
  uint8_t actual[8];

  NtlmBufferReader reader(expected, arraysize(expected));

  ASSERT_TRUE(reader.ReadBytes(actual, arraysize(actual)));
  ASSERT_EQ(0, memcmp(actual, expected, arraysize(actual)));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadBytes(actual, 1));
}

TEST(NtlmBufferReaderTest, ReadSecurityBuffer) {
  const uint8_t buf[8] = {0x22, 0x11, 0xFF, 0xEE, 0x88, 0x77, 0x66, 0x55};
  const uint16_t length = 0x1122;
  const uint32_t offset = 0x55667788;

  NtlmBufferReader reader(buf, arraysize(buf));

  SecurityBuffer sec_buf;
  ASSERT_TRUE(reader.ReadSecurityBuffer(&sec_buf));
  ASSERT_EQ(length, sec_buf.length);
  ASSERT_EQ(offset, sec_buf.offset);
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.ReadSecurityBuffer(&sec_buf));
}

TEST(NtlmBufferReaderTest, ReadSecurityBufferPastEob) {
  const uint8_t buf[7] = {0};
  NtlmBufferReader reader(buf, arraysize(buf));

  SecurityBuffer sec_buf;
  ASSERT_FALSE(reader.ReadSecurityBuffer(&sec_buf));
}

TEST(NtlmBufferReaderTest, SkipSecurityBuffer) {
  const uint8_t buf[kSecurityBufferLen] = {0};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_TRUE(reader.SkipSecurityBuffer());
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.SkipSecurityBuffer());
}

TEST(NtlmBufferReaderTest, SkipSecurityBufferPastEob) {
  // The buffer is one byte shorter than security buffer.
  const uint8_t buf[kSecurityBufferLen - 1] = {0};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_FALSE(reader.SkipSecurityBuffer());
}

TEST(NtlmBufferReaderTest, SkipSecurityBufferWithValidationEmpty) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest, SkipSecurityBufferWithValidationValid) {
  // A valid security buffer that points to the 1 payload byte.
  const uint8_t buf[kSecurityBufferLen + 1] = {
      0x01, 0, 0x01, 0, kSecurityBufferLen, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest,
     SkipSecurityBufferWithValidationPayloadLengthPastEob) {
  // Security buffer with length that points past the end of buffer.
  const uint8_t buf[kSecurityBufferLen + 1] = {
      0x02, 0, 0x02, 0, kSecurityBufferLen, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest,
     SkipSecurityBufferWithValidationPayloadOffsetPastEob) {
  // Security buffer with offset that points past the end of buffer.
  const uint8_t buf[kSecurityBufferLen + 1] = {
      0x02, 0, 0x02, 0, kSecurityBufferLen + 1, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_FALSE(reader.SkipSecurityBufferWithValidation());
}

TEST(NtlmBufferReaderTest,
     SkipSecurityBufferWithValidationZeroLengthPayloadOffsetPastEob) {
  // Security buffer with offset that points past the end of buffer but
  // length is 0.
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, kSecurityBufferLen + 1,
                                           0, 0, 0};

  NtlmBufferReader reader(buf, arraysize(buf));
  ASSERT_TRUE(reader.SkipSecurityBufferWithValidation());
  ASSERT_EQ(kSecurityBufferLen, reader.GetCursor());
}

TEST(NtlmBufferReaderTest, SkipBytes) {
  const uint8_t buf[8] = {0};

  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.SkipBytes(arraysize(buf)));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.SkipBytes(arraysize(buf)));
}

TEST(NtlmBufferReaderTest, SkipBytesPastEob) {
  const uint8_t buf[8] = {0};

  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_FALSE(reader.SkipBytes(arraysize(buf) + 1));
}

TEST(NtlmBufferReaderTest, MatchSignatureTooShort) {
  const uint8_t buf[7] = {0};

  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.CanRead(7));
  ASSERT_FALSE(reader.MatchSignature());
}

TEST(NtlmBufferReaderTest, MatchSignatureNoMatch) {
  // The last byte should be a 0.
  const uint8_t buf[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0xff};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.CanRead(8));
  ASSERT_FALSE(reader.MatchSignature());
}

TEST(NtlmBufferReaderTest, MatchSignatureOk) {
  const uint8_t buf[8] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.MatchSignature());
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadInvalidMessageType) {
  // Only 0x01, 0x02, and 0x03 are valid message types.
  const uint8_t buf[4] = {0x04, 0, 0, 0};
  NtlmBufferReader reader(buf, arraysize(buf));

  MessageType message_type;
  ASSERT_FALSE(reader.ReadMessageType(&message_type));
}

TEST(NtlmBufferReaderTest, ReadMessageTypeNegotiate) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kNegotiate), 0, 0,
                          0};
  NtlmBufferReader reader(buf, arraysize(buf));

  MessageType message_type;
  ASSERT_TRUE(reader.ReadMessageType(&message_type));
  ASSERT_EQ(MessageType::kNegotiate, message_type);
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadMessageTypeChallenge) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kChallenge), 0, 0,
                          0};
  NtlmBufferReader reader(buf, arraysize(buf));

  MessageType message_type;
  ASSERT_TRUE(reader.ReadMessageType(&message_type));
  ASSERT_EQ(MessageType::kChallenge, message_type);
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, ReadMessageTypeAuthenticate) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kAuthenticate), 0,
                          0, 0};
  NtlmBufferReader reader(buf, arraysize(buf));

  MessageType message_type;
  ASSERT_TRUE(reader.ReadMessageType(&message_type));
  ASSERT_EQ(MessageType::kAuthenticate, message_type);
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchMessageTypeAuthenticate) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kAuthenticate), 0,
                          0, 0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.MatchMessageType(MessageType::kAuthenticate));
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchMessageTypeInvalid) {
  // Only 0x01, 0x02, and 0x03 are valid message types.
  const uint8_t buf[4] = {0x04, 0, 0, 0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_FALSE(reader.MatchMessageType(MessageType::kAuthenticate));
}

TEST(NtlmBufferReaderTest, MatchMessageTypeMismatch) {
  const uint8_t buf[4] = {static_cast<uint8_t>(MessageType::kChallenge), 0, 0,
                          0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_FALSE(reader.MatchMessageType(MessageType::kAuthenticate));
}

TEST(NtlmBufferReaderTest, MatchAuthenticateHeader) {
  const uint8_t buf[12] = {
      'N', 'T', 'L',
      'M', 'S', 'S',
      'P', 0,   static_cast<uint8_t>(MessageType::kAuthenticate),
      0,   0,   0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.MatchMessageHeader(MessageType::kAuthenticate));
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchAuthenticateHeaderMisMatch) {
  const uint8_t buf[12] = {
      'N', 'T', 'L',
      'M', 'S', 'S',
      'P', 0,   static_cast<uint8_t>(MessageType::kChallenge),
      0,   0,   0};
  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_FALSE(reader.MatchMessageType(MessageType::kAuthenticate));
}

TEST(NtlmBufferReaderTest, MatchZeros) {
  const uint8_t buf[6] = {0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_TRUE(reader.MatchZeros(arraysize(buf)));
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.MatchZeros(1));
}

TEST(NtlmBufferReaderTest, MatchZerosFail) {
  const uint8_t buf[6] = {0, 0, 0, 0, 0, 0xFF};

  NtlmBufferReader reader(buf, arraysize(buf));

  ASSERT_FALSE(reader.MatchZeros(arraysize(buf)));
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBuffer) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0, 0, 0, 0};

  NtlmBufferReader reader(buf, kSecurityBufferLen);

  ASSERT_TRUE(reader.MatchEmptySecurityBuffer());
  ASSERT_TRUE(reader.IsEndOfBuffer());
  ASSERT_FALSE(reader.MatchEmptySecurityBuffer());
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBufferLengthZeroOffsetEnd) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0x08, 0, 0, 0};

  NtlmBufferReader reader(buf, kSecurityBufferLen);

  ASSERT_TRUE(reader.MatchEmptySecurityBuffer());
  ASSERT_TRUE(reader.IsEndOfBuffer());
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBufferLengthZeroPastEob) {
  const uint8_t buf[kSecurityBufferLen] = {0, 0, 0, 0, 0x09, 0, 0, 0};

  NtlmBufferReader reader(buf, kSecurityBufferLen);

  ASSERT_FALSE(reader.MatchEmptySecurityBuffer());
}

TEST(NtlmBufferReaderTest, MatchEmptySecurityBufferLengthNonZeroLength) {
  const uint8_t buf[kSecurityBufferLen + 1] = {0x01, 0, 0, 0,   0x08,
                                               0,    0, 0, 0xff};

  NtlmBufferReader reader(buf, kSecurityBufferLen);

  ASSERT_FALSE(reader.MatchEmptySecurityBuffer());
}

}  // namespace ntlm
}  // namespace net
