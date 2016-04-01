// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "base/numerics/safe_math.h"
#include "net/der/parse_values.h"
#include "net/der/parser.h"

namespace net {

namespace der {

Parser::Parser() : input_(Input()), advance_mark_(Mark::NullMark()) {
}

Parser::Parser(const Input& input)
    : input_(input), advance_mark_(Mark::NullMark()) {
}

bool Parser::PeekTagAndValue(Tag* tag, Input* out) {
  ByteReader reader = input_;

  // Don't support tags > 30.
  uint8_t tag_byte;
  if (!reader.ReadByte(&tag_byte))
    return false;

  // ITU-T X.690 section 8.1.2.3 specifies the format for identifiers with a
  // tag number no greater than 30. This parser only supports tag numbers up
  // to 30.
  // If the tag number is 31 (0x1F, the largest value that fits in the allotted
  // bytes), then the tag is more than one byte long and the continuation bytes
  // contain the real tag number. We only support tag numbers < 31 (and thus
  // single-byte tags).
  if ((tag_byte & kTagNumberMask) == 31)
    return false;

  // Parse length. The format for the length encoding is specified in
  // ITU-T X.690 section 8.1.3.
  size_t value_len = 0;  // Number of bytes used to encode just the value.

  uint8_t length_first_byte;
  if (!reader.ReadByte(&length_first_byte))
    return false;
  if ((length_first_byte & 0x80) == 0) {
    // Short form for length - it's only one byte long.
    value_len = length_first_byte & 0x7f;
  } else {
    // Long form for length - it's encoded across multiple bytes.
    if (length_first_byte == 0xff) {
      // ITU-T X.690 clause 8.1.3.5.c specifies the value 0xff shall not be
      // used.
      return false;
    }
    // The high bit indicated that this is the long form, while the next 7 bits
    // encode the number of subsequent octets used to encode the length
    // (ITU-T X.690 clause 8.1.3.5.b).
    size_t length_len = length_first_byte & 0x7f;
    if (length_len == 0) {
      // ITU-T X.690 section 10.1 (DER length forms) requires encoding the
      // length with the minimum number of octets. Besides, it makes no sense
      // for the length to be encoded in 0 octets.
      return false;
    }
    if (length_len > sizeof(value_len)) {
      // The length is encoded in multiple octets, with the first octet
      // indicating how many octets follow. Those octets need to be combined
      // to form a size_t, so the number of octets to follow (length_len)
      // must be small enough so that they fit in a size_t.
      return false;
    }
    uint8_t length_byte;
    for (size_t i = 0; i < length_len; i++) {
      if (!reader.ReadByte(&length_byte))
        return false;
      // A first length byte of all zeroes means the length was not encoded in
      // minimum length.
      if (i == 0 && length_byte == 0)
        return false;
      value_len <<= 8;
      value_len += length_byte;
    }
    if (value_len < 0x80) {
      // If value_len is < 0x80, then it could have been encoded in a single
      // byte, meaning it was not encoded in minimum length.
      return false;
    }
  }

  if (!reader.ReadBytes(value_len, out))
    return false;
  advance_mark_ = reader.NewMark();
  *tag = tag_byte;
  return true;
}

bool Parser::Advance() {
  if (advance_mark_.IsEmpty())
    return false;
  if (!input_.AdvanceToMark(advance_mark_))
    return false;
  advance_mark_ = Mark::NullMark();
  return true;
}

bool Parser::HasMore() {
  return input_.HasMore();
}

bool Parser::ReadRawTLV(Input* out) {
  Tag tag;
  Input value;
  if (!PeekTagAndValue(&tag, &value))
    return false;
  if (!input_.ReadToMark(advance_mark_, out))
    return false;
  advance_mark_ = Mark::NullMark();

  return true;
}

bool Parser::ReadTagAndValue(Tag* tag, Input* out) {
  if (!PeekTagAndValue(tag, out))
    return false;
  CHECK(Advance());
  return true;
}

bool Parser::ReadOptionalTag(Tag tag, Input* out, bool* present) {
  if (!HasMore()) {
    *present = false;
    return true;
  }

  Tag read_tag;
  Input value;
  if (!PeekTagAndValue(&read_tag, &value))
    return false;
  *present = false;
  if (read_tag == tag) {
    *present = true;
    *out = value;
    CHECK(Advance());
  } else {
    advance_mark_ = Mark::NullMark();
  }
  return true;
}

bool Parser::SkipOptionalTag(Tag tag, bool* present) {
  Input out;
  return ReadOptionalTag(tag, &out, present);
}

bool Parser::ReadTag(Tag tag, Input* out) {
  bool present;
  return ReadOptionalTag(tag, out, &present) && present;
}

bool Parser::SkipTag(Tag tag) {
  Input out;
  return ReadTag(tag, &out);
}

// Type-specific variants of ReadTag

bool Parser::ReadConstructed(Tag tag, Parser* out) {
  if (!IsConstructed(tag))
    return false;
  Input data;
  if (!ReadTag(tag, &data))
    return false;
  *out = Parser(data);
  return true;
}

bool Parser::ReadSequence(Parser* out) {
  return ReadConstructed(kSequence, out);
}

bool Parser::ReadUint8(uint8_t* out) {
  Input encoded_int;
  if (!ReadTag(kInteger, &encoded_int))
    return false;
  return ParseUint8(encoded_int, out);
}

bool Parser::ReadUint64(uint64_t* out) {
  Input encoded_int;
  if (!ReadTag(kInteger, &encoded_int))
    return false;
  return ParseUint64(encoded_int, out);
}

bool Parser::ReadBitString(BitString* bit_string) {
  Input value;
  if (!ReadTag(kBitString, &value))
    return false;
  return ParseBitString(value, bit_string);
}

bool Parser::ReadGeneralizedTime(GeneralizedTime* out) {
  Input value;
  if (!ReadTag(kGeneralizedTime, &value))
    return false;
  return ParseGeneralizedTime(value, out);
}

}  // namespace der

}  // namespace net
