// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ntlm/ntlm_buffer_reader.h"

#include <string.h>

#include "base/logging.h"

namespace net {
namespace ntlm {

NtlmBufferReader::NtlmBufferReader(const Buffer& buffer)
    : buffer_(buffer), cursor_(0) {
  DCHECK(buffer.data());
}

NtlmBufferReader::NtlmBufferReader(base::StringPiece str)
    : NtlmBufferReader(reinterpret_cast<const uint8_t*>(str.data()),
                       str.size()) {}

NtlmBufferReader::NtlmBufferReader(const uint8_t* ptr, size_t len)
    : NtlmBufferReader(Buffer(ptr, len)) {}

NtlmBufferReader::~NtlmBufferReader() {}

bool NtlmBufferReader::CanRead(size_t len) const {
  return CanReadFrom(GetCursor(), len);
}

bool NtlmBufferReader::CanReadFrom(size_t offset, size_t len) const {
  if (len == 0)
    return true;

  return (len <= GetLength() && offset <= GetLength() - len);
}

bool NtlmBufferReader::ReadUInt16(uint16_t* value) {
  return ReadUInt<uint16_t>(value);
}

bool NtlmBufferReader::ReadUInt32(uint32_t* value) {
  return ReadUInt<uint32_t>(value);
}

bool NtlmBufferReader::ReadUInt64(uint64_t* value) {
  return ReadUInt<uint64_t>(value);
}

bool NtlmBufferReader::ReadFlags(NegotiateFlags* flags) {
  uint32_t raw;
  if (!ReadUInt32(&raw))
    return false;

  *flags = static_cast<NegotiateFlags>(raw);
  return true;
}

bool NtlmBufferReader::ReadBytes(uint8_t* buffer, size_t len) {
  if (!CanRead(len))
    return false;

  memcpy(reinterpret_cast<void*>(buffer),
         reinterpret_cast<const void*>(GetBufferAtCursor()), len);

  AdvanceCursor(len);
  return true;
}

bool NtlmBufferReader::ReadBytesFrom(const SecurityBuffer& sec_buf,
                                     uint8_t* buffer) {
  if (!CanReadFrom(sec_buf))
    return false;

  memcpy(reinterpret_cast<void*>(buffer),
         reinterpret_cast<const void*>(GetBufferPtr() + sec_buf.offset),
         sec_buf.length);

  return true;
}

bool NtlmBufferReader::ReadSecurityBuffer(SecurityBuffer* sec_buf) {
  return ReadUInt16(&sec_buf->length) && SkipBytes(sizeof(uint16_t)) &&
         ReadUInt32(&sec_buf->offset);
}

bool NtlmBufferReader::ReadMessageType(MessageType* message_type) {
  uint32_t raw_message_type;
  if (!ReadUInt32(&raw_message_type))
    return false;

  *message_type = static_cast<MessageType>(raw_message_type);

  if (*message_type != MessageType::kNegotiate &&
      *message_type != MessageType::kChallenge &&
      *message_type != MessageType::kAuthenticate)
    return false;

  return true;
}

bool NtlmBufferReader::SkipSecurityBuffer() {
  return SkipBytes(kSecurityBufferLen);
}

bool NtlmBufferReader::SkipSecurityBufferWithValidation() {
  SecurityBuffer sec_buf;
  return ReadSecurityBuffer(&sec_buf) && CanReadFrom(sec_buf);
}

bool NtlmBufferReader::SkipBytes(size_t count) {
  if (!CanRead(count))
    return false;

  AdvanceCursor(count);
  return true;
}

bool NtlmBufferReader::MatchSignature() {
  if (!CanRead(kSignatureLen))
    return false;

  if (memcmp(kSignature, GetBufferAtCursor(), kSignatureLen) != 0)
    return false;

  AdvanceCursor(kSignatureLen);
  return true;
}

bool NtlmBufferReader::MatchMessageType(MessageType message_type) {
  MessageType actual_message_type;
  return ReadMessageType(&actual_message_type) &&
         (actual_message_type == message_type);
}

bool NtlmBufferReader::MatchMessageHeader(MessageType message_type) {
  return MatchSignature() && MatchMessageType(message_type);
}

bool NtlmBufferReader::MatchZeros(size_t count) {
  if (!CanRead(count))
    return false;

  for (size_t i = 0; i < count; i++) {
    if (GetBufferAtCursor()[i] != 0)
      return false;
  }

  AdvanceCursor(count);
  return true;
}

bool NtlmBufferReader::MatchEmptySecurityBuffer() {
  SecurityBuffer sec_buf;
  return ReadSecurityBuffer(&sec_buf) && (sec_buf.offset <= GetLength()) &&
         (sec_buf.length == 0);
}

template <typename T>
bool NtlmBufferReader::ReadUInt(T* value) {
  size_t int_size = sizeof(T);
  if (!CanRead(int_size))
    return false;

  *value = 0;
  for (size_t i = 0; i < int_size; i++) {
    *value += static_cast<T>(GetByteAtCursor()) << (i * 8);
    AdvanceCursor(1);
  }

  return true;
}

void NtlmBufferReader::SetCursor(size_t cursor) {
  DCHECK_LE(cursor, GetLength());

  cursor_ = cursor;
}

}  // namespace ntlm
}  // namespace net
