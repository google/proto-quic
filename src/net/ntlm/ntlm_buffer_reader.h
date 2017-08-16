// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_NTLM_BUFFER_READER_H_
#define NET_BASE_NTLM_BUFFER_READER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/ntlm/ntlm_constants.h"

namespace net {
namespace ntlm {

// Supports various bounds-checked low level buffer operations required by an
// NTLM implementation.
//
// The class supports the sequential read of a provided buffer. All reads
// perform bounds checking to ensure enough space is remaining in the buffer.
//
// Read* methods read from the buffer at the current cursor position and
// perform any necessary type conversion and provide the data in out params.
// After a successful read the cursor position is advanced past the read
// field.
//
// Failed Read*s or Match*s leave the cursor in an undefined position and the
// buffer MUST be discarded with no further operations performed.
//
// Read*Payload methods first reads a security buffer (see
// |ReadSecurityBuffer|), then reads the requested payload from the offset
// and length stated in the security buffer.
//
// If the length and offset in the security buffer would cause a read outside
// the message buffer the payload will not be read and the function will
// return false.
//
// Based on [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
// Specification version 28.0 [1]. Additional NTLM reference [2].
//
// [1] https://msdn.microsoft.com/en-us/library/cc236621.aspx
// [2] http://davenport.sourceforge.net/ntlm.html
class NET_EXPORT_PRIVATE NtlmBufferReader {
 public:
  explicit NtlmBufferReader(const Buffer& buffer);
  explicit NtlmBufferReader(base::StringPiece buffer);

  // This class does not take ownership of |ptr|, so the caller must ensure
  // that the buffer outlives the |NtlmBufferReader|.
  NtlmBufferReader(const uint8_t* ptr, size_t len);
  ~NtlmBufferReader();

  size_t GetLength() const { return buffer_.length(); }
  size_t GetCursor() const { return cursor_; }
  bool IsEndOfBuffer() const { return cursor_ >= GetLength(); }

  // Returns true if there are |len| more bytes between the current cursor
  // position and the end of the buffer.
  bool CanRead(size_t len) const;

  // Returns true if there are |len| more bytes between |offset| and the end
  // of the buffer. The cursor position is not used or modified.
  bool CanReadFrom(size_t offset, size_t len) const;

  // Returns true if it would be possible to read the payload described by the
  // security buffer.
  bool CanReadFrom(SecurityBuffer sec_buf) const {
    return CanReadFrom(sec_buf.offset, sec_buf.length);
  }

  // Reads a 16 bit value (little endian) as a uint16_t. If there are not 16
  // more bits available, it returns false.
  bool ReadUInt16(uint16_t* value) WARN_UNUSED_RESULT;

  // Reads a 32 bit value (little endian) as a uint32_t. If there are not 32
  // more bits available, it returns false.
  bool ReadUInt32(uint32_t* value) WARN_UNUSED_RESULT;

  // Reads a 64 bit value (little endian) as a uint64_t. If there are not 64
  // more bits available, it returns false.
  bool ReadUInt64(uint64_t* value) WARN_UNUSED_RESULT;

  // Calls |ReadUInt32| and returns it cast as |NegotiateFlags|. No
  // validation of the value takes place.
  bool ReadFlags(NegotiateFlags* flags) WARN_UNUSED_RESULT;

  // Reads |len| bytes and copies them into |buffer|.
  bool ReadBytes(uint8_t* buffer, size_t len) WARN_UNUSED_RESULT;

  // Reads |sec_buf.length| bytes from offset |sec_buf.offset| and copies them
  // into |buffer|. If the security buffer specifies a payload outside the
  // buffer, then the call fails. Unlike the other Read* methods, this does
  // not move the cursor.
  bool ReadBytesFrom(const SecurityBuffer& sec_buf,
                     uint8_t* buffer) WARN_UNUSED_RESULT;

  // A security buffer is an 8 byte structure that defines the offset and
  // length of a payload (string, struct or byte array) that appears after the
  // fixed part of the message.
  //
  // The structure is (little endian fields):
  //     uint16 - |length| Length of payload
  //     uint16 - Allocation (this is always ignored and not returned)
  //     uint32 - |offset| Offset from start of message
  bool ReadSecurityBuffer(SecurityBuffer* sec_buf) WARN_UNUSED_RESULT;

  // There are 3 message types Negotiate (sent by client), Challenge (sent by
  // server), and Authenticate (sent by client).
  //
  // This reads the message type from the header and will return false if the
  // value is invalid.
  bool ReadMessageType(MessageType* message_type) WARN_UNUSED_RESULT;

  // Skips over a security buffer field without reading the fields. This is
  // the equivalent of advancing the cursor 8 bytes. Returns false if there
  // are less than 8 bytes left in the buffer.
  bool SkipSecurityBuffer() WARN_UNUSED_RESULT;

  // Skips over the security buffer without returning the values, but fails if
  // the values would cause a read outside the buffer if the payload was
  // actually read.
  bool SkipSecurityBufferWithValidation() WARN_UNUSED_RESULT;

  // Skips over |count| bytes in the buffer. Returns false if there are not
  // |count| bytes left in the buffer.
  bool SkipBytes(size_t count) WARN_UNUSED_RESULT;

  // Reads and returns true if the next 8 bytes matches the signature in an
  // NTLM message "NTLMSSP\0". The cursor advances if the the signature
  // is matched.
  bool MatchSignature() WARN_UNUSED_RESULT;

  // Performs |ReadMessageType| and returns true if the value is
  // |message_type|. If the read fails or the message type does not match,
  // the buffer is invalid and MUST be discarded.
  bool MatchMessageType(MessageType message_type) WARN_UNUSED_RESULT;

  // Performs |MatchSignature| then |MatchMessageType|.
  bool MatchMessageHeader(MessageType message_type) WARN_UNUSED_RESULT;

  // Performs |ReadBytes(count)| and returns true if the contents is all
  // zero.
  bool MatchZeros(size_t count) WARN_UNUSED_RESULT;

  // Reads the security buffer and returns true if the length is 0 and
  // the offset is within the message. On failure, the buffer is invalid
  // and MUST be discarded.
  bool MatchEmptySecurityBuffer() WARN_UNUSED_RESULT;

 private:
  // Reads |sizeof(T)| bytes of an integer type from a little-endian buffer.
  template <typename T>
  bool ReadUInt(T* value);

  // Sets the cursor position. The caller should use |GetLength|, |CanRead|,
  // or |CanReadFrom| to verify the bounds before calling this method.
  void SetCursor(size_t cursor);

  // Advances the cursor by |count| bytes. The caller should use |GetLength|,
  // |CanRead|, or |CanReadFrom| to verify the bounds before calling this
  // method.
  void AdvanceCursor(size_t count) { SetCursor(GetCursor() + count); }

  // Returns a constant pointer to the start of the buffer.
  const uint8_t* GetBufferPtr() const { return buffer_.data(); }

  // Returns a pointer to the underlying buffer at the current cursor
  // position.
  const uint8_t* GetBufferAtCursor() const { return GetBufferPtr() + cursor_; }

  // Returns the byte at the current cursor position.
  uint8_t GetByteAtCursor() const {
    DCHECK(!IsEndOfBuffer());
    return *(GetBufferAtCursor());
  }

  const Buffer buffer_;
  size_t cursor_;

  DISALLOW_COPY_AND_ASSIGN(NtlmBufferReader);
};

}  // namespace ntlm
}  // namespace net

#endif  // NET_BASE_NTLM_BUFFER_READER_H_
