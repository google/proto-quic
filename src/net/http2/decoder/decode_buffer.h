// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_DECODER_DECODE_BUFFER_H_
#define NET_HTTP2_DECODER_DECODE_BUFFER_H_

// DecodeBuffer provides primitives for decoding various integer types found
// in HTTP/2 frames.
// DecodeBuffer wraps a byte array from which we can read and decode serialized
// HTTP/2 frames, or parts thereof. DecodeBuffer is intended only for stack
// allocation, where the caller is typically going to use the DecodeBuffer
// instance as part of decoding the entire buffer before returning to its own
// caller. Only the concrete Slow* methods are defined in the cc file,
// all other methods are defined in this header file to enable inlining.

#include <stddef.h>
#include <stdint.h>

#include <algorithm>

#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {
class DecodeBufferSubset;

class NET_EXPORT_PRIVATE DecodeBuffer {
 public:
  DecodeBuffer(const char* buffer, size_t len)
      : buffer_(buffer), cursor_(buffer), beyond_(buffer + len) {
    DCHECK(buffer != nullptr);
    DCHECK_LE(len, MaxDecodeBufferLength());
  }
  explicit DecodeBuffer(base::StringPiece s)
      : DecodeBuffer(s.data(), s.size()) {}
  // Constructor for character arrays, typically in tests. For example:
  //    const char input[] = { 0x11 };
  //    DecodeBuffer b(input);
  template <size_t N>
  explicit DecodeBuffer(const char (&buf)[N]) : DecodeBuffer(buf, N) {}

  bool Empty() const { return cursor_ >= beyond_; }
  bool HasData() const { return cursor_ < beyond_; }
  size_t Remaining() const {
    DCHECK_LE(cursor_, beyond_);
    return beyond_ - cursor_;
  }
  size_t Offset() const { return cursor_ - buffer_; }
  size_t FullSize() const { return beyond_ - buffer_; }

  // Returns the minimum of the number of bytes remaining in this DecodeBuffer
  // and |length|, in support of determining how much of some structure/payload
  // is in this DecodeBuffer.
  size_t MinLengthRemaining(size_t length) const {
    return std::min(length, Remaining());
  }

  // For string decoding, returns a pointer to the next byte/char to be decoded.
  const char* cursor() const { return cursor_; }
  // Advances the cursor (pointer to the next byte/char to be decoded).
  void AdvanceCursor(size_t amount) {
    DCHECK_LE(amount, Remaining());  // Need at least that much remaining.
    DCHECK_EQ(subset_, nullptr) << "Access via subset only when present.";
    cursor_ += amount;
  }

  // Only call methods starting "Decode" when there is enough input remaining.
  char DecodeChar() {
    DCHECK_LE(1u, Remaining());  // Need at least one byte remaining.
    DCHECK_EQ(subset_, nullptr) << "Access via subset only when present.";
    return *cursor_++;
  }

  uint8_t DecodeUInt8() { return static_cast<uint8_t>(DecodeChar()); }

  uint16_t DecodeUInt16() {
    DCHECK_LE(2u, Remaining());
    const uint8_t b1 = DecodeUInt8();
    const uint8_t b2 = DecodeUInt8();
    // Note that chars are automatically promoted to ints during arithmetic,
    // so the b1 << 8 doesn't end up as zero before being or-ed with b2.
    // And the left-shift operator has higher precedence than the or operator.
    return b1 << 8 | b2;
  }

  uint32_t DecodeUInt24() {
    DCHECK_LE(3u, Remaining());
    const uint8_t b1 = DecodeUInt8();
    const uint8_t b2 = DecodeUInt8();
    const uint8_t b3 = DecodeUInt8();
    return b1 << 16 | b2 << 8 | b3;
  }

  // For 31-bit unsigned integers, where the 32nd bit is reserved for future
  // use (i.e. the high-bit of the first byte of the encoding); examples:
  // the Stream Id in a frame header or the Window Size Increment in a
  // WINDOW_UPDATE frame.
  uint32_t DecodeUInt31() {
    DCHECK_LE(4u, Remaining());
    const uint8_t b1 = DecodeUInt8() & 0x7f;  // Mask out the high order bit.
    const uint8_t b2 = DecodeUInt8();
    const uint8_t b3 = DecodeUInt8();
    const uint8_t b4 = DecodeUInt8();
    return b1 << 24 | b2 << 16 | b3 << 8 | b4;
  }

  uint32_t DecodeUInt32() {
    DCHECK_LE(4u, Remaining());
    const uint8_t b1 = DecodeUInt8();
    const uint8_t b2 = DecodeUInt8();
    const uint8_t b3 = DecodeUInt8();
    const uint8_t b4 = DecodeUInt8();
    return b1 << 24 | b2 << 16 | b3 << 8 | b4;
  }

  // SlowDecode* routines are used for decoding a multi-field structure when
  // there may not be enough bytes in the buffer to decode the entirety of the
  // structure.

  // Read as much of an unsigned int field of an encoded structure as possible,
  // keeping track via decode_offset of our position in the encoded structure.
  // Returns true if the field has been fully decoded.
  // |field_size| is the number of bytes of the encoding of the field (usually
  // a compile time fixed value).
  // |field_offset| is the offset of the first byte of the encoding of the field
  // within the encoding of that structure (usually a compile time fixed value).
  // |*decode_offset| is the offset of the byte to be decoded next.
  // |*value| is the storage for the decoded value, and is used for storing
  // partially decoded values; if some, but not all, bytes of the encoding are
  // available then this method will return having stored the decoded bytes into
  // *value.
  bool SlowDecodeUnsignedInt(uint32_t field_size,
                             uint32_t field_offset,
                             uint32_t* decode_offset,
                             uint32_t* value);

  // Like SlowDecodeUnsignedInt, but specifically for 8-bit unsigned integers.
  // Obviously a byte can't be split (on our byte addressable machines), but
  // a larger structure containing such a field might be.
  bool SlowDecodeUInt8(uint32_t field_offset,
                       uint32_t* decode_offset,
                       uint8_t* value);

  // Like SlowDecodeUnsignedInt, but specifically for 16-bit unsigned integers.
  bool SlowDecodeUInt16(uint32_t field_offset,
                        uint32_t* decode_offset,
                        uint16_t* value);

  // Like SlowDecodeUnsignedInt, but specifically for 24-bit unsigned integers.
  bool SlowDecodeUInt24(uint32_t field_offset,
                        uint32_t* decode_offset,
                        uint32_t* value);

  // Like SlowDecodeUnsignedInt, but specifically for 31-bit unsigned integers.
  // (same definition as for DecodeUInt31).
  bool SlowDecodeUInt31(uint32_t field_offset,
                        uint32_t* decode_offset,
                        uint32_t* value);

  // Like SlowDecodeUnsignedInt, but specifically for 31-bit unsigned integers.
  bool SlowDecodeUInt32(uint32_t field_offset,
                        uint32_t* decode_offset,
                        uint32_t* value);

  // Decodes an enum value, where the size (in bytes) of the encoding must be
  // stated explicitly. It is assumed that under the covers enums are really
  // just integers, and that we can static_cast them to and from uint32.
  template <typename E>
  bool SlowDecodeEnum(uint32_t field_size,
                      uint32_t field_offset,
                      uint32_t* decode_offset,
                      E* value) {
    uint32_t tmp = static_cast<uint32_t>(*value);
    const bool done =
        SlowDecodeUnsignedInt(field_size, field_offset, decode_offset, &tmp);
    *value = static_cast<E>(tmp);
    DCHECK_EQ(tmp, static_cast<uint32_t>(*value));
    return done;
  }

  // We assume the decode buffers will typically be modest in size (i.e. a few
  // K).
  // Let's make sure during testing that we don't go very high, with 32MB
  // selected rather arbitrarily.
  static constexpr size_t MaxDecodeBufferLength() { return 1 << 25; }

 protected:
#ifndef NDEBUG
  // These are part of validating during tests that there is at most one
  // DecodeBufferSubset instance at a time for any DecodeBuffer instance.
  void set_subset_of_base(DecodeBuffer* base,
                          const DecodeBufferSubset* subset) {
    DCHECK_EQ(this, subset);
    base->set_subset(subset);
  }
  void clear_subset_of_base(DecodeBuffer* base,
                            const DecodeBufferSubset* subset) {
    DCHECK_EQ(this, subset);
    base->clear_subset(subset);
  }
#endif

 private:
#ifndef NDEBUG
  void set_subset(const DecodeBufferSubset* subset) {
    DCHECK(subset != nullptr);
    DCHECK_EQ(subset_, nullptr) << "There is already a subset";
    subset_ = subset;
  }
  void clear_subset(const DecodeBufferSubset* subset) {
    DCHECK(subset != nullptr);
    DCHECK_EQ(subset_, subset);
    subset_ = nullptr;
  }
#endif

  // Prevent heap allocation of DecodeBuffer.
  static void* operator new(size_t s);
  static void* operator new[](size_t s);
  static void operator delete(void* p);
  static void operator delete[](void* p);

  const char* const buffer_;
  const char* cursor_;
  const char* const beyond_;
  const DecodeBufferSubset* subset_ = nullptr;  // Used for DCHECKs.

  DISALLOW_COPY_AND_ASSIGN(DecodeBuffer);
};

// DecodeBufferSubset is used when decoding a known sized chunk of data, which
// starts at base->cursor(), and continues for subset_len, which may be
// entirely in |base|, or may extend beyond it (hence the MinLengthRemaining
// in the constructor).
// There are two benefits to using DecodeBufferSubset: it ensures that the
// cursor of |base| is advanced when the subset's destructor runs, and it
// ensures that the consumer of the subset can't go beyond the subset which
// it is intended to decode.
// There must be only a single DecodeBufferSubset at a time for a base
// DecodeBuffer, though they can be nested (i.e. a DecodeBufferSubset's
// base may itself be a DecodeBufferSubset). This avoids the AdvanceCursor
// being called erroneously.
class DecodeBufferSubset : public DecodeBuffer {
 public:
  DecodeBufferSubset(DecodeBuffer* base, size_t subset_len)
      : DecodeBuffer(base->cursor(), base->MinLengthRemaining(subset_len)),
#ifndef NDEBUG
        start_base_offset_(base->Offset()),
        max_base_offset_(start_base_offset_ + FullSize()),
#endif
        base_buffer_(base) {
#ifndef NDEBUG
    DCHECK_LE(max_base_offset_, base->FullSize());
    set_subset_of_base(base_buffer_, this);
#endif
  }

  ~DecodeBufferSubset() {
    size_t offset = Offset();
#ifndef NDEBUG
    clear_subset_of_base(base_buffer_, this);
    DCHECK_LE(Offset(), FullSize());
    DCHECK_EQ(start_base_offset_, base_buffer_->Offset())
        << "The base buffer was modified";
    DCHECK_LE(offset, FullSize());
    DCHECK_LE(start_base_offset_ + offset, base_buffer_->FullSize());
#endif
    base_buffer_->AdvanceCursor(offset);
#ifndef NDEBUG
    DCHECK_GE(max_base_offset_, base_buffer_->Offset());
#endif
  }

 private:
#ifndef NDEBUG
  const size_t start_base_offset_;  // Used for DCHECKs.
  const size_t max_base_offset_;    // Used for DCHECKs.
#endif
  DecodeBuffer* const base_buffer_;

  DISALLOW_COPY_AND_ASSIGN(DecodeBufferSubset);
};

}  // namespace net

#endif  // NET_HTTP2_DECODER_DECODE_BUFFER_H_
