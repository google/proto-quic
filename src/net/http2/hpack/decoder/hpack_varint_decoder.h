// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// HpackVarintDecoder decodes HPACK variable length unsigned integers. These
// integers are used to identify static or dynamic table index entries, to
// specify string lengths, and to update the size limit of the dynamic table.
//
// The caller will need to validate that the decoded value is in an acceptable
// range.
//
// In order to support naive encoders (i.e. which always output 5 extension
// bytes for a uint32 that is >= prefix_mask), the decoder supports an an
// encoding with up to 5 extension bytes, and a maximum value of 268,435,582
// (4 "full" extension bytes plus the maximum for a prefix, 127). It could be
// modified to support a lower maximum value (by requiring that extensions bytes
// be "empty"), or a larger value if valuable for some reason I can't see.
//
// For details of the encoding, see:
//        http://httpwg.org/specs/rfc7541.html#integer.representation
//
// TODO(jamessynge): Consider dropping support for encodings of more than 4
// bytes, including the prefix byte, as in practice we only see at most 3 bytes,
// and 4 bytes would cover any desire to support large (but not ridiculously
// large) header values.

#ifndef NET_HTTP2_HPACK_DECODER_HPACK_VARINT_DECODER_H_
#define NET_HTTP2_HPACK_DECODER_HPACK_VARINT_DECODER_H_

#include <string>

#include "base/logging.h"
#include "net/base/net_export.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"

namespace net {
// Decodes an HPACK variable length unsigned integer, in a resumable fashion
// so it can handle running out of input in the DecodeBuffer. Call Start or
// StartExtended the first time (when decoding the byte that contains the
// prefix), then call Resume later if it is necessary to resume. When done,
// call value() to retrieve the decoded value.
//
// No constructor or destructor. Holds no resources, so destruction isn't
// needed. Start and StartExtended handles the initialization of member
// variables. This is necessary in order for HpackVarintDecoder to be part
// of a union.
class NET_EXPORT_PRIVATE HpackVarintDecoder {
 public:
  // |prefix_value| is the first byte of the encoded varint.
  // |prefix_mask| is the mask of the valid bits, i.e. without the top 1 to 4
  // high-bits set, as appropriate for the item being decoded; must be a
  // contiguous sequence of set bits, starting with the low-order bits.
  DecodeStatus Start(uint8_t prefix_value,
                     uint8_t prefix_mask,
                     DecodeBuffer* db) {
    DCHECK_LE(15, prefix_mask) << std::hex << prefix_mask;
    DCHECK_LE(prefix_mask, 127) << std::hex << prefix_mask;
    // Confirm that |prefix_mask| is a contiguous sequence of bits.
    DCHECK_EQ(0, (prefix_mask + 1) & prefix_mask) << std::hex << prefix_mask;

    // Ignore the bits that aren't a part of the prefix of the varint.
    value_ = prefix_value & prefix_mask;

    if (value_ < prefix_mask) {
      MarkDone();
      return DecodeStatus::kDecodeDone;
    }

    offset_ = 0;
    return Resume(db);
  }

  // The caller has already determined that the encoding requires multiple
  // bytes, i.e. that the 4 to 7 low-order bits (the number determined by the
  // prefix length, a value not passed into this function) of the first byte are
  // are all 1. The caller passes in |prefix_mask|, which is 2^prefix_length-1.
  DecodeStatus StartExtended(uint8_t prefix_mask, DecodeBuffer* db) {
    DCHECK_LE(15, prefix_mask) << std::hex << prefix_mask;
    DCHECK_LE(prefix_mask, 127) << std::hex << prefix_mask;
    // Confirm that |prefix_mask| is a contiguous sequence of bits.
    DCHECK_EQ(0, prefix_mask & (prefix_mask + 1)) << std::hex << prefix_mask;

    value_ = prefix_mask;
    offset_ = 0;
    return Resume(db);
  }

  // Resume decoding a variable length integer after an earlier
  // call to Start or StartExtended returned kDecodeInProgress.
  DecodeStatus Resume(DecodeBuffer* db) {
    CheckNotDone();
    do {
      if (db->Empty()) {
        return DecodeStatus::kDecodeInProgress;
      }
      uint8_t byte = db->DecodeUInt8();
      value_ += (byte & 0x7f) << offset_;
      if ((byte & 0x80) == 0) {
        if (offset_ < MaxOffset() || byte == 0) {
          MarkDone();
          return DecodeStatus::kDecodeDone;
        }
        break;
      }
      offset_ += 7;
    } while (offset_ <= MaxOffset());
    DLOG(WARNING) << "Variable length int encoding is too large or too long. "
                  << DebugString();
    MarkDone();
    return DecodeStatus::kDecodeError;
  }

  uint32_t value() const {
    CheckDone();
    return value_;
  }

  // This supports optimizations for the case of a varint with zero extension
  // bytes, where the handling of the prefix is done by the caller.
  void set_value(uint32_t v) {
    MarkDone();
    value_ = v;
  }

  // All the public methods below are for supporting assertions and tests.

  std::string DebugString() const;

  // For benchmarking, these methods ensure the decoder
  // is NOT inlined into the caller.
  DecodeStatus StartForTest(uint8_t prefix_value,
                            uint8_t prefix_mask,
                            DecodeBuffer* db);
  DecodeStatus StartExtendedForTest(uint8_t prefix_mask, DecodeBuffer* db);
  DecodeStatus ResumeForTest(DecodeBuffer* db);

  static constexpr uint32_t MaxExtensionBytes() { return 5; }

  // Returns the highest value with the specified number of extension bytes and
  // the specified prefix length (bits).
  static uint64_t constexpr HiValueOfExtensionBytes(uint32_t extension_bytes,
                                                    uint32_t prefix_length) {
    return (1 << prefix_length) - 2 +
           (extension_bytes == 0 ? 0 : (1LLU << (extension_bytes * 7)));
  }

 private:
  // Protection in case Resume is called when it shouldn't be.
  void MarkDone() {
#ifndef NDEBUG
    // We support up to 5 extension bytes, so offset_ should never be > 28 when
    // it makes sense to call Resume().
    offset_ = MaxOffset() + 7;
#endif
  }
  void CheckNotDone() const {
#ifndef NDEBUG
    DCHECK_LE(offset_, MaxOffset());
#endif
  }
  void CheckDone() const {
#ifndef NDEBUG
    DCHECK_GT(offset_, MaxOffset());
#endif
  }
  static constexpr uint32_t MaxOffset() {
    return 7 * (MaxExtensionBytes() - 1);
  }

  // These fields are initialized just to keep ASAN happy about reading
  // them from DebugString().
  uint32_t value_ = 0;
  uint32_t offset_ = 0;
};

std::ostream& operator<<(std::ostream& out, const HpackVarintDecoder& v);

}  // namespace net

#endif  // NET_HTTP2_HPACK_DECODER_HPACK_VARINT_DECODER_H_
