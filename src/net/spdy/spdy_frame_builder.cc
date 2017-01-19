// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_frame_builder.h"

#include <limits>

#include "base/logging.h"
#include "net/spdy/spdy_bug_tracker.h"
#include "net/spdy/spdy_framer.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

SpdyFrameBuilder::SpdyFrameBuilder(size_t size)
    : buffer_(new char[size]), capacity_(size), length_(0), offset_(0) {}

SpdyFrameBuilder::~SpdyFrameBuilder() {
}

char* SpdyFrameBuilder::GetWritableBuffer(size_t length) {
  if (!CanWrite(length)) {
    return NULL;
  }
  return buffer_.get() + offset_ + length_;
}

bool SpdyFrameBuilder::Seek(size_t length) {
  if (!CanWrite(length)) {
    return false;
  }

  length_ += length;
  return true;
}

bool SpdyFrameBuilder::BeginNewFrame(const SpdyFramer& framer,
                                     SpdyFrameType type,
                                     uint8_t flags,
                                     SpdyStreamId stream_id) {
  DCHECK(IsValidFrameType(SerializeFrameType(type)));
  DCHECK_EQ(0u, stream_id & ~kStreamIdMask);
  bool success = true;
  if (length_ > 0) {
    // Update length field for previous frame.
    OverwriteLength(framer, length_ - kFrameHeaderSize);
    SPDY_BUG_IF(framer.GetFrameMaximumSize() < length_)
        << "Frame length  " << length_
        << " is longer than the maximum allowed length.";
  }

  offset_ += length_;
  length_ = 0;

  // Assume all remaining capacity will be used for this frame. If not,
  // the length will get overwritten when we begin the next frame.
  // Don't check for length limits here because this may be larger than the
  // actual frame length.
  success &= WriteUInt24(capacity_ - offset_ - kFrameHeaderSize);
  success &= WriteUInt8(SerializeFrameType(type));
  success &= WriteUInt8(flags);
  success &= WriteUInt32(stream_id);
  DCHECK_EQ(framer.GetDataFrameMinimumSize(), length_);
  return success;
}

bool SpdyFrameBuilder::BeginNewFrame(const SpdyFramer& framer,
                                     SpdyFrameType type,
                                     uint8_t flags,
                                     SpdyStreamId stream_id,
                                     size_t length) {
  DCHECK(IsValidFrameType(SerializeFrameType(type)));
  DCHECK_EQ(0u, stream_id & ~kStreamIdMask);
  bool success = true;
  SPDY_BUG_IF(framer.GetFrameMaximumSize() < length_)
      << "Frame length  " << length_
      << " is longer than the maximum allowed length.";

  offset_ += length_;
  length_ = 0;

  success &= WriteUInt24(length);
  success &= WriteUInt8(SerializeFrameType(type));
  success &= WriteUInt8(flags);
  success &= WriteUInt32(stream_id);
  DCHECK_EQ(framer.GetDataFrameMinimumSize(), length_);
  return success;
}

bool SpdyFrameBuilder::WriteStringPiece16(const base::StringPiece& value) {
  if (value.size() > 0xffff) {
    DCHECK(false) << "Tried to write string with length > 16bit.";
    return false;
  }

  if (!WriteUInt16(static_cast<uint16_t>(value.size()))) {
    return false;
  }

  return WriteBytes(value.data(), static_cast<uint16_t>(value.size()));
}

bool SpdyFrameBuilder::WriteStringPiece32(const base::StringPiece& value) {
  if (!WriteUInt32(value.size())) {
    return false;
  }

  return WriteBytes(value.data(), value.size());
}

bool SpdyFrameBuilder::WriteBytes(const void* data, uint32_t data_len) {
  if (!CanWrite(data_len)) {
    return false;
  }

  char* dest = GetWritableBuffer(data_len);
  memcpy(dest, data, data_len);
  Seek(data_len);
  return true;
}

bool SpdyFrameBuilder::RewriteLength(const SpdyFramer& framer) {
  return OverwriteLength(framer, length_ - framer.GetFrameHeaderSize());
}

bool SpdyFrameBuilder::OverwriteLength(const SpdyFramer& framer,
                                       size_t length) {
  DCHECK_GE(framer.GetFrameMaximumSize(), length);
  bool success = false;
  const size_t old_length = length_;

  length_ = 0;
  success = WriteUInt24(length);

  length_ = old_length;
  return success;
}

bool SpdyFrameBuilder::OverwriteFlags(const SpdyFramer& framer, uint8_t flags) {
  bool success = false;
  const size_t old_length = length_;
  // Flags are the fifth octet in the frame prefix.
  length_ = 4;
  success = WriteUInt8(flags);
  length_ = old_length;
  return success;
}

bool SpdyFrameBuilder::CanWrite(size_t length) const {
  if (length > kLengthMask) {
    DCHECK(false);
    return false;
  }

  if (offset_ + length_ + length > capacity_) {
    DCHECK(false);
    return false;
  }

  return true;
}

}  // namespace net
