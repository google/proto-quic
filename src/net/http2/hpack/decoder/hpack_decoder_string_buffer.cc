// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/hpack/decoder/hpack_decoder_string_buffer.h"

#include "base/logging.h"

using base::StringPiece;

namespace net {

std::ostream& operator<<(std::ostream& out,
                         const HpackDecoderStringBuffer::State v) {
  switch (v) {
    case HpackDecoderStringBuffer::State::RESET:
      return out << "RESET";
    case HpackDecoderStringBuffer::State::COLLECTING:
      return out << "COLLECTING";
    case HpackDecoderStringBuffer::State::COMPLETE:
      return out << "COMPLETE";
    default:
      return out << "Unknown HpackDecoderStringBuffer::State!";
  }
}

std::ostream& operator<<(std::ostream& out,
                         const HpackDecoderStringBuffer::Backing v) {
  switch (v) {
    case HpackDecoderStringBuffer::Backing::RESET:
      return out << "RESET";
    case HpackDecoderStringBuffer::Backing::UNBUFFERED:
      return out << "UNBUFFERED";
    case HpackDecoderStringBuffer::Backing::BUFFERED:
      return out << "BUFFERED";
    case HpackDecoderStringBuffer::Backing::STATIC:
      return out << "STATIC";
    default:
      return out << "Unknown HpackDecoderStringBuffer::Backing!";
  }
}

HpackDecoderStringBuffer::HpackDecoderStringBuffer() {
  Reset();
}
HpackDecoderStringBuffer::~HpackDecoderStringBuffer() {}

// TODO(jamessynge): Consider eliminating most of Reset (i.e. do less); in
// particular, if a variable won't be read again until after it is next set
// (e.g. is_huffman_encoded_ or remaining_len_), then it doesn't need to be
// cleared here. This will be easier when not supporting both HpackDecoder2
// (in net/spdy/hpack) and HpackWholeEntryDecoder, so we can eliminate
// the Set() and str() methods.
void HpackDecoderStringBuffer::Reset() {
  DVLOG(3) << "HpackDecoderStringBuffer::Reset";
  buffer_.clear();
  value_.clear();
  remaining_len_ = 0;
  is_huffman_encoded_ = false;
  state_ = State::RESET;
  backing_ = Backing::RESET;
}

void HpackDecoderStringBuffer::Set(StringPiece value, bool is_static) {
  DVLOG(2) << "HpackDecoderStringBuffer::Set";
  DCHECK_EQ(state_, State::RESET);
  DCHECK_EQ(backing_, Backing::RESET);
  value_ = value;
  state_ = State::COMPLETE;
  backing_ = is_static ? Backing::STATIC : Backing::UNBUFFERED;
}

void HpackDecoderStringBuffer::OnStart(bool huffman_encoded, size_t len) {
  DVLOG(2) << "HpackDecoderStringBuffer::OnStart";
  DCHECK_EQ(state_, State::RESET);
  DCHECK_EQ(backing_, Backing::RESET);
  buffer_.clear();
  value_.clear();

  remaining_len_ = len;
  is_huffman_encoded_ = huffman_encoded;

  state_ = State::COLLECTING;

  if (huffman_encoded) {
    decoder_.Reset();
    backing_ = Backing::BUFFERED;

    // Reserve space in buffer_ for the uncompressed string, assuming the
    // maximum expansion. The shortest Huffman codes in the RFC are 5 bits long,
    // which then expand to 8 bits during decoding (i.e. each code is for one
    // plain text octet, aka byte), so the maximum size is 60% longer than the
    // encoded size.
    len = len * 8 / 5;
    if (buffer_.capacity() < len) {
      buffer_.reserve(len);
    }
  } else {
    // Assume for now that we won't need to use buffer_, so don't reserve space
    // in it.
    backing_ = Backing::RESET;
  }
}

bool HpackDecoderStringBuffer::OnData(const char* data, size_t len) {
  DVLOG(2) << "HpackDecoderStringBuffer::OnData state=" << state_
           << ", backing=" << backing_;
  DCHECK_EQ(state_, State::COLLECTING);
  DCHECK_LE(len, remaining_len_);
  remaining_len_ -= len;

  if (is_huffman_encoded_) {
    DCHECK_EQ(backing_, Backing::BUFFERED);
    // We don't set value_ for buffered strings until OnEnd,
    // so it should be empty.
    DCHECK_EQ(0u, value_.size());
    return decoder_.Decode(StringPiece(data, len), &buffer_);
  }

  if (backing_ == Backing::RESET) {
    // This is the first call to OnData.
    DCHECK_EQ(0u, buffer_.size());
    DCHECK_EQ(0u, value_.size());
    // If data contains the entire string, don't copy the string. If we later
    // find that the HPACK entry is split across input buffers, then we'll
    // copy the string into buffer_.
    if (remaining_len_ == 0) {
      value_ = StringPiece(data, len);
      backing_ = Backing::UNBUFFERED;
      return true;
    }

    // We need to buffer the string because it is split across input buffers.
    backing_ = Backing::BUFFERED;
    buffer_.assign(data, len);
    return true;
  }

  // This is not the first call to OnData for this string, so it should be
  // buffered.
  DCHECK_EQ(backing_, Backing::BUFFERED);
  // We don't set value_ for buffered strings until OnEnd, so it should be
  // empty.
  DCHECK_EQ(0u, value_.size());

  // Append to the current contents of the buffer.
  buffer_.append(data, len);
  return true;
}

bool HpackDecoderStringBuffer::OnEnd() {
  DVLOG(2) << "HpackDecoderStringBuffer::OnEnd";
  DCHECK_EQ(state_, State::COLLECTING);
  DCHECK_EQ(0u, remaining_len_);

  if (is_huffman_encoded_) {
    DCHECK_EQ(backing_, Backing::BUFFERED);
    // Did the Huffman encoding of the string end properly?
    if (!decoder_.InputProperlyTerminated()) {
      return false;  // No, it didn't.
    }
  }
  state_ = State::COMPLETE;
  if (backing_ == Backing::BUFFERED) {
    value_ = buffer_;
  }
  return true;
}

void HpackDecoderStringBuffer::BufferStringIfUnbuffered() {
  DVLOG(3) << "HpackDecoderStringBuffer::BufferStringIfUnbuffered state="
           << state_ << ", backing=" << backing_;
  if (state_ != State::RESET && backing_ == Backing::UNBUFFERED) {
    DVLOG(2) << "HpackDecoderStringBuffer buffering string of length "
             << value_.size();
    value_.CopyToString(&buffer_);
    if (state_ == State::COMPLETE) {
      value_ = buffer_;
    }
    backing_ = Backing::BUFFERED;
  }
}

size_t HpackDecoderStringBuffer::BufferedLength() const {
  DVLOG(3) << "HpackDecoderStringBuffer::BufferedLength";
  return backing_ == Backing::BUFFERED ? buffer_.size() : 0;
}

StringPiece HpackDecoderStringBuffer::str() const {
  DVLOG(3) << "HpackDecoderStringBuffer::str";
  DCHECK_EQ(state_, State::COMPLETE);
  return value_;
}

void HpackDecoderStringBuffer::OutputDebugStringTo(std::ostream& out) const {
  out << "{state=" << state_;
  if (state_ != State::RESET) {
    out << ", backing=" << backing_;
    out << ", remaining_len=" << remaining_len_;
    out << ", is_huffman_encoded=" << is_huffman_encoded_;
    if (backing_ == Backing::BUFFERED) {
      out << ", buffer: " << buffer_;
    } else {
      out << ", value: " << value_;
    }
  }
  out << "}";
}

std::ostream& operator<<(std::ostream& out, const HpackDecoderStringBuffer& v) {
  v.OutputDebugStringTo(out);
  return out;
}

}  // namespace net
