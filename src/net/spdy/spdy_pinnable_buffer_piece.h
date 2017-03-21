// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_PINNABLE_BUFFER_PIECE_H_
#define NET_SPDY_SPDY_PINNABLE_BUFFER_PIECE_H_

#include <stddef.h>

#include <memory>

#include "net/base/net_export.h"
#include "net/spdy/platform/api/spdy_string_piece.h"

namespace net {

class SpdyPrefixedBufferReader;

// Helper class of SpdyPrefixedBufferReader.
// Represents a piece of consumed buffer which may (or may not) own its
// underlying storage. Users may "pin" the buffer at a later time to ensure
// a SpdyPinnableBufferPiece owns and retains storage of the buffer.
struct NET_EXPORT_PRIVATE SpdyPinnableBufferPiece {
 public:
  SpdyPinnableBufferPiece();
  ~SpdyPinnableBufferPiece();

  const char * buffer() const {
    return buffer_;
  }

  size_t length() const {
    return length_;
  }

  operator SpdyStringPiece() const { return SpdyStringPiece(buffer_, length_); }

  // Allocates and copies the buffer to internal storage.
  void Pin();

  bool IsPinned() const { return storage_ != nullptr; }

  // Swaps buffers, including internal storage, with |other|.
  void Swap(SpdyPinnableBufferPiece* other);

 private:
  friend class SpdyPrefixedBufferReader;

  const char * buffer_;
  size_t length_;
  // Null iff |buffer_| isn't pinned.
  std::unique_ptr<char[]> storage_;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_PINNABLE_BUFFER_PIECE_H_
