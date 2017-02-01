// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http2/decoder/decode_buffer.h"

namespace net {

#ifndef NDEBUG
// These are part of validating during tests that there is at most one
// DecodeBufferSubset instance at a time for any DecodeBuffer instance.
void DecodeBuffer::set_subset_of_base(DecodeBuffer* base,
                                      const DecodeBufferSubset* subset) {
  DCHECK_EQ(this, subset);
  base->set_subset(subset);
}
void DecodeBuffer::clear_subset_of_base(DecodeBuffer* base,
                                        const DecodeBufferSubset* subset) {
  DCHECK_EQ(this, subset);
  base->clear_subset(subset);
}
void DecodeBuffer::set_subset(const DecodeBufferSubset* subset) {
  DCHECK(subset != nullptr);
  DCHECK_EQ(subset_, nullptr) << "There is already a subset";
  subset_ = subset;
}
void DecodeBuffer::clear_subset(const DecodeBufferSubset* subset) {
  DCHECK(subset != nullptr);
  DCHECK_EQ(subset_, subset);
  subset_ = nullptr;
}
void DecodeBufferSubset::DebugSetup() {
  start_base_offset_ = base_buffer_->Offset();
  max_base_offset_ = start_base_offset_ + FullSize();
  DCHECK_LE(max_base_offset_, base_buffer_->FullSize());

  // Ensure that there is only one DecodeBufferSubset at a time for a base.
  set_subset_of_base(base_buffer_, this);
}
void DecodeBufferSubset::DebugTearDown() {
  // Ensure that the base hasn't been modified.
  DCHECK_EQ(start_base_offset_, base_buffer_->Offset())
      << "The base buffer was modified";

  // Ensure that we haven't gone beyond the maximum allowed offset.
  size_t offset = Offset();
  DCHECK_LE(offset, FullSize());
  DCHECK_LE(start_base_offset_ + offset, max_base_offset_);
  DCHECK_LE(max_base_offset_, base_buffer_->FullSize());

  clear_subset_of_base(base_buffer_, this);
}
#endif

}  // namespace net
