// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_HPACK_DECODER_HPACK_ENTRY_DECODER_H_
#define NET_HTTP2_HPACK_DECODER_HPACK_ENTRY_DECODER_H_

// HpackEntryDecoder decodes a single HPACK entry (i.e. one header or one
// dynamic table size update), in a resumable fashion. The first call, Start(),
// must provide a non-empty decode buffer. Continue with calls to Resume() if
// Start, and any subsequent calls to Resume, returns kDecodeInProgress.

#include <string>

#include "base/logging.h"
#include "net/base/net_export.h"
#include "net/http2/decoder/decode_buffer.h"
#include "net/http2/decoder/decode_status.h"
#include "net/http2/hpack/decoder/hpack_entry_decoder_listener.h"
#include "net/http2/hpack/decoder/hpack_entry_type_decoder.h"
#include "net/http2/hpack/decoder/hpack_string_decoder.h"
#include "net/http2/hpack/http2_hpack_constants.h"

namespace net {

class NET_EXPORT_PRIVATE HpackEntryDecoder {
 public:
  enum class EntryDecoderState {
    // Have started decoding the type/varint, but didn't finish on the previous
    // attempt.  Next state is kResumeDecodingType or kDecodedType.
    kResumeDecodingType,

    // Have just finished decoding the type/varint. Final state if the type is
    // kIndexedHeader or kDynamicTableSizeUpdate. Otherwise, the next state is
    // kStartDecodingName (if the varint is 0), else kStartDecodingValue.
    kDecodedType,

    // Ready to start decoding the literal name of a header entry. Next state
    // is kResumeDecodingName (if the name is split across decode buffers),
    // else kStartDecodingValue.
    kStartDecodingName,

    // Resume decoding the literal name of a header that is split across decode
    // buffers.
    kResumeDecodingName,

    // Ready to start decoding the literal value of a header entry. Final state
    // if the value string is entirely in the decode buffer, else the next state
    // is kResumeDecodingValue.
    kStartDecodingValue,

    // Resume decoding the literal value of a header that is split across decode
    // buffers.
    kResumeDecodingValue,
  };

  // Only call when the decode buffer has data (i.e. HpackBlockDecoder must
  // not call until there is data).
  DecodeStatus Start(DecodeBuffer* db, HpackEntryDecoderListener* listener) {
    DCHECK(db != nullptr);
    DCHECK(listener != nullptr);
    DCHECK(db->HasData());
    DecodeStatus status = entry_type_decoder_.Start(db);
    switch (status) {
      case DecodeStatus::kDecodeDone:
        // The type of the entry and its varint fit into the current decode
        // buffer.
        if (entry_type_decoder_.entry_type() ==
            HpackEntryType::kIndexedHeader) {
          // The entry consists solely of the entry type and varint. This
          // is by far the most common case in practice.
          listener->OnIndexedHeader(entry_type_decoder_.varint());
          return DecodeStatus::kDecodeDone;
        }
        state_ = EntryDecoderState::kDecodedType;
        return Resume(db, listener);
      case DecodeStatus::kDecodeInProgress:
        // Hit the end of the decode buffer before fully decoding the entry
        // type and varint.
        DCHECK_EQ(0u, db->Remaining());
        state_ = EntryDecoderState::kResumeDecodingType;
        return status;
      case DecodeStatus::kDecodeError:
        // The varint must have been invalid (too long).
        return status;
    }

    NOTREACHED();
    return DecodeStatus::kDecodeError;
  }

  // Only call Resume if the previous call (Start or Resume) returned
  // kDecodeInProgress; Resume is also called from Start when it has succeeded
  // in decoding the entry type and its varint.
  DecodeStatus Resume(DecodeBuffer* db, HpackEntryDecoderListener* listener);

  std::string DebugString() const;
  void OutputDebugString(std::ostream& out) const;

 private:
  // Implements handling state kDecodedType.
  bool DispatchOnType(HpackEntryDecoderListener* listener);

  HpackEntryTypeDecoder entry_type_decoder_;
  HpackStringDecoder string_decoder_;
  EntryDecoderState state_ = EntryDecoderState();
};

NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& out,
                                            const HpackEntryDecoder& v);
NET_EXPORT_PRIVATE std::ostream& operator<<(
    std::ostream& out,
    HpackEntryDecoder::EntryDecoderState state);

}  // namespace net

#endif  // NET_HTTP2_HPACK_DECODER_HPACK_ENTRY_DECODER_H_
