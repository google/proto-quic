// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_headers_stream.h"

#include "net/quic/core/quic_spdy_session.h"
#include "net/quic/platform/api/quic_flags.h"

namespace net {

QuicHeadersStream::CompressedHeaderInfo::CompressedHeaderInfo(
    QuicStreamOffset headers_stream_offset,
    QuicStreamOffset full_length,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener)
    : headers_stream_offset(headers_stream_offset),
      full_length(full_length),
      unacked_length(full_length),
      ack_listener(std::move(ack_listener)) {}

QuicHeadersStream::CompressedHeaderInfo::CompressedHeaderInfo(
    const CompressedHeaderInfo& other) = default;

QuicHeadersStream::CompressedHeaderInfo::~CompressedHeaderInfo() {}

QuicHeadersStream::QuicHeadersStream(QuicSpdySession* session)
    : QuicStream(kHeadersStreamId, session), spdy_session_(session) {
  // The headers stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

QuicHeadersStream::~QuicHeadersStream() {}

void QuicHeadersStream::OnDataAvailable() {
  char buffer[1024];
  struct iovec iov;
  QuicTime timestamp(QuicTime::Zero());
  while (true) {
    iov.iov_base = buffer;
    iov.iov_len = arraysize(buffer);
    if (!sequencer()->GetReadableRegion(&iov, &timestamp)) {
      // No more data to read.
      break;
    }
    if (spdy_session_->ProcessHeaderData(iov, timestamp) != iov.iov_len) {
      // Error processing data.
      return;
    }
    sequencer()->MarkConsumed(iov.iov_len);
    MaybeReleaseSequencerBuffer();
  }
}

void QuicHeadersStream::MaybeReleaseSequencerBuffer() {
  if (spdy_session_->ShouldReleaseHeadersStreamSequencerBuffer()) {
    sequencer()->ReleaseBufferIfEmpty();
  }
}

QuicConsumedData QuicHeadersStream::WritevDataInner(
    QuicIOVector iov,
    QuicStreamOffset offset,
    bool fin,
    QuicReferenceCountedPointer<QuicAckListenerInterface> ack_listener) {
  if (!session()->use_stream_notifier()) {
    return QuicStream::WritevDataInner(iov, offset, fin,
                                       std::move(ack_listener));
  }
  QuicConsumedData consumed =
      QuicStream::WritevDataInner(iov, offset, fin, nullptr);
  if (consumed.bytes_consumed == 0 || ack_listener == nullptr) {
    // No need to update unacked_headers_ if no byte is consumed or there is no
    // ack listener.
    return consumed;
  }

  if (!unacked_headers_.empty() &&
      (offset == unacked_headers_.back().headers_stream_offset +
                     unacked_headers_.back().full_length) &&
      ack_listener == unacked_headers_.back().ack_listener) {
    // Try to combine with latest inserted entry if they belong to the same
    // header (i.e., having contiguous offset and the same ack listener).
    unacked_headers_.back().full_length += consumed.bytes_consumed;
    unacked_headers_.back().unacked_length += consumed.bytes_consumed;
  } else {
    unacked_headers_.push_back(CompressedHeaderInfo(
        offset, consumed.bytes_consumed, std::move(ack_listener)));
  }
  return consumed;
}

void QuicHeadersStream::OnStreamFrameAcked(const QuicStreamFrame& frame,
                                           QuicTime::Delta ack_delay_time) {
  for (CompressedHeaderInfo& header : unacked_headers_) {
    if (frame.offset < header.headers_stream_offset) {
      // This header frame offset belongs to headers with smaller offset, stop
      // processing.
      break;
    }

    if (frame.offset >= header.headers_stream_offset + header.full_length) {
      // This header frame belongs to headers with larger offset.
      continue;
    }

    if (header.unacked_length < frame.data_length) {
      // This header frame is out of range.
      CloseConnectionWithDetails(QUIC_INTERNAL_ERROR,
                                 "Unsent stream data is acked");
      return;
    }

    header.unacked_length -= frame.data_length;

    if (header.ack_listener != nullptr) {
      header.ack_listener->OnPacketAcked(frame.data_length, ack_delay_time);
    }
    break;
  }

  // Remove headers which are fully acked. Please note, header frames can be
  // acked out of order, but unacked_headers_ is cleaned up in order.
  while (!unacked_headers_.empty() &&
         unacked_headers_.front().unacked_length == 0) {
    unacked_headers_.pop_front();
  }
  QuicStream::OnStreamFrameAcked(frame, ack_delay_time);
}

void QuicHeadersStream::OnStreamFrameRetransmitted(
    const QuicStreamFrame& frame) {
  for (CompressedHeaderInfo& header : unacked_headers_) {
    if (frame.offset < header.headers_stream_offset) {
      // This header frame offset belongs to headers with smaller offset, stop
      // processing.
      break;
    }

    if (frame.offset >= header.headers_stream_offset + header.full_length) {
      // This header frame belongs to headers with larger offset.
      continue;
    }

    if (header.ack_listener != nullptr) {
      header.ack_listener->OnPacketRetransmitted(frame.data_length);
    }
    break;
  }
}

}  // namespace net
