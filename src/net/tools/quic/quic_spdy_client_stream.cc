// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_spdy_client_stream.h"

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/quic_alarm.h"
#include "net/quic/quic_client_promised_info.h"
#include "net/quic/spdy_utils.h"
#include "net/spdy/spdy_protocol.h"
#include "net/tools/quic/quic_client_session.h"
#include "net/tools/quic/spdy_balsa_utils.h"

using base::StringPiece;
using std::string;
using base::StringToInt;

namespace net {

QuicSpdyClientStream::QuicSpdyClientStream(QuicStreamId id,
                                           QuicClientSession* session)
    : QuicSpdyStream(id, session),
      content_length_(-1),
      response_code_(0),
      header_bytes_read_(0),
      header_bytes_written_(0),
      allow_bidirectional_data_(false),
      session_(session) {}

QuicSpdyClientStream::~QuicSpdyClientStream() {}

void QuicSpdyClientStream::OnStreamFrame(const QuicStreamFrame& frame) {
  if (!allow_bidirectional_data_ && !write_side_closed()) {
    DVLOG(1) << "Got a response before the request was complete.  "
             << "Aborting request.";
    CloseWriteSide();
  }
  QuicSpdyStream::OnStreamFrame(frame);
}

void QuicSpdyClientStream::OnInitialHeadersComplete(bool fin,
                                                    size_t frame_len) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len);

  DCHECK(headers_decompressed());
  header_bytes_read_ += frame_len;
  if (!SpdyUtils::ParseHeaders(decompressed_headers().data(),
                               decompressed_headers().length(),
                               &content_length_, &response_headers_)) {
    DLOG(ERROR) << "Failed to parse headers: " << decompressed_headers();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  if (!ParseHeaderStatusCode(&response_headers_, &response_code_)) {
    DLOG(ERROR) << "Received invalid response code: "
                << response_headers_[":status"].as_string();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  MarkHeadersConsumed(decompressed_headers().length());
  DVLOG(1) << "headers complete for stream " << id();

  session_->OnInitialHeadersComplete(id(), response_headers_);
}

void QuicSpdyClientStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);

  DCHECK(headers_decompressed());
  header_bytes_read_ += frame_len;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &response_headers_)) {
    DLOG(ERROR) << "Failed to parse header list: " << header_list.DebugString();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  if (!ParseHeaderStatusCode(&response_headers_, &response_code_)) {
    DLOG(ERROR) << "Received invalid response code: "
                << response_headers_[":status"].as_string();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  ConsumeHeaderList();
  DVLOG(1) << "headers complete for stream " << id();

  session_->OnInitialHeadersComplete(id(), response_headers_);
}

void QuicSpdyClientStream::OnTrailingHeadersComplete(bool fin,
                                                     size_t frame_len) {
  QuicSpdyStream::OnTrailingHeadersComplete(fin, frame_len);
  MarkTrailersConsumed(decompressed_trailers().length());
}

void QuicSpdyClientStream::OnPromiseHeadersComplete(QuicStreamId promised_id,
                                                    size_t frame_len) {
  header_bytes_read_ += frame_len;
  int64_t content_length = -1;
  SpdyHeaderBlock promise_headers;
  if (!SpdyUtils::ParseHeaders(decompressed_headers().data(),
                               decompressed_headers().length(), &content_length,
                               &promise_headers)) {
    DLOG(ERROR) << "Failed to parse promise headers: "
                << decompressed_headers();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }
  MarkHeadersConsumed(decompressed_headers().length());

  session_->HandlePromised(id(), promised_id, promise_headers);
  if (visitor() != nullptr) {
    visitor()->OnPromiseHeadersComplete(promised_id, frame_len);
  }
}

void QuicSpdyClientStream::OnPromiseHeaderList(
    QuicStreamId promised_id,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  header_bytes_read_ += frame_len;
  int64_t content_length = -1;
  SpdyHeaderBlock promise_headers;
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length,
                                         &promise_headers)) {
    DLOG(ERROR) << "Failed to parse promise headers: "
                << header_list.DebugString();
    Reset(QUIC_BAD_APPLICATION_PAYLOAD);
    return;
  }

  session_->HandlePromised(id(), promised_id, promise_headers);
}

void QuicSpdyClientStream::OnDataAvailable() {
  if (FLAGS_quic_supports_push_promise) {
    // For push streams, visitor will not be set until the rendezvous
    // between server promise and client request is complete.
    if (visitor() == nullptr)
      return;
  }

  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Client processed " << iov.iov_len << " bytes for stream "
             << id();
    data_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        data_.size() > static_cast<uint64_t>(content_length_)) {
      DLOG(ERROR) << "Invalid content length (" << content_length_
                  << ") with data of size " << data_.size();
      Reset(QUIC_BAD_APPLICATION_PAYLOAD);
      return;
    }
    MarkConsumed(iov.iov_len);
  }
  if (sequencer()->IsClosed()) {
    OnFinRead();
  } else {
    sequencer()->SetUnblocked();
  }
}

size_t QuicSpdyClientStream::SendRequest(const SpdyHeaderBlock& headers,
                                         StringPiece body,
                                         bool fin) {
  bool send_fin_with_headers = fin && body.empty();
  size_t bytes_sent = body.size();
  header_bytes_written_ = WriteHeaders(headers, send_fin_with_headers, nullptr);
  bytes_sent += header_bytes_written_;

  if (!body.empty()) {
    WriteOrBufferData(body, fin, nullptr);
  }

  return bytes_sent;
}

}  // namespace net
