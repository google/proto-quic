// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server_stream.h"

#include <list>

#include "base/logging.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_spdy_stream.h"
#include "net/quic/spdy_utils.h"
#include "net/spdy/spdy_protocol.h"
#include "net/tools/quic/quic_in_memory_cache.h"
#include "net/tools/quic/quic_simple_server_session.h"

using base::StringPiece;
using base::StringToInt;
using std::string;

namespace net {

QuicSimpleServerStream::QuicSimpleServerStream(QuicStreamId id,
                                               QuicSpdySession* session)
    : QuicSpdyStream(id, session), content_length_(-1) {}

QuicSimpleServerStream::~QuicSimpleServerStream() {}

void QuicSimpleServerStream::OnInitialHeadersComplete(bool fin,
                                                      size_t frame_len) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len);
  if (!SpdyUtils::ParseHeaders(decompressed_headers().data(),
                               decompressed_headers().length(),
                               &content_length_, &request_headers_)) {
    DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }
  MarkHeadersConsumed(decompressed_headers().length());
}

void QuicSimpleServerStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &request_headers_)) {
    DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }
  ConsumeHeaderList();
}

void QuicSimpleServerStream::OnTrailingHeadersComplete(bool fin,
                                                       size_t frame_len) {
  QUIC_BUG << "Server does not support receiving Trailers.";
  SendErrorResponse();
}

void QuicSimpleServerStream::OnTrailingHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QUIC_BUG << "Server does not support receiving Trailers.";
  SendErrorResponse();
}

void QuicSimpleServerStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    DVLOG(1) << "Processed " << iov.iov_len << " bytes for stream " << id();
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        body_.size() > static_cast<uint64_t>(content_length_)) {
      DVLOG(1) << "Body size (" << body_.size() << ") > content length ("
               << content_length_ << ").";
      SendErrorResponse();
      return;
    }
    MarkConsumed(iov.iov_len);
  }
  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    return;
  }

  if (request_headers_.empty()) {
    DVLOG(1) << "Request headers empty.";
    SendErrorResponse();
    return;
  }

  if (content_length_ > 0 &&
      static_cast<uint64_t>(content_length_) != body_.size()) {
    DVLOG(1) << "Content length (" << content_length_ << ") != body size ("
             << body_.size() << ").";
    SendErrorResponse();
    return;
  }

  SendResponse();
}

void QuicSimpleServerStream::PushResponse(
    SpdyHeaderBlock push_request_headers) {
  if (id() % 2 != 0) {
    QUIC_BUG << "Client initiated stream shouldn't be used as promised stream.";
    return;
  }
  // Change the stream state to emulate a client request.
  request_headers_ = push_request_headers;
  content_length_ = 0;
  DVLOG(1) << "Stream " << id() << ": Ready to receive server push response.";

  // Set as if stream decompresed the headers and received fin.
  QuicSpdyStream::OnInitialHeadersComplete(/*fin=*/true, 0);
}

void QuicSimpleServerStream::SendResponse() {
  if (!ContainsKey(request_headers_, ":authority") ||
      !ContainsKey(request_headers_, ":path")) {
    DVLOG(1) << "Request headers do not contain :authority or :path.";
    SendErrorResponse();
    return;
  }

  // Find response in cache. If not found, send error response.
  const QuicInMemoryCache::Response* response =
      QuicInMemoryCache::GetInstance()->GetResponse(
          request_headers_[":authority"], request_headers_[":path"]);
  if (response == nullptr) {
    DVLOG(1) << "Response not found in cache.";
    SendNotFoundResponse();
    return;
  }

  if (response->response_type() == QuicInMemoryCache::CLOSE_CONNECTION) {
    DVLOG(1) << "Special response: closing connection.";
    CloseConnectionWithDetails(QUIC_NO_ERROR, "Toy server forcing close");
    return;
  }

  if (response->response_type() == QuicInMemoryCache::IGNORE_REQUEST) {
    DVLOG(1) << "Special response: ignoring request.";
    return;
  }

  // Examing response status, if it was not pure integer as typical h2 response
  // status, send error response.
  string request_url = request_headers_[":authority"].as_string() +
                       request_headers_[":path"].as_string();
  int response_code;
  SpdyHeaderBlock response_headers = response->headers();
  if (!ParseHeaderStatusCode(&response_headers, &response_code)) {
    DVLOG(1) << "Illegal (non-integer) response :status from cache: "
             << response_headers[":status"].as_string() << " for request "
             << request_url;
    SendErrorResponse();
    return;
  }

  if (id() % 2 == 0) {
    // A server initiated stream is only used for a server push response,
    // and only 200 and 30X response codes are supported for server push.
    // This behavior mirrors the HTTP/2 implementation.
    bool is_redirection = response_code / 100 == 3;
    if (response_code != 200 && !is_redirection) {
      LOG(WARNING) << "Response to server push request " << request_url
                   << " result in response code " << response_code;
      Reset(QUIC_STREAM_CANCELLED);
      return;
    }
  }
  std::list<QuicInMemoryCache::ServerPushInfo> resources =
      QuicInMemoryCache::GetInstance()->GetServerPushResources(request_url);
  DVLOG(1) << "Found " << resources.size() << " push resources for stream "
           << id();

  if (!resources.empty()) {
    QuicSimpleServerSession* session =
        static_cast<QuicSimpleServerSession*>(spdy_session());
    session->PromisePushResources(request_url, resources, id(),
                                  request_headers_);
  }

  DVLOG(1) << "Sending response for stream " << id();
  SendHeadersAndBodyAndTrailers(response->headers(), response->body(),
                                response->trailers());
}

void QuicSimpleServerStream::SendNotFoundResponse() {
  DVLOG(1) << "Sending not found response for stream " << id();
  SpdyHeaderBlock headers;
  headers[":status"] = "404";
  headers["content-length"] = base::IntToString(strlen(kNotFoundResponseBody));
  SendHeadersAndBody(headers, kNotFoundResponseBody);
}

void QuicSimpleServerStream::SendErrorResponse() {
  DVLOG(1) << "Sending error response for stream " << id();
  SpdyHeaderBlock headers;
  headers[":status"] = "500";
  headers["content-length"] = base::UintToString(strlen(kErrorResponseBody));
  SendHeadersAndBody(headers, kErrorResponseBody);
}

void QuicSimpleServerStream::SendHeadersAndBody(
    const SpdyHeaderBlock& response_headers,
    StringPiece body) {
  SendHeadersAndBodyAndTrailers(response_headers, body, SpdyHeaderBlock());
}

void QuicSimpleServerStream::SendHeadersAndBodyAndTrailers(
    const SpdyHeaderBlock& response_headers,
    StringPiece body,
    const SpdyHeaderBlock& response_trailers) {
  // This server only supports SPDY and HTTP, and neither handles bidirectional
  // streaming.
  if (!reading_stopped()) {
    StopReading();
  }

  // Send the headers, with a FIN if there's nothing else to send.
  bool send_fin = (body.empty() && response_trailers.empty());
  DVLOG(1) << "Writing headers (fin = " << send_fin
           << ") : " << response_headers.DebugString();
  WriteHeaders(response_headers, send_fin, nullptr);
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the body, with a FIN if there's nothing else to send.
  send_fin = response_trailers.empty();
  DVLOG(1) << "Writing body (fin = " << send_fin
           << ") with size: " << body.size();
  WriteOrBufferData(body, send_fin, nullptr);
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the trailers. A FIN is always sent with trailers.
  DVLOG(1) << "Writing trailers (fin = true): "
           << response_trailers.DebugString();
  WriteTrailers(response_trailers, nullptr);
}

const char* const QuicSimpleServerStream::kErrorResponseBody = "bad";
const char* const QuicSimpleServerStream::kNotFoundResponseBody =
    "file not found";

}  // namespace net
