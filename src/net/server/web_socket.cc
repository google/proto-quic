// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/server/web_socket.h"

#include <vector>

#include "base/base64.h"
#include "base/logging.h"
#include "base/sha1.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/sys_byteorder.h"
#include "net/server/http_connection.h"
#include "net/server/http_server.h"
#include "net/server/http_server_request_info.h"
#include "net/server/http_server_response_info.h"
#include "net/server/web_socket_encoder.h"
#include "net/websockets/websocket_deflate_parameters.h"
#include "net/websockets/websocket_extension.h"
#include "net/websockets/websocket_handshake_constants.h"

namespace net {

namespace {

std::string ExtensionsHeaderString(
    const std::vector<WebSocketExtension>& extensions) {
  if (extensions.empty())
    return std::string();

  std::string result = "Sec-WebSocket-Extensions: " + extensions[0].ToString();
  for (size_t i = 1; i < extensions.size(); ++i)
    result += ", " + extensions[i].ToString();
  return result + "\r\n";
}

std::string ValidResponseString(
    const std::string& accept_hash,
    const std::vector<WebSocketExtension> extensions) {
  return base::StringPrintf(
      "HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
      "Upgrade: WebSocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: %s\r\n"
      "%s"
      "\r\n",
      accept_hash.c_str(), ExtensionsHeaderString(extensions).c_str());
}

}  // namespace

WebSocket::WebSocket(HttpServer* server, HttpConnection* connection)
    : server_(server), connection_(connection), closed_(false) {}

WebSocket::~WebSocket() {}

void WebSocket::Accept(const HttpServerRequestInfo& request) {
  std::string version = request.GetHeaderValue("sec-websocket-version");
  if (version != "8" && version != "13") {
    SendErrorResponse("Invalid request format. The version is not valid.");
    return;
  }

  std::string key = request.GetHeaderValue("sec-websocket-key");
  if (key.empty()) {
    SendErrorResponse(
        "Invalid request format. Sec-WebSocket-Key is empty or isn't "
        "specified.");
    return;
  }
  std::string encoded_hash;
  base::Base64Encode(base::SHA1HashString(key + websockets::kWebSocketGuid),
                     &encoded_hash);

  std::vector<WebSocketExtension> response_extensions;
  auto i = request.headers.find("sec-websocket-extensions");
  if (i == request.headers.end()) {
    encoder_ = WebSocketEncoder::CreateServer();
  } else {
    WebSocketDeflateParameters params;
    encoder_ = WebSocketEncoder::CreateServer(i->second, &params);
    if (!encoder_) {
      Fail();
      return;
    }
    if (encoder_->deflate_enabled()) {
      DCHECK(params.IsValidAsResponse());
      response_extensions.push_back(params.AsExtension());
    }
  }
  server_->SendRaw(connection_->id(),
                   ValidResponseString(encoded_hash, response_extensions));
}

WebSocket::ParseResult WebSocket::Read(std::string* message) {
  if (closed_)
    return FRAME_CLOSE;

  HttpConnection::ReadIOBuffer* read_buf = connection_->read_buf();
  base::StringPiece frame(read_buf->StartOfBuffer(), read_buf->GetSize());
  int bytes_consumed = 0;
  ParseResult result = encoder_->DecodeFrame(frame, &bytes_consumed, message);
  if (result == FRAME_OK)
    read_buf->DidConsume(bytes_consumed);
  if (result == FRAME_CLOSE)
    closed_ = true;
  return result;
}

void WebSocket::Send(const std::string& message) {
  if (closed_)
    return;
  std::string encoded;
  encoder_->EncodeFrame(message, 0, &encoded);
  server_->SendRaw(connection_->id(), encoded);
}

void WebSocket::Fail() {
  closed_ = true;
  // TODO(yhirano): The server SHOULD log the problem.
  server_->Close(connection_->id());
}

void WebSocket::SendErrorResponse(const std::string& message) {
  if (closed_)
    return;
  closed_ = true;
  server_->Send500(connection_->id(), message);
}

}  // namespace net
