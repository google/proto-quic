// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SERVER_WEB_SOCKET_H_
#define NET_SERVER_WEB_SOCKET_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"

namespace net {

class HttpConnection;
class HttpServer;
class HttpServerRequestInfo;
class WebSocketEncoder;

class WebSocket final {
 public:
  enum ParseResult {
    FRAME_OK,
    FRAME_INCOMPLETE,
    FRAME_CLOSE,
    FRAME_ERROR
  };

  WebSocket(HttpServer* server, HttpConnection* connection);

  void Accept(const HttpServerRequestInfo& request);
  ParseResult Read(std::string* message);
  void Send(const std::string& message);
  ~WebSocket();

 private:
  void Fail();
  void SendErrorResponse(const std::string& message);

  HttpServer* const server_;
  HttpConnection* const connection_;
  std::unique_ptr<WebSocketEncoder> encoder_;
  bool closed_;

  DISALLOW_COPY_AND_ASSIGN(WebSocket);
};

}  // namespace net

#endif  // NET_SERVER_WEB_SOCKET_H_
