// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_handshake_stream_create_helper.h"

#include <utility>

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/memory/weak_ptr.h"
#include "net/socket/client_socket_handle.h"
#include "net/spdy/spdy_session.h"
#include "net/websockets/websocket_basic_handshake_stream.h"

namespace net {

WebSocketHandshakeStreamCreateHelper::WebSocketHandshakeStreamCreateHelper(
    WebSocketStream::ConnectDelegate* connect_delegate,
    const std::vector<std::string>& requested_subprotocols)
    : requested_subprotocols_(requested_subprotocols),
      stream_(NULL),
      connect_delegate_(connect_delegate),
      failure_message_(NULL) {
  DCHECK(connect_delegate_);
}

WebSocketHandshakeStreamCreateHelper::~WebSocketHandshakeStreamCreateHelper() {}

WebSocketHandshakeStreamBase*
WebSocketHandshakeStreamCreateHelper::CreateBasicStream(
    scoped_ptr<ClientSocketHandle> connection,
    bool using_proxy) {
  DCHECK(failure_message_) << "set_failure_message() must be called";
  // The list of supported extensions and parameters is hard-coded.
  // TODO(ricea): If more extensions are added, consider a more flexible
  // method.
  std::vector<std::string> extensions(
      1, "permessage-deflate; client_max_window_bits");
  WebSocketBasicHandshakeStream* stream = new WebSocketBasicHandshakeStream(
      std::move(connection), connect_delegate_, using_proxy,
      requested_subprotocols_, extensions, failure_message_);
  OnStreamCreated(stream);
  stream_ = stream;
  return stream;
}

// TODO(ricea): Create a WebSocketSpdyHandshakeStream. crbug.com/323852
WebSocketHandshakeStreamBase*
WebSocketHandshakeStreamCreateHelper::CreateSpdyStream(
    const base::WeakPtr<SpdySession>& session,
    bool use_relative_url) {
  NOTREACHED() << "Not implemented";
  return NULL;
}

scoped_ptr<WebSocketStream> WebSocketHandshakeStreamCreateHelper::Upgrade() {
  DCHECK(stream_);
  WebSocketHandshakeStreamBase* stream = stream_;
  stream_ = NULL;
  return stream->Upgrade();
}

void WebSocketHandshakeStreamCreateHelper::OnStreamCreated(
    WebSocketBasicHandshakeStream* stream) {
}

}  // namespace net
