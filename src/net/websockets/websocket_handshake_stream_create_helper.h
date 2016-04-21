// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_WEBSOCKETS_WEBSOCKET_HANDSHAKE_STREAM_CREATE_HELPER_H_
#define NET_WEBSOCKETS_WEBSOCKET_HANDSHAKE_STREAM_CREATE_HELPER_H_

#include <memory>
#include <string>
#include <vector>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "net/websockets/websocket_stream.h"

namespace net {

class WebSocketBasicHandshakeStream;

// Implementation of WebSocketHandshakeStreamBase::CreateHelper. This class is
// used in the implementation of WebSocketStream::CreateAndConnectStream() and
// is not intended to be used by itself.
//
// Holds the information needed to construct a
// WebSocketBasicHandshakeStreamBase.
class NET_EXPORT_PRIVATE WebSocketHandshakeStreamCreateHelper
    : public WebSocketHandshakeStreamBase::CreateHelper {
 public:
  // |connect_delegate| must out-live this object.
  explicit WebSocketHandshakeStreamCreateHelper(
      WebSocketStream::ConnectDelegate* connect_delegate,
      const std::vector<std::string>& requested_subprotocols);

  ~WebSocketHandshakeStreamCreateHelper() override;

  // WebSocketHandshakeStreamBase::CreateHelper methods

  // Create a WebSocketBasicHandshakeStream.
  WebSocketHandshakeStreamBase* CreateBasicStream(
      std::unique_ptr<ClientSocketHandle> connection,
      bool using_proxy) override;

  // Unimplemented as of November 2013.
  WebSocketHandshakeStreamBase* CreateSpdyStream(
      const base::WeakPtr<SpdySession>& session,
      bool use_relative_url) override;

  // Call Upgrade() on the WebSocketHandshakeStream and return the result. This
  // must only be called if the handshake succeeded.
  std::unique_ptr<WebSocketStream> Upgrade();

  // Set a pointer to the std::string into which to write any failure messages
  // that are encountered. This method must be called before CreateBasicStream()
  // or CreateSpdyStream(). The |failure_message| pointer must remain valid as
  // long as this object exists.
  void set_failure_message(std::string* failure_message) {
    failure_message_ = failure_message;
  }

 protected:
  // This is used by DeterministicKeyWebSocketHandshakeStreamCreateHelper.
  // The default implementation does nothing.
  virtual void OnStreamCreated(WebSocketBasicHandshakeStream* stream);

 private:
  const std::vector<std::string> requested_subprotocols_;

  // This is owned by the caller of CreateBaseStream() or
  // CreateSpdyStream(). Both the stream and this object will be destroyed
  // during the destruction of the URLRequest object associated with the
  // handshake. This is only guaranteed to be a valid pointer if the handshake
  // succeeded.
  WebSocketHandshakeStreamBase* stream_;

  WebSocketStream::ConnectDelegate* connect_delegate_;
  std::string* failure_message_;

  DISALLOW_COPY_AND_ASSIGN(WebSocketHandshakeStreamCreateHelper);
};

}  // namespace net

#endif  // NET_WEBSOCKETS_WEBSOCKET_HANDSHAKE_STREAM_CREATE_HELPER_H_
