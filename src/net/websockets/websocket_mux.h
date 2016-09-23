// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_WEBSOCKETS_WEBSOCKET_MUX_H_
#define NET_WEBSOCKETS_WEBSOCKET_MUX_H_

namespace net {

// Reason codes used by the mux extension.
enum WebSocketMuxError {
  // Codes starting with 2000 apply to the physical connection. They are used
  // for dropping the control channel.
  kWebSocketMuxErrorPhysicalConnectionFailed = 2000,
  kWebSocketMuxErrorInvalidEncapsulatingMessage = 2001,
  kWebSocketMuxErrorChannelIdTruncated = 2002,
  kWebSocketMuxErrorEncapsulatedFrameIsTruncated = 2003,
  kWebSocketMuxErrorUnknownMuxOpcode = 2004,
  kWebSocketMuxErrorInvalidMuxControlBlock = 2005,
  kWebSocketMuxErrorChannelAlreadyExists = 2006,
  kWebSocketMuxErrorNewChannelSlotViolation = 2007,
  kWebSocketMuxErrorNewChannelSlotOverflow = 2008,
  kWebSocketMuxErrorBadRequest = 2009,
  kWebSocketMuxErrorUnknownRequestEncoding = 2010,
  kWebSocketMuxErrorBadResponse = 2011,
  kWebSocketMuxErrorUnknownResponseEncoding = 2012,

  // Codes starting with 3000 apply to the logical connection.
  kWebSocketMuxErrorLogicalChannelFailed = 3000,
  kWebSocketMuxErrorSendQuotaViolation = 3005,
  kWebSocketMuxErrorSendQuotaOverflow = 3006,
  kWebSocketMuxErrorIdleTimeout = 3007,
  kWebSocketMuxErrorDropChannelAck = 3008,
  kWebSocketMuxErrorBadFragmentation = 3009,
};

}  // namespace net

#endif  // NET_WEBSOCKETS_WEBSOCKET_MUX_H_
