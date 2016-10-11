// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_NEXT_PROTO_H_
#define NET_SOCKET_NEXT_PROTO_H_

#include <vector>

namespace net {

// This enum is used in Net.SSLNegotiatedAlpnProtocol histogram.
// Do not change or re-use values.
enum NextProto {
  kProtoUnknown = 0,
  kProtoHTTP11 = 1,
  kProtoHTTP2 = 2,
  kProtoQUIC1SPDY3 = 3,
  kProtoLast = kProtoQUIC1SPDY3
};

// List of protocols to use for NPN, used for configuring HttpNetworkSessions.
typedef std::vector<NextProto> NextProtoVector;

}  // namespace net

#endif  // NET_SOCKET_NEXT_PROTO_H_
