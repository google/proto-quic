// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_NEXT_PROTO_H_
#define NET_SOCKET_NEXT_PROTO_H_

#include <vector>

#include "net/base/net_export.h"

namespace net {

// Next Protocol Negotiation (NPN), if successful, results in agreement on an
// application-level string that specifies the application level protocol to
// use over the TLS connection. NextProto enumerates the application level
// protocols that we recognize.  Do not change or reuse values, because they
// are used to collect statistics on UMA.  Also, values must be in [0,499),
// because of the way TLS protocol negotiation extension information is added to
// UMA histogram.
const int kProtoSPDYHistogramOffset = 100;
enum NextProto {
  kProtoUnknown = 0,
  kProtoHTTP11 = 1,
  kProtoMinimumVersion = kProtoHTTP11,

  kProtoSPDY31 = 102,
  kProtoSPDYMinimumVersion = kProtoSPDY31,
  // kProtoHTTP2_14 = 103,  // HTTP/2 draft-14
  // kProtoHTTP2_15 = 104,  // HTTP/2 draft-15
  // kProtoHTTP2_16 = 105,  // HTTP/2 draft-16
  // kProtoHTTP2_17 = 106,  // HTTP/2 draft-17
  kProtoHTTP2 = 107,  // HTTP/2, see https://tools.ietf.org/html/rfc7540.
  kProtoSPDYMaximumVersion = kProtoHTTP2,

  kProtoQUIC1SPDY3 = 200,

  kProtoMaximumVersion = kProtoQUIC1SPDY3,
};

// List of protocols to use for NPN, used for configuring HttpNetworkSessions.
typedef std::vector<NextProto> NextProtoVector;

// Convenience functions to create NextProtoVector.

// Returns true if |next_proto| is a version of SPDY or HTTP/2.
bool NextProtoIsSPDY(NextProto next_proto);

// Remove HTTP/2 from |next_protos|.
NET_EXPORT void DisableHTTP2(NextProtoVector* next_protos);

}  // namespace net

#endif  // NET_SOCKET_NEXT_PROTO_H_
