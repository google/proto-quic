// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/next_proto.h"

namespace net {

NextProto NextProtoFromString(base::StringPiece proto_string) {
  if (proto_string == "http1.1" || proto_string == "http/1.1")
    return kProtoHTTP11;
  // "npn-h2" and "npn-spdy/3.1" are accepted here so that persisted
  // settings with the old string can be loaded from disk.
  // TODO(bnc):  Remove around 2016 December.
  if (proto_string == "h2" || proto_string == "npn-h2" ||
      proto_string == "npn-spdy/3.1") {
    return kProtoHTTP2;
  }
  if (proto_string == "quic")
    return kProtoQUIC;

  return kProtoUnknown;
}

const char* NextProtoToString(NextProto next_proto) {
  switch (next_proto) {
    case kProtoHTTP11:
      return "http/1.1";
    case kProtoHTTP2:
      return "h2";
    case kProtoQUIC:
      return "quic";
    case kProtoUnknown:
      break;
  }
  return "unknown";
}

}  // namespace net
