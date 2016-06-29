// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/next_proto.h"

namespace net {

bool NextProtoIsSPDY(NextProto next_proto) {
  return next_proto >= kProtoSPDYMinimumVersion &&
         next_proto <= kProtoSPDYMaximumVersion;
}

}  // namespace net
