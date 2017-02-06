// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/api/quic_url_utils.h"

using base::StringPiece;
using std::string;

namespace net {

// static
string QuicUrlUtils::HostName(StringPiece url) {
  return QuicUrlUtilsImpl::HostName(url);
}

// static
bool QuicUrlUtils::IsValidUrl(StringPiece url) {
  return QuicUrlUtilsImpl::IsValidUrl(url);
}

// static
bool QuicUrlUtils::IsValidSNI(StringPiece sni) {
  return QuicUrlUtilsImpl::IsValidSNI(sni);
}

// static
char* QuicUrlUtils::NormalizeHostname(char* hostname) {
  return QuicUrlUtilsImpl::NormalizeHostname(hostname);
}

// static
void QuicUrlUtils::StringToQuicServerId(const string& str, QuicServerId* out) {
  QuicUrlUtilsImpl::StringToQuicServerId(str, out);
}

}  // namespace net
