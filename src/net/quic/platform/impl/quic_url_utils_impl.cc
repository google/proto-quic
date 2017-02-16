// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/platform/impl/quic_url_utils_impl.h"

#include "url/gurl.h"

using base::StringPiece;
using std::string;

namespace net {

// static
string QuicUrlUtilsImpl::HostName(StringPiece url) {
  return GURL(url).host();
}

// static
bool QuicUrlUtilsImpl::IsValidUrl(StringPiece url) {
  return GURL(url).is_valid();
}

}  // namespace net
