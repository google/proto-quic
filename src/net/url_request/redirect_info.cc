// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/redirect_info.h"

namespace net {

RedirectInfo::RedirectInfo() : status_code(-1) {}

RedirectInfo::RedirectInfo(const RedirectInfo& other) = default;

RedirectInfo::~RedirectInfo() {}

}  // namespace net
