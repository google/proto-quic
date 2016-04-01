// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_BALSA_HTTP_MESSAGE_CONSTANTS_H__
#define NET_TOOLS_BALSA_HTTP_MESSAGE_CONSTANTS_H__

namespace net {

const char* get_http_status_message(int status_message);
extern const int http_status_codes[];
extern const int http_status_code_count;

}  // namespace net

#endif  // NET_TOOLS_BALSA_HTTP_MESSAGE_CONSTANTS_H__

