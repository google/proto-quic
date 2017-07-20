// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_HTTP2_PLATFORM_IMPL_HTTP2_STRING_UTILS_IMPL_H_
#define NET_HTTP2_PLATFORM_IMPL_HTTP2_STRING_UTILS_IMPL_H_

#include <sstream>
#include <utility>

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/http2/platform/api/http2_string.h"

namespace net {

template <typename... Args>
inline Http2String Http2StrCatImpl(const Args&... args) {
  std::ostringstream oss;
  int dummy[] = {1, (oss << args, 0)...};
  static_cast<void>(dummy);
  return oss.str();
}

template <typename... Args>
inline void Http2StrAppendImpl(Http2String* output, Args... args) {
  output->append(Http2StrCatImpl(args...));
}

template <typename... Args>
inline Http2String Http2StringPrintfImpl(const Args&... args) {
  return base::StringPrintf(std::forward<const Args&>(args)...);
}

}  // namespace net

#endif  // NET_HTTP2_PLATFORM_IMPL_HTTP2_STRING_UTILS_IMPL_H_
