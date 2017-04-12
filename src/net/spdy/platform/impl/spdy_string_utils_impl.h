// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_PLATFORM_IMPL_SPDY_STRING_UTILS_IMPL_H_
#define NET_SPDY_PLATFORM_IMPL_SPDY_STRING_UTILS_IMPL_H_

#include <sstream>
#include <utility>

#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "net/spdy/platform/api/spdy_string.h"

namespace net {

template <typename... Args>
inline SpdyString SpdyStrCatImpl(const Args&... args) {
  std::ostringstream oss;
  int dummy[] = {1, (oss << args, 0)...};
  static_cast<void>(dummy);
  return oss.str();
}

template <typename... Args>
inline void SpdyStrAppendImpl(SpdyString* output, Args... args) {
  output->append(SpdyStrCatImpl(args...));
}

template <typename... Args>
inline SpdyString SpdyStringPrintfImpl(const Args&... args) {
  return base::StringPrintf(std::forward<const Args&>(args)...);
}

template <typename... Args>
inline void SpdyStringAppendFImpl(const Args&... args) {
  base::StringAppendF(std::forward<const Args&>(args)...);
}

inline char SpdyHexDigitToIntImpl(char c) {
  return base::HexDigitToInt(c);
}

}  // namespace net

#endif  // NET_SPDY_PLATFORM_IMPL_SPDY_STRING_UTILS_IMPL_H_
