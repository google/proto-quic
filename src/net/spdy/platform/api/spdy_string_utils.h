// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_PLATFORM_API_SPDY_STRING_UTILS_H_
#define NET_SPDY_PLATFORM_API_SPDY_STRING_UTILS_H_

#include <utility>

#include "net/spdy/platform/api/spdy_string.h"
#include "net/spdy/platform/impl/spdy_string_utils_impl.h"

namespace net {

template <typename... Args>
inline SpdyString SpdyStrCat(const Args&... args) {
  return SpdyStrCatImpl(std::forward<const Args&>(args)...);
}

template <typename... Args>
inline void SpdyStrAppend(SpdyString* output, const Args&... args) {
  SpdyStrAppendImpl(output, std::forward<const Args&>(args)...);
}

template <typename... Args>
inline SpdyString SpdyStringPrintf(const Args&... args) {
  return SpdyStringPrintfImpl(std::forward<const Args&>(args)...);
}

template <typename... Args>
inline void SpdyStringAppendF(const Args&... args) {
  SpdyStringAppendFImpl(std::forward<const Args&>(args)...);
}

inline char SpdyHexDigitToInt(char c) {
  return SpdyHexDigitToIntImpl(c);
}

}  // namespace net

#endif  // NET_SPDY_PLATFORM_API_SPDY_STRING_UTILS_H_
