// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/zap.h"

#include <string.h>

namespace net {

void ZapBuf(void* buf, size_t buf_len) {
  memset(buf, 0x0, buf_len);
}

void ZapString(std::string* s) {
  if (!s->empty())
    ZapBuf(&(*s)[0], s->length() * sizeof(char));
}

void ZapString(base::string16* s) {
  if (!s->empty())
    ZapBuf(&(*s)[0], s->length() * sizeof(base::char16));
}

}  // net
