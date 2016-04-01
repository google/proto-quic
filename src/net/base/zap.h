// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_ZAP_H_
#define NET_BASE_ZAP_H_

#include <stddef.h>

#include <string>

#include "base/strings/string16.h"

namespace net {

// Zap functions are used to clear sensitive data in RAM to minimize the
// time that people can access them once they are written to disk.

// Overwrite a buffer  with 0's.
void ZapBuf(void* buf, size_t buf_len);

// Overwrite a string's internal buffer with 0's.
void ZapString(std::string* s);

// Overwrite a base::string16's internal buffer with 0's.
void ZapString(base::string16* s);

}  // net

#endif  // NET_BASE_ZAP_H_
